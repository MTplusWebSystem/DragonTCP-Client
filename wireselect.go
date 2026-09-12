package main

import (
	"fmt"
	"net"
	"sync"
	"time"

	"dragontcp/internal/cover"
	"dragontcp/internal/wire"
	"dragontcp/internal/xorchunk"
)

// DragonTCP speaks three wires that are not interchangeable:
//
//	b — compact binary records (29/5-byte headers, SHA-256-masked payloads by default)
//	bp — compatible registration/upload/download/ACK records, SHA-256-masked by default
//	x — legacy UP/OK framing with XOR 0xAD over ASCII chunk commands
//
// Networks differ in which they pass, so the client can be pinned to either or
// left on auto. Startup performs a tiny server-local profile probe and caches
// the first wire/header profile that survives the carrier.
const (
	WireBinary = "b"
	WireBP     = "bp"
	WireXOR    = "x"
	WireAuto   = "auto"
)

// Header/profile discovery uses one tiny server-local protocol transaction.
// It does not open an Internet target and therefore measures only whether the
// candidate DragonTCP framing survives the carrier and is understood by the
// server. Path chunk calibration runs separately after a header is selected.
const profileProbeTimeout = 2 * time.Second

type wireSelector struct {
	mu           sync.Mutex
	configured   string // b, x or auto
	resolved     wireChoice
	hasChoice    bool
	serverAddr   string
	token        string
	binOpts      chunkClientOptions
	xorOpts      xorchunk.Options
	probeDelay   time.Duration
	probeThreads int
	forceClear   bool

	// Test hooks are nil in production.
	candidateOverride []wireChoice
	probeOverride     func(wireChoice) bool
}

type wireChoice struct {
	mode  string
	mask  byte
	cover cover.Profile
}

// forcedClearChoice builds a clear-payload cover profile with an explicit
// binary header mask. Clear payload and header masking are independent: a
// 0x00 header mask can still carry a fully clear payload because the cover
// preface advertises Clear=true to the server.
//
// --force-clear-payload deliberately tries mask 0x00 first, then 0x25. Both
// profiles keep SHA-256 payload masking disabled. A successful choice is cached
// for the process lifetime, so all reconnects use the same clear profile.
func forcedClearChoice(mode string, headerMask byte) wireChoice {
	id := uint16(0x0000)
	if headerMask == 0x25 {
		// Retain the previously deployed clear profile ID for the 0x25 fallback.
		id = 0x0065
	}
	profile := cover.Profile{
		Enabled:    true,
		ID:         id,
		Padding:    0,
		HeaderMask: headerMask,
		XOR:        false,
		Clear:      true,
	}
	return wireChoice{mode: mode, mask: profile.HeaderMask, cover: profile}
}

// validBinaryHeaderMask reports whether a direct B/BP header mask is
// unambiguous to the server's legacy classifier. B/BP encode the request mode
// in the low three bits (0..4), so those bits in the mask must be zero. This
// leaves exactly 32 valid masks: 00,08,10,...,F8.
func validBinaryHeaderMask(mask byte) bool {
	return mask&0x07 == 0
}

// validXORHeaderMask reports whether a direct X mask remains in the X side of
// the server's first-byte partition. X starts with 'U'^mask and the server
// recognizes X only when those low three bits are 5, 6, or 7. There are 96
// such masks.
func validXORHeaderMask(mask byte) bool {
	return ('U'^mask)&0x07 >= 5
}

func (c wireChoice) String() string {
	if c.mode == WireBP {
		if c.cover.Enabled {
			return fmt.Sprintf("bp/%s", c.cover)
		}
		return "bp/direct"
	}
	if c.cover.Enabled {
		return fmt.Sprintf("%s/mask-%02x/%s", c.mode, c.mask, c.cover)
	}
	return fmt.Sprintf("%s/mask-%02x/direct", c.mode, c.mask)
}

func newWireSelector(configured, serverAddr, token string, binOpts chunkClientOptions, xorOpts xorchunk.Options, probeDelay time.Duration, probeThreads int, forceClear bool) *wireSelector {
	s := &wireSelector{
		configured:   configured,
		serverAddr:   serverAddr,
		token:        token,
		binOpts:      binOpts,
		xorOpts:      xorOpts,
		probeDelay:   probeDelay,
		probeThreads: probeThreads,
		forceClear:   forceClear,
	}
	return s
}

// resolveOnly validates and locks the wire/header profile without running UP/DW
// chunk calibration. Port-range discovery uses this to ensure a TCP-open port is
// actually a DragonTCP endpoint before it is exposed as the WORKING PORT.
func (s *wireSelector) resolveOnly() (wireChoice, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hasChoice {
		return s.resolved, nil
	}
	choice, ok := s.detectLocked()
	if !ok {
		return wireChoice{}, fmt.Errorf("no validated DragonTCP wire/header profile")
	}
	s.resolved = choice
	s.hasChoice = true
	return choice, nil
}

// prepare resolves/authenticates the wire and calibrates its carrier limits
// before latency-sensitive protocols (notably SSH) are allowed to start. The
// successful wire choice and path profile are cached, so the real SSH OPEN does
// not repeat discovery/calibration.
func (s *wireSelector) prepare() (wireChoice, error) {
	fmt.Printf("[D-TCP] phase=AUTH state=starting configured_wire=%s force_clear_payload=%t\n", s.configured, s.forceClear)

	s.mu.Lock()
	choice := s.resolved
	ok := s.hasChoice
	if !ok {
		choice, ok = s.detectLocked()
		if ok {
			s.resolved = choice
			s.hasChoice = true
		}
	}
	opts := s.binOpts
	s.mu.Unlock()

	if !ok {
		fmt.Printf("[D-TCP] phase=AUTH state=failed reason=no_validated_wire\n")
		return wireChoice{}, fmt.Errorf("DragonTCP authentication/wire validation failed")
	}
	fmt.Printf("[D-TCP] phase=AUTH state=success wire=%s header_mask=%02x clear_payload=%t cover_id=%04x\n", choice.mode, choice.mask, choice.cover.Clear, choice.cover.ID)

	if choice.mode == WireXOR {
		xopts := s.xorOpts
		if choice.cover.Enabled {
			xopts = xopts.WithCoverProfile(choice.cover)
		} else {
			xopts = xopts.WithHeaderMask(choice.mask)
		}
		fmt.Printf("[D-TCP] phase=CALIBRATION state=starting wire=x strategy=ascending min=%d max=%d growth=4x fine_resolution=%d up_down=sequential\n", xopts.MinSize(), xopts.MaxSize(), calibrationFineResolution)
		up, down, persistent := xorchunk.Calibrate(s.serverAddr, s.token, xopts, calibrationFineResolution)
		xopts = xopts.WithCalibratedChunks(up, down)
		s.mu.Lock()
		s.xorOpts = xopts
		s.mu.Unlock()
		fmt.Printf("[D-TCP] phase=CALIBRATION state=success wire=x upload=%d download=%d persistent=%t lock_runtime_chunks=true\n", up, down, persistent)
		fmt.Printf("[D-TCP] phase=ACTIVE wire=%s header_mask=%02x clear_payload=%t upload_chunk=%d download_chunk=%d calibrated_locked=true runtime_adaptive=false\n", choice.mode, choice.mask, choice.cover.Clear, up, down)
		return choice, nil
	}

	opts.headerMask = choice.mask
	opts.coverProfile = choice.cover
	strategy := "ascending"
	if opts.forceMaxStart {
		strategy = "max-first"
	}
	if opts.forceMaxStart {
		fmt.Printf("[D-TCP] phase=CALIBRATION state=starting strategy=%s min=%d max=%d coarse_step=%d fine_resolution=%d\n", strategy, opts.minSize, opts.maxSize, maxFirstCoarseStep, maxFirstFineResolution)
	} else {
		fmt.Printf("[D-TCP] phase=CALIBRATION state=starting strategy=%s min=%d max=%d growth=4x fine_resolution=%d up_down=sequential\n", strategy, opts.minSize, opts.maxSize, calibrationFineResolution)
	}
	profile := getPathProfile(s.serverAddr, s.token, opts)
	fmt.Printf("[D-TCP] phase=CALIBRATION state=success upload=%d download=%d persistent=%t\n", profile.upload, profile.download, profile.persistent)
	fmt.Printf("[D-TCP] phase=ACTIVE wire=%s header_mask=%02x clear_payload=%t upload_chunk=%d download_chunk=%d\n", choice.mode, choice.mask, choice.cover.Clear, profile.upload, profile.download)
	return choice, nil
}

// dial opens a tunnel over the active wire, resolving the wire first if needed.
func (s *wireSelector) dial(host string, port int) (net.Conn, error) {
	choice := s.mode()
	if choice.mode == WireBP {
		opts := s.binOpts
		opts.headerMask = choice.mask
		opts.coverProfile = choice.cover
		return openBPTunnel(s.serverAddr, s.token, host, port, opts)
	}
	if choice.mode == WireXOR {
		if choice.cover.Enabled {
			return xorchunk.Open(s.serverAddr, s.token, host, port, s.xorOpts.WithCoverProfile(choice.cover))
		}
		return xorchunk.Open(s.serverAddr, s.token, host, port, s.xorOpts.WithHeaderMask(choice.mask))
	}
	opts := s.binOpts
	opts.headerMask = choice.mask
	opts.coverProfile = choice.cover
	return openChunkTunnel(s.serverAddr, s.token, host, port, opts)
}

// mode returns the wire to use, running detection once if configured as auto.
// Detection failure is not cached, so a client that starts before the network
// is usable retries on the next connection instead of latching a bad guess.
func (s *wireSelector) mode() wireChoice {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hasChoice {
		return s.resolved
	}
	if picked, ok := s.detectLocked(); ok {
		s.resolved = picked
		s.hasChoice = true
		return picked
	}
	if s.forceClear {
		// Hard guarantee: never silently fall back to a legacy SHA-256-masked
		// payload if the user explicitly requested clear payloads.
		if candidates := s.profileCandidates(); len(candidates) > 0 {
			return candidates[0]
		}
	}
	// Undecided: honor an explicitly pinned family for this attempt without
	// caching it. Auto retains the original B fallback and retries discovery on
	// the next connection.
	switch s.configured {
	case WireBP:
		return wireChoice{mode: WireBP}
	case WireXOR:
		return wireChoice{mode: WireXOR}
	default:
		return wireChoice{mode: WireBinary}
	}
}

// profileCandidates returns only masks that are mathematically valid for the
// direct server classifier. Numeric order keeps mask 0x00 first on permissive
// networks and avoids the old exhaustive covered 0x00..0xFF scan.
func (s *wireSelector) profileCandidates() []wireChoice {
	// A forced clear payload is retained for CLI compatibility/testing only.
	// Android does not expose it. Clear payload and header mask are independent.
	if s.forceClear {
		switch s.configured {
		case WireBinary:
			return []wireChoice{
				forcedClearChoice(WireBinary, 0x00),
				forcedClearChoice(WireBinary, 0x25),
			}
		case WireBP:
			return []wireChoice{
				forcedClearChoice(WireBP, 0x00),
				forcedClearChoice(WireBP, 0x25),
			}
		case WireAuto:
			return []wireChoice{
				forcedClearChoice(WireBinary, 0x00),
				forcedClearChoice(WireBP, 0x00),
				forcedClearChoice(WireBinary, 0x25),
				forcedClearChoice(WireBP, 0x25),
			}
		default:
			return nil
		}
	}

	wantB := s.configured == WireAuto || s.configured == WireBinary
	wantBP := s.configured == WireAuto || s.configured == WireBP
	wantX := s.configured == WireAuto || s.configured == WireXOR

	// Normal masked discovery uses only masks that the direct wire classifier
	// can decode without a cover preface. This removes the old 0x00..0xFF x 3
	// covered scan. Auto stays ordered by numeric mask so 0x00 is tested first.
	//
	// B/BP: 32 masks (low 3 bits must be zero).
	// X:    96 masks (('U'^mask)&7 must land in 5..7).
	// Auto: 160 total candidates, rather than ~900 covered/direct probes.
	out := make([]wireChoice, 0, 160)
	for n := 0; n < 256; n++ {
		mask := byte(n)
		if validBinaryHeaderMask(mask) {
			if wantB {
				out = append(out, wireChoice{mode: WireBinary, mask: mask})
			}
			if wantBP {
				out = append(out, wireChoice{mode: WireBP, mask: mask})
			}
		}
		if wantX && validXORHeaderMask(mask) {
			out = append(out, wireChoice{mode: WireXOR, mask: mask})
		}
	}

	return out
}

// detectLocked validates header/profile candidates with tiny server-local
// protocol probes. The default is one worker. Users may explicitly allow more
// workers, while the launch delay still spaces new attempts globally.
func (s *wireSelector) detectLocked() (wireChoice, bool) {
	candidates := s.profileCandidates()
	if s.candidateOverride != nil {
		candidates = s.candidateOverride
	}
	threads := s.probeThreads
	if threads < 1 {
		threads = 1
	}
	if threads > 16 {
		threads = 16
	}
	delay := s.probeDelay
	if delay <= 0 {
		delay = 100 * time.Millisecond
	}
	type result struct {
		choice wireChoice
		ok     bool
	}
	results := make(chan result, threads)
	next := 0
	inflight := 0
	completed := 0
	started := time.Now()
	var lastLaunch time.Time
	for next < len(candidates) || inflight > 0 {
		canLaunch := next < len(candidates) && inflight < threads
		if canLaunch && (lastLaunch.IsZero() || time.Since(lastLaunch) >= delay) {
			candidate := candidates[next]
			next++
			inflight++
			lastLaunch = time.Now()
			go func(choice wireChoice) {
				validated := false
				if s.probeOverride != nil {
					validated = s.probeOverride(choice)
				} else {
					validated = s.probe(choice)
				}
				results <- result{choice: choice, ok: validated}
			}(candidate)
			continue
		}

		var got result
		if canLaunch {
			wait := delay - time.Since(lastLaunch)
			timer := time.NewTimer(wait)
			select {
			case got = <-results:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
			case <-timer.C:
				continue
			}
		} else {
			got = <-results
		}
		inflight--
		completed++
		if got.ok {
			fmt.Printf("wire probe: selected=%s header_mask=%02x completed=%d launched=%d elapsed=%s protocol_probe=true threads=%d fixed_until_restart=true\n", got.choice, got.choice.mask, completed, next, time.Since(started).Round(time.Millisecond), threads)
			return got.choice, true
		}
		if completed%32 == 0 {
			fmt.Printf("wire probe: completed=%d/%d launched=%d elapsed=%s protocol_probe=true no validated profile yet\n", completed, len(candidates), next, time.Since(started).Round(time.Millisecond))
		}
	}
	fmt.Printf("wire probe: no header/profile validated after %d candidates in %s; retrying later\n", completed, time.Since(started).Round(time.Millisecond))
	return wireChoice{}, false
}

// probe performs one small server-local framing transaction. This is purposely
// separate from UP/DW fake-iperf calibration: header discovery answers "which
// byte/profile survives?", while calibration answers "what chunk size is safe?".
func (s *wireSelector) probe(choice wireChoice) bool {
	switch choice.mode {
	case WireXOR:
		opts := s.xorOpts
		if choice.cover.Enabled {
			opts = opts.WithCoverProfile(choice.cover)
		} else {
			opts = opts.WithHeaderMask(choice.mask)
		}
		return xorchunk.ProbeProfile(s.serverAddr, s.token, opts)

	case WireBP:
		opts := s.binOpts
		opts.headerMask = choice.mask
		opts.coverProfile = choice.cover
		if opts.txnTimeout <= 0 || opts.txnTimeout > profileProbeTimeout {
			opts.txnTimeout = profileProbeTimeout
		}
		return probeBPProfile(s.serverAddr, opts)

	default:
		opts := s.binOpts
		opts.headerMask = choice.mask
		opts.coverProfile = choice.cover
		opts.skipPathProbe = true
		opts.minSize = 32
		opts.startSize = 32
		opts.maxSize = 32
		if opts.txnTimeout <= 0 || opts.txnTimeout > profileProbeTimeout {
			opts.txnTimeout = profileProbeTimeout
		}
		return probeOne(s.serverAddr, s.token, opts, wire.ProbeKeepalive, 0)
	}
}
