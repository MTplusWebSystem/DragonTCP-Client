package main

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"dragontcp/internal/cover"
	"dragontcp/internal/protocol"
	"dragontcp/internal/wire"
)

type chunkClientOptions struct {
	startSize      int
	minSize        int
	maxSize        int
	adaptive       bool
	adaptSuccesses int
	shrinkAfter    int
	shrinkStep     int
	adaptLog       bool
	pollers        int
	reconnectEvery int
	pollDelay      time.Duration
	txnTimeout     time.Duration
	tcpBuffer      int
	minPipeline    int
	maxPipeline    int
	headerMask     byte
	coverProfile   cover.Profile
	skipPathProbe  bool
	forceMaxStart  bool
}

type adaptiveSizer struct {
	mu             sync.Mutex
	name           string
	current        int
	min            int
	max            int
	adaptive       bool
	adaptSuccesses int
	shrinkAfter    int
	shrinkStep     int
	failures       int
	successes      int
	good           int
	bad            int
	logChanges     bool
}

func newAdaptiveSizer(name string, start int, opts chunkClientOptions) *adaptiveSizer {
	if start < opts.minSize {
		start = opts.minSize
	}
	if start > opts.maxSize {
		start = opts.maxSize
	}
	return &adaptiveSizer{
		name:     name,
		current:  start,
		min:      opts.minSize,
		max:      opts.maxSize,
		adaptive: opts.adaptive,
		adaptSuccesses: func() int {
			if opts.adaptSuccesses > 0 {
				return opts.adaptSuccesses
			}
			return 64
		}(),
		shrinkAfter: func() int {
			if opts.shrinkAfter > 0 {
				return opts.shrinkAfter
			}
			return 1
		}(),
		shrinkStep: opts.shrinkStep,
		logChanges: opts.adaptLog,
	}
}

func (s *adaptiveSizer) Current() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.current
}

func (s *adaptiveSizer) Success(attempted int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.adaptive || attempted != s.current {
		return
	}
	// A real success proves the current size still works. In max-first mode this
	// resets the consecutive-failure budget so isolated carrier errors never
	// cause a downshift.
	s.failures = 0
	if s.current >= s.max {
		return
	}
	if attempted > s.good {
		s.good = attempted
	}
	s.successes++
	growAfter := s.adaptSuccesses
	if s.bad > 0 && s.bad-s.good <= 64 {
		growAfter *= 8
	}
	if s.successes < growAfter {
		return
	}
	s.successes = 0

	old := s.current
	next := 0
	if s.bad > old+1 {
		next = old + (s.bad-old)/2
	} else {
		if s.bad > 0 {
			s.bad = 0
		}
		step := old / 4
		if step < 32 {
			step = 32
		}
		next = old + step
	}
	if next > s.max {
		next = s.max
	}
	if next <= old {
		return
	}
	s.current = next
	if s.logChanges {
		fmt.Printf("adaptive %s chunk: %d -> %d after stable success\n", s.name, old, next)
	}
}

func (s *adaptiveSizer) Failure(attempted int) (int, int) {
	return s.FailureReason(attempted, nil)
}

func (s *adaptiveSizer) FailureReason(attempted int, cause error) (int, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.current
	if !s.adaptive || attempted != s.current {
		return old, old
	}
	s.successes = 0
	s.failures++
	if s.failures < s.shrinkAfter {
		if s.logChanges && s.shrinkAfter > 1 {
			fmt.Printf("adaptive %s chunk: holding %d after failure %d/%d: %v\n", s.name, old, s.failures, s.shrinkAfter, cause)
		}
		return old, old
	}
	s.failures = 0
	if s.bad == 0 || attempted < s.bad {
		s.bad = attempted
	}
	next := attempted / 2
	if s.shrinkStep > 0 {
		next = attempted - s.shrinkStep
		// MAX-FIRST linear downgrade intentionally ignores an older known-good
		// point: the goal is to walk down in small deterministic steps instead
		// of making a large jump after a transient carrier rejection.
		s.good = 0
	} else if s.good > 0 && s.good < attempted {
		next = s.good
	} else {
		s.good = 0
	}
	if next < s.min {
		next = s.min
	}
	if next >= attempted && attempted > s.min {
		next = attempted - 1
	}
	if next < s.min {
		next = s.min
	}
	s.current = next
	if s.logChanges && old != next {
		if cause != nil {
			fmt.Printf("adaptive %s chunk: %d -> %d after transport failure: %v\n", s.name, old, next, cause)
		} else {
			fmt.Printf("adaptive %s chunk: %d -> %d after transport failure\n", s.name, old, next)
		}
	}
	return old, next
}

type physicalConn struct {
	conn     net.Conn
	requests int
}

type requestLane struct {
	mu             sync.Mutex
	serverAddr     string
	tcpBuffer      int
	reconnectEvery int
	timeout        time.Duration
	headerMask     byte
	coverProfile   cover.Profile
	autoReconnect  bool
	pc             *physicalConn
	closed         bool
}

func newRequestLane(serverAddr string, tcpBuffer, reconnectEvery int, timeout time.Duration, headerMask byte, coverProfile cover.Profile) *requestLane {
	autoReconnect := reconnectEvery == 1
	if autoReconnect {
		// Auto starts persistent. If a request fails only after this lane has
		// already completed traffic on the connection, it learns that reuse is
		// unsafe and switches itself to one request per connection.
		reconnectEvery = 0
	}
	return &requestLane{
		serverAddr:     serverAddr,
		tcpBuffer:      tcpBuffer,
		reconnectEvery: reconnectEvery,
		timeout:        timeout,
		headerMask:     headerMask,
		coverProfile:   coverProfile,
		autoReconnect:  autoReconnect,
	}
}

func (l *requestLane) transportFailureLocked(reused bool) {
	if l.autoReconnect && reused {
		l.reconnectEvery = 1
	}
	l.discardLocked()
}

func (l *requestLane) discardLocked() {
	if l.pc != nil {
		_ = l.pc.conn.Close()
		l.pc = nil
	}
}

func (l *requestLane) closeAfterLocked() {
	if l.pc != nil && l.reconnectEvery > 0 && l.pc.requests >= l.reconnectEvery {
		l.discardLocked()
	}
}

func (l *requestLane) ensureLocked() error {
	if l.closed {
		return net.ErrClosed
	}
	if l.pc != nil {
		if l.reconnectEvery <= 0 || l.pc.requests < l.reconnectEvery {
			return nil
		}
		l.discardLocked()
	}
	d := net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	conn, err := d.Dial("tcp", l.serverAddr)
	if err != nil {
		return err
	}
	if err := cover.WritePreface(conn, l.coverProfile); err != nil {
		_ = conn.Close()
		return err
	}
	protocol.TuneTCP(conn)
	protocol.TuneTCPBuffer(conn, l.tcpBuffer)
	l.pc = &physicalConn{conn: conn}
	return nil
}

func (l *requestLane) Close() {
	l.mu.Lock()
	l.closed = true
	l.discardLocked()
	l.mu.Unlock()
}

func (l *requestLane) single(mode byte, sid wire.SessionID, seq uint64, payload []byte) (byte, []byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	timeout := l.timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if err := l.ensureLocked(); err != nil {
			// A dial timeout is a dead path for this logical tunnel. Do not
			// spend another timeout replaying the same request.
			if isTransportTimeout(err) {
				return 0, nil, err
			}
			lastErr = err
			continue
		}
		reused := l.pc.requests > 0
		_ = l.pc.conn.SetDeadline(time.Now().Add(timeout))
		if err := wire.WriteRequestProfileEncoding(l.pc.conn, mode, sid, seq, payload, l.headerMask, l.coverProfile.Clear); err != nil {
			l.transportFailureLocked(reused)
			if isTransportTimeout(err) {
				return 0, nil, err
			}
			lastErr = err
			continue
		}
		status, body, err := wire.ReadResponseProfile(l.pc.conn, l.headerMask)
		if err != nil {
			l.transportFailureLocked(reused)
			if isTransportTimeout(err) {
				return 0, nil, err
			}
			lastErr = err
			continue
		}
		l.pc.requests++
		_ = l.pc.conn.SetDeadline(time.Time{})
		l.closeAfterLocked()
		if status != wire.StatusError && len(body) > 0 && !l.coverProfile.Clear {
			body = wire.DecodeMaskedResponse(status, body, sid, mode, seq)
		}
		return status, body, nil
	}
	return 0, nil, fmt.Errorf("request failed after reconnect: %w", lastErr)
}

// download sends one compact request and consumes up to count response records.
// startOffset is also the response keystream sequence. Each DATA response advances
// it by exactly the returned byte count.
func (l *requestLane) download(sid wire.SessionID, startOffset, ackOffset uint64, maxChunk, count int) ([][]byte, byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	timeout := l.timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	payload := make([]byte, 14)
	binary.BigEndian.PutUint64(payload[0:8], ackOffset)
	binary.BigEndian.PutUint32(payload[8:12], uint32(maxChunk))
	binary.BigEndian.PutUint16(payload[12:14], uint16(count))
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if err := l.ensureLocked(); err != nil {
			if isTransportTimeout(err) {
				return nil, 0, err
			}
			lastErr = err
			continue
		}
		reused := l.pc.requests > 0
		_ = l.pc.conn.SetDeadline(time.Now().Add(timeout))
		if err := wire.WriteRequestProfileEncoding(l.pc.conn, wire.ModeDownload, sid, startOffset, payload, l.headerMask, l.coverProfile.Clear); err != nil {
			l.transportFailureLocked(reused)
			if isTransportTimeout(err) {
				return nil, 0, err
			}
			lastErr = err
			continue
		}

		out := make([][]byte, 0, count)
		offset := startOffset
		lastStatus := wire.StatusOK
		for i := 0; i < count; i++ {
			status, body, err := wire.ReadResponseProfile(l.pc.conn, l.headerMask)
			if err != nil {
				l.transportFailureLocked(reused)
				if isTransportTimeout(err) {
					return nil, 0, err
				}
				lastErr = err
				goto retry
			}
			lastStatus = status
			switch status {
			case wire.StatusData:
				if !l.coverProfile.Clear {
					body = wire.DecodeMaskedResponse(status, body, sid, wire.ModeDownload, offset)
				}
				if len(body) == 0 {
					l.discardLocked()
					return out, status, fmt.Errorf("empty DATA response")
				}
				out = append(out, body)
				offset += uint64(len(body))
			case wire.StatusWait, wire.StatusEOF:
				i = count // stop after this response
			case wire.StatusError:
				l.discardLocked()
				return out, status, fmt.Errorf("%s", string(body))
			default:
				l.discardLocked()
				return out, status, fmt.Errorf("unknown response status %d", status)
			}
			if status == wire.StatusWait || status == wire.StatusEOF {
				break
			}
		}

		l.pc.requests++
		_ = l.pc.conn.SetDeadline(time.Time{})
		l.closeAfterLocked()
		return out, lastStatus, nil
	retry:
	}
	return nil, 0, fmt.Errorf("download request failed after reconnect: %w", lastErr)
}

type pathProfile struct {
	upload     int
	download   int
	persistent bool
	at         time.Time
}

var profileState struct {
	sync.Mutex
	key string
	p   pathProfile
}

var probeSeq atomic.Uint64

func randomSessionID() (wire.SessionID, error) {
	var sid wire.SessionID
	_, err := rand.Read(sid[:])
	return sid, err
}

func probePattern(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte((i*31 + 17) & 0xff)
	}
	return out
}

func makeProbePayload(kind byte, value, total int, token string) []byte {
	base := 11 + len(token)
	if total < base {
		total = base
	}
	out := make([]byte, total)
	copy(out[:4], wire.ProbeMagic[:])
	out[4] = kind
	binary.BigEndian.PutUint16(out[5:7], uint16(len(token)))
	binary.BigEndian.PutUint32(out[7:11], uint32(value))
	copy(out[11:11+len(token)], token)
	for i := base; i < len(out); i++ {
		out[i] = byte((i*31 + 17) & 0xff)
	}
	return out
}

func probeOne(serverAddr, token string, opts chunkClientOptions, kind byte, candidate int) bool {
	sid, err := randomSessionID()
	if err != nil {
		return false
	}
	timeout := opts.txnTimeout
	if timeout <= 0 || timeout > 2500*time.Millisecond {
		timeout = 2500 * time.Millisecond
	}
	lane := newRequestLane(serverAddr, opts.tcpBuffer, 1, timeout, opts.headerMask, opts.coverProfile)
	defer lane.Close()
	seq := probeSeq.Add(1)

	total := 0
	value := candidate
	if kind == wire.ProbeUpload {
		total = candidate
	}
	payload := makeProbePayload(kind, value, total, token)
	status, body, err := lane.single(wire.ModeProbe, sid, seq, payload)
	if err != nil {
		return false
	}
	if kind == wire.ProbeUpload {
		return status == wire.StatusOK
	}
	if kind == wire.ProbeDownload {
		if status != wire.StatusData || len(body) != candidate {
			return false
		}
		want := probePattern(candidate)
		for i := range body {
			if body[i] != want[i] {
				return false
			}
		}
		return true
	}
	return status == wire.StatusOK
}

type iperfProbeResult struct {
	ok      bool
	bytes   int
	elapsed time.Duration
	err     error
}

func (r iperfProbeResult) mbps() float64 {
	if r.elapsed <= 0 || r.bytes <= 0 {
		return 0
	}
	return (float64(r.bytes) * 8) / r.elapsed.Seconds() / 1_000_000
}

func calibrationDeadline(opts chunkClientOptions) time.Duration {
	t := opts.txnTimeout
	if t < 8*time.Second {
		t = 8 * time.Second
	}
	if t > 20*time.Second {
		t = 20 * time.Second
	}
	return t
}

func dialProbeConn(serverAddr string, opts chunkClientOptions) (net.Conn, error) {
	d := net.Dialer{Timeout: minDuration(calibrationDeadline(opts), 10*time.Second), KeepAlive: 30 * time.Second}
	conn, err := d.Dial("tcp", serverAddr)
	if err != nil {
		return nil, err
	}
	if err := cover.WritePreface(conn, opts.coverProfile); err != nil {
		_ = conn.Close()
		return nil, err
	}
	protocol.TuneTCP(conn)
	protocol.TuneTCPBuffer(conn, opts.tcpBuffer)
	_ = conn.SetDeadline(time.Now().Add(calibrationDeadline(opts)))
	return conn, nil
}

// probeIperfOne validates one UP or DW record at a time against the DragonTCP
// server. Calibration is intentionally single-poller and never pipelines
// multiple outstanding records: it measures a single lane's safe record size,
// not aggregate throughput. Boundary confirmation retries happen sequentially
// on fresh connections.
func probeIperfOne(serverAddr, token string, opts chunkClientOptions, kind byte, candidate int) iperfProbeResult {
	count := wire.ProbeBurstCount(candidate)
	totalBytes := candidate * count
	conn, err := dialProbeConn(serverAddr, opts)
	if err != nil {
		return iperfProbeResult{err: err}
	}
	defer conn.Close()

	sid, err := randomSessionID()
	if err != nil {
		return iperfProbeResult{err: err}
	}
	startSeq := probeSeq.Add(uint64(count)) - uint64(count) + 1
	started := time.Now()

	switch kind {
	case wire.ProbeUpload:
		payload := makeProbePayload(wire.ProbeIperfUpload, candidate, candidate, token)
		totalBytes = len(payload) * count
		for i := 0; i < count; i++ {
			seq := startSeq + uint64(i)
			if err := wire.WriteRequestProfileEncoding(conn, wire.ModeProbe, sid, seq, payload, opts.headerMask, opts.coverProfile.Clear); err != nil {
				return iperfProbeResult{bytes: i * len(payload), elapsed: time.Since(started), err: err}
			}
		}
		for i := 0; i < count; i++ {
			status, body, err := wire.ReadResponseProfile(conn, opts.headerMask)
			if err != nil {
				return iperfProbeResult{bytes: totalBytes, elapsed: time.Since(started), err: err}
			}
			if status != wire.StatusOK {
				return iperfProbeResult{bytes: totalBytes, elapsed: time.Since(started), err: fmt.Errorf("upload status=%d body=%s", status, string(body))}
			}
		}
		return iperfProbeResult{ok: true, bytes: totalBytes, elapsed: time.Since(started)}

	case wire.ProbeDownload:
		payload := makeProbePayload(wire.ProbeIperfDownload, candidate, 0, token)
		if err := wire.WriteRequestProfileEncoding(conn, wire.ModeProbe, sid, startSeq, payload, opts.headerMask, opts.coverProfile.Clear); err != nil {
			return iperfProbeResult{elapsed: time.Since(started), err: err}
		}
		want := probePattern(candidate)
		gotBytes := 0
		for i := 0; i < count; i++ {
			status, body, err := wire.ReadResponseProfile(conn, opts.headerMask)
			if err != nil {
				return iperfProbeResult{bytes: gotBytes, elapsed: time.Since(started), err: err}
			}
			seq := startSeq + uint64(i)
			if status != wire.StatusError && len(body) > 0 && !opts.coverProfile.Clear {
				body = wire.DecodeMaskedResponse(status, body, sid, wire.ModeProbe, seq)
			}
			if status != wire.StatusData || !bytes.Equal(body, want) {
				return iperfProbeResult{bytes: gotBytes, elapsed: time.Since(started), err: fmt.Errorf("download validation failed status=%d len=%d want=%d", status, len(body), candidate)}
			}
			gotBytes += len(body)
		}
		return iperfProbeResult{ok: true, bytes: gotBytes, elapsed: time.Since(started)}
	default:
		return iperfProbeResult{err: fmt.Errorf("unknown iperf probe kind %d", kind)}
	}
}

func minDuration(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

func probePersistent(serverAddr, token string, opts chunkClientOptions) bool {
	sid, err := randomSessionID()
	if err != nil {
		return false
	}
	timeout := opts.txnTimeout
	if timeout <= 0 || timeout > 2500*time.Millisecond {
		timeout = 2500 * time.Millisecond
	}
	lane := newRequestLane(serverAddr, opts.tcpBuffer, 0, timeout, opts.headerMask, opts.coverProfile)
	defer lane.Close()
	for i := 0; i < 8; i++ {
		seq := probeSeq.Add(1)
		payload := makeProbePayload(wire.ProbeKeepalive, i, 32+len(token), token)
		status, _, err := lane.single(wire.ModeProbe, sid, seq, payload)
		if err != nil || status != wire.StatusOK {
			return false
		}
	}
	return true
}

func probeCandidates(minSize, maxSize int) []int {
	base := []int{32, 64, 128, 256, 512, 1024, 1200, 1280, 1320, 1350, 1360, 1380, 1400, 1450, 1600, 2048, 3205, 4096, 8192, 16384, 32768, 65536, 98304, 131072, 262144, 524288, 786432, 1048576}
	seen := map[int]bool{}
	out := make([]int, 0, len(base)+2)
	for _, n := range base {
		if n >= minSize && n <= maxSize && !seen[n] {
			out = append(out, n)
			seen[n] = true
		}
	}
	if !seen[minSize] {
		out = append(out, minSize)
	}
	if !seen[maxSize] {
		out = append(out, maxSize)
	}
	sort.Ints(out)
	return out
}

const calibrationFineResolution = 32

const calibrationDecisionAttempts = 3

// confirmIperfResult makes boundary decisions resistant to one transient
// carrier hiccup. The caller provides the first observation; this function
// opens fresh probe connections until either success or non-timeout failure has
// a 2-of-3 majority. Connection-level timeouts are inconclusive and never count
// as proof that a chunk size is too large.
func confirmIperfResult(serverAddr, token string, opts chunkClientOptions, kind byte, candidate int, first iperfProbeResult, stage string) iperfProbeResult {
	name := probeKindName(kind)
	successes, failures := 0, 0
	var lastSuccess, lastFailure, lastTimeout iperfProbeResult

	observe := func(r iperfProbeResult) {
		if r.ok {
			successes++
			lastSuccess = r
			return
		}
		if isTransportTimeout(r.err) {
			lastTimeout = r
			return
		}
		failures++
		lastFailure = r
	}

	observe(first)
	for attempt := 2; attempt <= calibrationDecisionAttempts && successes < 2 && failures < 2; attempt++ {
		r := probeIperfOne(serverAddr, token, opts, kind, candidate)
		observe(r)
		result := "failure"
		if r.ok {
			result = "success"
		} else if isTransportTimeout(r.err) {
			result = "connection_timeout"
		}
		fmt.Printf("[D-TCP] phase=CALIBRATION fake_iperf=%s stage=%s chunk=%d confirmation=%d/%d result=%s\n", name, stage, candidate, attempt, calibrationDecisionAttempts, result)
	}

	if successes >= 2 {
		return lastSuccess
	}
	if failures >= 2 {
		return lastFailure
	}
	// No majority means connection health was too unstable to classify the
	// candidate. Preserve the old timeout semantics by reporting the timeout and
	// keeping the last known-good size.
	if lastTimeout.err != nil {
		return lastTimeout
	}
	if successes > failures && lastSuccess.ok {
		return lastSuccess
	}
	return lastFailure
}

func probeMaximum(serverAddr, token string, opts chunkClientOptions, kind byte) int {
	name := probeKindName(kind)
	// Startup calibration precision is independent from the runtime shrink step.
	// Grow quickly, then resolve only the final good/bad boundary to 32 bytes.
	fine := calibrationFineResolution

	// Ascending calibration deliberately starts small and grows geometrically in large steps.
	// This avoids hammering a constrained carrier with 1 MiB records before we
	// know they are viable, while still reaching the ceiling in O(log N) probes.
	// Once the first failure is found, binary refinement resolves the highest
	// known-good size to roughly `fine` bytes (32 B in the Android build).
	good := 0
	bad := 0
	candidate := opts.minSize
	if candidate < 32 {
		candidate = 32
	}
	if candidate > opts.maxSize {
		candidate = opts.maxSize
	}

	for {
		result := probeIperfOne(serverAddr, token, opts, kind, candidate)
		if result.ok {
			fmt.Printf("[D-TCP] phase=CALIBRATION fake_iperf=%s stage=ascend chunk=%d records=%d bytes=%d mbps=%.2f result=success\n", name, candidate, wire.ProbeBurstCount(candidate), result.bytes, result.mbps())
			good = candidate
			if candidate >= opts.maxSize {
				return opts.maxSize
			}
			next := candidate * 4
			// Do not waste many tiny probes when the configured floor is very
			// small. After proving the floor, jump to at least 512 B and then
			// continue growing by 4x.
			if candidate == opts.minSize && next < 512 && opts.maxSize >= 512 {
				next = 512
			}
			if next > opts.maxSize {
				next = opts.maxSize
			}
			if next <= candidate {
				return good
			}
			fmt.Printf("[D-TCP] phase=CALIBRATION probe=%s stage=ascend chunk_upgrade=%d->%d\n", name, candidate, next)
			candidate = next
			continue
		}

		// A first failure may be transient. Re-test this exact size on fresh
		// connections before declaring the ascending ceiling.
		result = confirmIperfResult(serverAddr, token, opts, kind, candidate, result, "ascend-confirm")
		if result.ok {
			fmt.Printf("[D-TCP] phase=CALIBRATION fake_iperf=%s stage=ascend chunk=%d result=recovered_after_retry\n", name, candidate)
			good = candidate
			if candidate >= opts.maxSize {
				return opts.maxSize
			}
			next := candidate * 4
			if candidate == opts.minSize && next < 512 && opts.maxSize >= 512 {
				next = 512
			}
			if next > opts.maxSize {
				next = opts.maxSize
			}
			if next <= candidate {
				return good
			}
			fmt.Printf("[D-TCP] phase=CALIBRATION probe=%s stage=ascend chunk_upgrade=%d->%d\n", name, candidate, next)
			candidate = next
			continue
		}

		if isTransportTimeout(result.err) {
			// A real I/O timeout means the physical connection is dead. It is not
			// evidence that this record size is invalid, so stop calibration at
			// the last proven size instead of walking the size ladder.
			selected := good
			if selected == 0 {
				selected = opts.minSize
			}
			fmt.Printf("[D-TCP] phase=CALIBRATION fake_iperf=%s stage=ascend chunk=%d result=connection_timeout action=keep_known_good known_good=%d err=%v\n", name, candidate, selected, result.err)
			return selected
		}

		fmt.Printf("[D-TCP] phase=CALIBRATION fake_iperf=%s stage=ascend chunk=%d records=%d bytes=%d mbps=%.2f result=failure err=%v\n", name, candidate, wire.ProbeBurstCount(candidate), result.bytes, result.mbps(), result.err)
		bad = candidate
		if good == 0 {
			return opts.minSize
		}
		break
	}

	for bad-good > fine {
		next := good + (bad-good)/2
		if next <= good || next >= bad {
			break
		}
		result := probeIperfOne(serverAddr, token, opts, kind, next)
		result = confirmIperfResult(serverAddr, token, opts, kind, next, result, "refine-confirm")
		if result.ok {
			fmt.Printf("[D-TCP] phase=CALIBRATION fake_iperf=%s stage=refine chunk=%d records=%d bytes=%d mbps=%.2f result=success\n", name, next, wire.ProbeBurstCount(next), result.bytes, result.mbps())
			good = next
			continue
		}
		if isTransportTimeout(result.err) {
			fmt.Printf("[D-TCP] phase=CALIBRATION fake_iperf=%s stage=refine chunk=%d result=connection_timeout action=keep_known_good known_good=%d err=%v\n", name, next, good, result.err)
			return good
		}
		fmt.Printf("[D-TCP] phase=CALIBRATION fake_iperf=%s stage=refine chunk=%d records=%d bytes=%d mbps=%.2f result=failure err=%v\n", name, next, wire.ProbeBurstCount(next), result.bytes, result.mbps(), result.err)
		bad = next
	}

	fmt.Printf("[D-TCP] phase=CALIBRATION probe=%s stage=refine selected=%d failed_above=%d resolution=%d\n", name, good, bad, fine)
	return good
}

func probeKindName(kind byte) string {
	if kind == wire.ProbeDownload {
		return "download"
	}
	return "upload"
}

const (
	// A literal 200-byte descent from 1 MiB can require more than five thousand
	// carrier probes per direction. MAX-FIRST therefore finds a working region
	// with a bounded coarse descent, then resolves the final good/bad boundary to
	// approximately 32 bytes. This preserves fine sizing without probe floods.
	maxFirstCoarseStep     = 128 * 1024
	maxFirstFineResolution = calibrationFineResolution
)

// probeMaximumMaxFirst always validates the configured ceiling first. On a
// recoverable size rejection it descends by 128 KiB until it finds a known-good
// size, then binary-refines the interval between that good size and the nearest
// failed size to <= 32 bytes. A connection-level timeout is never interpreted
// as evidence that the chunk is too large, so it does not trigger a size sweep.
func probeMaximumMaxFirst(serverAddr, token string, opts chunkClientOptions, kind byte) int {
	fine := maxFirstFineResolution
	candidate := opts.maxSize
	if candidate < opts.minSize {
		candidate = opts.minSize
	}
	name := probeKindName(kind)
	failedHigh := 0

	// Coarse descent: at most about eight probes from 1 MiB to the bottom of
	// the normal range, instead of thousands of 200-byte requests.
	for {
		result := probeIperfOne(serverAddr, token, opts, kind, candidate)
		if result.ok {
			fmt.Printf("[D-TCP] phase=CALIBRATION fake_iperf=%s stage=coarse chunk=%d records=%d bytes=%d mbps=%.2f result=success\n", name, candidate, wire.ProbeBurstCount(candidate), result.bytes, result.mbps())
			if failedHigh == 0 {
				return candidate
			}
			break
		}
		if isTransportTimeout(result.err) {
			fmt.Printf("[D-TCP] phase=CALIBRATION fake_iperf=%s stage=coarse chunk=%d result=connection_timeout action=keep_size_and_replace_connection err=%v\n", name, candidate, result.err)
			return candidate
		}
		fmt.Printf("[D-TCP] phase=CALIBRATION fake_iperf=%s stage=coarse chunk=%d records=%d bytes=%d mbps=%.2f result=failure err=%v\n", name, candidate, wire.ProbeBurstCount(candidate), result.bytes, result.mbps(), result.err)
		failedHigh = candidate
		if candidate <= opts.minSize {
			return opts.minSize
		}
		next := candidate - maxFirstCoarseStep
		if next < opts.minSize {
			next = opts.minSize
		}
		if next >= candidate {
			next = opts.minSize
		}
		fmt.Printf("[D-TCP] phase=CALIBRATION probe=%s stage=coarse chunk_downgrade=%d->%d step=%d\n", name, candidate, next, maxFirstCoarseStep)
		candidate = next
	}

	// Fine boundary search. candidate is known-good and failedHigh is known-bad.
	good := candidate
	bad := failedHigh
	for bad-good > fine {
		next := good + (bad-good)/2
		if next <= good {
			break
		}
		result := probeIperfOne(serverAddr, token, opts, kind, next)
		if result.ok {
			fmt.Printf("[D-TCP] phase=CALIBRATION fake_iperf=%s stage=fine chunk=%d records=%d bytes=%d mbps=%.2f result=success\n", name, next, wire.ProbeBurstCount(next), result.bytes, result.mbps())
			good = next
			continue
		}
		if isTransportTimeout(result.err) {
			fmt.Printf("[D-TCP] phase=CALIBRATION fake_iperf=%s stage=fine chunk=%d result=connection_timeout action=keep_known_good known_good=%d err=%v\n", name, next, good, result.err)
			return good
		}
		fmt.Printf("[D-TCP] phase=CALIBRATION fake_iperf=%s stage=fine chunk=%d records=%d bytes=%d mbps=%.2f result=failure err=%v\n", name, next, wire.ProbeBurstCount(next), result.bytes, result.mbps(), result.err)
		bad = next
	}
	fmt.Printf("[D-TCP] phase=CALIBRATION probe=%s stage=fine selected=%d failed_above=%d resolution=%d\n", name, good, bad, fine)
	return good
}

func getPathProfile(serverAddr, token string, opts chunkClientOptions) pathProfile {
	key := fmt.Sprintf("%s|%s|%d|%d|%02x|%t|%04x|%d|%t|maxfirst=%t|shrink=%d|step=%d", serverAddr, token, opts.minSize, opts.maxSize, opts.headerMask, opts.coverProfile.Enabled, opts.coverProfile.ID, opts.coverProfile.Padding, opts.coverProfile.Clear, opts.forceMaxStart, opts.shrinkAfter, opts.shrinkStep)
	profileState.Lock()
	if profileState.key == key && time.Since(profileState.p.at) < 30*time.Minute {
		p := profileState.p
		profileState.Unlock()
		return p
	}
	profileState.Unlock()

	fallbackUp := minInt(opts.maxSize, maxInt(opts.minSize, 32768))
	fallbackDown := minInt(opts.maxSize, maxInt(opts.minSize, 1350))

	p := pathProfile{upload: fallbackUp, download: fallbackDown, persistent: false, at: time.Now()}
	if opts.forceMaxStart {
		// Legacy CLI-only mode retained for compatibility. The Android app no
		// longer exposes MAX FIRST and uses the ascending path below.
		p.upload = probeMaximumMaxFirst(serverAddr, token, opts, wire.ProbeUpload)
		p.download = probeMaximumMaxFirst(serverAddr, token, opts, wire.ProbeDownload)
	} else {
		// Keep UP and DW calibration sequential. Running both fake-iperf probes
		// together can look like a traffic burst and distort the carrier limit we
		// are trying to measure.
		p.upload = probeMaximum(serverAddr, token, opts, wire.ProbeUpload)
		p.download = probeMaximum(serverAddr, token, opts, wire.ProbeDownload)
	}
	p.persistent = probePersistent(serverAddr, token, opts)

	fmt.Printf("path probe: strategy=%s upload=%d download=%d persistent=%t\n", func() string {
		if opts.forceMaxStart {
			return "max-first"
		}
		return "ascending"
	}(), p.upload, p.download, p.persistent)

	profileState.Lock()
	profileState.key = key
	profileState.p = p
	profileState.Unlock()
	return p
}

func encodeOpen(token, host string, port int) ([]byte, error) {
	if len(token) > 65535 || len(host) > 65535 {
		return nil, fmt.Errorf("token or hostname too long")
	}
	out := make([]byte, 6+len(token)+len(host))
	binary.BigEndian.PutUint16(out[0:2], uint16(len(token)))
	binary.BigEndian.PutUint16(out[2:4], uint16(len(host)))
	binary.BigEndian.PutUint16(out[4:6], uint16(port))
	copy(out[6:6+len(token)], token)
	copy(out[6+len(token):], host)
	return out, nil
}

type chunkConn struct {
	sid          wire.SessionID
	opts         chunkClientOptions
	uploadLane   *requestLane
	downloadLane *requestLane
	serverMax    int
	upSizer      *adaptiveSizer
	downSizer    *adaptiveSizer

	writeMu  sync.Mutex
	upOffset uint64

	readMu         sync.Mutex
	readBuf        []byte
	downloadOffset uint64
	consumedOffset uint64
	eof            bool
	pipeline       int
	minPipeline    int
	maxPipeline    int

	closeOnce sync.Once
	dead      atomic.Bool
}

// appendChunkParts keeps the single-response fast path zero-copy. For a batch,
// it reserves the complete size once rather than repeatedly growing and copying
// the aggregate read buffer.
func appendChunkParts(dst []byte, parts [][]byte) []byte {
	if len(parts) == 0 {
		return dst
	}
	if len(dst) == 0 && len(parts) == 1 {
		return parts[0]
	}
	total := len(dst)
	for _, part := range parts {
		total += len(part)
	}
	if cap(dst) < total {
		grown := make([]byte, len(dst), total)
		copy(grown, dst)
		dst = grown
	}
	for _, part := range parts {
		dst = append(dst, part...)
	}
	return dst
}

func openChunkTunnel(serverAddr, token, targetHost string, targetPort int, opts chunkClientOptions) (net.Conn, error) {
	if opts.minSize < 32 {
		opts.minSize = 32
	}
	if opts.maxSize < opts.minSize {
		opts.maxSize = opts.minSize
	}
	if opts.maxSize > 1024*1024 {
		opts.maxSize = 1024 * 1024
	}
	if opts.txnTimeout <= 0 {
		opts.txnTimeout = 5 * time.Second
	}
	if opts.adaptSuccesses < 1 {
		opts.adaptSuccesses = 64
	}
	if opts.shrinkAfter < 1 {
		opts.shrinkAfter = 1
	}
	if opts.forceMaxStart {
		opts.startSize = opts.maxSize
	}
	if opts.reconnectEvery < 0 {
		opts.reconnectEvery = 0
	}
	if opts.maxPipeline < 1 {
		opts.maxPipeline = 1
	}
	if opts.maxPipeline > 256 {
		opts.maxPipeline = 256
	}
	if opts.minPipeline < 1 {
		opts.minPipeline = 1
	}
	if opts.minPipeline > opts.maxPipeline {
		opts.minPipeline = opts.maxPipeline
	}

	defaultStart := opts.minSize
	if opts.forceMaxStart {
		defaultStart = opts.maxSize
	}
	profile := pathProfile{
		upload:     defaultStart,
		download:   defaultStart,
		persistent: false,
		at:         time.Now(),
	}
	if !opts.skipPathProbe {
		profile = getPathProfile(serverAddr, token, opts)
	}
	reconnect := opts.reconnectEvery
	// Compatibility-friendly reconnect modes:
	//   0 = persistent (CLI explicit)
	//   1 = auto: start persistent, then learn one request/connection only if
	//       reuse fails during real traffic
	//   N>=2 = force connection rotation after N logical requests

	sid, err := randomSessionID()
	if err != nil {
		return nil, err
	}
	// OPEN rides the upload lane instead of a throwaway connection. A dedicated
	// control connection cost one extra dial per proxied flow, which shows up on
	// the server as connection churn on top of the steady-state count.
	uploadLane := newRequestLane(serverAddr, opts.tcpBuffer, reconnect, opts.txnTimeout, opts.headerMask, opts.coverProfile)
	payload, err := encodeOpen(token, targetHost, targetPort)
	if err != nil {
		uploadLane.Close()
		return nil, err
	}
	status, body, err := uploadLane.single(wire.ModeOpen, sid, 0, payload)
	if err != nil {
		uploadLane.Close()
		return nil, err
	}
	if status == wire.StatusError {
		uploadLane.Close()
		return nil, fmt.Errorf("%s", string(body))
	}
	if status != wire.StatusOK || len(body) != 4 {
		uploadLane.Close()
		return nil, fmt.Errorf("bad OPEN response")
	}
	serverMax := int(binary.BigEndian.Uint32(body))
	if serverMax < opts.minSize {
		uploadLane.Close()
		return nil, fmt.Errorf("server maximum chunk %d is below client minimum %d", serverMax, opts.minSize)
	}
	if opts.maxSize > serverMax {
		opts.maxSize = serverMax
	}
	upStart := minInt(profile.upload, opts.maxSize)
	downStart := minInt(profile.download, opts.maxSize)
	if upStart < opts.minSize {
		upStart = opts.minSize
	}
	if downStart < opts.minSize {
		downStart = opts.minSize
	}

	c := &chunkConn{
		sid:          sid,
		opts:         opts,
		serverMax:    serverMax,
		uploadLane:   uploadLane,
		downloadLane: newRequestLane(serverAddr, opts.tcpBuffer, reconnect, opts.txnTimeout, opts.headerMask, opts.coverProfile),
		// Start at the configured ceiling. On transport failure the batch is
		// halved but never below minPipeline; successful data grows it back by
		// one. When min == max the depth is pinned and never adapts, which is
		// what paths that only work at one specific batch size need.
		pipeline:    opts.maxPipeline,
		minPipeline: opts.minPipeline,
		maxPipeline: opts.maxPipeline,
	}
	upSizerOpts := opts
	downSizerOpts := opts
	if !opts.skipPathProbe {
		// Calibration is the path ceiling for this VPN session. Runtime
		// adaptation may shrink after repeated failures and recover to this
		// value, but it must not grow above a size the UP/DW test did not prove.
		upSizerOpts.maxSize = upStart
		downSizerOpts.maxSize = downStart
	}
	c.upSizer = newAdaptiveSizer("upload", upStart, upSizerOpts)
	c.downSizer = newAdaptiveSizer("download", downStart, downSizerOpts)
	return c, nil
}

func (c *chunkConn) fillReadBuffer() error {
	if c.eof {
		return io.EOF
	}
	minFailures := 0
	for len(c.readBuf) == 0 && !c.eof {
		chunk := c.downSizer.Current()
		count := c.pipeline
		if count < c.minPipeline {
			count = c.minPipeline
		}
		if count > c.maxPipeline {
			count = c.maxPipeline
		}
		// Bound each batch to roughly 1 MiB of useful data, but never below the
		// configured floor: a pinned depth is a path requirement, not a hint.
		if maxCount := (1024 * 1024) / maxInt(chunk, 1); maxCount < count {
			count = maxInt(maxCount, c.minPipeline)
		}

		data, status, err := c.downloadLane.download(c.sid, c.downloadOffset, c.consumedOffset, chunk, count)
		c.readBuf = appendChunkParts(c.readBuf, data)
		for _, part := range data {
			c.downloadOffset += uint64(len(part))
		}
		if len(data) > 0 {
			c.downSizer.Success(chunk)
			if c.pipeline < c.maxPipeline {
				c.pipeline++
			}
			minFailures = 0
		}
		if err != nil {
			if isTransportTimeout(err) {
				c.dead.Store(true)
				return err
			}
			if c.pipeline > c.minPipeline {
				old := c.pipeline
				c.pipeline /= 2
				if c.pipeline < c.minPipeline {
					c.pipeline = c.minPipeline
				}
				if c.opts.adaptLog && old != c.pipeline {
					fmt.Printf("adaptive download pipeline: %d -> %d after transport failure: %v\n", old, c.pipeline, err)
				}
			} else {
				old, next := c.downSizer.FailureReason(chunk, err)
				if old == next && next == c.opts.minSize {
					minFailures++
					if minFailures >= 8 {
						return fmt.Errorf("download failed at minimum chunk %d: %w", next, err)
					}
				}
			}
			time.Sleep(30 * time.Millisecond)
			if len(c.readBuf) > 0 {
				return nil
			}
			continue
		}
		switch status {
		case wire.StatusEOF:
			c.eof = true
		case wire.StatusWait:
			if c.opts.pollDelay > 0 {
				time.Sleep(c.opts.pollDelay)
			} else {
				time.Sleep(5 * time.Millisecond)
			}
		}
		if len(c.readBuf) > 0 {
			return nil
		}
	}
	if c.eof && len(c.readBuf) == 0 {
		return io.EOF
	}
	return nil
}

func (c *chunkConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	if len(c.readBuf) == 0 {
		if err := c.fillReadBuffer(); err != nil {
			return 0, err
		}
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	c.consumedOffset += uint64(n)
	return n, nil
}

func (c *chunkConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if len(p) == 0 {
		return 0, nil
	}
	total := 0
	minFailures := 0
	for len(p) > 0 {
		size := c.upSizer.Current()
		n := minInt(size, len(p))
		status, body, err := c.uploadLane.single(wire.ModeUpload, c.sid, c.upOffset, p[:n])
		if err != nil {
			if isTransportTimeout(err) {
				c.dead.Store(true)
				return total, err
			}
			old, next := c.upSizer.FailureReason(size, err)
			if old == next && next == c.opts.minSize {
				minFailures++
				if minFailures >= 8 {
					return total, fmt.Errorf("upload failed at minimum chunk %d: %w", next, err)
				}
			} else {
				minFailures = 0
			}
			time.Sleep(30 * time.Millisecond)
			continue
		}
		if status == wire.StatusError {
			return total, fmt.Errorf("%s", string(body))
		}
		if status != wire.StatusOK {
			return total, fmt.Errorf("unexpected upload status %d", status)
		}
		c.upOffset += uint64(n)
		total += n
		p = p[n:]
		c.upSizer.Success(size)
		minFailures = 0
	}
	return total, nil
}

func (c *chunkConn) Close() error {
	c.closeOnce.Do(func() {
		// A timed-out tunnel is already dead. Do not redial merely to send a
		// graceful CLOSE for a session that the caller is abandoning.
		if !c.dead.Load() {
			// Reuse the upload lane rather than dialling a connection just to say
			// goodbye; that was a second wasted dial per flow.
			_, _, _ = c.uploadLane.single(wire.ModeClose, c.sid, 0, nil)
		}
		c.uploadLane.Close()
		c.downloadLane.Close()
	})
	return nil
}

func (c *chunkConn) LocalAddr() net.Addr              { return dummyAddr("dragontcp-binary-local") }
func (c *chunkConn) RemoteAddr() net.Addr             { return dummyAddr("dragontcp-binary-remote") }
func (c *chunkConn) SetDeadline(time.Time) error      { return nil }
func (c *chunkConn) SetReadDeadline(time.Time) error  { return nil }
func (c *chunkConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr string

func (d dummyAddr) Network() string { return "dragontcp-binary" }
func (d dummyAddr) String() string  { return string(d) }

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
