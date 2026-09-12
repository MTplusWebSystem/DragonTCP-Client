// Package xorchunk is the LiteVPN v4 XOR chunk transport, carried over verbatim
// so DragonTCP can speak the legacy UP/OK + XOR 0xAD wire on networks that pass
// it but reject the newer binary records.
//
// It lives in its own package purely to avoid symbol collisions with the binary
// transport in package main, which uses many of the same names.
package xorchunk

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"dragontcp/internal/cover"
	"dragontcp/internal/protocol"
)

// requestCounter correlates UP request frames with their OK responses. It lived
// in v4's main.go; the transport needs it, so it moves in here.
var requestCounter atomic.Uint32

// NewOptions builds the transport options from the values the CLI already
// parses, keeping the struct fields unexported as in the original.
func NewOptions(startSize, minSize, maxSize int, adaptive bool, adaptSuccesses, shrinkAfter int, adaptLog bool,
	pollers, reconnectEvery int, pollDelay, txnTimeout time.Duration, tcpBuffer int) Options {
	return Options{
		startSize:      startSize,
		minSize:        minSize,
		maxSize:        maxSize,
		adaptive:       adaptive,
		adaptSuccesses: adaptSuccesses,
		shrinkAfter:    shrinkAfter,
		adaptLog:       adaptLog,
		pollers:        pollers,
		reconnectEvery: reconnectEvery,
		pollDelay:      pollDelay,
		txnTimeout:     txnTimeout,
		tcpBuffer:      tcpBuffer,
	}
}

type Options struct {
	startSize         int
	minSize           int
	maxSize           int
	uploadStartSize   int
	downloadStartSize int
	uploadMaxSize     int
	downloadMaxSize   int
	adaptive          bool
	adaptSuccesses    int
	shrinkAfter       int
	adaptLog          bool
	pollers           int
	reconnectEvery    int
	pollDelay         time.Duration
	txnTimeout        time.Duration
	tcpBuffer         int
	headerMask        byte
	coverProfile      cover.Profile
}

// WithHeaderMask returns a copy using one fixed frame-magic profile. The mask
// is selected during startup discovery and remains unchanged for normal data.
func (o Options) WithHeaderMask(mask byte) Options {
	o.headerMask = mask
	o.coverProfile = cover.Profile{}
	return o
}

// WithCoverProfile returns a copy using a fixed startup-selected preface,
// padding length, and frame mask.
func (o Options) WithCoverProfile(profile cover.Profile) Options {
	o.coverProfile = profile
	o.headerMask = profile.HeaderMask
	return o
}

// MinSize and MaxSize expose the configured X carrier calibration bounds.
func (o Options) MinSize() int { return o.minSize }
func (o Options) MaxSize() int { return o.maxSize }

// WithCalibratedChunks locks X to the UP/DW sizes proven by the pre-tunnel
// fake-iperf calibration. Once calibration succeeds, runtime adaptive sizing is
// disabled for X: transport successes cannot grow the chunk and transport
// failures cannot shrink it. Failed physical transactions reconnect/retry using
// the same calibrated size.
func (o Options) WithCalibratedChunks(upload, download int) Options {
	if upload < o.minSize {
		upload = o.minSize
	}
	if download < o.minSize {
		download = o.minSize
	}
	if upload > o.maxSize {
		upload = o.maxSize
	}
	if download > o.maxSize {
		download = o.maxSize
	}
	o.uploadStartSize = upload
	o.downloadStartSize = download
	o.uploadMaxSize = upload
	o.downloadMaxSize = download
	// Calibration replaces runtime X chunk adaptation. The calibrated values are
	// the operating sizes for this session, not merely adaptive ceilings.
	o.adaptive = false
	return o
}

func wireToken(token string) string {
	if token == "" {
		return "-"
	}
	return token
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
	failures       int
	successes      int
	good           int
	bad            int
	logChanges     bool
}

func newAdaptiveSizer(name string, start, ceiling int, opts Options) *adaptiveSizer {
	if ceiling <= 0 || ceiling > opts.maxSize {
		ceiling = opts.maxSize
	}
	if ceiling < opts.minSize {
		ceiling = opts.minSize
	}
	if start <= 0 {
		start = opts.startSize
	}
	if start < opts.minSize {
		start = opts.minSize
	}
	if start > ceiling {
		start = ceiling
	}
	return &adaptiveSizer{
		name:           name,
		current:        start,
		min:            opts.minSize,
		max:            ceiling,
		adaptive:       opts.adaptive,
		adaptSuccesses: opts.adaptSuccesses,
		shrinkAfter: func() int {
			if opts.shrinkAfter > 0 {
				return opts.shrinkAfter
			}
			return 1
		}(),
		logChanges: opts.adaptLog,
	}
}

func (s *adaptiveSizer) Current() int {
	s.mu.Lock()
	n := s.current
	s.mu.Unlock()
	return n
}

func (s *adaptiveSizer) Success(attempted int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.adaptive {
		return
	}
	// Ignore stale successes from records that were already in flight when
	// another worker changed the shared size.
	if attempted != s.current {
		return
	}
	s.failures = 0
	if s.current >= s.max {
		return
	}

	if attempted > s.good {
		s.good = attempted
	}
	s.successes++

	growAfter := s.adaptSuccesses
	// When we have converged close to a known failure boundary, stay stable
	// longer before probing again. This also lets us discover later network
	// improvements without constantly oscillating around the boundary.
	if s.bad > 0 && s.bad-s.good <= 32 {
		growAfter *= 8
	}
	if s.successes < growAfter {
		return
	}
	s.successes = 0

	old := s.current
	var next int
	if s.bad > old+1 {
		// Binary-search the gap between known-good and known-bad sizes.
		next = old + (s.bad-old)/2
	} else {
		// Either there is no known ceiling, or we have stayed stable long enough
		// at it to probe the network again in case conditions improved.
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

func (s *adaptiveSizer) Failure(attempted int) (old, next int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	old = s.current

	if !s.adaptive {
		return old, old
	}
	// Multiple pollers can fail on the same oversized value at once. Only the
	// first failure for the current value is allowed to reduce it.
	if attempted != s.current {
		return old, old
	}
	s.successes = 0
	s.failures++
	if s.failures < s.shrinkAfter {
		if s.logChanges && s.shrinkAfter > 1 {
			fmt.Printf("adaptive %s chunk: holding %d after failure %d/%d\n", s.name, old, s.failures, s.shrinkAfter)
		}
		return old, old
	}
	s.failures = 0

	if s.bad == 0 || attempted < s.bad {
		s.bad = attempted
	}

	if s.good > 0 && s.good < attempted {
		// Return directly to the last size that was proven to work.
		next = s.good
	} else {
		// A previously-good value just failed, so conditions worsened. Forget
		// the old lower bound and use multiplicative decrease.
		s.good = 0
		next = attempted / 2
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

	if s.logChanges && next != old {
		fmt.Printf("adaptive %s chunk: %d -> %d after transport failure\n", s.name, old, next)
	}
	return old, next
}

type txnLane struct {
	mu             sync.Mutex
	serverAddr     string
	tcpBuffer      int
	reconnectEvery int
	timeout        time.Duration
	headerMask     byte
	coverProfile   cover.Profile
	conn           net.Conn
	count          int
	closed         bool
}

func newTxnLane(serverAddr string, tcpBuffer, reconnectEvery int, timeout time.Duration, headerMask byte, coverProfile cover.Profile) *txnLane {
	return &txnLane{
		serverAddr:     serverAddr,
		tcpBuffer:      tcpBuffer,
		reconnectEvery: reconnectEvery,
		timeout:        timeout,
		headerMask:     headerMask,
		coverProfile:   coverProfile,
	}
}

func (l *txnLane) closeLocked() {
	if l.conn != nil {
		_ = l.conn.Close()
		l.conn = nil
	}
	l.count = 0
}

func (l *txnLane) Close() {
	l.mu.Lock()
	l.closed = true
	l.closeLocked()
	l.mu.Unlock()
}

func (l *txnLane) ensureConn() error {
	if l.closed {
		return net.ErrClosed
	}
	if l.conn != nil && (l.reconnectEvery <= 0 || l.count < l.reconnectEvery) {
		return nil
	}

	l.closeLocked()
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
	l.conn = conn
	return nil
}

// Do performs exactly one framed transaction. Higher layers decide whether a
// failed data record should be retried at a smaller adaptive size.
func (l *txnLane) Do(payload []byte) ([]byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if err := l.ensureConn(); err != nil {
		return nil, err
	}

	timeout := l.timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	_ = l.conn.SetDeadline(time.Now().Add(timeout))
	requestID := requestCounter.Add(1)

	if err := protocol.WriteRequestFrameProfile(l.conn, requestID, payload, l.headerMask); err != nil {
		l.closeLocked()
		return nil, err
	}

	responseID, response, err := protocol.ReadResponseFrameProfile(l.conn, l.headerMask)
	if err != nil {
		l.closeLocked()
		return nil, err
	}
	if responseID != requestID {
		l.closeLocked()
		return nil, fmt.Errorf("request ID mismatch")
	}

	l.count++
	_ = l.conn.SetDeadline(time.Time{})
	if l.reconnectEvery > 0 && l.count >= l.reconnectEvery {
		// For restrictive TCP/53 networks, reconnectEvery=1 must really mean
		// one request/response per TCP connection. Close immediately after
		// receiving the response rather than waiting for the next request.
		l.closeLocked()
	}
	return response, nil
}

func doControl(lane *txnLane, payload []byte) ([]byte, error) {
	var lastErr error
	for attempt := 0; attempt < 5; attempt++ {
		resp, err := lane.Do(payload)
		if err == nil {
			return resp, nil
		}
		lastErr = err
		time.Sleep(time.Duration(attempt+1) * 40 * time.Millisecond)
	}
	return nil, lastErr
}

// ProbeProfile performs one small authenticated transaction using the selected
// frame-magic mask. It does not create a target session.
func ProbeProfile(serverAddr, token string, opts Options) bool {
	timeout := opts.txnTimeout
	if timeout <= 0 || timeout > 2*time.Second {
		timeout = 2 * time.Second
	}
	lane := newTxnLane(serverAddr, opts.tcpBuffer, 1, timeout, opts.headerMask, opts.coverProfile)
	defer lane.Close()
	resp, err := lane.Do([]byte("CPROBE " + wireToken(token)))
	if err != nil {
		return false
	}
	if string(resp) == "PROBEOK" {
		return true
	}
	// Servers predating profile discovery do not know CPROBE, but receiving a
	// correctly framed error still proves that the legacy mask-zero header
	// survived. The subsequent end-to-end probe remains authoritative.
	return opts.headerMask == 0 && strings.HasPrefix(string(resp), "ERR expected TUNNEL")
}

type calibrationProbeResult struct {
	ok      bool
	bytes   int
	elapsed time.Duration
	err     error
}

func (r calibrationProbeResult) mbps() float64 {
	if r.bytes <= 0 || r.elapsed <= 0 {
		return 0
	}
	return float64(r.bytes*8) / r.elapsed.Seconds() / 1_000_000
}

func calibrationPattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte((i*31 + 17) & 0xff)
	}
	return b
}

func calibrationBurstCount(chunk int) int {
	// Calibration is strictly single-poller/single-outstanding-request. Runtime
	// X traffic may use its normal concurrency after calibration completes.
	return 1
}

func calibrationTimeout(opts Options) time.Duration {
	t := opts.txnTimeout
	if t < 8*time.Second {
		t = 8 * time.Second
	}
	if t > 20*time.Second {
		t = 20 * time.Second
	}
	return t
}

func isCalibrationTimeout(err error) bool {
	if err == nil {
		return false
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "i/o timeout") || strings.Contains(strings.ToLower(err.Error()), "timeout")
}

const calibrationDecisionAttempts = 3

// confirmCalibrationResult uses a 2-of-3 decision near the carrier boundary.
// Each retry gets a fresh X connection. Timeouts are treated as inconclusive
// connection failures, not as evidence that the candidate chunk is too large.
func confirmCalibrationResult(serverAddr, token string, opts Options, download bool, candidate int, first calibrationProbeResult, stage string) calibrationProbeResult {
	name := "upload"
	if download {
		name = "download"
	}
	successes, failures := 0, 0
	var lastSuccess, lastFailure, lastTimeout calibrationProbeResult

	observe := func(r calibrationProbeResult) {
		if r.ok {
			successes++
			lastSuccess = r
			return
		}
		if isCalibrationTimeout(r.err) {
			lastTimeout = r
			return
		}
		failures++
		lastFailure = r
	}

	observe(first)
	for attempt := 2; attempt <= calibrationDecisionAttempts && successes < 2 && failures < 2; attempt++ {
		r := probeCalibrationSize(serverAddr, token, opts, download, candidate)
		observe(r)
		result := "failure"
		if r.ok {
			result = "success"
		} else if isCalibrationTimeout(r.err) {
			result = "connection_timeout"
		}
		fmt.Printf("[D-TCP] phase=CALIBRATION fake_iperf=%s wire=x stage=%s chunk=%d confirmation=%d/%d result=%s\n", name, stage, candidate, attempt, calibrationDecisionAttempts, result)
	}

	if successes >= 2 {
		return lastSuccess
	}
	if failures >= 2 {
		return lastFailure
	}
	if lastTimeout.err != nil {
		return lastTimeout
	}
	if successes > failures && lastSuccess.ok {
		return lastSuccess
	}
	return lastFailure
}

// probeCalibrationSize runs a short repeated UP or DW transfer over one X
// physical connection. It exercises the same UP/OK framing and XOR payload path
// as real X traffic without opening a destination tunnel.
func probeCalibrationSize(serverAddr, token string, opts Options, download bool, candidate int) calibrationProbeResult {
	timeout := calibrationTimeout(opts)
	lane := newTxnLane(serverAddr, opts.tcpBuffer, 0, timeout, opts.headerMask, opts.coverProfile)
	defer lane.Close()
	count := calibrationBurstCount(candidate)
	started := time.Now()
	total := 0
	want := calibrationPattern(candidate)

	for i := 0; i < count; i++ {
		if download {
			resp, err := lane.Do([]byte(fmt.Sprintf("CIPERFDW %s %d", wireToken(token), candidate)))
			if err != nil {
				return calibrationProbeResult{bytes: total, elapsed: time.Since(started), err: err}
			}
			if !bytes.Equal(resp, want) {
				return calibrationProbeResult{bytes: total, elapsed: time.Since(started), err: fmt.Errorf("X download validation failed len=%d want=%d", len(resp), candidate)}
			}
			total += len(resp)
			continue
		}

		prefix := []byte(fmt.Sprintf("CIPERFUP %s %d ", wireToken(token), candidate))
		payload := make([]byte, len(prefix)+len(want))
		copy(payload, prefix)
		copy(payload[len(prefix):], want)
		resp, err := lane.Do(payload)
		if err != nil {
			return calibrationProbeResult{bytes: total, elapsed: time.Since(started), err: err}
		}
		if string(resp) != "IPERFOK" {
			return calibrationProbeResult{bytes: total, elapsed: time.Since(started), err: fmt.Errorf("X upload rejected: %s", string(resp))}
		}
		total += candidate
	}
	return calibrationProbeResult{ok: true, bytes: total, elapsed: time.Since(started)}
}

func calibrateMaximum(serverAddr, token string, opts Options, download bool, fine int) int {
	if fine < 1 {
		fine = 32
	}
	name := "upload"
	if download {
		name = "download"
	}
	candidate := opts.minSize
	if candidate < 32 {
		candidate = 32
	}
	if candidate > opts.maxSize {
		candidate = opts.maxSize
	}
	good, bad := 0, 0

	for {
		r := probeCalibrationSize(serverAddr, token, opts, download, candidate)
		if r.ok {
			fmt.Printf("[D-TCP] phase=CALIBRATION fake_iperf=%s wire=x stage=ascend chunk=%d records=%d bytes=%d mbps=%.2f result=success\n", name, candidate, calibrationBurstCount(candidate), r.bytes, r.mbps())
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
			fmt.Printf("[D-TCP] phase=CALIBRATION probe=%s wire=x stage=ascend chunk_upgrade=%d->%d\n", name, candidate, next)
			candidate = next
			continue
		}
		r = confirmCalibrationResult(serverAddr, token, opts, download, candidate, r, "ascend-confirm")
		if r.ok {
			fmt.Printf("[D-TCP] phase=CALIBRATION fake_iperf=%s wire=x stage=ascend chunk=%d result=recovered_after_retry\n", name, candidate)
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
			fmt.Printf("[D-TCP] phase=CALIBRATION probe=%s wire=x stage=ascend chunk_upgrade=%d->%d\n", name, candidate, next)
			candidate = next
			continue
		}
		if isCalibrationTimeout(r.err) {
			selected := good
			if selected == 0 {
				selected = opts.minSize
			}
			fmt.Printf("[D-TCP] phase=CALIBRATION fake_iperf=%s wire=x stage=ascend chunk=%d result=connection_timeout action=keep_known_good known_good=%d err=%v\n", name, candidate, selected, r.err)
			return selected
		}
		fmt.Printf("[D-TCP] phase=CALIBRATION fake_iperf=%s wire=x stage=ascend chunk=%d records=%d bytes=%d mbps=%.2f result=failure err=%v\n", name, candidate, calibrationBurstCount(candidate), r.bytes, r.mbps(), r.err)
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
		r := probeCalibrationSize(serverAddr, token, opts, download, next)
		r = confirmCalibrationResult(serverAddr, token, opts, download, next, r, "refine-confirm")
		if r.ok {
			fmt.Printf("[D-TCP] phase=CALIBRATION fake_iperf=%s wire=x stage=refine chunk=%d records=%d bytes=%d mbps=%.2f result=success\n", name, next, calibrationBurstCount(next), r.bytes, r.mbps())
			good = next
			continue
		}
		if isCalibrationTimeout(r.err) {
			fmt.Printf("[D-TCP] phase=CALIBRATION fake_iperf=%s wire=x stage=refine chunk=%d result=connection_timeout action=keep_known_good known_good=%d err=%v\n", name, next, good, r.err)
			return good
		}
		fmt.Printf("[D-TCP] phase=CALIBRATION fake_iperf=%s wire=x stage=refine chunk=%d records=%d bytes=%d mbps=%.2f result=failure err=%v\n", name, next, calibrationBurstCount(next), r.bytes, r.mbps(), r.err)
		bad = next
	}
	fmt.Printf("[D-TCP] phase=CALIBRATION probe=%s wire=x stage=refine selected=%d failed_above=%d resolution=%d\n", name, good, bad, fine)
	return good
}

func probePersistent(serverAddr, token string, opts Options) bool {
	lane := newTxnLane(serverAddr, opts.tcpBuffer, 0, minDurationX(calibrationTimeout(opts), 2500*time.Millisecond), opts.headerMask, opts.coverProfile)
	defer lane.Close()
	for i := 0; i < 8; i++ {
		resp, err := lane.Do([]byte("CPROBE " + wireToken(token)))
		if err != nil || string(resp) != "PROBEOK" {
			return false
		}
	}
	return true
}

func minDurationX(a, b time.Duration) time.Duration {
	if a < b {
		return a
	}
	return b
}

// Calibrate performs the X wire's pre-tunnel UP/DW fake-iperf calibration.
// It ascends by 4x and only spends extra probes around the first failure, where
// it resolves the highest stable boundary to the requested byte precision.
func Calibrate(serverAddr, token string, opts Options, fine int) (upload, download int, persistent bool) {
	if opts.minSize < 32 {
		opts.minSize = 32
	}
	if opts.maxSize < opts.minSize {
		opts.maxSize = opts.minSize
	}
	if opts.maxSize > protocol.MaxChunkPayload {
		opts.maxSize = protocol.MaxChunkPayload
	}
	upload = calibrateMaximum(serverAddr, token, opts, false, fine)
	download = calibrateMaximum(serverAddr, token, opts, true, fine)
	persistent = probePersistent(serverAddr, token, opts)
	return
}

type chunkResult struct {
	seq   uint64
	data  []byte
	final uint64
	eof   bool
	err   error
}

type chunkConn struct {
	serverAddr string
	token      string
	sid        string
	opts       Options

	pushLane  *txnLane
	pullLanes []*txnLane

	upSizer   *adaptiveSizer
	downSizer *adaptiveSizer
	serverMax int

	ctx    context.Context
	cancel context.CancelFunc
	once   sync.Once

	writeMu sync.Mutex
	upSeq   uint64

	claim atomic.Uint64
	ack   atomic.Int64

	results chan chunkResult
	workers sync.WaitGroup

	readMu      sync.Mutex
	pending     map[uint64][]byte
	nextRead    uint64
	current     []byte
	currentSeq  uint64
	finalKnown  bool
	finalSeq    uint64
	terminalErr error
}

func randomSessionID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func Open(serverAddr, token, targetHost string, targetPort int, opts Options) (net.Conn, error) {
	if opts.minSize < 32 {
		opts.minSize = 32
	}
	if opts.maxSize < opts.minSize {
		opts.maxSize = opts.minSize
	}
	if opts.maxSize > protocol.MaxChunkPayload {
		opts.maxSize = protocol.MaxChunkPayload
	}
	if opts.startSize < opts.minSize {
		opts.startSize = opts.minSize
	}
	if opts.startSize > opts.maxSize {
		opts.startSize = opts.maxSize
	}
	if opts.adaptSuccesses < 1 {
		opts.adaptSuccesses = 64
	}
	if opts.pollers < 1 {
		opts.pollers = 1
	}
	if opts.pollers > 128 {
		opts.pollers = 128
	}
	if opts.txnTimeout <= 0 {
		opts.txnTimeout = 5 * time.Second
	}

	sid, err := randomSessionID()
	if err != nil {
		return nil, err
	}

	ctx, cancel := context.WithCancel(context.Background())
	c := &chunkConn{
		serverAddr: serverAddr,
		token:      token,
		sid:        sid,
		opts:       opts,
		ctx:        ctx,
		cancel:     cancel,
		results:    make(chan chunkResult, opts.pollers*4),
		pending:    make(map[uint64][]byte, opts.pollers*2),
	}
	c.ack.Store(-1)
	c.upSizer = newAdaptiveSizer("upload", opts.uploadStartSize, opts.uploadMaxSize, opts)
	c.downSizer = newAdaptiveSizer("download", opts.downloadStartSize, opts.downloadMaxSize, opts)

	c.pushLane = newTxnLane(serverAddr, opts.tcpBuffer, opts.reconnectEvery, opts.txnTimeout, opts.headerMask, opts.coverProfile)

	openPayload := []byte(fmt.Sprintf(
		"COPEN %s %s %s %d",
		wireToken(token), sid, targetHost, targetPort,
	))
	resp, err := doControl(c.pushLane, openPayload)
	if err != nil {
		c.pushLane.Close()
		cancel()
		return nil, err
	}
	fields := strings.Fields(string(resp))
	if len(fields) != 2 || fields[0] != "OPENED" {
		c.pushLane.Close()
		cancel()
		return nil, fmt.Errorf("%s", resp)
	}
	serverMax, err := strconv.Atoi(fields[1])
	if err != nil || serverMax < 32 {
		c.pushLane.Close()
		cancel()
		return nil, fmt.Errorf("bad OPENED response: %q", resp)
	}
	c.serverMax = serverMax
	if serverMax < c.opts.maxSize {
		c.opts.maxSize = serverMax
		c.upSizer.max = serverMax
		c.downSizer.max = serverMax
		if c.upSizer.current > serverMax {
			c.upSizer.current = serverMax
		}
		if c.downSizer.current > serverMax {
			c.downSizer.current = serverMax
		}
	}

	c.pullLanes = make([]*txnLane, opts.pollers)
	for i := 0; i < opts.pollers; i++ {
		lane := newTxnLane(serverAddr, opts.tcpBuffer, opts.reconnectEvery, opts.txnTimeout, opts.headerMask, opts.coverProfile)
		c.pullLanes[i] = lane
		c.workers.Add(1)
		go c.pullWorker(lane)
	}

	return c, nil
}

func parseDataResponse(resp []byte) (seq uint64, offset int, total int, data []byte, err error) {
	if len(resp) < 6 || string(resp[:5]) != "DATA " {
		return 0, 0, 0, nil, fmt.Errorf("not DATA")
	}

	rest := resp[5:]
	fields := make([][]byte, 0, 3)
	start := 0
	for i := 0; i < len(rest) && len(fields) < 3; i++ {
		if rest[i] == ' ' {
			fields = append(fields, rest[start:i])
			start = i + 1
		}
	}
	if len(fields) != 3 {
		return 0, 0, 0, nil, fmt.Errorf("bad DATA response")
	}

	seq, err = strconv.ParseUint(string(fields[0]), 10, 64)
	if err != nil {
		return 0, 0, 0, nil, err
	}
	offset, err = strconv.Atoi(string(fields[1]))
	if err != nil || offset < 0 {
		return 0, 0, 0, nil, fmt.Errorf("bad DATA offset")
	}
	total, err = strconv.Atoi(string(fields[2]))
	if err != nil || total < 0 {
		return 0, 0, 0, nil, fmt.Errorf("bad DATA total")
	}

	// start now points immediately after the third separator.
	return seq, offset, total, rest[start:], nil
}

func (c *chunkConn) pullWorker(lane *txnLane) {
	defer c.workers.Done()

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		seq := c.claim.Add(1) - 1
		offset := 0
		var assembled []byte
		consecutiveMinFailures := 0

		for {
			select {
			case <-c.ctx.Done():
				return
			default:
			}

			limit := c.downSizer.Current()
			ack := c.ack.Load()
			payload := []byte(fmt.Sprintf(
				"CPULL %s %s %d %d %d %d",
				wireToken(c.token), c.sid, ack, seq, offset, limit,
			))

			resp, err := lane.Do(payload)
			if err != nil {
				old, next := c.downSizer.Failure(limit)
				if !c.opts.adaptive || (next == old && next == c.opts.minSize) {
					consecutiveMinFailures++
				} else {
					consecutiveMinFailures = 0
				}
				if consecutiveMinFailures >= 8 {
					detail := fmt.Sprintf("download failed at minimum chunk %d", next)
					if !c.opts.adaptive {
						detail = fmt.Sprintf("download failed repeatedly at fixed calibrated chunk %d", next)
					}
					select {
					case c.results <- chunkResult{seq: seq, err: fmt.Errorf("%s: %w", detail, err)}:
					case <-c.ctx.Done():
					}
					return
				}
				time.Sleep(30 * time.Millisecond)
				continue
			}

			if string(resp) == "WAIT" {
				if c.opts.pollDelay > 0 {
					select {
					case <-time.After(c.opts.pollDelay):
					case <-c.ctx.Done():
						return
					}
				}
				continue
			}

			if strings.HasPrefix(string(resp), "ERR ") {
				select {
				case c.results <- chunkResult{seq: seq, err: fmt.Errorf("%s", resp)}:
				case <-c.ctx.Done():
				}
				return
			}

			if strings.HasPrefix(string(resp), "EOF ") {
				n, err := strconv.ParseUint(strings.TrimSpace(string(resp[4:])), 10, 64)
				if err != nil {
					select {
					case c.results <- chunkResult{seq: seq, err: err}:
					case <-c.ctx.Done():
					}
					return
				}
				select {
				case c.results <- chunkResult{seq: seq, eof: true, final: n}:
				case <-c.ctx.Done():
				}
				break
			}

			gotSeq, gotOffset, total, fragment, err := parseDataResponse(resp)
			if err != nil {
				select {
				case c.results <- chunkResult{seq: seq, err: err}:
				case <-c.ctx.Done():
				}
				return
			}
			if gotSeq != seq || gotOffset != offset {
				select {
				case c.results <- chunkResult{seq: seq, err: fmt.Errorf("DATA position mismatch")}:
				case <-c.ctx.Done():
				}
				return
			}
			if total > c.serverMax || total < offset+len(fragment) || len(fragment) == 0 {
				select {
				case c.results <- chunkResult{seq: seq, err: fmt.Errorf("invalid DATA fragment size")}:
				case <-c.ctx.Done():
				}
				return
			}

			if assembled == nil {
				assembled = make([]byte, 0, total)
			}
			assembled = append(assembled, fragment...)
			offset += len(fragment)
			consecutiveMinFailures = 0
			c.downSizer.Success(limit)

			if offset == total {
				select {
				case c.results <- chunkResult{seq: seq, data: assembled}:
				case <-c.ctx.Done():
				}
				break
			}
		}
	}
}

func (c *chunkConn) Read(p []byte) (int, error) {
	c.readMu.Lock()
	defer c.readMu.Unlock()

	for {
		if len(c.current) > 0 {
			n := copy(p, c.current)
			c.current = c.current[n:]
			if len(c.current) == 0 {
				c.nextRead++
				c.ack.Store(int64(c.currentSeq))
			}
			return n, nil
		}

		if c.terminalErr != nil {
			return 0, c.terminalErr
		}

		if c.finalKnown && c.nextRead >= c.finalSeq {
			return 0, io.EOF
		}

		if data, ok := c.pending[c.nextRead]; ok {
			delete(c.pending, c.nextRead)
			c.current = data
			c.currentSeq = c.nextRead
			continue
		}

		result, ok := <-c.results
		if !ok {
			return 0, io.EOF
		}
		if result.err != nil {
			c.terminalErr = result.err
			return 0, result.err
		}
		if result.eof {
			if !c.finalKnown || result.final < c.finalSeq {
				c.finalKnown = true
				c.finalSeq = result.final
			}
			continue
		}
		if result.seq < c.nextRead {
			continue
		}
		c.pending[result.seq] = result.data
	}
}

func parseAck(resp []byte, expectedSeq uint64) (int, error) {
	fields := strings.Fields(string(resp))
	if len(fields) != 3 || fields[0] != "ACK" {
		return 0, fmt.Errorf("bad CPUSH response: %q", resp)
	}
	seq, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil || seq != expectedSeq {
		return 0, fmt.Errorf("bad CPUSH sequence: %q", resp)
	}
	n, err := strconv.Atoi(fields[2])
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("bad CPUSH length: %q", resp)
	}
	return n, nil
}

func (c *chunkConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	total := 0
	consecutiveMinFailures := 0

	for len(p) > 0 {
		size := c.upSizer.Current()
		n := size
		if len(p) < n {
			n = len(p)
		}

		seq := c.upSeq
		prefix := []byte(fmt.Sprintf("CPUSH %s %s %d ", wireToken(c.token), c.sid, seq))
		payload := make([]byte, len(prefix)+n)
		copy(payload, prefix)
		copy(payload[len(prefix):], p[:n])

		resp, err := c.pushLane.Do(payload)
		if err != nil {
			old, next := c.upSizer.Failure(size)
			if !c.opts.adaptive || (next == old && next == c.opts.minSize) {
				consecutiveMinFailures++
			} else {
				consecutiveMinFailures = 0
			}
			if consecutiveMinFailures >= 8 {
				if !c.opts.adaptive {
					return total, fmt.Errorf("upload failed repeatedly at fixed calibrated chunk %d: %w", next, err)
				}
				return total, fmt.Errorf("upload failed at minimum chunk %d: %w", next, err)
			}
			time.Sleep(30 * time.Millisecond)
			continue
		}

		if strings.HasPrefix(string(resp), "ERR ") {
			return total, fmt.Errorf("%s", resp)
		}

		accepted, err := parseAck(resp, seq)
		if err != nil {
			return total, err
		}
		if accepted > len(p) {
			return total, fmt.Errorf("server ACK length %d exceeds pending write %d", accepted, len(p))
		}

		c.upSeq++
		total += accepted
		p = p[accepted:]
		consecutiveMinFailures = 0
		c.upSizer.Success(size)
	}

	return total, nil
}

func (c *chunkConn) Close() error {
	c.once.Do(func() {
		c.cancel()

		lane := newTxnLane(c.serverAddr, c.opts.tcpBuffer, 1, c.opts.txnTimeout, c.opts.headerMask, c.opts.coverProfile)
		_, _ = doControl(lane, []byte(fmt.Sprintf("CCLOSE %s %s", wireToken(c.token), c.sid)))
		lane.Close()

		if c.pushLane != nil {
			c.pushLane.Close()
		}
		for _, lane := range c.pullLanes {
			lane.Close()
		}
		c.workers.Wait()
		close(c.results)
	})
	return nil
}

func (c *chunkConn) LocalAddr() net.Addr              { return dummyAddr("dragontcp-chunk-local") }
func (c *chunkConn) RemoteAddr() net.Addr             { return dummyAddr("dragontcp-chunk-remote") }
func (c *chunkConn) SetDeadline(time.Time) error      { return nil }
func (c *chunkConn) SetReadDeadline(time.Time) error  { return nil }
func (c *chunkConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr string

func (d dummyAddr) Network() string { return "dragontcp-chunk" }
func (d dummyAddr) String() string  { return string(d) }
