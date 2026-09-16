package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"dragontcp/internal/cover"
	"dragontcp/internal/protocol"
	"dragontcp/internal/wire"
)

const (
	bpModeProbe         byte = 0
	bpModeUpload        byte = 1
	bpModeDownload      byte = 2
	bpModeBatchDownload byte = 3
	bpModeACK           byte = 4
	bpHeaderSize             = 29
)

var bpOpenMagic = [4]byte{'D', 'O', 'P', '1'}
var bpCloseMagic = [4]byte{'D', 'C', 'L', '1'}

type bpPhysicalConn struct {
	conn     net.Conn
	requests int
}

type bpLane struct {
	mu             sync.Mutex
	serverAddr     string
	tcpBuffer      int
	reconnectEvery int
	timeout        time.Duration
	headerMask     byte
	coverProfile   cover.Profile
	autoReconnect  bool
	pc             *bpPhysicalConn
	closed         bool
}

func newBPLane(serverAddr string, tcpBuffer, reconnectEvery int, timeout time.Duration, coverProfile cover.Profile) *bpLane {
	return newBPLaneWithMask(serverAddr, tcpBuffer, reconnectEvery, timeout, coverProfile.HeaderMask, coverProfile)
}

func newBPLaneWithMask(serverAddr string, tcpBuffer, reconnectEvery int, timeout time.Duration, headerMask byte, coverProfile cover.Profile) *bpLane {
	autoReconnect := reconnectEvery == 1
	if autoReconnect {
		reconnectEvery = 0
	}
	return &bpLane{
		serverAddr:     serverAddr,
		tcpBuffer:      tcpBuffer,
		reconnectEvery: reconnectEvery,
		timeout:        timeout,
		headerMask:     headerMask,
		coverProfile:   coverProfile,
		autoReconnect:  autoReconnect,
	}
}

func (l *bpLane) transportFailureLocked(reused bool) {
	if l.autoReconnect && reused {
		l.reconnectEvery = 1
	}
	l.discardLocked()
}

func (l *bpLane) discardLocked() {
	if l.pc != nil {
		_ = l.pc.conn.Close()
		l.pc = nil
	}
}

func (l *bpLane) closeAfterLocked() {
	if l.pc != nil && l.reconnectEvery > 0 && l.pc.requests >= l.reconnectEvery {
		l.discardLocked()
	}
}

func (l *bpLane) ensureLocked() error {
	if l.closed {
		return net.ErrClosed
	}
	if l.pc != nil {
		if l.reconnectEvery <= 0 || l.pc.requests < l.reconnectEvery {
			return nil
		}
		l.discardLocked()
	}
	conn, err := protocol.DialTCP("tcp", l.serverAddr, 10*time.Second, l.tcpBuffer)
	if err != nil {
		return err
	}
	if err := cover.WritePreface(conn, l.coverProfile); err != nil {
		_ = conn.Close()
		return err
	}
	l.pc = &bpPhysicalConn{conn: conn}
	return nil
}

func (l *bpLane) Close() {
	l.mu.Lock()
	l.closed = true
	l.discardLocked()
	l.mu.Unlock()
}

func writeBPRequest(w io.Writer, mode byte, sid wire.SessionID, seq uint64, payload []byte, downloadHint uint32, headerMask byte, clear bool) error {
	n := uint32(len(payload))
	if mode == bpModeDownload {
		n = downloadHint
		payload = nil
	}
	if len(payload) > wire.MaxPayload {
		return fmt.Errorf("BP payload too large: %d", len(payload))
	}
	var header [bpHeaderSize]byte
	header[0] = mode ^ headerMask
	copy(header[1:17], sid[:])
	binary.BigEndian.PutUint64(header[17:25], seq)
	binary.BigEndian.PutUint32(header[25:29], n)
	if clear {
		buffers := net.Buffers{header[:], payload}
		_, err := buffers.WriteTo(w)
		return err
	}
	packet := make([]byte, bpHeaderSize+len(payload))
	copy(packet[:bpHeaderSize], header[:])
	copy(packet[bpHeaderSize:], payload)
	wire.MaskInPlace(packet[bpHeaderSize:], sid, mode, seq, false)
	for len(packet) > 0 {
		written, err := w.Write(packet)
		if err != nil {
			return err
		}
		if written <= 0 {
			return io.ErrShortWrite
		}
		packet = packet[written:]
	}
	return nil
}

func readBPResponse(r io.Reader, sid wire.SessionID, mode byte, seq uint64, headerMask byte, clear bool) (byte, []byte, error) {
	status, body, err := wire.ReadResponseProfile(r, headerMask)
	if err == nil && status != wire.StatusError && len(body) > 0 && !clear {
		wire.MaskInPlace(body, sid, mode, seq, true)
	}
	return status, body, err
}

func (l *bpLane) single(mode byte, sid wire.SessionID, seq uint64, payload []byte, downloadHint uint32) (byte, []byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	timeout := l.timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		if err := l.ensureLocked(); err != nil {
			if isTransportTimeout(err) {
				return 0, nil, err
			}
			lastErr = err
			continue
		}
		reused := l.pc.requests > 0
		_ = l.pc.conn.SetDeadline(time.Now().Add(timeout))
		if err := writeBPRequest(l.pc.conn, mode, sid, seq, payload, downloadHint, l.headerMask, l.coverProfile.Clear); err != nil {
			l.transportFailureLocked(reused)
			if isTransportTimeout(err) {
				return 0, nil, err
			}
			lastErr = err
			continue
		}
		status, body, err := readBPResponse(l.pc.conn, sid, mode, seq, l.headerMask, l.coverProfile.Clear)
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
		return status, body, nil
	}
	return 0, nil, fmt.Errorf("BP request failed after reconnect: %w", lastErr)
}

// probeBPProfile validates one BP header/cover profile with a single small
// BHP1 echo transaction. It deliberately does not register/open a target
// session; authenticated DTP2 calibration runs immediately after profile
// selection and remains authoritative for the configured server token.
func probeBPProfile(serverAddr string, opts chunkClientOptions) bool {
	sid, err := randomSessionID()
	if err != nil {
		return false
	}
	timeout := opts.txnTimeout
	if timeout <= 0 || timeout > profileProbeTimeout {
		timeout = profileProbeTimeout
	}
	lane := newBPLaneWithMask(serverAddr, opts.tcpBuffer, 1, timeout, opts.headerMask, opts.coverProfile)
	defer lane.Close()

	payload := make([]byte, 10)
	copy(payload[:4], []byte("BHP1"))
	payload[4] = 1
	payload[5] = bpModeUpload
	binary.BigEndian.PutUint32(payload[6:10], 0)
	status, body, err := lane.single(bpModeProbe, sid, 0, payload, 0)
	return err == nil && status == wire.StatusOK && bytes.Equal(body, payload)
}

func decodeBPData(body []byte) ([]byte, error) {
	if len(body) < 4 {
		return nil, fmt.Errorf("short BP DATA body")
	}
	n := int(binary.BigEndian.Uint32(body[:4]))
	if n < 0 || n > len(body)-4 {
		return nil, fmt.Errorf("bad BP DATA length")
	}
	return append([]byte(nil), body[4:4+n]...), nil
}

func (l *bpLane) download(sid wire.SessionID, offset uint64, maxChunk, count int) ([][]byte, byte, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	timeout := l.timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	mode := bpModeDownload
	payload := []byte(nil)
	hint := uint32(maxChunk)
	if count > 1 {
		mode = bpModeBatchDownload
		payload = make([]byte, 6)
		binary.BigEndian.PutUint32(payload[:4], uint32(maxChunk))
		binary.BigEndian.PutUint16(payload[4:6], uint16(count))
		hint = 0
	}
	responses := 1
	if mode == bpModeBatchDownload {
		responses = count
	}
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
		if err := writeBPRequest(l.pc.conn, mode, sid, offset, payload, hint, l.headerMask, l.coverProfile.Clear); err != nil {
			l.transportFailureLocked(reused)
			if isTransportTimeout(err) {
				return nil, 0, err
			}
			lastErr = err
			continue
		}

		out := make([][]byte, 0, responses)
		lastStatus := wire.StatusOK
		for i := 0; i < responses; i++ {
			status, body, err := readBPResponse(l.pc.conn, sid, mode, offset, l.headerMask, l.coverProfile.Clear)
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
				data, err := decodeBPData(body)
				if err != nil {
					l.discardLocked()
					return out, status, err
				}
				if len(data) > 0 {
					out = append(out, data)
				}
			case wire.StatusOK, wire.StatusWait:
			case wire.StatusEOF:
			case wire.StatusError:
				l.discardLocked()
				return out, status, fmt.Errorf("%s", string(body))
			default:
				l.discardLocked()
				return out, status, fmt.Errorf("unexpected BP download status %d", status)
			}
		}
		l.pc.requests++
		_ = l.pc.conn.SetDeadline(time.Time{})
		l.closeAfterLocked()
		return out, lastStatus, nil
	retry:
	}
	return nil, 0, fmt.Errorf("BP download request failed after reconnect: %w", lastErr)
}

type bpConn struct {
	sid          wire.SessionID
	opts         chunkClientOptions
	uploadLane   *bpLane
	downloadLane *bpLane
	upSizer      *adaptiveSizer
	downSizer    *adaptiveSizer

	writeMu  sync.Mutex
	upOffset uint64

	readMu         sync.Mutex
	readBuf        []byte
	downloadOffset uint64
	consumedOffset uint64
	lastAck        uint64
	eof            bool
	pipeline       int

	closeOnce sync.Once
	dead      atomic.Bool
}

func openBPTunnel(serverAddr, token, targetHost string, targetPort int, opts chunkClientOptions) (net.Conn, error) {
	if opts.minSize < 32 {
		opts.minSize = 32
	}
	if opts.maxSize < opts.minSize {
		opts.maxSize = opts.minSize
	}
	if opts.maxSize > 1024*1024 {
		opts.maxSize = 1024 * 1024
	}
	if opts.startSize < opts.minSize || opts.startSize > opts.maxSize {
		opts.startSize = opts.maxSize
	}
	if opts.forceMaxStart {
		opts.startSize = opts.maxSize
	}
	if opts.txnTimeout <= 0 {
		opts.txnTimeout = 5 * time.Second
	}
	if opts.shrinkAfter < 1 {
		opts.shrinkAfter = 1
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
	reconnect := opts.reconnectEvery
	if reconnect < 0 {
		reconnect = 0
	}

	profile := pathProfile{
		upload:     opts.startSize,
		download:   opts.startSize,
		persistent: false,
		at:         time.Now(),
	}
	if !opts.skipPathProbe {
		// BP uses the same binary framing sizes and cover preface as the native B
		// transport. Reuse the authenticated DTP2 probe machinery to calibrate
		// the carrier before BP starts moving SSH/application data.
		profile = getPathProfile(serverAddr, token, opts)
		if profile.pollers > opts.pollers {
			opts.pollers = profile.pollers
		}
	}

	sid, err := randomSessionID()
	if err != nil {
		return nil, err
	}
	uploadLane := newBPLaneWithMask(serverAddr, opts.tcpBuffer, reconnect, opts.txnTimeout, opts.headerMask, opts.coverProfile)
	status, body, err := uploadLane.single(bpModeUpload, sid, 0, nil, 0)
	if err != nil {
		uploadLane.Close()
		return nil, err
	}
	if status == wire.StatusError {
		uploadLane.Close()
		return nil, fmt.Errorf("%s", string(body))
	}
	if status != wire.StatusOK {
		uploadLane.Close()
		return nil, fmt.Errorf("bad BP registration response %d", status)
	}
	openPayload, err := encodeOpen(token, targetHost, targetPort)
	if err != nil {
		uploadLane.Close()
		return nil, err
	}
	openPayload = append(append([]byte(nil), bpOpenMagic[:]...), openPayload...)
	status, body, err = uploadLane.single(bpModeUpload, sid, 1, openPayload, 0)
	if err != nil {
		uploadLane.Close()
		return nil, err
	}
	if status == wire.StatusError {
		uploadLane.Close()
		return nil, fmt.Errorf("%s", string(body))
	}
	if status != wire.StatusOK {
		uploadLane.Close()
		return nil, fmt.Errorf("bad BP OPEN response %d", status)
	}

	c := &bpConn{
		sid:          sid,
		opts:         opts,
		uploadLane:   uploadLane,
		downloadLane: newBPLaneWithMask(serverAddr, opts.tcpBuffer, reconnect, opts.txnTimeout, opts.headerMask, opts.coverProfile),
		pipeline:     opts.maxPipeline,
	}
	upStart := minInt(profile.upload, opts.maxSize)
	downStart := minInt(profile.download, opts.maxSize)
	if upStart < opts.minSize {
		upStart = opts.minSize
	}
	if downStart < opts.minSize {
		downStart = opts.minSize
	}
	upSizerOpts := opts
	downSizerOpts := opts
	if !opts.skipPathProbe {
		upSizerOpts.maxSize = upStart
		downSizerOpts.maxSize = downStart
	}
	c.upSizer = newAdaptiveSizer("BP upload", upStart, upSizerOpts)
	c.downSizer = newAdaptiveSizer("BP download", downStart, downSizerOpts)
	return c, nil
}

func (c *bpConn) fillReadBuffer() error {
	if c.eof {
		return io.EOF
	}
	for len(c.readBuf) == 0 && !c.eof {
		if c.consumedOffset > c.lastAck {
			status, body, err := c.downloadLane.single(bpModeACK, c.sid, c.consumedOffset, nil, 0)
			if err != nil {
				if isTransportTimeout(err) {
					c.dead.Store(true)
				}
				return err
			}
			if status == wire.StatusError {
				return fmt.Errorf("%s", string(body))
			}
			c.lastAck = c.consumedOffset
		}
		chunk := c.downSizer.Current()
		count := c.pipeline
		if count < c.opts.minPipeline {
			count = c.opts.minPipeline
		}
		if count > c.opts.maxPipeline {
			count = c.opts.maxPipeline
		}
		data, status, err := c.downloadLane.download(c.sid, c.downloadOffset, chunk, count)
		if err != nil {
			if isTransportTimeout(err) {
				c.dead.Store(true)
				return err
			}
			old, next := c.downSizer.FailureReason(chunk, err)
			if old == next && next == c.opts.minSize {
				return err
			}
			time.Sleep(30 * time.Millisecond)
			continue
		}
		c.readBuf = appendChunkParts(c.readBuf, data)
		for _, part := range data {
			c.downloadOffset += uint64(len(part))
		}
		if len(data) > 0 {
			c.downSizer.Success(chunk)
			if c.pipeline < c.opts.maxPipeline {
				c.pipeline++
			}
		}
		if status == wire.StatusEOF {
			c.eof = true
		}
		if len(c.readBuf) == 0 && !c.eof {
			delay := c.opts.pollDelay
			if delay <= 0 {
				delay = 5 * time.Millisecond
			}
			time.Sleep(delay)
		}
	}
	if c.eof && len(c.readBuf) == 0 {
		return io.EOF
	}
	return nil
}

func (c *bpConn) Read(p []byte) (int, error) {
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

func (c *bpConn) Write(p []byte) (int, error) {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	total := 0
	for len(p) > 0 {
		size := c.upSizer.Current()
		n := minInt(size, len(p))
		status, body, err := c.uploadLane.single(bpModeUpload, c.sid, c.upOffset+2, p[:n], 0)
		if err != nil {
			if isTransportTimeout(err) {
				c.dead.Store(true)
				return total, err
			}
			old, next := c.upSizer.FailureReason(size, err)
			if old == next && next == c.opts.minSize {
				return total, err
			}
			time.Sleep(30 * time.Millisecond)
			continue
		}
		if status == wire.StatusError {
			return total, fmt.Errorf("%s", string(body))
		}
		if status != wire.StatusOK {
			return total, fmt.Errorf("unexpected BP upload status %d", status)
		}
		c.upOffset += uint64(n)
		total += n
		p = p[n:]
		c.upSizer.Success(size)
	}
	return total, nil
}

func (c *bpConn) Close() error {
	c.closeOnce.Do(func() {
		// A timeout is a hard tunnel boundary. Do not create a fresh physical
		// connection only to close a session that has already been abandoned.
		if !c.dead.Load() {
			_, _, _ = c.downloadLane.single(bpModeACK, c.sid, c.consumedOffset, bpCloseMagic[:], 0)
		}
		c.uploadLane.Close()
		c.downloadLane.Close()
	})
	return nil
}

func (c *bpConn) LocalAddr() net.Addr              { return dummyAddr("dragontcp-bp-local") }
func (c *bpConn) RemoteAddr() net.Addr             { return dummyAddr("dragontcp-bp-remote") }
func (c *bpConn) SetDeadline(time.Time) error      { return nil }
func (c *bpConn) SetReadDeadline(time.Time) error  { return nil }
func (c *bpConn) SetWriteDeadline(time.Time) error { return nil }
