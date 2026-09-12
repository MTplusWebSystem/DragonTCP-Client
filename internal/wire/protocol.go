package wire

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
)

const (
	RequestHeaderSize     = 29
	ResponseHeaderSize    = 5
	MuxRequestHeaderSize  = 33
	MuxResponseHeaderSize = 9
	MaxPayload            = 2 * 1024 * 1024

	ModeProbe    byte = 0
	ModeOpen     byte = 1
	ModeUpload   byte = 2
	ModeDownload byte = 3
	ModeClose    byte = 4

	StatusOK    byte = 0
	StatusError byte = 1
	StatusData  byte = 2
	StatusWait  byte = 3
	StatusEOF   byte = 4

	ProbeUpload        byte = 1
	ProbeDownload      byte = 2
	ProbeKeepalive     byte = 3
	ProbeBatch         byte = 4
	ProbeIperfUpload   byte = 5
	ProbeIperfDownload byte = 6
)

var ProbeMagic = [4]byte{'D', 'T', 'P', '2'}

// ProbeBurstCount is deliberately fixed at one. Startup calibration measures
// the safe record size of a single DragonTCP lane, not aggregate throughput.
// Multiple outstanding calibration records can make a constrained carrier look
// artificially better or worse and can produce a false ceiling. Confirmation
// retries are performed sequentially on fresh connections by the client.
func ProbeBurstCount(chunk int) int {
	return 1
}

type SessionID [16]byte

type Request struct {
	Mode    byte
	Session SessionID
	Seq     uint64
	Payload []byte
}

type MuxRequest struct {
	Mode      byte
	Session   SessionID
	Seq       uint64
	RequestID uint32
	Payload   []byte
}

type MuxResponse struct {
	Status    byte
	RequestID uint32
	Body      []byte
}

func MaskInPlace(data []byte, sid SessionID, mode byte, seq uint64, response bool) {
	if len(data) == 0 {
		return
	}

	var seed [30]byte
	copy(seed[:16], sid[:])
	seed[16] = mode
	binary.BigEndian.PutUint64(seed[17:25], seq)
	if response {
		seed[25] = 1
	}

	var counter uint32
	for off := 0; off < len(data); {
		binary.BigEndian.PutUint32(seed[26:30], counter)
		block := sha256.Sum256(seed[:])
		n := len(data) - off
		if n > len(block) {
			n = len(block)
		}
		for i := 0; i < n; i++ {
			data[off+i] ^= block[i]
		}
		off += n
		counter++
	}
}

func WriteRequest(w io.Writer, mode byte, sid SessionID, seq uint64, plaintext []byte) error {
	return WriteRequestProfile(w, mode, sid, seq, plaintext, 0)
}

// WriteRequestProfile writes a binary request whose first byte is XORed with
// headerMask. The remaining framing and payload encoding stay unchanged.
// Masks are selected once at client startup and then remain fixed.
func WriteRequestProfile(w io.Writer, mode byte, sid SessionID, seq uint64, plaintext []byte, headerMask byte) error {
	return WriteRequestProfileEncoding(w, mode, sid, seq, plaintext, headerMask, false)
}

// WriteRequestProfileEncoding optionally leaves the payload clear. Clear mode
// is signalled by the connection cover preface, so legacy peers continue to use
// the SHA-256 compatibility mask unchanged.
func WriteRequestProfileEncoding(w io.Writer, mode byte, sid SessionID, seq uint64, plaintext []byte, headerMask byte, clear bool) error {
	if len(plaintext) > MaxPayload {
		return fmt.Errorf("request payload too large: %d", len(plaintext))
	}
	if clear {
		var header [RequestHeaderSize]byte
		header[0] = mode ^ headerMask
		copy(header[1:17], sid[:])
		binary.BigEndian.PutUint64(header[17:25], seq)
		binary.BigEndian.PutUint32(header[25:29], uint32(len(plaintext)))
		buffers := net.Buffers{header[:], plaintext}
		_, err := buffers.WriteTo(w)
		return err
	}

	packet := make([]byte, RequestHeaderSize+len(plaintext))
	packet[0] = mode ^ headerMask
	copy(packet[1:17], sid[:])
	binary.BigEndian.PutUint64(packet[17:25], seq)
	binary.BigEndian.PutUint32(packet[25:29], uint32(len(plaintext)))
	copy(packet[29:], plaintext)
	MaskInPlace(packet[29:], sid, mode, seq, false)
	return writeAll(w, packet)
}

func ReadRequest(r io.Reader) (Request, error) {
	return ReadRequestProfile(r, 0)
}

// ReadRequestProfile decodes a request written with WriteRequestProfile.
func ReadRequestProfile(r io.Reader, headerMask byte) (Request, error) {
	return ReadRequestProfileEncoding(r, headerMask, false)
}

func ReadRequestProfileEncoding(r io.Reader, headerMask byte, clear bool) (Request, error) {
	var req Request
	var header [RequestHeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return req, err
	}

	req.Mode = header[0] ^ headerMask
	if req.Mode > ModeClose {
		return req, errors.New("unknown request mode")
	}
	copy(req.Session[:], header[1:17])
	req.Seq = binary.BigEndian.Uint64(header[17:25])
	n := binary.BigEndian.Uint32(header[25:29])
	if n > MaxPayload {
		return req, errors.New("request payload too large")
	}

	if n > 0 {
		req.Payload = make([]byte, int(n))
		if _, err := io.ReadFull(r, req.Payload); err != nil {
			return req, err
		}
		if !clear {
			MaskInPlace(req.Payload, req.Session, req.Mode, req.Seq, false)
		}
	}
	return req, nil
}

func WriteMuxRequest(w io.Writer, mode byte, sid SessionID, seq uint64, reqID uint32, plaintext []byte) error {
	return WriteMuxRequestProfile(w, mode, sid, seq, reqID, plaintext, 0)
}

// WriteMuxRequestProfile writes a 33-byte multiplexed binary request whose
// first byte is XORed with headerMask.
func WriteMuxRequestProfile(w io.Writer, mode byte, sid SessionID, seq uint64, reqID uint32, plaintext []byte, headerMask byte) error {
	return WriteMuxRequestProfileEncoding(w, mode, sid, seq, reqID, plaintext, headerMask, false)
}

// WriteMuxRequestProfileEncoding optionally leaves the payload clear.
func WriteMuxRequestProfileEncoding(w io.Writer, mode byte, sid SessionID, seq uint64, reqID uint32, plaintext []byte, headerMask byte, clear bool) error {
	if len(plaintext) > MaxPayload {
		return fmt.Errorf("request payload too large: %d", len(plaintext))
	}
	if clear {
		var header [MuxRequestHeaderSize]byte
		header[0] = mode ^ headerMask
		copy(header[1:17], sid[:])
		binary.BigEndian.PutUint64(header[17:25], seq)
		binary.BigEndian.PutUint32(header[25:29], reqID)
		binary.BigEndian.PutUint32(header[29:33], uint32(len(plaintext)))
		buffers := net.Buffers{header[:], plaintext}
		_, err := buffers.WriteTo(w)
		return err
	}

	packet := make([]byte, MuxRequestHeaderSize+len(plaintext))
	packet[0] = mode ^ headerMask
	copy(packet[1:17], sid[:])
	binary.BigEndian.PutUint64(packet[17:25], seq)
	binary.BigEndian.PutUint32(packet[25:29], reqID)
	binary.BigEndian.PutUint32(packet[29:33], uint32(len(plaintext)))
	copy(packet[33:], plaintext)
	MaskInPlace(packet[33:], sid, mode, seq, false)
	return writeAll(w, packet)
}

func ReadMuxRequest(r io.Reader) (MuxRequest, error) {
	return ReadMuxRequestProfile(r, 0)
}

// ReadMuxRequestProfile decodes a multiplexed request written with WriteMuxRequestProfile.
func ReadMuxRequestProfile(r io.Reader, headerMask byte) (MuxRequest, error) {
	return ReadMuxRequestProfileEncoding(r, headerMask, false)
}

func ReadMuxRequestProfileEncoding(r io.Reader, headerMask byte, clear bool) (MuxRequest, error) {
	var req MuxRequest
	var header [MuxRequestHeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return req, err
	}

	req.Mode = header[0] ^ headerMask
	if req.Mode > ModeClose {
		return req, errors.New("unknown request mode")
	}
	copy(req.Session[:], header[1:17])
	req.Seq = binary.BigEndian.Uint64(header[17:25])
	req.RequestID = binary.BigEndian.Uint32(header[25:29])
	n := binary.BigEndian.Uint32(header[29:33])
	if n > MaxPayload {
		return req, errors.New("request payload too large")
	}

	if n > 0 {
		req.Payload = make([]byte, int(n))
		if _, err := io.ReadFull(r, req.Payload); err != nil {
			return req, err
		}
		if !clear {
			MaskInPlace(req.Payload, req.Session, req.Mode, req.Seq, false)
		}
	}
	return req, nil
}

func WriteResponse(w io.Writer, status byte, body []byte) error {
	return WriteResponseProfile(w, status, body, writerHeaderMask(w))
}

// WriteResponseProfile writes a response using the selected first-byte mask.
func WriteResponseProfile(w io.Writer, status byte, body []byte, headerMask byte) error {
	if len(body) > MaxPayload {
		return fmt.Errorf("response body too large: %d", len(body))
	}
	packet := make([]byte, ResponseHeaderSize+len(body))
	packet[0] = status ^ headerMask
	binary.BigEndian.PutUint32(packet[1:5], uint32(len(body)))
	copy(packet[5:], body)
	return writeAll(w, packet)
}

func WriteMaskedResponse(w io.Writer, status byte, body []byte, sid SessionID, mode byte, seq uint64) error {
	return WriteMaskedResponseProfileEncoding(w, status, body, sid, mode, seq, writerHeaderMask(w), writerClearPayload(w))
}

// WriteMaskedResponseProfile combines the normal payload mask with the
// selected first-byte header mask.
func WriteMaskedResponseProfile(w io.Writer, status byte, body []byte, sid SessionID, mode byte, seq uint64, headerMask byte) error {
	return WriteMaskedResponseProfileEncoding(w, status, body, sid, mode, seq, headerMask, false)
}

func WriteMaskedResponseProfileEncoding(w io.Writer, status byte, body []byte, sid SessionID, mode byte, seq uint64, headerMask byte, clear bool) error {
	if len(body) > MaxPayload {
		return fmt.Errorf("response body too large: %d", len(body))
	}
	if clear {
		var header [ResponseHeaderSize]byte
		header[0] = status ^ headerMask
		binary.BigEndian.PutUint32(header[1:5], uint32(len(body)))
		buffers := net.Buffers{header[:], body}
		_, err := buffers.WriteTo(w)
		return err
	}
	packet := make([]byte, ResponseHeaderSize+len(body))
	packet[0] = status ^ headerMask
	binary.BigEndian.PutUint32(packet[1:5], uint32(len(body)))
	copy(packet[5:], body)
	MaskInPlace(packet[5:], sid, mode, seq, true)
	return writeAll(w, packet)
}

func ReadResponse(r io.Reader) (byte, []byte, error) {
	return ReadResponseProfile(r, 0)
}

// ReadResponseProfile decodes a response written with a header profile.
func ReadResponseProfile(r io.Reader, headerMask byte) (byte, []byte, error) {
	var header [ResponseHeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}
	n := binary.BigEndian.Uint32(header[1:5])
	if n > MaxPayload {
		return 0, nil, errors.New("response body too large")
	}
	var body []byte
	if n > 0 {
		body = make([]byte, int(n))
		if _, err := io.ReadFull(r, body); err != nil {
			return 0, nil, err
		}
	}
	status := header[0] ^ headerMask
	if status > StatusEOF {
		return 0, nil, errors.New("unknown response status")
	}
	return status, body, nil
}

func DecodeMaskedResponse(status byte, body []byte, sid SessionID, mode byte, seq uint64) []byte {
	if len(body) == 0 || status == StatusError {
		return body
	}
	MaskInPlace(body, sid, mode, seq, true)
	return body
}

func WriteMuxResponse(w io.Writer, status byte, reqID uint32, body []byte) error {
	return WriteMuxResponseProfile(w, status, reqID, body, writerHeaderMask(w))
}

// WriteMuxResponseProfile writes an unmasked multiplexed response using the
// selected first-byte mask.
func WriteMuxResponseProfile(w io.Writer, status byte, reqID uint32, body []byte, headerMask byte) error {
	if len(body) > MaxPayload {
		return fmt.Errorf("response body too large: %d", len(body))
	}
	packet := make([]byte, MuxResponseHeaderSize+len(body))
	packet[0] = status ^ headerMask
	binary.BigEndian.PutUint32(packet[1:5], reqID)
	binary.BigEndian.PutUint32(packet[5:9], uint32(len(body)))
	copy(packet[9:], body)
	return writeAll(w, packet)
}

func WriteMaskedMuxResponse(w io.Writer, status byte, reqID uint32, body []byte, sid SessionID, mode byte, seq uint64) error {
	return WriteMaskedMuxResponseProfileEncoding(w, status, reqID, body, sid, mode, seq, writerHeaderMask(w), writerClearPayload(w))
}

// WriteMaskedMuxResponseProfile combines the payload mask with the selected
// first-byte header mask.
func WriteMaskedMuxResponseProfile(w io.Writer, status byte, reqID uint32, body []byte, sid SessionID, mode byte, seq uint64, headerMask byte) error {
	return WriteMaskedMuxResponseProfileEncoding(w, status, reqID, body, sid, mode, seq, headerMask, false)
}

func WriteMaskedMuxResponseProfileEncoding(w io.Writer, status byte, reqID uint32, body []byte, sid SessionID, mode byte, seq uint64, headerMask byte, clear bool) error {
	if len(body) > MaxPayload {
		return fmt.Errorf("response body too large: %d", len(body))
	}
	if clear {
		var header [MuxResponseHeaderSize]byte
		header[0] = status ^ headerMask
		binary.BigEndian.PutUint32(header[1:5], reqID)
		binary.BigEndian.PutUint32(header[5:9], uint32(len(body)))
		buffers := net.Buffers{header[:], body}
		_, err := buffers.WriteTo(w)
		return err
	}
	packet := make([]byte, MuxResponseHeaderSize+len(body))
	packet[0] = status ^ headerMask
	binary.BigEndian.PutUint32(packet[1:5], reqID)
	binary.BigEndian.PutUint32(packet[5:9], uint32(len(body)))
	copy(packet[9:], body)
	MaskInPlace(packet[9:], sid, mode, seq, true)
	return writeAll(w, packet)
}

func ReadMuxResponse(r io.Reader) (MuxResponse, error) {
	return ReadMuxResponseProfile(r, 0)
}

// ReadMuxResponseProfile decodes a 9-byte multiplexed response written with WriteMuxResponseProfile.
func ReadMuxResponseProfile(r io.Reader, headerMask byte) (MuxResponse, error) {
	var resp MuxResponse
	var header [MuxResponseHeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return resp, err
	}
	resp.Status = header[0] ^ headerMask
	if resp.Status > StatusEOF {
		return resp, errors.New("unknown response status")
	}
	resp.RequestID = binary.BigEndian.Uint32(header[1:5])
	n := binary.BigEndian.Uint32(header[5:9])
	if n > MaxPayload {
		return resp, errors.New("response body too large")
	}
	if n > 0 {
		resp.Body = make([]byte, int(n))
		if _, err := io.ReadFull(r, resp.Body); err != nil {
			return resp, err
		}
	}
	return resp, nil
}

func DecodeMaskedMuxResponse(resp MuxResponse, sid SessionID, mode byte, seq uint64) []byte {
	return DecodeMaskedResponse(resp.Status, resp.Body, sid, mode, seq)
}

// IsTerminalStatus reports whether a status code represents the end of a request
// transaction or download sequence.
func IsTerminalStatus(status byte) bool {
	return status == StatusWait || status == StatusEOF || status == StatusError || status == StatusOK
}

// RequestIDPool manages a recycling free-list pool of 32-bit request IDs.
// IDs are allocated from the pool for in-flight requests and recycled
// once a terminal response has been processed.
type RequestIDPool struct {
	mu       sync.Mutex
	free     []uint32
	next     uint32
	inFlight int
}

// NewRequestIDPool creates a new pool. If start is 0, it defaults to 1.
func NewRequestIDPool(start uint32) *RequestIDPool {
	if start == 0 {
		start = 1
	}
	return &RequestIDPool{
		next: start,
	}
}

// Alloc reserves an ID from the pool.
func (p *RequestIDPool) Alloc() uint32 {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.inFlight++
	if n := len(p.free); n > 0 {
		id := p.free[n-1]
		p.free = p.free[:n-1]
		return id
	}
	id := p.next
	p.next++
	if p.next == 0 {
		p.next = 1
	}
	return id
}

// Release returns an ID back to the free-list for reuse.
func (p *RequestIDPool) Release(id uint32) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.inFlight > 0 {
		p.inFlight--
	}
	p.free = append(p.free, id)
}

// InFlight returns the number of IDs currently allocated and not yet released.
func (p *RequestIDPool) InFlight() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.inFlight
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}

func writerHeaderMask(w io.Writer) byte {
	if profiled, ok := w.(interface{ HeaderMask() byte }); ok {
		return profiled.HeaderMask()
	}
	return 0
}

func writerClearPayload(w io.Writer) bool {
	if profiled, ok := w.(interface{ ClearPayload() bool }); ok {
		return profiled.ClearPayload()
	}
	return false
}
