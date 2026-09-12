package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const (
	XORKey byte = 0xAD

	// MaxChunkPayload is the hard application-record payload ceiling.
	// The adaptive chunk protocol may use any size from 32 bytes through 1 MiB.
	MaxChunkPayload = 1024 * 1024

	// Framed CPUSH/DATA messages include text metadata in addition to chunk
	// bytes, so keep the frame ceiling comfortably above MaxChunkPayload.
	MaxHandshake = 2 * 1024 * 1024
)

// 64 KiB balances throughput with memory use at high connection counts.
var BufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, 64*1024)
		return &b
	},
}

func ReadRequestFrame(r io.Reader) (uint32, uint32, []byte, error) {
	return ReadRequestFrameProfile(r, 0)
}

// ReadRequestFrameProfile decodes the UP magic after applying headerMask.
func ReadRequestFrameProfile(r io.Reader, headerMask byte) (uint32, uint32, []byte, error) {
	var header [14]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, 0, nil, err
	}

	if header[0]^headerMask != 'U' || header[1]^headerMask != 'P' {
		return 0, 0, nil, errors.New("bad request magic")
	}

	requestID := binary.BigEndian.Uint32(header[2:6])
	reserved := binary.BigEndian.Uint32(header[6:10])
	length := binary.BigEndian.Uint32(header[10:14])

	if length > MaxHandshake {
		return 0, 0, nil, errors.New("handshake payload too large")
	}

	payload := make([]byte, int(length))
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, 0, nil, err
	}
	XorInPlace(payload)

	return requestID, reserved, payload, nil
}

func WriteRequestFrame(w io.Writer, requestID uint32, payload []byte) error {
	return WriteRequestFrameProfile(w, requestID, payload, 0)
}

// WriteRequestFrameProfile masks the two-byte UP magic with headerMask.
func WriteRequestFrameProfile(w io.Writer, requestID uint32, payload []byte, headerMask byte) error {
	if len(payload) > MaxHandshake {
		return errors.New("request frame payload too large")
	}
	packet := make([]byte, 14+len(payload))
	packet[0], packet[1] = 'U'^headerMask, 'P'^headerMask
	binary.BigEndian.PutUint32(packet[2:6], requestID)
	binary.BigEndian.PutUint32(packet[6:10], 0)
	binary.BigEndian.PutUint32(packet[10:14], uint32(len(payload)))
	copy(packet[14:], payload)
	XorInPlace(packet[14:])
	return writeAll(w, packet)
}

func ReadResponseFrame(r io.Reader) (uint32, []byte, error) {
	return ReadResponseFrameProfile(r, 0)
}

// ReadResponseFrameProfile decodes the OK magic after applying headerMask.
func ReadResponseFrameProfile(r io.Reader, headerMask byte) (uint32, []byte, error) {
	var header [10]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, nil, err
	}

	if header[0]^headerMask != 'O' || header[1]^headerMask != 'K' {
		return 0, nil, fmt.Errorf("bad response magic: %q", header[:2])
	}

	requestID := binary.BigEndian.Uint32(header[2:6])
	length := binary.BigEndian.Uint32(header[6:10])

	if length > MaxHandshake {
		return 0, nil, errors.New("handshake response too large")
	}

	payload := make([]byte, int(length))
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	XorInPlace(payload)

	return requestID, payload, nil
}

func WriteResponseFrame(w io.Writer, requestID uint32, payload []byte) error {
	return WriteResponseFrameProfile(w, requestID, payload, writerHeaderMask(w))
}

// WriteResponseFrameProfile masks the two-byte OK magic with headerMask.
func WriteResponseFrameProfile(w io.Writer, requestID uint32, payload []byte, headerMask byte) error {
	if len(payload) > MaxHandshake {
		return errors.New("response frame payload too large")
	}
	packet := make([]byte, 10+len(payload))
	packet[0], packet[1] = 'O'^headerMask, 'K'^headerMask
	binary.BigEndian.PutUint32(packet[2:6], requestID)
	binary.BigEndian.PutUint32(packet[6:10], uint32(len(payload)))
	copy(packet[10:], payload)
	XorInPlace(packet[10:])
	return writeAll(w, packet)
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
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

func CopyXOR(dst net.Conn, src net.Conn) error {
	ptr := BufferPool.Get().(*[]byte)
	buf := *ptr
	defer BufferPool.Put(ptr)

	for {
		n, err := src.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			XorInPlace(chunk)

			if err2 := writeAll(dst, chunk); err2 != nil {
				return err2
			}

			// No restore pass is needed. The next Read overwrites these bytes.
		}

		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func relayPair(a, b net.Conn, copier func(net.Conn, net.Conn) error) {
	done := make(chan struct{}, 2)

	go func() {
		_ = copier(b, a)
		if cw, ok := b.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}()

	go func() {
		_ = copier(a, b)
		if cw, ok := a.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}()

	// Preserve normal TCP half-close semantics. The old implementation set a
	// 2-second deadline on both connections after the first copy direction
	// ended, which truncated slow or large responses. Wait for the remaining
	// direction to drain naturally instead.
	<-done
	<-done
}

func RelayXOR(a, b net.Conn) {
	relayPair(a, b, CopyXOR)
}

// RelayRaw allows Go/Linux to use the optimized TCP io.Copy path. On Linux,
// TCP-to-TCP copies can use splice, eliminating the userspace XOR/copy loop.
func RelayRaw(a, b net.Conn) {
	relayPair(a, b, func(dst, src net.Conn) error {
		_, err := io.Copy(dst, src)
		return err
	})
}

func TuneTCP(conn net.Conn) {
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetNoDelay(true)
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	}
}

// TuneTCPBuffer optionally requests larger kernel socket buffers. A value <= 0
// leaves Linux/Android autotuning untouched, which is the recommended default
// for large connection counts. For a small number of high-BDP mobile links,
// values such as 1048576 or 4194304 can improve throughput.
func TuneTCPBuffer(conn net.Conn, size int) {
	if size <= 0 {
		return
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetReadBuffer(size)
		_ = tcp.SetWriteBuffer(size)
	}
}
