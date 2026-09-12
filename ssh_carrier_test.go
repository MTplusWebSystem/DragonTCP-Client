package main

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

type carrierTestConn struct {
	mu     sync.Mutex
	writes int
	buf    bytes.Buffer
	closed bool
}

func (c *carrierTestConn) Read([]byte) (int, error) { return 0, io.EOF }
func (c *carrierTestConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, net.ErrClosed
	}
	c.writes++
	return c.buf.Write(p)
}
func (c *carrierTestConn) Close() error                     { c.mu.Lock(); c.closed = true; c.mu.Unlock(); return nil }
func (c *carrierTestConn) LocalAddr() net.Addr              { return dummyAddr("local") }
func (c *carrierTestConn) RemoteAddr() net.Addr             { return dummyAddr("remote") }
func (c *carrierTestConn) SetDeadline(time.Time) error      { return nil }
func (c *carrierTestConn) SetReadDeadline(time.Time) error  { return nil }
func (c *carrierTestConn) SetWriteDeadline(time.Time) error { return nil }

func TestSSHCarrierCombinesPacketWrites(t *testing.T) {
	raw := &carrierTestConn{}
	conn := newSSHCarrierConn(raw, 128*1024, 512*1024, 5*time.Millisecond)
	want := make([]byte, 0, 128*1024)
	for i := 0; i < 4; i++ {
		part := bytes.Repeat([]byte{byte(i + 1)}, 32*1024)
		want = append(want, part...)
		if n, err := conn.Write(part); err != nil || n != len(part) {
			t.Fatalf("Write %d = %d, %v", i, n, err)
		}
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	raw.mu.Lock()
	got := append([]byte(nil), raw.buf.Bytes()...)
	writes := raw.writes
	raw.mu.Unlock()
	if !bytes.Equal(got, want) {
		t.Fatal("carrier changed byte order/content")
	}
	if writes >= 4 {
		t.Fatalf("expected packet writes to be combined, raw writes=%d", writes)
	}
}
