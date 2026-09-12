package main

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// sshCarrierConn absorbs the relatively small encrypted writes produced by the
// SSH packet layer and combines them before handing them to DragonTCP.
//
// This matters because a DragonTCP upload is a request/ack transaction. Without
// write combining, one SSH packet can become one full network round trip even
// when the discovered DragonTCP path supports much larger chunks. The wrapper
// deliberately behaves like a kernel socket send buffer: Write returns after
// the bytes have been copied into a bounded queue, while a single ordered
// writer drains that queue to the underlying DragonTCP stream.
type sshCarrierConn struct {
	raw         net.Conn
	flushBytes  int
	maxBuffered int
	flushDelay  time.Duration

	mu             sync.Mutex
	cond           *sync.Cond
	buf            []byte
	closing        bool
	writeErr       error
	coalesceLogged bool
	done           chan struct{}
	closeOnce      sync.Once
}

func newSSHCarrierConn(raw net.Conn, flushBytes, maxBuffered int, flushDelay time.Duration) net.Conn {
	if raw == nil {
		return nil
	}
	if flushBytes < 32*1024 {
		flushBytes = 32 * 1024
	}
	if maxBuffered < flushBytes*2 {
		maxBuffered = flushBytes * 2
	}
	if flushDelay <= 0 {
		flushDelay = time.Millisecond
	}
	c := &sshCarrierConn{
		raw:         raw,
		flushBytes:  flushBytes,
		maxBuffered: maxBuffered,
		flushDelay:  flushDelay,
		done:        make(chan struct{}),
	}
	c.cond = sync.NewCond(&c.mu)
	go c.writeLoop()
	return c
}

func (c *sshCarrierConn) writeLoop() {
	defer close(c.done)
	defer c.raw.Close()

	for {
		c.mu.Lock()
		for len(c.buf) == 0 && !c.closing && c.writeErr == nil {
			c.cond.Wait()
		}
		if c.writeErr != nil {
			c.mu.Unlock()
			return
		}
		if len(c.buf) == 0 && c.closing {
			c.mu.Unlock()
			return
		}
		shouldDelay := len(c.buf) < c.flushBytes && !c.closing
		c.mu.Unlock()

		// Give consecutive SSH packets a very small window to accumulate. The
		// delay is tiny compared with a WAN RTT, but it lets 32 KiB SSH packets
		// become a 256 KiB-1 MiB DragonTCP write on a busy stream.
		if shouldDelay {
			time.Sleep(c.flushDelay)
		}

		c.mu.Lock()
		if c.writeErr != nil {
			c.mu.Unlock()
			return
		}
		n := len(c.buf)
		if n > c.flushBytes {
			n = c.flushBytes
		}
		batch := make([]byte, n)
		copy(batch, c.buf[:n])
		if n == len(c.buf) {
			c.buf = c.buf[:0]
		} else {
			copy(c.buf, c.buf[n:])
			c.buf = c.buf[:len(c.buf)-n]
		}
		c.cond.Broadcast()
		c.mu.Unlock()

		if !c.coalesceLogged && len(batch) >= 128*1024 {
			c.coalesceLogged = true
			fmt.Printf("ssh carrier: packet coalescing active batch=%d\n", len(batch))
		}

		if err := writeCarrierFull(c.raw, batch); err != nil {
			c.mu.Lock()
			if c.writeErr == nil {
				c.writeErr = err
			}
			c.closing = true
			c.cond.Broadcast()
			c.mu.Unlock()
			return
		}
	}
}

func writeCarrierFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

func (c *sshCarrierConn) Read(p []byte) (int, error) {
	n, err := c.raw.Read(p)
	if n > 0 || err == nil {
		return n, err
	}
	c.mu.Lock()
	writeErr := c.writeErr
	c.mu.Unlock()
	if writeErr != nil {
		return 0, writeErr
	}
	return n, err
}

func (c *sshCarrierConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	written := 0
	for written < len(p) {
		c.mu.Lock()
		for len(c.buf) >= c.maxBuffered && !c.closing && c.writeErr == nil {
			c.cond.Wait()
		}
		if c.writeErr != nil {
			err := c.writeErr
			c.mu.Unlock()
			return written, err
		}
		if c.closing {
			c.mu.Unlock()
			if written > 0 {
				return written, net.ErrClosed
			}
			return 0, net.ErrClosed
		}
		room := c.maxBuffered - len(c.buf)
		if room < 1 {
			c.mu.Unlock()
			continue
		}
		take := len(p) - written
		if take > room {
			take = room
		}
		c.buf = append(c.buf, p[written:written+take]...)
		written += take
		c.cond.Signal()
		c.mu.Unlock()
	}
	return written, nil
}

func (c *sshCarrierConn) Close() error {
	c.closeOnce.Do(func() {
		c.mu.Lock()
		c.closing = true
		c.cond.Broadcast()
		c.mu.Unlock()
		<-c.done
	})
	c.mu.Lock()
	err := c.writeErr
	c.mu.Unlock()
	return err
}

func (c *sshCarrierConn) LocalAddr() net.Addr                { return c.raw.LocalAddr() }
func (c *sshCarrierConn) RemoteAddr() net.Addr               { return c.raw.RemoteAddr() }
func (c *sshCarrierConn) SetDeadline(t time.Time) error      { return c.raw.SetDeadline(t) }
func (c *sshCarrierConn) SetReadDeadline(t time.Time) error  { return c.raw.SetReadDeadline(t) }
func (c *sshCarrierConn) SetWriteDeadline(t time.Time) error { return c.raw.SetWriteDeadline(t) }
