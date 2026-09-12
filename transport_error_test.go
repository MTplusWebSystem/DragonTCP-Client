package main

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"dragontcp/internal/cover"
)

func startStallingTCPServer(t *testing.T) (string, *atomic.Int32, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var accepted atomic.Int32
	var conns sync.WaitGroup
	stop := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			accepted.Add(1)
			conns.Add(1)
			go func(c net.Conn) {
				defer conns.Done()
				defer c.Close()
				<-stop
			}(conn)
		}
	}()
	cleanup := func() {
		close(stop)
		_ = ln.Close()
		conns.Wait()
	}
	return ln.Addr().String(), &accepted, cleanup
}

func timeoutTestOptions() chunkClientOptions {
	return chunkClientOptions{
		startSize:      1024 * 1024,
		minSize:        32,
		maxSize:        1024 * 1024,
		adaptive:       true,
		adaptSuccesses: 16,
		txnTimeout:     60 * time.Millisecond,
		minPipeline:    1,
		maxPipeline:    1,
	}
}

func TestBPDownloadTimeoutIsHardTunnelBoundary(t *testing.T) {
	addr, accepted, cleanup := startStallingTCPServer(t)
	defer cleanup()

	opts := timeoutTestOptions()
	lane := newBPLane(addr, 0, 0, opts.txnTimeout, cover.Profile{})
	c := &bpConn{
		opts:         opts,
		uploadLane:   newBPLane(addr, 0, 0, opts.txnTimeout, cover.Profile{}),
		downloadLane: lane,
		pipeline:     1,
	}
	c.downSizer = newAdaptiveSizer("BP download", opts.startSize, opts)

	started := time.Now()
	err := c.fillReadBuffer()
	elapsed := time.Since(started)
	if err == nil || !isTransportTimeout(err) {
		t.Fatalf("err=%v, want transport timeout", err)
	}
	if got := c.downSizer.Current(); got != opts.startSize {
		t.Fatalf("download chunk changed after timeout: got %d want %d", got, opts.startSize)
	}
	if got := accepted.Load(); got != 1 {
		t.Fatalf("timeout opened %d physical connections, want exactly 1", got)
	}
	if elapsed > 300*time.Millisecond {
		t.Fatalf("timeout path took %s; expected immediate hard failure", elapsed)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if got := accepted.Load(); got != 1 {
		t.Fatalf("Close redialed after timeout: physical connections=%d, want 1", got)
	}
}

func TestBinaryDownloadTimeoutIsHardTunnelBoundary(t *testing.T) {
	addr, accepted, cleanup := startStallingTCPServer(t)
	defer cleanup()

	opts := timeoutTestOptions()
	lane := newRequestLane(addr, 0, 0, opts.txnTimeout, 0, cover.Profile{})
	c := &chunkConn{
		opts:         opts,
		uploadLane:   newRequestLane(addr, 0, 0, opts.txnTimeout, 0, cover.Profile{}),
		downloadLane: lane,
		pipeline:     1,
		minPipeline:  1,
		maxPipeline:  1,
	}
	c.downSizer = newAdaptiveSizer("download", opts.startSize, opts)

	started := time.Now()
	err := c.fillReadBuffer()
	elapsed := time.Since(started)
	if err == nil || !isTransportTimeout(err) {
		t.Fatalf("err=%v, want transport timeout", err)
	}
	if got := c.downSizer.Current(); got != opts.startSize {
		t.Fatalf("download chunk changed after timeout: got %d want %d", got, opts.startSize)
	}
	if got := accepted.Load(); got != 1 {
		t.Fatalf("timeout opened %d physical connections, want exactly 1", got)
	}
	if elapsed > 300*time.Millisecond {
		t.Fatalf("timeout path took %s; expected immediate hard failure", elapsed)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if got := accepted.Load(); got != 1 {
		t.Fatalf("Close redialed after timeout: physical connections=%d, want 1", got)
	}
}
