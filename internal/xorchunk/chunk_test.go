package xorchunk

import (
	"bytes"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"dragontcp/internal/protocol"
)

func TestAdaptiveSizerShrinkBudget(t *testing.T) {
	opts := Options{
		startSize:   1024,
		minSize:     32,
		maxSize:     1024,
		adaptive:    true,
		shrinkAfter: 3,
	}
	s := newAdaptiveSizer("test", opts.startSize, opts.maxSize, opts)
	for i := 1; i <= 2; i++ {
		_, next := s.Failure(1024)
		if next != 1024 {
			t.Fatalf("failure %d reduced early to %d", i, next)
		}
	}
	s.Success(1024)
	for i := 1; i <= 2; i++ {
		_, next := s.Failure(1024)
		if next != 1024 {
			t.Fatalf("post-success failure %d reduced early to %d", i, next)
		}
	}
	_, next := s.Failure(1024)
	if next != 512 {
		t.Fatalf("third consecutive failure reduced to %d, want 512", next)
	}
}

func startCalibrationTestServer(t *testing.T, threshold int) (string, func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				for {
					id, _, payload, err := protocol.ReadRequestFrameProfile(c, 0)
					if err != nil {
						return
					}
					if bytes.HasPrefix(payload, []byte("CIPERFUP ")) {
						parts := bytes.SplitN(payload, []byte(" "), 4)
						if len(parts) != 4 {
							_ = protocol.WriteResponseFrame(c, id, []byte("ERR bad upload"))
							continue
						}
						size, _ := strconv.Atoi(string(parts[2]))
						if size > threshold || len(parts[3]) != size || !bytes.Equal(parts[3], calibrationPattern(size)) {
							_ = protocol.WriteResponseFrame(c, id, []byte("ERR too large"))
							continue
						}
						_ = protocol.WriteResponseFrame(c, id, []byte("IPERFOK"))
						continue
					}
					if bytes.HasPrefix(payload, []byte("CIPERFDW ")) {
						parts := strings.Fields(string(payload))
						if len(parts) != 3 {
							_ = protocol.WriteResponseFrame(c, id, []byte("ERR bad download"))
							continue
						}
						size, _ := strconv.Atoi(parts[2])
						if size > threshold {
							_ = protocol.WriteResponseFrame(c, id, []byte("ERR too large"))
							continue
						}
						_ = protocol.WriteResponseFrame(c, id, calibrationPattern(size))
						continue
					}
					if bytes.HasPrefix(payload, []byte("CPROBE ")) {
						_ = protocol.WriteResponseFrame(c, id, []byte("PROBEOK"))
						continue
					}
					_ = protocol.WriteResponseFrame(c, id, []byte("ERR unsupported"))
				}
			}(conn)
		}
	}()
	return ln.Addr().String(), func() {
		close(stop)
		_ = ln.Close()
	}
}

func TestXCalibrationRefinesUploadAndDownloadTo32Bytes(t *testing.T) {
	const threshold = 731237
	addr, closeServer := startCalibrationTestServer(t, threshold)
	defer closeServer()
	opts := Options{
		startSize:  1024 * 1024,
		minSize:    32,
		maxSize:    1024 * 1024,
		txnTimeout: time.Second,
	}
	for _, tc := range []struct {
		name     string
		download bool
	}{
		{"upload", false},
		{"download", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := calibrateMaximum(addr, "", opts, tc.download, 32)
			if got > threshold {
				t.Fatalf("calibrated size=%d exceeds threshold=%d", got, threshold)
			}
			if threshold-got > 32 {
				t.Fatalf("calibrated size=%d is more than 32 bytes below threshold=%d", got, threshold)
			}
		})
	}
}

func TestXCalibrationRetriesTransientFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	const (
		threshold      = 4096
		transientChunk = 2048
	)
	var transient atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				for {
					id, _, payload, err := protocol.ReadRequestFrameProfile(c, 0)
					if err != nil {
						return
					}
					if !bytes.HasPrefix(payload, []byte("CIPERFUP ")) {
						_ = protocol.WriteResponseFrame(c, id, []byte("ERR unsupported"))
						continue
					}
					parts := bytes.SplitN(payload, []byte(" "), 4)
					if len(parts) != 4 {
						_ = protocol.WriteResponseFrame(c, id, []byte("ERR bad upload"))
						continue
					}
					size, _ := strconv.Atoi(string(parts[2]))
					if size == transientChunk && transient.CompareAndSwap(0, 1) {
						_ = protocol.WriteResponseFrame(c, id, []byte("ERR transient"))
						return
					}
					if size > threshold || len(parts[3]) != size || !bytes.Equal(parts[3], calibrationPattern(size)) {
						_ = protocol.WriteResponseFrame(c, id, []byte("ERR too large"))
						continue
					}
					_ = protocol.WriteResponseFrame(c, id, []byte("IPERFOK"))
				}
			}(conn)
		}
	}()

	opts := Options{
		startSize:  16 * 1024,
		minSize:    32,
		maxSize:    16 * 1024,
		txnTimeout: time.Second,
	}
	got := calibrateMaximum(ln.Addr().String(), "", opts, false, 32)
	if transient.Load() != 1 {
		t.Fatalf("transient failure count=%d, want 1", transient.Load())
	}
	if got < transientChunk {
		t.Fatalf("X calibration collapsed below transiently failed %d-byte probe: got %d", transientChunk, got)
	}
	if got > threshold || threshold-got > 32 {
		t.Fatalf("X calibrated size=%d, want within 32 bytes below threshold=%d", got, threshold)
	}
}

func TestWithCalibratedChunksLocksIndependentXSizes(t *testing.T) {
	opts := Options{minSize: 32, maxSize: 1024 * 1024, startSize: 1024 * 1024, adaptive: true}
	opts = opts.WithCalibratedChunks(900000, 500000)
	if opts.adaptive {
		t.Fatal("X runtime adaptation remained enabled after calibration")
	}

	up := newAdaptiveSizer("upload", opts.uploadStartSize, opts.uploadMaxSize, opts)
	down := newAdaptiveSizer("download", opts.downloadStartSize, opts.downloadMaxSize, opts)
	if up.Current() != 900000 || up.max != 900000 {
		t.Fatalf("upload current/max=%d/%d, want 900000", up.Current(), up.max)
	}
	if down.Current() != 500000 || down.max != 500000 {
		t.Fatalf("download current/max=%d/%d, want 500000", down.Current(), down.max)
	}

	// The calibrated sizes are immutable during the X session. Neither a
	// transport failure nor a long run of successes may move them.
	if old, next := up.Failure(900000); old != 900000 || next != 900000 {
		t.Fatalf("upload failure changed calibrated chunk: %d -> %d", old, next)
	}
	for i := 0; i < 1000; i++ {
		up.Success(900000)
		down.Success(500000)
	}
	if up.Current() != 900000 {
		t.Fatalf("upload success changed calibrated chunk to %d", up.Current())
	}
	if old, next := down.Failure(500000); old != 500000 || next != 500000 {
		t.Fatalf("download failure changed calibrated chunk: %d -> %d", old, next)
	}
	if down.Current() != 500000 {
		t.Fatalf("download calibrated chunk changed to %d", down.Current())
	}
}

func TestCalculateParallelWorkers(t *testing.T) {
	tests := []struct {
		chunkSize int
		want      int
	}{
		{chunkSize: 16 * 1024, want: 64},
		{chunkSize: 32 * 1024, want: 32},
		{chunkSize: 64 * 1024, want: 16},
		{chunkSize: 128 * 1024, want: 8},
		{chunkSize: 256 * 1024, want: 4},
		{chunkSize: 512 * 1024, want: 2},
		{chunkSize: 1024 * 1024, want: 1},
		{chunkSize: 0, want: 64},
		{chunkSize: -50, want: 64},
		{chunkSize: 8 * 1024, want: 64},        // capped at 64
		{chunkSize: 2 * 1024 * 1024, want: 1}, // capped at 1
	}

	for _, tt := range tests {
		got := CalculateParallelWorkers(tt.chunkSize)
		if got != tt.want {
			t.Errorf("CalculateParallelWorkers(%d) = %d, want %d", tt.chunkSize, got, tt.want)
		}
	}
}
