package main

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"dragontcp/internal/cover"
	"dragontcp/internal/wire"
)

func TestAdaptiveSizerRecoversFromMinimum(t *testing.T) {
	opts := chunkClientOptions{
		startSize:      64,
		minSize:        32,
		maxSize:        1024,
		adaptive:       true,
		adaptSuccesses: 2,
	}
	s := newAdaptiveSizer("test", 64, opts)
	_, next := s.Failure(64)
	if next != 32 {
		t.Fatalf("failure should reduce 64 -> 32, got %d", next)
	}
	for i := 0; i < 16; i++ {
		s.Success(32)
	}
	if got := s.Current(); got <= 32 {
		t.Fatalf("adaptive controller remained stuck at minimum: %d", got)
	}
}

func TestAdaptiveSizerWaitsForFailureBudgetBeforeShrinking(t *testing.T) {
	opts := chunkClientOptions{
		startSize:   1024,
		minSize:     32,
		maxSize:     1024,
		adaptive:    true,
		shrinkAfter: 3,
	}
	s := newAdaptiveSizer("test", 1024, opts)

	for i := 1; i <= 2; i++ {
		old, next := s.Failure(1024)
		if old != 1024 || next != 1024 || s.Current() != 1024 {
			t.Fatalf("failure %d reduced early: old=%d next=%d current=%d", i, old, next, s.Current())
		}
	}

	// Any successful record resets the consecutive-failure budget.
	s.Success(1024)
	for i := 1; i <= 2; i++ {
		_, next := s.Failure(1024)
		if next != 1024 {
			t.Fatalf("post-success failure %d reduced early to %d", i, next)
		}
	}
	_, next := s.Failure(1024)
	if next != 512 || s.Current() != 512 {
		t.Fatalf("third consecutive failure should reduce 1024 -> 512, next=%d current=%d", next, s.Current())
	}
}

func TestForceMaxStartCalibratesAtCeiling(t *testing.T) {
	profileState.Lock()
	profileState.key = ""
	profileState.p = pathProfile{}
	profileState.Unlock()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverErr := make(chan error, 1)
	go func() {
		defer close(serverErr)
		for connection := 0; connection < 4; connection++ {
			conn, err := ln.Accept()
			if err != nil {
				serverErr <- err
				return
			}
			req, err := wire.ReadRequest(conn)
			if err != nil {
				_ = conn.Close()
				serverErr <- err
				return
			}

			if req.Mode == wire.ModeOpen {
				body := make([]byte, 4)
				binary.BigEndian.PutUint32(body, 1024)
				err = wire.WriteMaskedResponse(conn, wire.StatusOK, body, req.Session, req.Mode, req.Seq)
				_ = conn.Close()
				if err != nil {
					serverErr <- err
				}
				continue
			}
			if req.Mode != wire.ModeProbe || len(req.Payload) < 11 {
				_ = conn.Close()
				serverErr <- &testError{"expected calibration probe"}
				return
			}
			kind := req.Payload[4]
			candidate := int(binary.BigEndian.Uint32(req.Payload[7:11]))
			switch kind {
			case wire.ProbeIperfUpload:
				count := wire.ProbeBurstCount(candidate)
				for i := 0; i < count; i++ {
					if i > 0 {
						req, err = wire.ReadRequest(conn)
						if err != nil {
							break
						}
					}
					if len(req.Payload) != candidate {
						err = &testError{"wrong upload calibration size"}
						break
					}
					if err = wire.WriteResponse(conn, wire.StatusOK, nil); err != nil {
						break
					}
				}
			case wire.ProbeIperfDownload:
				for i := 0; i < wire.ProbeBurstCount(candidate); i++ {
					if err = wire.WriteMaskedResponse(conn, wire.StatusData, probePattern(candidate), req.Session, wire.ModeProbe, req.Seq+uint64(i)); err != nil {
						break
					}
				}
			case wire.ProbeKeepalive:
				for i := 0; i < 8; i++ {
					if i > 0 {
						req, err = wire.ReadRequest(conn)
						if err != nil {
							break
						}
					}
					if err = wire.WriteResponse(conn, wire.StatusOK, nil); err != nil {
						break
					}
				}
			default:
				err = &testError{"unexpected calibration kind"}
			}
			_ = conn.Close()
			if err != nil {
				serverErr <- err
				return
			}
		}
	}()

	opts := chunkClientOptions{
		startSize:     32,
		minSize:       32,
		maxSize:       1024,
		adaptive:      true,
		shrinkAfter:   3,
		minPipeline:   1,
		maxPipeline:   1,
		txnTimeout:    time.Second,
		forceMaxStart: true,
		skipPathProbe: false,
	}
	conn, err := openChunkTunnel(ln.Addr().String(), "", "example.com", 443, opts)
	if err != nil {
		t.Fatal(err)
	}
	c := conn.(*chunkConn)
	if got := c.upSizer.Current(); got != 1024 {
		t.Fatalf("upload start=%d, want calibrated max 1024", got)
	}
	if got := c.downSizer.Current(); got != 1024 {
		t.Fatalf("download start=%d, want calibrated max 1024", got)
	}
	c.uploadLane.Close()
	c.downloadLane.Close()
	for err := range serverErr {
		if err != nil {
			t.Fatal(err)
		}
	}
}

type testError struct{ message string }

func (e *testError) Error() string { return e.message }

func TestReconnectAutoLearnsFromRealReuseFailure(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	serverErr := make(chan error, 1)
	go func() {
		first, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		if _, err := wire.ReadRequest(first); err != nil {
			serverErr <- err
			return
		}
		if err := wire.WriteResponse(first, wire.StatusOK, nil); err != nil {
			serverErr <- err
			return
		}
		_ = first.Close() // Force the next logical request to reconnect.

		second, err := ln.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer second.Close()
		if _, err := wire.ReadRequest(second); err != nil {
			serverErr <- err
			return
		}
		serverErr <- wire.WriteResponse(second, wire.StatusOK, nil)
	}()

	lane := newRequestLane(ln.Addr().String(), 0, 1, time.Second, 0, cover.Profile{})
	defer lane.Close()
	if !lane.autoReconnect || lane.reconnectEvery != 0 {
		t.Fatalf("auto lane started auto=%t reconnectEvery=%d", lane.autoReconnect, lane.reconnectEvery)
	}
	var sid wire.SessionID
	if status, _, err := lane.single(wire.ModeProbe, sid, 1, nil); err != nil || status != wire.StatusOK {
		t.Fatalf("first request status=%d err=%v", status, err)
	}
	if status, _, err := lane.single(wire.ModeProbe, sid, 2, nil); err != nil || status != wire.StatusOK {
		t.Fatalf("retried request status=%d err=%v", status, err)
	}
	if lane.reconnectEvery != 1 || lane.pc != nil {
		t.Fatalf("auto lane did not learn single-request mode: reconnectEvery=%d pc=%v", lane.reconnectEvery, lane.pc)
	}
	if err := <-serverErr; err != nil {
		t.Fatal(err)
	}
}

func TestReconnectZeroMeansPersistent(t *testing.T) {
	lane := newRequestLane("127.0.0.1:1", 0, 0, 0, 0, cover.Profile{})
	if lane.reconnectEvery != 0 {
		t.Fatalf("reconnectEvery=%d, want 0", lane.reconnectEvery)
	}
}

func TestBPAutoStartsPersistent(t *testing.T) {
	lane := newBPLane("127.0.0.1:1", 0, 1, time.Second, cover.Profile{})
	if !lane.autoReconnect || lane.reconnectEvery != 0 {
		t.Fatalf("BP auto lane started auto=%t reconnectEvery=%d", lane.autoReconnect, lane.reconnectEvery)
	}
}

func TestAscendingIperfFindsBoundaryWithoutFlood(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	const threshold = 900000
	attempts := make(chan int, 64)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		defer close(attempts)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			req, err := wire.ReadRequest(conn)
			if err != nil {
				_ = conn.Close()
				continue
			}
			candidate := int(binary.BigEndian.Uint32(req.Payload[7:11]))
			attempts <- candidate
			if candidate > threshold {
				_ = wire.WriteResponse(conn, wire.StatusError, []byte("synthetic carrier rejection"))
				_ = conn.Close()
				continue
			}
			count := wire.ProbeBurstCount(candidate)
			for i := 0; i < count; i++ {
				if i > 0 {
					req, err = wire.ReadRequest(conn)
					if err != nil {
						break
					}
				}
				if err = wire.WriteResponse(conn, wire.StatusOK, nil); err != nil {
					break
				}
			}
			_ = conn.Close()
		}
	}()

	opts := chunkClientOptions{
		minSize:      32,
		maxSize:      1024 * 1024,
		shrinkAfter:  1,
		shrinkStep:   200,
		txnTimeout:   time.Second,
		coverProfile: cover.Profile{},
	}
	got := probeMaximum(ln.Addr().String(), "", opts, wire.ProbeUpload)
	_ = ln.Close()
	<-serverDone

	if got > threshold {
		t.Fatalf("calibrated size=%d exceeds threshold=%d", got, threshold)
	}
	if threshold-got > calibrationFineResolution {
		t.Fatalf("calibrated size=%d is more than %d bytes below threshold=%d", got, calibrationFineResolution, threshold)
	}
	var seen []int
	for candidate := range attempts {
		seen = append(seen, candidate)
	}
	if len(seen) > 40 {
		t.Fatalf("ascending calibration used %d probes, want <=40 with boundary confirmation; attempts=%v", len(seen), seen)
	}
	if len(seen) == 0 || seen[0] != 32 {
		t.Fatalf("first ascending probe=%v, want minimum 32", seen)
	}
	if len(seen) < 2 || seen[1] != 512 {
		t.Fatalf("second ascending probe=%v, want fast jump to 512", seen)
	}
	for i := 1; i < len(seen); i++ {
		if seen[i] > threshold {
			break
		}
		if seen[i] < seen[i-1] {
			t.Fatalf("coarse ascending phase moved backward: %v", seen)
		}
	}
}

func TestAscendingIperfRetriesTransientFailureBeforeLoweringCeiling(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	const (
		threshold      = 4096
		transientChunk = 2048
	)
	var transientAttempts int
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			req, err := wire.ReadRequest(conn)
			if err != nil {
				_ = conn.Close()
				continue
			}
			candidate := int(binary.BigEndian.Uint32(req.Payload[7:11]))
			if candidate == transientChunk && transientAttempts == 0 {
				transientAttempts++
				_ = wire.WriteResponse(conn, wire.StatusError, []byte("synthetic transient rejection"))
				_ = conn.Close()
				continue
			}
			if candidate > threshold {
				_ = wire.WriteResponse(conn, wire.StatusError, []byte("synthetic carrier rejection"))
				_ = conn.Close()
				continue
			}
			count := wire.ProbeBurstCount(candidate)
			for i := 0; i < count; i++ {
				if i > 0 {
					req, err = wire.ReadRequest(conn)
					if err != nil {
						break
					}
				}
				if err = wire.WriteResponse(conn, wire.StatusOK, nil); err != nil {
					break
				}
			}
			_ = conn.Close()
		}
	}()

	opts := chunkClientOptions{
		minSize:      32,
		maxSize:      16 * 1024,
		shrinkAfter:  1,
		shrinkStep:   200,
		txnTimeout:   time.Second,
		coverProfile: cover.Profile{},
	}
	got := probeMaximum(ln.Addr().String(), "", opts, wire.ProbeUpload)
	_ = ln.Close()
	<-serverDone

	if transientAttempts != 1 {
		t.Fatalf("transient failure count=%d, want 1", transientAttempts)
	}
	if got < transientChunk {
		t.Fatalf("calibration collapsed below transiently failed %d-byte probe: got %d", transientChunk, got)
	}
	if got > threshold || threshold-got > calibrationFineResolution {
		t.Fatalf("calibrated size=%d, want within %d bytes below threshold=%d", got, calibrationFineResolution, threshold)
	}
}

func TestMaxFirstIperfUsesBoundedCoarseFineSearch(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	const threshold = 900000
	attempts := make(chan int, 64)
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		defer close(attempts)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			req, err := wire.ReadRequest(conn)
			if err != nil {
				_ = conn.Close()
				continue
			}
			candidate := int(binary.BigEndian.Uint32(req.Payload[7:11]))
			attempts <- candidate
			if candidate > threshold {
				_ = wire.WriteResponse(conn, wire.StatusError, []byte("synthetic carrier rejection"))
				_ = conn.Close()
				continue
			}
			count := wire.ProbeBurstCount(candidate)
			for i := 0; i < count; i++ {
				if i > 0 {
					req, err = wire.ReadRequest(conn)
					if err != nil {
						break
					}
				}
				if err = wire.WriteResponse(conn, wire.StatusOK, nil); err != nil {
					break
				}
			}
			_ = conn.Close()
		}
	}()

	opts := chunkClientOptions{
		minSize:      32,
		maxSize:      1024 * 1024,
		shrinkAfter:  1,
		shrinkStep:   200,
		txnTimeout:   time.Second,
		coverProfile: cover.Profile{},
	}
	got := probeMaximumMaxFirst(ln.Addr().String(), "", opts, wire.ProbeUpload)
	_ = ln.Close()
	<-serverDone

	if got > threshold {
		t.Fatalf("calibrated size=%d exceeds threshold=%d", got, threshold)
	}
	if threshold-got > calibrationFineResolution {
		t.Fatalf("calibrated size=%d is more than %d bytes below threshold=%d", got, calibrationFineResolution, threshold)
	}
	var seen []int
	for candidate := range attempts {
		seen = append(seen, candidate)
	}
	if len(seen) > 24 {
		t.Fatalf("calibration used %d probes, want <=24; attempts=%v", len(seen), seen)
	}
	if len(seen) == 0 || seen[0] != 1024*1024 {
		t.Fatalf("first probe=%v, want maximum %d", seen, 1024*1024)
	}
}

func TestAdaptiveSizerLinearShrinkStep(t *testing.T) {
	opts := chunkClientOptions{
		startSize:   1024,
		minSize:     256,
		maxSize:     1024,
		adaptive:    true,
		shrinkAfter: 1,
		shrinkStep:  200,
	}
	s := newAdaptiveSizer("test", 1024, opts)
	_, next := s.Failure(1024)
	if next != 824 {
		t.Fatalf("linear failure should reduce 1024 -> 824, got %d", next)
	}
	_, next = s.Failure(824)
	if next != 624 {
		t.Fatalf("linear failure should reduce 824 -> 624, got %d", next)
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
		{chunkSize: -100, want: 64},
		{chunkSize: 8 * 1024, want: 64},        // capped at 64
		{chunkSize: 2 * 1024 * 1024, want: 1}, // capped at 1
	}

	for _, tt := range tests {
		got := calculateParallelWorkers(tt.chunkSize)
		if got != tt.want {
			t.Errorf("calculateParallelWorkers(%d) = %d, want %d", tt.chunkSize, got, tt.want)
		}
	}
}

func TestProbeIperfSustainedParallel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				for {
					req, err := wire.ReadRequest(c)
					if err != nil {
						return
					}
					if err := wire.WriteResponse(c, wire.StatusOK, nil); err != nil {
						return
					}
					_ = req
				}
			}(conn)
		}
	}()

	opts := chunkClientOptions{
		minSize:    32,
		maxSize:    1024 * 1024,
		txnTimeout: 500 * time.Millisecond,
	}

	// Run sustained probe for 100ms targeting 1.0 Mbps with 16KB chunk (64 workers)
	res := probeIperfSustainedParallel(ln.Addr().String(), "", opts, wire.ProbeUpload, 16*1024, 100*time.Millisecond, 1.0)

	if !res.ok {
		t.Fatalf("expected sustained probe ok=true, got ok=false (bytes=%d, err=%v)", res.bytes, res.err)
	}
	if res.bytes <= 0 {
		t.Fatalf("expected bytes > 0, got %d", res.bytes)
	}
}
