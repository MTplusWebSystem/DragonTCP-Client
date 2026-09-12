package wire

import (
	"bytes"
	"io"
	"testing"
)

func TestMaskChangesWithSequenceAndRoundTrips(t *testing.T) {
	var sid SessionID
	for i := range sid {
		sid[i] = byte(i + 1)
	}
	plain := bytes.Repeat([]byte("DragonTCP"), 100)
	a := append([]byte(nil), plain...)
	b := append([]byte(nil), plain...)
	MaskInPlace(a, sid, ModeUpload, 1, false)
	MaskInPlace(b, sid, ModeUpload, 2, false)
	if bytes.Equal(a, b) {
		t.Fatal("different sequences produced identical wire bytes")
	}
	MaskInPlace(a, sid, ModeUpload, 1, false)
	if !bytes.Equal(a, plain) {
		t.Fatal("mask did not round-trip")
	}
}

func TestBinaryHeaderProfilesRoundTrip(t *testing.T) {
	var sid SessionID
	for i := range sid {
		sid[i] = byte(i + 1)
	}
	for n := 0; n < 256; n += 8 {
		mask := byte(n)
		var request bytes.Buffer
		if err := WriteRequestProfile(&request, ModeUpload, sid, 42, []byte("payload"), mask); err != nil {
			t.Fatal(err)
		}
		if got := request.Bytes()[0]; got != ModeUpload^mask {
			t.Fatalf("mask %02x first byte=%02x", mask, got)
		}
		req, err := ReadRequestProfile(&request, mask)
		if err != nil {
			t.Fatalf("mask %02x: %v", mask, err)
		}
		if req.Mode != ModeUpload || req.Seq != 42 || !bytes.Equal(req.Payload, []byte("payload")) {
			t.Fatalf("mask %02x request did not round-trip", mask)
		}

		var response bytes.Buffer
		if err := WriteResponseProfile(&response, StatusOK, []byte("ok"), mask); err != nil {
			t.Fatal(err)
		}
		status, body, err := ReadResponseProfile(&response, mask)
		if err != nil || status != StatusOK || !bytes.Equal(body, []byte("ok")) {
			t.Fatalf("mask %02x response did not round-trip: status=%d body=%q err=%v", mask, status, body, err)
		}
	}
}

type profiledBuffer struct {
	bytes.Buffer
	mask byte
}

func (b *profiledBuffer) HeaderMask() byte { return b.mask }

func TestServerResponseUsesConnectionProfile(t *testing.T) {
	profiled := &profiledBuffer{mask: 0xa0}
	if err := WriteResponse(profiled, StatusOK, []byte("ok")); err != nil {
		t.Fatal(err)
	}
	if got := profiled.Bytes()[0]; got != StatusOK^profiled.mask {
		t.Fatalf("first byte=%02x, want %02x", got, StatusOK^profiled.mask)
	}
}

func BenchmarkMask1MiB(b *testing.B) {
	var sid SessionID
	data := make([]byte, 1024*1024)
	b.SetBytes(int64(len(data)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		MaskInPlace(data, sid, ModeUpload, uint64(i), false)
	}
}

func BenchmarkWriteRequest1MiB(b *testing.B) {
	var sid SessionID
	data := make([]byte, 1024*1024)
	for _, tc := range []struct {
		name  string
		clear bool
	}{{"sha256-compat", false}, {"clear", true}} {
		b.Run(tc.name, func(b *testing.B) {
			b.SetBytes(int64(len(data)))
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if err := WriteRequestProfileEncoding(io.Discard, ModeUpload, sid, uint64(i), data, 0, tc.clear); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestProbeBurstCountSinglePoller(t *testing.T) {
	for _, chunk := range []int{0, 1, 1024, 128 * 1024, 512 * 1024, 1024 * 1024} {
		if got := ProbeBurstCount(chunk); got != 1 {
			t.Fatalf("ProbeBurstCount(%d)=%d, want 1", chunk, got)
		}
	}
}

func TestMuxHeaderSizes(t *testing.T) {
	var sid SessionID
	copy(sid[:], []byte("0123456789abcdef"))

	var reqBuf bytes.Buffer
	if err := WriteMuxRequestProfileEncoding(&reqBuf, ModeUpload, sid, 0x1122334455667788, 0xdeadbeef, nil, 0, true); err != nil {
		t.Fatal(err)
	}
	if reqBuf.Len() != MuxRequestHeaderSize {
		t.Fatalf("MuxRequestHeaderSize = %d, want %d", reqBuf.Len(), MuxRequestHeaderSize)
	}

	var respBuf bytes.Buffer
	if err := WriteMuxResponseProfile(&respBuf, StatusOK, 0x12345678, nil, 0); err != nil {
		t.Fatal(err)
	}
	if respBuf.Len() != MuxResponseHeaderSize {
		t.Fatalf("MuxResponseHeaderSize = %d, want %d", respBuf.Len(), MuxResponseHeaderSize)
	}
}

func TestMuxHeaderProfilesRoundTrip(t *testing.T) {
	var sid SessionID
	for i := range sid {
		sid[i] = byte(i + 7)
	}
	payload := []byte("DragonTCP Multiplexed Wire V2 Test Payload")

	for n := 0; n < 256; n += 8 {
		mask := byte(n)
		reqID := uint32(1000 + n)
		seq := uint64(5000 + n)

		// 1. MuxRequest masked
		var reqBuf bytes.Buffer
		if err := WriteMuxRequestProfile(&reqBuf, ModeUpload, sid, seq, reqID, payload, mask); err != nil {
			t.Fatal(err)
		}
		if reqBuf.Bytes()[0] != ModeUpload^mask {
			t.Fatalf("mask %02x first byte = %02x, want %02x", mask, reqBuf.Bytes()[0], ModeUpload^mask)
		}
		req, err := ReadMuxRequestProfile(&reqBuf, mask)
		if err != nil {
			t.Fatalf("ReadMuxRequestProfile failed (mask %02x): %v", mask, err)
		}
		if req.Mode != ModeUpload || req.Session != sid || req.Seq != seq || req.RequestID != reqID || !bytes.Equal(req.Payload, payload) {
			t.Fatalf("MuxRequest masked round-trip mismatch (mask %02x)", mask)
		}

		// 2. MuxRequest clear
		reqBuf.Reset()
		if err := WriteMuxRequestProfileEncoding(&reqBuf, ModeDownload, sid, seq, reqID, payload, mask, true); err != nil {
			t.Fatal(err)
		}
		req, err = ReadMuxRequestProfileEncoding(&reqBuf, mask, true)
		if err != nil {
			t.Fatalf("ReadMuxRequestProfileEncoding clear failed: %v", err)
		}
		if req.Mode != ModeDownload || req.RequestID != reqID || !bytes.Equal(req.Payload, payload) {
			t.Fatalf("MuxRequest clear round-trip mismatch")
		}

		// 3. MuxResponse unmasked
		var respBuf bytes.Buffer
		if err := WriteMuxResponseProfile(&respBuf, StatusData, reqID, payload, mask); err != nil {
			t.Fatal(err)
		}
		resp, err := ReadMuxResponseProfile(&respBuf, mask)
		if err != nil {
			t.Fatalf("ReadMuxResponseProfile failed: %v", err)
		}
		if resp.Status != StatusData || resp.RequestID != reqID || !bytes.Equal(resp.Body, payload) {
			t.Fatalf("MuxResponse round-trip mismatch")
		}

		// 4. MuxResponse masked
		respBuf.Reset()
		if err := WriteMaskedMuxResponseProfile(&respBuf, StatusData, reqID, payload, sid, ModeDownload, seq, mask); err != nil {
			t.Fatal(err)
		}
		resp, err = ReadMuxResponseProfile(&respBuf, mask)
		if err != nil {
			t.Fatalf("ReadMuxResponseProfile masked failed: %v", err)
		}
		decoded := DecodeMaskedMuxResponse(resp, sid, ModeDownload, seq)
		if !bytes.Equal(decoded, payload) {
			t.Fatalf("DecodeMaskedMuxResponse mismatch")
		}
	}
}

func TestRequestIDPool(t *testing.T) {
	pool := NewRequestIDPool(1)

	// Sequential alloc
	id1 := pool.Alloc()
	id2 := pool.Alloc()
	id3 := pool.Alloc()

	if id1 != 1 || id2 != 2 || id3 != 3 {
		t.Fatalf("alloc sequence: got %d, %d, %d, want 1, 2, 3", id1, id2, id3)
	}
	if pool.InFlight() != 3 {
		t.Fatalf("in-flight = %d, want 3", pool.InFlight())
	}

	// Release and reuse
	pool.Release(id2)
	if pool.InFlight() != 2 {
		t.Fatalf("in-flight after release = %d, want 2", pool.InFlight())
	}
	reused := pool.Alloc()
	if reused != id2 {
		t.Fatalf("expected reused ID %d, got %d", id2, reused)
	}

	// Concurrency test
	const goroutines = 20
	const iters = 500
	done := make(chan struct{}, goroutines)

	for g := 0; g < goroutines; g++ {
		go func() {
			for i := 0; i < iters; i++ {
				id := pool.Alloc()
				pool.Release(id)
			}
			done <- struct{}{}
		}()
	}

	for g := 0; g < goroutines; g++ {
		<-done
	}
}

func TestIsTerminalStatus(t *testing.T) {
	if !IsTerminalStatus(StatusOK) {
		t.Errorf("StatusOK should be terminal")
	}
	if !IsTerminalStatus(StatusWait) {
		t.Errorf("StatusWait should be terminal")
	}
	if !IsTerminalStatus(StatusEOF) {
		t.Errorf("StatusEOF should be terminal")
	}
	if !IsTerminalStatus(StatusError) {
		t.Errorf("StatusError should be terminal")
	}
	if IsTerminalStatus(StatusData) {
		t.Errorf("StatusData should NOT be terminal")
	}
	if IsTerminalStatus(255) {
		t.Errorf("arbitrary byte should NOT be terminal")
	}
}
