package protocol

import (
	"bytes"
	"testing"
)

func TestXORHeaderProfilesRoundTrip(t *testing.T) {
	for n := 0; n < 256; n++ {
		mask := byte(n)
		if ('U'^mask)&7 < 5 {
			continue
		}

		var request bytes.Buffer
		if err := WriteRequestFrameProfile(&request, 7, []byte("CPROBE -"), mask); err != nil {
			t.Fatal(err)
		}
		requestID, _, payload, err := ReadRequestFrameProfile(&request, mask)
		if err != nil || requestID != 7 || !bytes.Equal(payload, []byte("CPROBE -")) {
			t.Fatalf("mask %02x request did not round-trip: id=%d payload=%q err=%v", mask, requestID, payload, err)
		}

		var response bytes.Buffer
		if err := WriteResponseFrameProfile(&response, 7, []byte("PROBEOK"), mask); err != nil {
			t.Fatal(err)
		}
		responseID, payload, err := ReadResponseFrameProfile(&response, mask)
		if err != nil || responseID != 7 || !bytes.Equal(payload, []byte("PROBEOK")) {
			t.Fatalf("mask %02x response did not round-trip: id=%d payload=%q err=%v", mask, responseID, payload, err)
		}
	}
}

type profiledBuffer struct {
	bytes.Buffer
	mask byte
}

func (b *profiledBuffer) HeaderMask() byte { return b.mask }

func TestServerResponseUsesConnectionProfile(t *testing.T) {
	profiled := &profiledBuffer{mask: 0x3a}
	if err := WriteResponseFrame(profiled, 9, []byte("ok")); err != nil {
		t.Fatal(err)
	}
	if got := profiled.Bytes()[0]; got != 'O'^profiled.mask {
		t.Fatalf("first byte=%02x, want %02x", got, byte('O')^profiled.mask)
	}
}

func TestFormatPayload(t *testing.T) {
	tmpl := "GET / HTTP/1.1[crlf]Host: [host]:[port][crlf]Upgrade: websocket[crlf][crlf]"
	formatted := FormatPayload(tmpl, "1.2.3.4", "80")
	expected := "GET / HTTP/1.1\r\nHost: 1.2.3.4:80\r\nUpgrade: websocket\r\n\r\n"
	if formatted != expected {
		t.Fatalf("got %q, want %q", formatted, expected)
	}
}

