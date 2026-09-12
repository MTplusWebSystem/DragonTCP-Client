package cover

import (
	"bytes"
	"testing"
)

func TestProfileRoundTripAcrossRange(t *testing.T) {
	for id := 0; id < 65536; id += 257 {
		for _, xor := range []bool{false, true} {
			for _, clear := range []bool{false, true} {
				want := Profile{Enabled: true, ID: uint16(id), Padding: uint16(id % (MaxPadding + 1)), HeaderMask: byte(id), XOR: xor, Clear: clear}
				encoded, err := EncodePreface(want)
				if err != nil {
					t.Fatal(err)
				}
				got, ok := DecodePreface(encoded)
				if !ok || got != want {
					t.Fatalf("id=%04x xor=%t clear=%t got=%+v ok=%t", id, xor, clear, got, ok)
				}
			}
		}
	}
}

func TestWritePrefaceIncludesFixedPadding(t *testing.T) {
	p := Profile{Enabled: true, ID: 0x1234, Padding: 64, HeaderMask: 0x9a, XOR: true}
	var out bytes.Buffer
	if err := WritePreface(&out, p); err != nil {
		t.Fatal(err)
	}
	if out.Len() != PrefaceSize+64 {
		t.Fatalf("length=%d", out.Len())
	}
	var encoded [PrefaceSize]byte
	copy(encoded[:], out.Bytes())
	got, ok := DecodePreface(encoded)
	if !ok || got != p {
		t.Fatalf("got=%+v ok=%t", got, ok)
	}
}
