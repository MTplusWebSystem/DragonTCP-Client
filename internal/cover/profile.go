// Package cover implements the optional connection preface used by startup
// profile discovery. Legacy connections have no preface and remain supported.
package cover

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	PrefaceSize = 12
	MaxPadding  = 4096
)

// Profile is selected once during startup and then reused unchanged. Padding
// bytes are freshly random on each physical connection, but their length and
// all header fields remain fixed.
type Profile struct {
	Enabled    bool
	ID         uint16
	Padding    uint16
	HeaderMask byte
	XOR        bool
	Clear      bool
}

func (p Profile) String() string {
	if !p.Enabled {
		return "direct"
	}
	encoding := "masked"
	if p.Clear {
		encoding = "clear"
	}
	return fmt.Sprintf("cover-%04x/pad-%d/%s", p.ID, p.Padding, encoding)
}

func key(id uint16) [32]byte {
	var seed [16]byte
	copy(seed[:12], []byte("DragonTCP-C3"))
	binary.BigEndian.PutUint16(seed[12:14], id)
	seed[14], seed[15] = byte(id)^0x6d, byte(id>>8)^0xb2
	return sha256.Sum256(seed[:])
}

// EncodePreface returns the fixed-size, self-describing portion. The first two
// bytes are the mutable profile ID; all metadata after them is masked.
func EncodePreface(p Profile) ([PrefaceSize]byte, error) {
	var out [PrefaceSize]byte
	if !p.Enabled {
		return out, fmt.Errorf("cover profile is disabled")
	}
	if p.Padding > MaxPadding {
		return out, fmt.Errorf("cover padding too large: %d", p.Padding)
	}

	binary.BigEndian.PutUint16(out[0:2], p.ID)
	var plain [10]byte
	copy(plain[0:4], []byte("DTC3"))
	if p.XOR {
		plain[4] |= 1
	}
	if p.Clear {
		plain[4] |= 2
	}
	plain[5] = p.HeaderMask
	binary.BigEndian.PutUint16(plain[6:8], p.Padding)
	plain[8] = plain[4] ^ plain[5] ^ 0xa5
	plain[9] = plain[6] ^ plain[7] ^ 0x5a
	k := key(p.ID)
	for i := range plain {
		out[2+i] = plain[i] ^ k[i]
	}
	return out, nil
}

// DecodePreface recognizes an encoded cover profile. ok=false means the bytes
// belong to a legacy/direct connection and must be replayed unchanged.
func DecodePreface(in [PrefaceSize]byte) (p Profile, ok bool) {
	id := binary.BigEndian.Uint16(in[0:2])
	k := key(id)
	var plain [10]byte
	for i := range plain {
		plain[i] = in[2+i] ^ k[i]
	}
	if string(plain[0:4]) != "DTC3" || plain[4]&^byte(3) != 0 {
		return Profile{}, false
	}
	if plain[8] != plain[4]^plain[5]^0xa5 || plain[9] != plain[6]^plain[7]^0x5a {
		return Profile{}, false
	}
	padding := binary.BigEndian.Uint16(plain[6:8])
	if padding > MaxPadding {
		return Profile{}, false
	}
	return Profile{
		Enabled:    true,
		ID:         id,
		Padding:    padding,
		HeaderMask: plain[5],
		XOR:        plain[4]&1 != 0,
		Clear:      plain[4]&2 != 0,
	}, true
}

// WritePreface sends the encoded profile followed by its fixed amount of
// random padding.
func WritePreface(w io.Writer, p Profile) error {
	if !p.Enabled {
		return nil
	}
	preface, err := EncodePreface(p)
	if err != nil {
		return err
	}
	packet := make([]byte, PrefaceSize+int(p.Padding))
	copy(packet, preface[:])
	if p.Padding > 0 {
		if _, err := rand.Read(packet[PrefaceSize:]); err != nil {
			return err
		}
	}
	return writeAll(w, packet)
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
