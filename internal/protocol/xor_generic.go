//go:build !amd64 && !arm64 && !arm && !386

package protocol

// Generic fallback for 32-bit and uncommon architectures.
func XorInPlace(b []byte) {
	for i := range b {
		b[i] ^= XORKey
	}
}
