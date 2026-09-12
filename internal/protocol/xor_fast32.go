//go:build arm || 386

package protocol

import "unsafe"

const xorWordMask32 uint32 = 0xADADADAD

// XorInPlace is the 32-bit optimized path used by ARMv7/386 builds.
// It aligns once, then processes 32 bytes per iteration with native uint32
// operations instead of a byte-at-a-time loop.
func XorInPlace(b []byte) {
	n := len(b)
	if n == 0 {
		return
	}

	i := 0
	for i < n && (uintptr(unsafe.Pointer(&b[i]))&3) != 0 {
		b[i] ^= XORKey
		i++
	}

	for ; i+32 <= n; i += 32 {
		p := unsafe.Pointer(&b[i])
		*(*uint32)(unsafe.Add(p, 0)) ^= xorWordMask32
		*(*uint32)(unsafe.Add(p, 4)) ^= xorWordMask32
		*(*uint32)(unsafe.Add(p, 8)) ^= xorWordMask32
		*(*uint32)(unsafe.Add(p, 12)) ^= xorWordMask32
		*(*uint32)(unsafe.Add(p, 16)) ^= xorWordMask32
		*(*uint32)(unsafe.Add(p, 20)) ^= xorWordMask32
		*(*uint32)(unsafe.Add(p, 24)) ^= xorWordMask32
		*(*uint32)(unsafe.Add(p, 28)) ^= xorWordMask32
	}

	for ; i+4 <= n; i += 4 {
		p := (*uint32)(unsafe.Pointer(&b[i]))
		*p ^= xorWordMask32
	}

	for ; i < n; i++ {
		b[i] ^= XORKey
	}
}
