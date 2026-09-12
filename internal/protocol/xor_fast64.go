//go:build amd64 || arm64

package protocol

import "unsafe"

const xorWordMask uint64 = 0xADADADADADADADAD

// XorInPlace is optimized for 64-bit targets (amd64/arm64).
//
// It aligns the input once, then XORs 64 bytes per loop iteration using
// eight native 64-bit operations. This removes the encoding/binary call
// overhead from the hot relay path and lets the compiler generate a tight
// load/xor/store loop.
func XorInPlace(b []byte) {
	n := len(b)
	if n == 0 {
		return
	}

	i := 0

	// Align the pointer for native uint64 accesses. This is normally already
	// aligned for pooled relay buffers, but also makes this safe for subslices.
	for i < n && (uintptr(unsafe.Pointer(&b[i]))&7) != 0 {
		b[i] ^= XORKey
		i++
	}

	for ; i+64 <= n; i += 64 {
		p := unsafe.Pointer(&b[i])
		*(*uint64)(unsafe.Add(p, 0)) ^= xorWordMask
		*(*uint64)(unsafe.Add(p, 8)) ^= xorWordMask
		*(*uint64)(unsafe.Add(p, 16)) ^= xorWordMask
		*(*uint64)(unsafe.Add(p, 24)) ^= xorWordMask
		*(*uint64)(unsafe.Add(p, 32)) ^= xorWordMask
		*(*uint64)(unsafe.Add(p, 40)) ^= xorWordMask
		*(*uint64)(unsafe.Add(p, 48)) ^= xorWordMask
		*(*uint64)(unsafe.Add(p, 56)) ^= xorWordMask
	}

	for ; i+8 <= n; i += 8 {
		p := (*uint64)(unsafe.Pointer(&b[i]))
		*p ^= xorWordMask
	}

	for ; i < n; i++ {
		b[i] ^= XORKey
	}
}
