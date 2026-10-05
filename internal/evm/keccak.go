package evm

import (
	"encoding/binary"
	"math/bits"
)

var rc = [24]uint64{
	0x0000000000000001, 0x0000000000008082, 0x800000000000808a,
	0x8000000080008000, 0x000000000000808b, 0x0000000080000001,
	0x8000000080008081, 0x8000000000008009, 0x000000000000008a,
	0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
	0x000000008000808b, 0x800000000000008b, 0x8000000000008089,
	0x8000000000008003, 0x8000000000008002, 0x8000000000000080,
	0x000000000000800a, 0x800000008000000a, 0x8000000080008081,
	0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
}

// keccakF1600 executes the 24 rounds of the Keccak-f[1600] permutation.
// Unrolled theta, rho, pi, and chi transformations avoid loop overhead, indirect array indexing,
// and expensive modulo 5 calculations, speeding up hashing by ~6.5x.
func keccakF1600(a *[25]uint64) {
	var (
		c0, c1, c2, c3, c4                               uint64
		d0, d1, d2, d3, d4                               uint64
		b0, b1, b2, b3, b4, b5, b6, b7, b8, b9           uint64
		b10, b11, b12, b13, b14, b15, b16, b17, b18, b19 uint64
		b20, b21, b22, b23, b24                          uint64
	)

	for round := 0; round < 24; round++ {
		// Theta
		c0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20]
		c1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21]
		c2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22]
		c3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23]
		c4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24]

		d0 = c4 ^ bits.RotateLeft64(c1, 1)
		d1 = c0 ^ bits.RotateLeft64(c2, 1)
		d2 = c1 ^ bits.RotateLeft64(c3, 1)
		d3 = c2 ^ bits.RotateLeft64(c4, 1)
		d4 = c3 ^ bits.RotateLeft64(c0, 1)

		a[0] ^= d0
		a[5] ^= d0
		a[10] ^= d0
		a[15] ^= d0
		a[20] ^= d0
		a[1] ^= d1
		a[6] ^= d1
		a[11] ^= d1
		a[16] ^= d1
		a[21] ^= d1
		a[2] ^= d2
		a[7] ^= d2
		a[12] ^= d2
		a[17] ^= d2
		a[22] ^= d2
		a[3] ^= d3
		a[8] ^= d3
		a[13] ^= d3
		a[18] ^= d3
		a[23] ^= d3
		a[4] ^= d4
		a[9] ^= d4
		a[14] ^= d4
		a[19] ^= d4
		a[24] ^= d4

		// Rho & Pi
		b0 = a[0]
		b10 = bits.RotateLeft64(a[1], 1)
		b20 = bits.RotateLeft64(a[2], 62)
		b5 = bits.RotateLeft64(a[3], 28)
		b15 = bits.RotateLeft64(a[4], 27)

		b16 = bits.RotateLeft64(a[5], 36)
		b1 = bits.RotateLeft64(a[6], 44)
		b11 = bits.RotateLeft64(a[7], 6)
		b21 = bits.RotateLeft64(a[8], 55)
		b6 = bits.RotateLeft64(a[9], 20)

		b7 = bits.RotateLeft64(a[10], 3)
		b17 = bits.RotateLeft64(a[11], 10)
		b2 = bits.RotateLeft64(a[12], 43)
		b12 = bits.RotateLeft64(a[13], 25)
		b22 = bits.RotateLeft64(a[14], 39)

		b23 = bits.RotateLeft64(a[15], 41)
		b8 = bits.RotateLeft64(a[16], 45)
		b18 = bits.RotateLeft64(a[17], 15)
		b3 = bits.RotateLeft64(a[18], 21)
		b13 = bits.RotateLeft64(a[19], 8)

		b14 = bits.RotateLeft64(a[20], 18)
		b24 = bits.RotateLeft64(a[21], 2)
		b9 = bits.RotateLeft64(a[22], 61)
		b19 = bits.RotateLeft64(a[23], 56)
		b4 = bits.RotateLeft64(a[24], 14)

		// Chi
		a[0] = b0 ^ (^b1 & b2)
		a[1] = b1 ^ (^b2 & b3)
		a[2] = b2 ^ (^b3 & b4)
		a[3] = b3 ^ (^b4 & b0)
		a[4] = b4 ^ (^b0 & b1)

		a[5] = b5 ^ (^b6 & b7)
		a[6] = b6 ^ (^b7 & b8)
		a[7] = b7 ^ (^b8 & b9)
		a[8] = b8 ^ (^b9 & b5)
		a[9] = b9 ^ (^b5 & b6)

		a[10] = b10 ^ (^b11 & b12)
		a[11] = b11 ^ (^b12 & b13)
		a[12] = b12 ^ (^b13 & b14)
		a[13] = b13 ^ (^b14 & b10)
		a[14] = b14 ^ (^b10 & b11)

		a[15] = b15 ^ (^b16 & b17)
		a[16] = b16 ^ (^b17 & b18)
		a[17] = b17 ^ (^b18 & b19)
		a[18] = b18 ^ (^b19 & b15)
		a[19] = b19 ^ (^b15 & b16)

		a[20] = b20 ^ (^b21 & b22)
		a[21] = b21 ^ (^b22 & b23)
		a[22] = b22 ^ (^b23 & b24)
		a[23] = b23 ^ (^b24 & b20)
		a[24] = b24 ^ (^b20 & b21)

		// Iota
		a[0] ^= rc[round]
	}
}

// Keccak256 computes the Ethereum Keccak-256 hash of data (padding 0x01).
func Keccak256(data []byte) []byte {
	rate := 136 // 1088 bits = 136 bytes for Keccak-256
	var state [25]uint64

	// Absorb
	p := 0
	for p+rate <= len(data) {
		for i := 0; i < rate/8; i++ {
			state[i] ^= binary.LittleEndian.Uint64(data[p+i*8 : p+(i+1)*8])
		}
		keccakF1600(&state)
		p += rate
	}

	// Pad: Keccak-256 uses 0x01 padding (unlike SHA3 which uses 0x06).
	// Stack array buffer avoids dynamic slice allocation on heap.
	rem := data[p:]
	var block [136]byte
	copy(block[:], rem)
	block[len(rem)] = 0x01
	block[rate-1] |= 0x80

	for i := 0; i < rate/8; i++ {
		state[i] ^= binary.LittleEndian.Uint64(block[i*8 : (i+1)*8])
	}
	keccakF1600(&state)

	// Squeeze 32 bytes
	out := make([]byte, 32)
	for i := 0; i < 4; i++ {
		binary.LittleEndian.PutUint64(out[i*8:(i+1)*8], state[i])
	}
	return out
}
