## 2025-05-10 - Unrolling Keccak-f[1600] State Permutations and Eliminating Block Heap Allocation
**Learning:** In Go implementation of Keccak256, unrolling loop transformations ($\Theta$, $\rho$, $\pi$, $\chi$) and replacing slice allocations for block padding with fixed stack arrays ([136]byte) yields an ~85% reduction in execution time (~5500 ns/op -> ~847 ns/op) by eliminating modulo operations, slice indexing overhead, and heap allocations.
**Action:** When optimizing loop-heavy cryptographic hashing algorithms in Go, evaluate loop unrolling for state permutations and use array stack allocation for padding blocks.

## 2026-03-29 - Eliminating `math/big` Allocations in Base58 Encoding/Decoding for DID Keys
**Learning:** Using `math/big` (`big.Int`) for fixed-size Base58 encoding and decoding (such as 34-byte DID keys) causes excessive heap allocations and multi-precision overhead. Replacing `math/big` with direct radix arithmetic on byte slices using fixed stack buffers (`[128]byte`) speeds up `DecodeBase58`/`ToVerifyingKey` by ~3.5x (~3764 ns/op -> ~1077 ns/op) and reduces heap allocations by 68% (152 B/op -> 48 B/op).
**Action:** Avoid `math/big` for fixed-size byte string encoding/decoding like Base58; use byte slice radix conversion with stack array buffers.
