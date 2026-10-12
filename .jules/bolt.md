## 2025-05-10 - Unrolling Keccak-f[1600] State Permutations and Eliminating Block Heap Allocation
**Learning:** In Go implementation of Keccak256, unrolling loop transformations ($\Theta$, $\rho$, $\pi$, $\chi$) and replacing slice allocations for block padding with fixed stack arrays ([136]byte) yields an ~85% reduction in execution time (~5500 ns/op -> ~847 ns/op) by eliminating modulo operations, slice indexing overhead, and heap allocations.
**Action:** When optimizing loop-heavy cryptographic hashing algorithms in Go, evaluate loop unrolling for state permutations and use array stack allocation for padding blocks.

## 2026-03-31 - Replacing math/big.Int with Stack-Allocated Base58 Arithmetic
**Learning:** In Go implementations of Base58 encoding/decoding for DID multicodecs, replacing `math/big.Int` arbitrary-precision integer arithmetic with custom byte-array arithmetic backed by fixed stack buffers ([128]byte) eliminates heap allocations (4 allocs -> 1 alloc per op) and reduces encoding time by ~50% (~4.7 µs -> ~2.3 µs) and decoding time by ~50% (~2.3 µs -> ~1.1 µs).
**Action:** Avoid `math/big.Int` for small fixed-size encoding/decoding schemes (e.g. Base58 for 32-byte Ed25519 keys) and prefer fixed stack array buffers.
