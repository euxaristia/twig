## 2025-05-10 - Unrolling Keccak-f[1600] State Permutations and Eliminating Block Heap Allocation
**Learning:** In Go implementation of Keccak256, unrolling loop transformations ($\Theta$, $\rho$, $\pi$, $\chi$) and replacing slice allocations for block padding with fixed stack arrays ([136]byte) yields an ~85% reduction in execution time (~5500 ns/op -> ~847 ns/op) by eliminating modulo operations, slice indexing overhead, and heap allocations.
**Action:** When optimizing loop-heavy cryptographic hashing algorithms in Go, evaluate loop unrolling for state permutations and use array stack allocation for padding blocks.

## 2026-03-30 - Eliminating big.Int in Base58 Encoding/Decoding with Stack Byte Buffers
**Learning:** In Go Base58 string encoding/decoding and DID key operations, replacing `math/big.Int` arbitrary-precision arithmetic with direct in-place base conversion using fixed-size stack arrays (`[128]byte` / `[256]byte`) achieves ~46% faster execution (~4700 ns/op -> ~2500 ns/op for encoding, ~2300 ns/op -> ~1260 ns/op for decoding) and reduces heap allocations by ~70% (4 allocs/op -> 1 alloc/op).
**Action:** Prefer direct byte array digit-by-digit base conversion with stack-allocated buffers over `math/big.Int` for small fixed-width cryptographic or multibase encoding operations in Go.
