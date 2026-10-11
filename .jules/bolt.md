## 2026-03-30 - Eliminating math/big Heap Allocations in Base58 & DID Encoding
**Learning:** Base58 encoding and decoding using `math/big.Int` incurs significant heap allocation and division overhead. Replacing `math/big` arithmetic with direct integer base conversion and stack buffers (`[128]byte`) reduces execution time by 20-38% and cuts heap allocations by 50-75% for DID keys.
**Action:** Avoid `math/big` for fixed-size multibase encoding/decoding; prefer stack-allocated byte arrays for base conversions in Go identity utilities.

## 2025-05-10 - Unrolling Keccak-f[1600] State Permutations and Eliminating Block Heap Allocation
**Learning:** In Go implementation of Keccak256, unrolling loop transformations ($\Theta$, $\rho$, $\pi$, $\chi$) and replacing slice allocations for block padding with fixed stack arrays ([136]byte) yields an ~85% reduction in execution time (~5500 ns/op -> ~847 ns/op) by eliminating modulo operations, slice indexing overhead, and heap allocations.
**Action:** When optimizing loop-heavy cryptographic hashing algorithms in Go, evaluate loop unrolling for state permutations and use array stack allocation for padding blocks.
