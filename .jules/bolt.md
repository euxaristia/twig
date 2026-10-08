## 2025-05-10 - Unrolling Keccak-f[1600] State Permutations and Eliminating Block Heap Allocation
**Learning:** In Go implementation of Keccak256, unrolling loop transformations ($\Theta$, $\rho$, $\pi$, $\chi$) and replacing slice allocations for block padding with fixed stack arrays ([136]byte) yields an ~85% reduction in execution time (~5500 ns/op -> ~847 ns/op) by eliminating modulo operations, slice indexing overhead, and heap allocations.
**Action:** When optimizing loop-heavy cryptographic hashing algorithms in Go, evaluate loop unrolling for state permutations and use array stack allocation for padding blocks.

## 2026-03-29 - Replacing math/big in Base58 Encoding/Decoding with Direct Radix Byte Operations
**Learning:** Replacing Go's `math/big.Int` arithmetic (`DivMod`, `Mul`, `Add`) in Base58 encoding and decoding with direct byte-slice radix conversions reduces execution time by ~30-35% and eliminates temporary heap allocations for big integer instances.
**Action:** In encoding routines operating on small byte slices (e.g. 32-byte public keys / hash digests), replace generic `math/big` arithmetic with optimized direct radix byte-array conversions.
