## 2026-03-29 - Eliminating math/big and Heap Allocations in Base58 Encoding/Decoding
**Learning:** In Go, replacing `math/big` big-integer arithmetic for Base58 encoding/decoding with array-based byte conversion and fixed stack buffers (`[128]byte`) reduces execution time by ~42% (4608 ns -> 2650 ns) and reduces allocations from 4 allocs (200 B/op) to 1 alloc (48 B/op, for string output creation).
**Action:** Avoid `math/big` for fixed/small cryptographic encoding algorithms like Base58; use stack byte arrays and shift/multiply math instead.

## 2025-05-10 - Unrolling Keccak-f[1600] State Permutations and Eliminating Block Heap Allocation
**Learning:** In Go implementation of Keccak256, unrolling loop transformations ($\Theta$, $\rho$, $\pi$, $\chi$) and replacing slice allocations for block padding with fixed stack arrays ([136]byte) yields an ~85% reduction in execution time (~5500 ns/op -> ~847 ns/op) by eliminating modulo operations, slice indexing overhead, and heap allocations.
**Action:** When optimizing loop-heavy cryptographic hashing algorithms in Go, evaluate loop unrolling for state permutations and use array stack allocation for padding blocks.
