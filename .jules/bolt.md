## 2025-05-11 - Eliminating math/big Heap Allocations in Base58 DID Operations
**Learning:** Replacing `math/big.Int` in Base58 encoding/decoding with uint32 byte-array base conversion algorithms and fixed stack array buffers (`[128]byte` for base58 digits, `[34]byte` for Ed25519 multicodec prefixes) yields a ~50% reduction in execution time (4467 ns/op -> 2210 ns/op) and up to 80% reduction in memory allocations (248 B/op -> 48 B/op).
**Action:** When implementing Base58 or multibase encoding/decoding in Go for fixed-size cryptographic keys, avoid `math/big.Int` and use direct uint32 byte-array conversion with stack buffers.

## 2025-05-10 - Unrolling Keccak-f[1600] State Permutations and Eliminating Block Heap Allocation
**Learning:** In Go implementation of Keccak256, unrolling loop transformations ($\Theta$, $\rho$, $\pi$, $\chi$) and replacing slice allocations for block padding with fixed stack arrays ([136]byte) yields an ~85% reduction in execution time (~5500 ns/op -> ~847 ns/op) by eliminating modulo operations, slice indexing overhead, and heap allocations.
**Action:** When optimizing loop-heavy cryptographic hashing algorithms in Go, evaluate loop unrolling for state permutations and use array stack allocation for padding blocks.
