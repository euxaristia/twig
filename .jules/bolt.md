## 2025-05-10 - Unrolling Keccak-f[1600] State Permutations and Eliminating Block Heap Allocation
**Learning:** In Go implementation of Keccak256, unrolling loop transformations ($\Theta$, $\rho$, $\pi$, $\chi$) and replacing slice allocations for block padding with fixed stack arrays ([136]byte) yields an ~85% reduction in execution time (~5500 ns/op -> ~847 ns/op) by eliminating modulo operations, slice indexing overhead, and heap allocations.
**Action:** When optimizing loop-heavy cryptographic hashing algorithms in Go, evaluate loop unrolling for state permutations and use array stack allocation for padding blocks.

## 2025-05-18 - Replacing big.Int Base58 with Stack Array Byte Arithmetic in DID Key Encoding
**Learning:** Using `math/big` (`big.Int`) for Base58 encoding/decoding of fixed-length cryptographic keys (e.g., 34-byte Ed25519 multicodec keys in `did:key`) causes excessive heap allocations and CPU overhead due to big-integer division and allocations in loops. Replacing `big.Int` with stack-allocated byte buffer arithmetic and `strings.Builder` improves encoding/decoding speed by 2-2.5x and reduces allocations by 75% (down to 1 alloc/op).
**Action:** Avoid `math/big` for fixed-size cryptographic key conversions; use stack-allocated array arithmetic and `strings.Builder`.
