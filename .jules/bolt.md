## 2025-05-10 - Unrolling Keccak-f[1600] State Permutations and Eliminating Block Heap Allocation
**Learning:** In Go implementation of Keccak256, unrolling loop transformations ($\Theta$, $\rho$, $\pi$, $\chi$) and replacing slice allocations for block padding with fixed stack arrays ([136]byte) yields an ~85% reduction in execution time (~5500 ns/op -> ~847 ns/op) by eliminating modulo operations, slice indexing overhead, and heap allocations.
**Action:** When optimizing loop-heavy cryptographic hashing algorithms in Go, evaluate loop unrolling for state permutations and use array stack allocation for padding blocks.

## 2025-05-18 - Replacing big.Int Base58 with Stack Array Byte Arithmetic in DID Key Encoding
**Learning:** Using `math/big` (`big.Int`) for Base58 encoding/decoding of fixed-length cryptographic keys (e.g., 34-byte Ed25519 multicodec keys in `did:key`) causes excessive heap allocations and CPU overhead due to big-integer division and allocations in loops. Replacing `big.Int` with stack-allocated byte buffer arithmetic and `strings.Builder` improves encoding/decoding speed by 2-2.5x and reduces allocations by 75% (down to 1 alloc/op).
**Action:** Avoid `math/big` for fixed-size cryptographic key conversions; use stack-allocated array arithmetic and `strings.Builder`.

## 2025-05-24 - Zero-Allocation Loop Formatting and Bit Counting in iCaptcha PoW Solving
**Learning:** In Proof of Work (PoW) iterations, using `fmt.Sprintf` and string concatenation inside the loop generates millions of heap allocations (24,000+ allocs/op for 16-bit difficulty). Pre-allocating a single byte slice buffer with prefix challenge and appending hex nonces via `strconv.AppendUint(buf[:prefixLen], i, 16)` reduces per-iteration heap allocations to 0 (allocations reduced from 24,008 to 2). Combined with `math/bits.LeadingZeros8` for hardware-accelerated leading zero bit counting, PoW solving speed improved by ~38% (from ~6.15ms to ~3.81ms per PoW solution).
**Action:** Always avoid `fmt.Sprintf` or string concatenation inside high-frequency PoW or hash loops; use a slice buffer with `strconv.AppendUint` and `math/bits`.

## 2025-05-31 - Single-Slice Allocation Padding and Stack-Array Public Key Derivation
**Learning:** Appending to a slice with insufficient capacity (e.g. `append(make([]byte, padLen), b...)`) causes double heap allocations in Go: first for the zero slice and second during `append` growth. Pre-allocating `make([]byte, totalLen)` and using `copy()` eliminates redundant allocations (2 -> 1 alloc). Furthermore, assembling fixed-length cryptographic headers/keys (e.g. 64-byte uncompressed secp256k1 public keys) directly in a fixed `[64]byte` stack array completely avoids heap allocation for padding and concatenation slices.
**Action:** Replace `append(make([]byte, pad), b...)` with single-allocation `copy()` and use fixed-size stack arrays when concatenating fixed-length public key or hash buffers.
