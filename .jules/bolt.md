## 2025-05-18 - Unrolling Keccak-256 Permutation Loop

**Learning:** Loop overhead and modulo operations (`% 5`) inside the 24-round Keccak-f[1600] permutation account for ~85% of standard Keccak256 hash time in Go when implemented with simple nested loops. Unrolling the state transformations into scalar variables directly eliminates table lookups, bounds checks, and modulo arithmetic, yielding a ~6.5x speedup (from ~5400ns to ~830ns per operation). Additionally, replacing dynamic byte slice allocations (`make([]byte, rate)`) for padding with stack arrays avoids unnecessary heap pressure.
**Action:** When implementing cryptographic permutations or tight matrix transformations, unroll small 5x5 fixed-size state operations and avoid heap allocation for temporary block buffers.
