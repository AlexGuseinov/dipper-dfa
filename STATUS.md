# STATUS

## 20 Oct 2026

**Step 0 — done**
- Literature: no fault attack on Dipper found (LITERATURE.md; numbers there are from abstracts only).
- `make test` (10,000 random keys per key size, seed 0x5EED0001): variant code == ref/dipper.c,
  TV1–TV4 pass; fact 1 (`Finv(C) == x27 ^ rk27`) holds; fact 2 + key-schedule inversion
  recovers the master key from rk26, rk27 (64/96) and rk25, rk26, rk27 (64/128): 0 failures.
- DFS filter cross-checked against a direct full-state check (`bin/dfa verify`, 5 keys,
  8 pairs per group, 200,000 random guesses per group): 0 disagreements for dipper M1, M2, M3.

**Findings so far (from runs)**
- Near filter (fault at round T-1, target rk_T), M1: the top bit of each 16-bit word of
  P^-1(rk_T) never changes a difference, so at least 4 candidates per group / 16 per round
  key remain. The 16 rk27 candidates are cut to 1 by the round-25 faults.
- xor and none variants, M1, near filter: 100% of random key guesses pass, i.e. no
  information on rk_T (only the modular addition makes the activity pattern key-dependent).
  These variants need the fault one round earlier (attack/deep.h).

**Step 2 — running**: dipper, 64/96, M1, 1000 keys, seed 0xD1FA0101, stop rules floor / θ=8 / θ=12
(`sim/batches/step2_d96_M1.sh`).

**Next**: 64/128 options A and B; ablation xor/none (deep filter); M2, M3; tables, figures, RESULTS.md.
