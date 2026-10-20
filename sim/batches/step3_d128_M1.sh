#!/usr/bin/env bash
# Step 3: dipper, 64/128, M1. Option A: rk27, rk26, rk25 from faults at rounds 26, 25, 24.
# Option B: rk27, rk26 only; the 2^32 search is run by `dfa brute128` (sim/batches/step3b_brute.sh).
cd "$(dirname "$0")/../.."
sim/run_batch.sh d128A_M1_strict dipper ks128A M1 near 1000 0xD1FA0201 4 -1 1000000 8
sim/run_batch.sh d128A_M1_th8    dipper ks128A M1 near 1000 0xD1FA0201 4 8  1000000 8
sim/run_batch.sh d128A_M1_th12   dipper ks128A M1 near 1000 0xD1FA0201 4 12 1000000 8
sim/run_batch.sh d128B_M1_strict dipper ks128B M1 near 1000 0xD1FA0201 4 -1 1000000 8
