#!/usr/bin/env bash
# Step 2: dipper, 64/96, M1, fault rounds 26 (rk27) and 25 (rk26). Same seed = same keys and fault stream.
cd "$(dirname "$0")/../.."
sim/run_batch.sh d96_M1_strict dipper ks96 M1 near 1000 0xD1FA0101 4 -1 1000000 8
sim/run_batch.sh d96_M1_th8    dipper ks96 M1 near 1000 0xD1FA0101 4 8  1000000 8
sim/run_batch.sh d96_M1_th12   dipper ks96 M1 near 1000 0xD1FA0101 4 12 1000000 8
