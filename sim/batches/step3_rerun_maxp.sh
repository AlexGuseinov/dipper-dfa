#!/usr/bin/env bash
# Rerun of the strict 64/128 runs after raising DFA_MAXP from 256 to 1024 pairs per group
# (2 of 1000 keys needed more than 256 faults in one group and were cut off by the old limit).
cd "$(dirname "$0")/../.."
sim/run_batch.sh d128A_M1_strict dipper ks128A M1 near 1000 0xD1FA0201 4 -1 1000000 8
sim/run_batch.sh d128B_M1_strict dipper ks128B M1 near 1000 0xD1FA0201 4 -1 1000000 8
