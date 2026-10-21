#!/usr/bin/env bash
# dipper M3 near: with floor 4, 265/1000 keys stayed at 8 survivors in one group until the
# 1000-fault cap, so the reachable minimum under M3 is 8 per group for some keys. Rerun with floor 8.
cd "$(dirname "$0")/../.."
sim/run_batch.sh dipper96_M3_near_floor8 dipper ks96 M3 near 1000 0xD1FA0101 8 -1 1000000 8
