#!/usr/bin/env bash
# Step 5: secondary fault models, 64/96, strict stop rule, same seed as step 2.
# M2 (one bit): the near filter works for all three variants (S^-1 values matter), floor 1.
# M3 (one aligned byte): near filter for dipper (floor 4, same top-bit freedom as M1);
#   xor/none get no information from the near filter (as for M1), so they use the deep filter.
cd "$(dirname "$0")/../.."
for v in dipper xor none; do
  sim/run_batch.sh ${v}96_M2_near_strict $v ks96 M2 near 1000 0xD1FA0101 1 -1 1000000 8
done
sim/run_batch.sh dipper96_M3_near_strict dipper ks96 M3 near 1000 0xD1FA0101 4 -1 1000000 8
for v in xor none; do
  sim/run_batch.sh ${v}96_M3_deep_strict $v ks96 M3 deep 1000 0xD1FA0101 1 -1 1000000 8
done
