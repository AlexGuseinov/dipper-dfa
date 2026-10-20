#!/usr/bin/env bash
# Step 4: ablation, M1. xor and none are analysis-only variants (not proposed as ciphers).
# The near filter gives no information on them under M1 (see bin/dfa verify), so they use the
# deep filter (fault two rounds before the target round key). Same seeds as steps 2 and 3.
cd "$(dirname "$0")/../.."
for v in xor none; do
  sim/run_batch.sh ${v}96_M1_deep_strict  $v ks96   M1 deep 1000 0xD1FA0101 1 -1 1000000 8
  sim/run_batch.sh ${v}96_M1_deep_th8     $v ks96   M1 deep 1000 0xD1FA0101 1 8  1000000 8
  sim/run_batch.sh ${v}96_M1_deep_th12    $v ks96   M1 deep 1000 0xD1FA0101 1 12 1000000 8
  sim/run_batch.sh ${v}128A_M1_deep_strict $v ks128A M1 deep 1000 0xD1FA0201 1 -1 1000000 8
done
