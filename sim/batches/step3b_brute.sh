#!/usr/bin/env bash
# Step 3, option B: full 2^32 search of (K6,K7) per consistent (rk26,rk27) tuple, 5 keys.
# Same seed as d128B_M1_strict, so these are its first 5 keys and faults.
cd "$(dirname "$0")/../.."
mkdir -p results/raw
{ echo "command: bin/dfa brute128 dipper 5 0xD1FA0201 4 -1 1000000 8"; echo "started: $(date -u +%FT%TZ)"; } > results/raw/d128B_M1_brute.meta
bin/dfa brute128 dipper 5 0xD1FA0201 4 -1 1000000 8 > results/raw/d128B_M1_brute.jsonl
echo "finished: $(date -u +%FT%TZ)" >> results/raw/d128B_M1_brute.meta
