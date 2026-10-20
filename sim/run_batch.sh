#!/usr/bin/env bash
# Run one batch configuration and store raw results + metadata.
#   sim/run_batch.sh <name> <dfa attack args...>
# Writes results/raw/<name>.jsonl (one JSON line per key) and <name>.meta.
set -euo pipefail
cd "$(dirname "$0")/.."
name=$1; shift
mkdir -p results/raw
out=results/raw/$name.jsonl
meta=results/raw/$name.meta
{
  echo "name: $name"
  echo "command: bin/dfa attack $*"
  echo "started: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "host: $(hostname)  cpu: $(lscpu | sed -n 's/^Model name: *//p' | head -1)"
  echo "compiler: $(gcc --version | head -1)"
  echo "code sha256: $(cat attack/*.h sim/*.h sim/*.c variants/*.h ref/*.h ref/dipper.c | sha256sum | cut -c1-16)"
} > "$meta"
/usr/bin/time -f "wall_s: %e\nuser_s: %U" -a -o "$meta" bin/dfa attack "$@" > "$out"
echo "finished: $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$meta"
echo "lines: $(wc -l < "$out")" >> "$meta"
