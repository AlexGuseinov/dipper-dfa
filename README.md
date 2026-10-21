# dipper-dfa

Differential fault analysis of the Dipper block cipher (64/96 and 64/128) in software
simulation, with an ablation on two analysis-only variants (`xor`, `none`) that are **not**
proposed as ciphers. Main tables: `RESULTS.md`.

Reference code in `ref/` is copied from
https://github.com/AlexGuseinov/Dipper-lightweight-cipher at commit
`3ae6788c7348749eed2113b05fb6c5cfb2651a9e`.

## Layout

```
ref/        reference Dipper code (copied), key-schedule inversion (ks_inv.h), step-0 tests
variants/   cipher with selectable mixing layer: dipper / xor / none
attack/     dfa.h (near filter), deep.h (deep filter, linear variants), chain.h (full key recovery)
sim/        fault.h (fault models), dfa_run.c (CLI), run_batch.sh, batches/ (exact run scripts)
analysis/   summarize.py (tables), figures.py (figures), show.py (debug view)
results/raw/      one JSON line per key, plus .meta (command, seed, times)
results/summary/  per-run summaries and summary_table.md
figures/    fig1-fig5 (PNG), produced by analysis/figures.py
```

## Reproduce (Linux server, gcc)

```bash
make && make test
```

```bash
sim/batches/step2_d96_M1.sh
sim/batches/step3_d128_M1.sh
sim/batches/step3_rerun_maxp.sh
sim/batches/step3b_brute.sh
sim/batches/step4_ablation_M1.sh
sim/batches/step5_M2_M3.sh
sim/batches/step5b_M3_floor8.sh
```

```bash
python3 analysis/summarize.py results/raw/*.jsonl
```

Figures need matplotlib (we used 3.9.2):

```bash
python analysis/figures.py
```

Checks of the filter against a direct full-state check, and of the zero-information result
for the variants:

```bash
bin/dfa verify dipper M1 26 8 5 0xAB02 200000
```

```bash
bin/dfa verify xor M1 26 8 5 0xAB02 200000
```

Notes
- `results/raw/dipper96_M3_near_strict.*` is the M3 run with floor 4 (265/1000 keys did not reach
  it within 1000 faults per stage); it is superseded by `dipper96_M3_near_floor8`.
- `d128A_M1_strict` and `d128B_M1_strict` were rerun after raising the per-group pair limit from
  256 to 1024 (`step3_rerun_maxp.sh`); the first runs lost 2 keys to the old limit.
- All runs are deterministic: the same command and seed give the same output.
