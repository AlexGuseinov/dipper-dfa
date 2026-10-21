# RESULTS

Paper-ready tables and the discussion are in `paper/paper.tex` (Tables 1-3). All rows below are produced by `analysis/summarize.py` from `results/raw/`; faults are simulated in software, 1000 random keys per row.

xor and none are analysis-only variants, not proposed as ciphers.

| run | variant | key | model | mode | stop | keys | success | faults mean | median | max | per stage (mean) | max masters checked | CPU s/key |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| d128A_M1_strict | dipper | 128A | M1 | near | floor | 1000 | 1000/1000 | 332.0 | 316 | 743 | 109.5 / 111.6 / 110.9 | 16 | 2.74 |
| d128A_M1_th12 | dipper | 128A | M1 | near | 12 | 1000 | 1000/1000 | 137.4 | 137 | 216 | 45.7 / 45.8 / 45.8 | 4096 | 29.13 |
| d128A_M1_th8 | dipper | 128A | M1 | near | 8 | 1000 | 1000/1000 | 175.9 | 175 | 253 | 58.8 / 58.7 / 58.5 | 256 | 5.65 |
| d128B_M1_strict | dipper | 128B | M1 | near | floor | 1000 | 0/1000 | 221.1 | 208 | 604 | 109.5 / 111.6 | 0 | 1.61 |
| d96_M1_strict | dipper | 96 | M1 | near | floor | 1000 | 1000/1000 | 225.2 | 210 | 546 | 112.5 / 112.7 | 16 | 1.67 |
| d96_M1_th12 | dipper | 96 | M1 | near | 12 | 1000 | 1000/1000 | 91.9 | 91 | 142 | 46.0 / 45.9 | 4096 | 14.26 |
| d96_M1_th8 | dipper | 96 | M1 | near | 8 | 1000 | 1000/1000 | 118.3 | 116 | 186 | 59.1 / 59.2 | 256 | 3.22 |
| dipper96_M2_near_strict | dipper | 96 | M2 | near | floor | 1000 | 1000/1000 | 126.0 | 115 | 338 | 62.5 / 63.5 | 1 | 0.40 |
| dipper96_M3_near_floor8 | dipper | 96 | M3 | near | floor | 1000 | 1000/1000 | 126.7 | 121 | 404 | 63.6 / 63.1 | 64 | 1.16 |
| none128A_M1_deep_strict | none | 128A | M1 | deep | floor | 1000 | 1000/1000 | 221.6 | 215 | 380 | 72.8 / 74.5 / 74.3 | 1 | 12.41 |
| none96_M1_deep_strict | none | 96 | M1 | deep | floor | 1000 | 1000/1000 | 149.5 | 145 | 278 | 74.5 / 75.0 | 1 | 8.28 |
| none96_M1_deep_th12 | none | 96 | M1 | deep | 12 | 1000 | 1000/1000 | 61.7 | 60 | 119 | 31.1 / 30.6 | 4096 | 295.86 |
| none96_M1_deep_th8 | none | 96 | M1 | deep | 8 | 1000 | 1000/1000 | 72.3 | 72 | 119 | 36.7 / 35.7 | 256 | 43.97 |
| none96_M2_near_strict | none | 96 | M2 | near | floor | 1000 | 1000/1000 | 308.2 | 299 | 646 | 153.2 / 155.0 | 1 | 3.73 |
| none96_M3_deep_strict | none | 96 | M3 | deep | floor | 1000 | 1000/1000 | 159.8 | 152 | 468 | 79.7 / 80.1 | 1 | 9.24 |
| xor128A_M1_deep_strict | xor | 128A | M1 | deep | floor | 1000 | 1000/1000 | 126.1 | 123 | 226 | 42.3 / 41.2 / 42.7 | 1 | 4.75 |
| xor96_M1_deep_strict | xor | 96 | M1 | deep | floor | 1000 | 1000/1000 | 84.1 | 81 | 184 | 42.3 / 41.8 | 1 | 3.11 |
| xor96_M1_deep_th12 | xor | 96 | M1 | deep | 12 | 1000 | 1000/1000 | 34.8 | 34 | 65 | 17.4 / 17.4 | 4096 | 94.71 |
| xor96_M1_deep_th8 | xor | 96 | M1 | deep | 8 | 1000 | 1000/1000 | 40.3 | 40 | 75 | 20.1 / 20.1 | 256 | 14.28 |
| xor96_M2_near_strict | xor | 96 | M2 | near | floor | 1000 | 1000/1000 | 307.9 | 299 | 615 | 154.0 / 153.9 | 1 | 3.93 |
| xor96_M3_deep_strict | xor | 96 | M3 | deep | floor | 1000 | 1000/1000 | 52.2 | 50 | 123 | 26.2 / 26.1 | 1 | 2.69 |

64/128 option B: 1000/1000 keys leave exactly one (rk26, rk27) tuple after the key-schedule consistency check, and it is the true one. Full 2^32 search (results/raw/d128B_M1_brute.jsonl): 5/5 keys correct and unique, 150.5-152.3 s wall on 8 threads (1202.9-1217.4 s CPU) per key.

Last round (Observation 1 in the paper): C = F(x27 xor rk27) with F = P o ARX o S public and invertible, so F^-1(C) = x27 xor rk27 needs no key. The last round adds the key rk27 but no keyed nonlinear layer; the 28 rounds amount to 27 keyed nonlinear rounds plus a whitening key.
