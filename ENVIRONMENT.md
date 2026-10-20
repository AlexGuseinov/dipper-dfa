# Environment

All attack runs were built and run on the Linux server (Contabo VPS). Code was
edited on a Mac and copied to the server with rsync; nothing was run on the Mac
except git.

| Item | Value |
|---|---|
| Machine | x86-64 KVM guest (Contabo VPS), 8 vCPU, 1 thread per core, 23 GB RAM |
| CPU (as reported by `lscpu`) | AMD EPYC Processor (with IBPB), 2.0 GHz |
| OS | Ubuntu 24.04.5 LTS, kernel 6.8.0-147-generic |
| Compiler | gcc 13.3.0 (Ubuntu 13.3.0-6ubuntu2~24.04.1) |
| Flags | `-O3 -march=native -std=c11 -D_GNU_SOURCE -Wall -Wextra -Wno-unused-function`, linked with `-lm -lpthread` |
| Python (analysis) | 3.12.3 |
| Dates | runs started 20 Oct 2026 |

Dipper reference code: copied from
https://github.com/AlexGuseinov/Dipper-lightweight-cipher at commit
`3ae6788c7348749eed2113b05fb6c5cfb2651a9e` (see `ref/SOURCE_COMMIT`).

**CPU time note.** CPU times are per-thread CPU time
(`CLOCK_THREAD_CPUTIME_ID`). During the runs another long job of Ali's used all
8 vCPUs of the server, so CPU times are measured under contention and are an
upper bound for an idle machine. Use them only to compare runs with each other.
