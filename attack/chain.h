/*
 * Full DFA key recovery: round keys rk27, rk26 (and rk25 for 64/128 option A)
 * one stage at a time, then master key via ref/ks_inv.h, then a check against
 * one known plaintext/ciphertext pair.
 *
 * Stage for target rk_T: new faults are injected at the S-box input of round
 * T-1 (attack "near", attack/dfa.h) or T-2 (attack "deep", attack/deep.h,
 * linear variants only). Every surviving "prefix" (candidate values of
 * rk27..rk_{T+1}) is kept; each prefix peels the ciphertexts with its own keys
 * and runs the group filter. A prefix dies when a fault pair is impossible
 * under it (near: both groups active; any: a group with zero survivors).
 *
 * Stop rule (attacker side, uses no knowledge of the key). A stage ends when
 * the filter finished without hitting the node cap for every live prefix and
 *   (a) every group of every live prefix has at most `floor` survivors, or
 *   (b) log2(total survivors over all prefixes) <= theta   (theta < 0: off).
 * `floor` = smallest set the fault model can reach (M1 near: 4 per group, the
 * top bit of each kappa word never changes a difference; see RESULTS.md).
 */
#ifndef DFA_CHAIN_H
#define DFA_CHAIN_H
#include <math.h>
#include <time.h>
#include "dfa.h"
#include "deep.h"
#include "../sim/fault.h"
#include "../ref/ks_inv.h"

#define MAXPREF 65536
#define MAXFAULTS 2048
#define CANDCAP 2048

typedef struct {
    uint64_t rk[28];          /* rk[T+1..27] valid for this prefix */
    int n[2], ncap[2];
    gpair_t *gp[2];
    long long cnt[2];
    int capped[2];
    uint32_t *cand[2];
    int alive;
} prefix_t;

typedef struct {
    int faults, faults_g[2];
    double log2_after[MAXFAULTS];   /* log2(total survivors) after f faults; lower bound if capped */
    unsigned char capped_after[MAXFAULTS];
    long long nodes, level_max;
    int prefixes_in, live_end;
    long long cands_out;
    int true_kept, reached;
    double cpu;
} stage_t;

typedef struct {
    int v, model, deep, floor_, maxfaults;
    double theta;
    long long cap;
    const hyp_t *H;
} attack_cfg_t;

static inline double tcpu(void) {
    struct timespec ts; clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
    return ts.tv_sec + 1e-9 * ts.tv_nsec;
}

static void prefix_reset(prefix_t *P) {
    for (int g = 0; g < 2; g++) {
        if (!P->gp[g]) { P->ncap[g] = 32; P->gp[g] = malloc(sizeof(gpair_t) * 32); }
        if (!P->cand[g]) P->cand[g] = malloc(sizeof(uint32_t) * CANDCAP);
        P->n[g] = 0; P->cnt[g] = 1LL << 32; P->capped[g] = 1;
    }
    P->alive = 1;
}
static int prefix_add(prefix_t *P, int g, const gpair_t *x) {
    if (P->n[g] >= DFA_MAXP) return 0;
    if (P->n[g] == P->ncap[g]) { P->ncap[g] *= 2; P->gp[g] = realloc(P->gp[g], sizeof(gpair_t) * P->ncap[g]); }
    P->gp[g][P->n[g]++] = *x;
    return 1;
}

static int run_stage(const attack_cfg_t *A, int T, const uint64_t *rk_true, uint64_t *rng,
                     prefix_t *pre, int npre, prefix_t *out, int *nout, stage_t *st) {
    double t0 = tcpu();
    memset(st, 0, sizeof(*st));
    st->prefixes_in = npre;
    int fr = A->deep ? T - 2 : T - 1;
    for (int q = 0; q < npre; q++) prefix_reset(&pre[q]);
    gres_t res; uint32_t *cbuf = malloc(sizeof(uint32_t) * CANDCAP);
    int f;
    for (f = 0; f < A->maxfaults; f++) {
        uint64_t p = sm64(rng), m = fault_mask(A->model, rng);
        uint64_t c = encrypt_v(p, rk_true, A->v), cf = encrypt_fault(p, rk_true, A->v, fr, m);
        if (!A->deep) { gpair_t gt; int g = to_gpair(peel(c, rk_true, T, A->v), peel(cf, rk_true, T, A->v), &gt); if (g >= 0) st->faults_g[g]++; }
        for (int q = 0; q < npre; q++) {
            prefix_t *P = &pre[q];
            if (!P->alive) continue;
            uint64_t w = peel(c, P->rk, T, A->v), wf = peel(cf, P->rk, T, A->v);
            if (w == wf) { P->alive = 0; continue; }
            gpair_t gp2[2]; int gs[2], ng = 0;
            if (A->deep) { to_gpair_both(w, wf, gp2); gs[0] = 0; gs[1] = 1; ng = 2; }
            else { int g = to_gpair(w, wf, &gp2[0]); if (g < 0) { P->alive = 0; continue; } gp2[1] = gp2[0]; gs[0] = g; ng = 1; }
            for (int k = 0; k < ng && P->alive; k++) {
                int g = gs[k];
                if (!prefix_add(P, g, &gp2[A->deep ? g : 0])) { P->alive = 0; break; }
                res.cand = cbuf; res.cand_cap = CANDCAP;
                if (A->deep) dfa_group_deep(P->gp[g], P->n[g], g, A->v, A->H, A->cap, &res);
                else dfa_group(P->gp[g], P->n[g], g, A->v, A->model, A->cap, &res);
                st->nodes += res.nodes;
                if (res.level_max > st->level_max) st->level_max = res.level_max;
                P->cnt[g] = res.leaves; P->capped[g] = res.capped;
                if (!res.capped && res.leaves == 0) { P->alive = 0; break; }
                if (!res.capped && res.leaves <= CANDCAP) memcpy(P->cand[g], cbuf, sizeof(uint32_t) * res.leaves);
            }
        }
        double tot = 0; int anycap = 0, flo = 1, live = 0;
        for (int q = 0; q < npre; q++) {
            prefix_t *P = &pre[q];
            if (!P->alive) continue;
            live++;
            tot += (double)P->cnt[0] * (double)P->cnt[1];
            for (int g = 0; g < 2; g++) {
                if (P->capped[g] || P->cnt[g] > CANDCAP) anycap = 1;
                if (P->cnt[g] > A->floor_) flo = 0;
            }
        }
        if (f < MAXFAULTS) { st->log2_after[f] = live ? log2(tot) : -1; st->capped_after[f] = (unsigned char)anycap; }
        if (!live) { f++; break; }
        if (!anycap && tot <= MAXPREF && (flo || (A->theta >= 0 && log2(tot) <= A->theta + 1e-9))) { f++; st->reached = 1; break; }
    }
    st->faults = f;
    int no = 0;
    uint64_t kap = perm_inv(rk_true[T]);
    for (int q = 0; q < npre; q++) {
        prefix_t *P = &pre[q];
        if (!P->alive || !st->reached) continue;
        st->live_end++;
        for (long long a = 0; a < P->cnt[0]; a++)
            for (long long b = 0; b < P->cnt[1] && no < MAXPREF; b++) {
                prefix_t *O = &out[no++];
                memcpy(O->rk, P->rk, sizeof(O->rk));
                O->rk[T] = kappa_to_rk(P->cand[0][a], P->cand[1][b]);
                O->alive = 1;
                int istrue = P->cand[0][a] == (uint32_t)(kap >> 32) && P->cand[1][b] == (uint32_t)kap;
                for (int r = T + 1; r < 28; r++) istrue &= P->rk[r] == rk_true[r];
                if (istrue) st->true_kept = 1;   /* bookkeeping only; the attack never uses it */
            }
    }
    *nout = no;
    st->cands_out = no;
    free(cbuf);
    st->cpu = tcpu() - t0;
    return st->reached && no > 0;
}
#endif
