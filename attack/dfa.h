/*
 * DFA key-candidate filter for one round key of Dipper (and the analysis-only
 * variants xor / none).
 *
 * Setting. For each fault we know w and w' = the S-box input of round t+1
 * (key already added), for the correct and the faulty run. The fault was
 * injected at the S-box input of round t. Target: K = rk_{t+1}.
 *
 *   x  = w ^ K                       (state entering round t+1)
 *   u  = P^-1(x) = P^-1(w) ^ P^-1(K) (words A2,B1,C2,D1)
 *   A1 = A2 - B1, C1 = C2 - D1       (dipper; xor: ^ ; none: A1 = A2)
 *   y_t = S^-1(rotr(A1,1) | rotr(B1,4) | rotr(C1,7) | rotr(D1,11))
 * and Delta y_t must fit the fault model.
 *
 * We guess kappa = P^-1(K) instead of K (same thing, P is a bit permutation).
 * The words split into two independent groups:
 *   group 0: (kA, kB) acting on (A2, B1)    group 1: (kC, kD) acting on (C2, D1)
 * A fault lies in one group; the group is read off from P^-1(w ^ w'), which is
 * key-free. Inside a group the guess goes bit by bit from bit 0 to bit 15:
 * at bit i we guess (kX_i, kY_i) (2 bits) and carry the subtraction borrow of
 * every stored fault pair to bit i+1. A y_t nibble is tested as soon as the
 * guessed bits decide its activity (any bit difference makes it active) and,
 * for M2, as soon as all its bits are known.
 */
#ifndef DFA_ATTACK_H
#define DFA_ATTACK_H
#include <stdint.h>
#include <stdlib.h>
#include "../variants/cipher.h"

enum { M1 = 1, M2 = 2, M3 = 3 };
#define DFA_MAXP 1024

typedef struct { uint16_t x, xf, y, yf; } gpair_t;   /* X = A2 or C2 part, Y = B1 or D1 part, before key */

typedef struct {
    long long leaves;        /* surviving (kX,kY) guesses */
    long long nodes;         /* partial guesses evaluated (all levels) */
    long long level_max;     /* largest number of live partial guesses at one bit level */
    int capped;              /* 1 if node_cap was reached: leaves is then a lower bound */
    uint32_t *cand;          /* stored candidates (kX<<16 | kY), up to cand_cap */
    long long cand_cap;
} gres_t;

typedef struct {
    const gpair_t *P; int n;
    int v, model, rX, rY;
    uint16_t mX[4], mY[4];   /* intermediate-bit masks of each output nibble */
    int cX[4], cY[4];        /* bit level at which the nibble is complete */
    uint16_t X1[17][DFA_MAXP], X1f[17][DFA_MAXP];
    uint8_t  b[17][DFA_MAXP], bf[17][DFA_MAXP];
    long long node_cap, level_cnt[16];
    gres_t *res;
} gctx_t;

static inline int fits_model(unsigned act, int model) {
    /* act: 8-bit mask, bits 0..3 = X-word nibbles, 4..7 = Y-word nibbles */
    if (act == 0) return 1;                       /* partial: nothing active yet */
    if (model == M1 || model == M2) return (act & (act - 1)) == 0;
    /* M3: inside one aligned byte = nibbles {0,1} or {2,3} of one word */
    return (act & ~0x03u) == 0 || (act & ~0x0Cu) == 0 || (act & ~0x30u) == 0 || (act & ~0xC0u) == 0;
}

static void gdfs(gctx_t *c, int i, uint16_t kx, uint16_t ky) {
    gres_t *r = c->res;
    if (r->capped) return;
    uint16_t lvl = (uint16_t)((2u << i) - 1);
    for (int g = 0; g < 4; g++) {
        uint16_t kxi = (uint16_t)(kx | ((g & 1) << i)), kyi = (uint16_t)(ky | ((g >> 1) << i));
        if (++r->nodes > c->node_cap) { r->capped = 1; return; }
        int ok = 1;
        for (int j = 0; j < c->n && ok; j++) {
            const gpair_t *p = &c->P[j];
            int X2 = ((p->x ^ kxi) >> i) & 1, X2f = ((p->xf ^ kxi) >> i) & 1;
            int Y1 = ((p->y ^ kyi) >> i) & 1, Y1f = ((p->yf ^ kyi) >> i) & 1;
            int x1, x1f, nb = 0, nbf = 0;
            if (c->v == V_DIPPER) {
                int bo = c->b[i][j], bof = c->bf[i][j];
                x1 = X2 ^ Y1 ^ bo;   nb  = ((!X2) & Y1)  | ((!(X2 ^ Y1)) & bo);
                x1f = X2f ^ Y1f ^ bof; nbf = ((!X2f) & Y1f) | ((!(X2f ^ Y1f)) & bof);
            } else if (c->v == V_XOR) { x1 = X2 ^ Y1; x1f = X2f ^ Y1f; }
            else { x1 = X2; x1f = X2f; }
            uint16_t X1 = (uint16_t)(c->X1[i][j] | (x1 << i)), X1f = (uint16_t)(c->X1f[i][j] | (x1f << i));
            c->X1[i + 1][j] = X1; c->X1f[i + 1][j] = X1f;
            c->b[i + 1][j] = (uint8_t)nb; c->bf[i + 1][j] = (uint8_t)nbf;
            uint16_t dX = (uint16_t)((X1 ^ X1f) & lvl), dY = (uint16_t)(p->y ^ p->yf);
            unsigned act = 0;
            for (int t = 0; t < 4; t++) {
                if (dX & c->mX[t]) act |= 1u << t;
                if (dY & c->mY[t]) act |= 1u << (4 + t);
            }
            if (!fits_model(act, c->model)) { ok = 0; break; }
            if (c->model == M2 && act) {
                int t = __builtin_ctz(act);
                if (t < 4 && i >= c->cX[t]) {
                    int a = (rotr16(X1, c->rX) >> (4 * t)) & 0xF, af = (rotr16(X1f, c->rX) >> (4 * t)) & 0xF;
                    if (__builtin_popcount(SBI[a] ^ SBI[af]) != 1) ok = 0;
                } else if (t >= 4 && i >= c->cY[t - 4]) {
                    uint16_t Yv = (uint16_t)(p->y ^ kyi), Yf = (uint16_t)(p->yf ^ kyi);
                    int a = (rotr16(Yv, c->rY) >> (4 * (t - 4))) & 0xF, af = (rotr16(Yf, c->rY) >> (4 * (t - 4))) & 0xF;
                    if (__builtin_popcount(SBI[a] ^ SBI[af]) != 1) ok = 0;
                }
            }
        }
        if (!ok) continue;
        c->level_cnt[i]++;
        if (i == 15) {
            if (r->leaves < r->cand_cap && r->cand) r->cand[r->leaves] = (uint32_t)kxi << 16 | kyi;
            r->leaves++;
        } else gdfs(c, i + 1, kxi, kyi);
    }
}

/* Filter (kX,kY) of group g with n fault pairs. Returns number of survivors. */
static long long dfa_group(const gpair_t *P, int n, int g, int v, int model, long long node_cap, gres_t *res) {
    static __thread gctx_t c;   /* large; one per thread */
    c.P = P; c.n = n; c.v = v; c.model = model; c.node_cap = node_cap; c.res = res;
    c.rX = ROT[2 * g]; c.rY = ROT[2 * g + 1];
    for (int t = 0; t < 4; t++) {
        c.mX[t] = c.mY[t] = 0; c.cX[t] = c.cY[t] = 0;
        for (int q = 0; q < 4; q++) {
            int bx = (4 * t + q + c.rX) & 15, by = (4 * t + q + c.rY) & 15;
            c.mX[t] |= (uint16_t)(1u << bx); c.mY[t] |= (uint16_t)(1u << by);
            if (bx > c.cX[t]) c.cX[t] = bx;
            if (by > c.cY[t]) c.cY[t] = by;
        }
    }
    for (int j = 0; j < n; j++) { c.X1[0][j] = c.X1f[0][j] = 0; c.b[0][j] = c.bf[0][j] = 0; }
    for (int i = 0; i < 16; i++) c.level_cnt[i] = 0;
    res->leaves = res->nodes = 0; res->capped = 0; res->level_max = 0;
    gdfs(&c, 0, 0, 0);
    for (int i = 0; i < 16; i++) if (c.level_cnt[i] > res->level_max) res->level_max = c.level_cnt[i];
    return res->leaves;
}

/* Split a known pair (w, w') into its group; returns -1 if both groups are active
 * (impossible for a single-word fault: this happens only under a wrong earlier key). */
static inline int to_gpair(uint64_t w, uint64_t wf, gpair_t *gp) {
    uint64_t u = perm_inv(w), uf = perm_inv(wf), d = u ^ uf;
    int hi = (d >> 32) != 0, lo = (uint32_t)d != 0;
    if (hi && lo) return -1;
    int g = hi ? 0 : 1;
    int sx = g == 0 ? 48 : 16, sy = g == 0 ? 32 : 0;
    gp->x = (uint16_t)(u >> sx); gp->xf = (uint16_t)(uf >> sx);
    gp->y = (uint16_t)(u >> sy); gp->yf = (uint16_t)(uf >> sy);
    return g;
}
/* kappa words -> round key */
static inline uint64_t kappa_to_rk(uint32_t g0, uint32_t g1) {
    return perm((uint64_t)g0 << 32 | g1);
}
#endif
