/*
 * Two-round-deep DFA filter, used for the analysis-only variants xor / none
 * (whose mixing layer is linear).
 *
 * Fault at the S-box input of round T-2, target K = rk_T, known w = y_T.
 * For a linear mixing layer the difference entering round T-1 is
 *     Delta y_{T-1} = P(ARX(dS))       (rk_{T-1} cancels)
 * where dS is the S-box output difference of the faulted nibble(s). Each
 * possible dS gives one "hypothesis" h with an exact required difference
 * req[h] on all 16 nibbles of y_{T-1}. A key guess survives a fault pair if at
 * least one hypothesis matches all nibbles it computes.
 *
 * The guess runs per group (kX,kY) bit by bit as in dfa.h; every pair carries
 * the set of hypotheses still possible (bitset), cut down each time one of its
 * y_{T-1} nibbles becomes complete. Groups are filtered independently; this is
 * a relaxation (a hypothesis may be used differently in the two groups), so
 * the true key always survives and a final joint check is done in chain.h.
 */
#ifndef DFA_DEEP_H
#define DFA_DEEP_H
#include "dfa.h"

#define HW 32                       /* up to 2048 hypotheses */
typedef struct { uint64_t w[HW]; } hset_t;

typedef struct {
    int nh, nw;
    uint64_t req[2048];
    hset_t M[16][16];               /* M[nibble][delta] = hypotheses with req nibble == delta */
} hyp_t;

/* all S-box output differences reachable from the fault model, mapped through P o ARX */
static void build_hyp(hyp_t *H, int v, int model) {
    static uint64_t seen_tmp[2048];
    int nh = 0;
    for (int pos = 0; pos < (model == M3 ? 8 : 16); pos++) {
        if (model == M1 || model == M2) {
            int outs[16] = {0};
            for (int e = 1; e < 16; e++) {
                if (model == M2 && __builtin_popcount(e) != 1) continue;
                for (int x = 0; x < 16; x++) outs[SB[x] ^ SB[x ^ e]] = 1;
            }
            for (int d = 1; d < 16; d++) if (outs[d]) seen_tmp[nh++] = perm(arx((uint64_t)d << (4 * pos), v));
        } else {
            for (int d = 1; d < 256; d++) seen_tmp[nh++] = perm(arx((uint64_t)d << (8 * pos), v));
        }
    }
    H->nh = nh; H->nw = (nh + 63) / 64;
    memcpy(H->req, seen_tmp, sizeof(uint64_t) * nh);
    memset(H->M, 0, sizeof(H->M));
    for (int h = 0; h < nh; h++)
        for (int t = 0; t < 16; t++) {
            int d = (H->req[h] >> (4 * t)) & 0xF;
            H->M[t][d].w[h >> 6] |= 1ULL << (h & 63);
        }
}

typedef struct {
    const gpair_t *P; int n, g, v, rX, rY, nw;
    const hyp_t *H;
    uint16_t mX[4], mY[4]; int cX[4], cY[4];
    hset_t S[17][DFA_MAXP];
    long long node_cap, level_cnt[16];
    gres_t *res;
} dctx_t;

static inline int hand(hset_t *dst, const hset_t *a, const hset_t *b, int nw) {
    uint64_t any = 0;
    for (int k = 0; k < nw; k++) { dst->w[k] = a->w[k] & b->w[k]; any |= dst->w[k]; }
    return any != 0;
}

static void ddfs(dctx_t *c, int i, uint16_t kx, uint16_t ky) {
    gres_t *r = c->res;
    if (r->capped) return;
    for (int g = 0; g < 4; g++) {
        uint16_t kxi = (uint16_t)(kx | ((g & 1) << i)), kyi = (uint16_t)(ky | ((g >> 1) << i));
        if (++r->nodes > c->node_cap) { r->capped = 1; return; }
        int ok = 1;
        for (int j = 0; j < c->n && ok; j++) {
            const gpair_t *p = &c->P[j];
            hset_t cur = c->S[i][j];
            uint16_t Y1 = (uint16_t)(p->y ^ kyi), Y1f = (uint16_t)(p->yf ^ kyi);
            uint16_t X2 = (uint16_t)(p->x ^ kxi), X2f = (uint16_t)(p->xf ^ kxi);
            uint16_t X1 = mixop_inv(X2, Y1, c->v), X1f = mixop_inv(X2f, Y1f, c->v);
            for (int t = 0; t < 4 && ok; t++) {
                if (c->cX[t] == i) {
                    int a = (rotr16(X1, c->rX) >> (4 * t)) & 0xF, af = (rotr16(X1f, c->rX) >> (4 * t)) & 0xF;
                    int gn = 4 * (3 - 2 * c->g) + t;
                    ok = hand(&cur, &cur, &c->H->M[gn][SBI[a] ^ SBI[af]], c->nw);
                }
                if (ok && c->cY[t] == i) {
                    int a = (rotr16(Y1, c->rY) >> (4 * t)) & 0xF, af = (rotr16(Y1f, c->rY) >> (4 * t)) & 0xF;
                    int gn = 4 * (2 - 2 * c->g) + t;
                    ok = hand(&cur, &cur, &c->H->M[gn][SBI[a] ^ SBI[af]], c->nw);
                }
            }
            c->S[i + 1][j] = cur;
        }
        if (!ok) continue;
        c->level_cnt[i]++;
        if (i == 15) {
            if (r->leaves < r->cand_cap && r->cand) r->cand[r->leaves] = (uint32_t)kxi << 16 | kyi;
            r->leaves++;
        } else ddfs(c, i + 1, kxi, kyi);
    }
}

/* Only valid for V_XOR and V_NONE (no carries: bit i of X1 needs only bit i of the key). */
static long long dfa_group_deep(const gpair_t *P, int n, int g, int v, const hyp_t *H, long long node_cap, gres_t *res) {
    static __thread dctx_t *c;
    if (!c) c = malloc(sizeof(dctx_t));
    c->P = P; c->n = n; c->g = g; c->v = v; c->H = H; c->nw = H->nw; c->node_cap = node_cap; c->res = res;
    c->rX = ROT[2 * g]; c->rY = ROT[2 * g + 1];
    for (int t = 0; t < 4; t++) {
        c->cX[t] = c->cY[t] = 0;
        for (int q = 0; q < 4; q++) {
            int bx = (4 * t + q + c->rX) & 15, by = (4 * t + q + c->rY) & 15;
            if (bx > c->cX[t]) c->cX[t] = bx;
            if (by > c->cY[t]) c->cY[t] = by;
        }
    }
    for (int j = 0; j < n; j++) { memset(&c->S[0][j], 0, sizeof(hset_t)); for (int k = 0; k < H->nw; k++) c->S[0][j].w[k] = ~0ULL; }
    for (int i = 0; i < 16; i++) c->level_cnt[i] = 0;
    res->leaves = res->nodes = 0; res->capped = 0; res->level_max = 0;
    ddfs(c, 0, 0, 0);
    for (int i = 0; i < 16; i++) if (c->level_cnt[i] > res->level_max) res->level_max = c->level_cnt[i];
    return res->leaves;
}

/* both group parts of a pair (no group selection: a 2-round fault reaches both) */
static inline void to_gpair_both(uint64_t w, uint64_t wf, gpair_t gp[2]) {
    uint64_t u = perm_inv(w), uf = perm_inv(wf);
    for (int g = 0; g < 2; g++) {
        int sx = g == 0 ? 48 : 16, sy = g == 0 ? 32 : 0;
        gp[g].x = (uint16_t)(u >> sx); gp[g].xf = (uint16_t)(uf >> sx);
        gp[g].y = (uint16_t)(u >> sy); gp[g].yf = (uint16_t)(uf >> sy);
    }
}
#endif
