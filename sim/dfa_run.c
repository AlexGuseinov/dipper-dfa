/*
 * dfa attack <variant> <ks96|ks128A|ks128B> <M1|M2|M3> <near|deep> <trials> <seed> <floor> <theta> <node_cap> <threads> [maxfaults]
 *   full key recovery, one JSON line per trial on stdout.
 *   ks128A: rk25 from faults at round 24; ks128B: only rk27, rk26, then a 2^32
 *   search per surviving tuple (cost counted here, run by `dfa brute128`).
 *
 * dfa explore: one-stage attack with full logging (earlier round keys taken
 * as known and correct). Used to check the attack on a few keys.
 *
 *   bin/dfa explore <variant> <ks96|ks128> <M1|M2|M3> <fault_round> <trials> <faults> <seed> [node_cap]
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../sim/fault.h"
#include "../ref/ks_inv.h"
#include "../attack/chain.h"
#include <pthread.h>

void dipper_expand_96(const uint16_t k[6], uint64_t rk[28]);
void dipper_expand_128(const uint16_t k[8], uint64_t rk[28]);

static int parse_variant(const char *s) { for (int v = 0; v < 3; v++) if (!strcmp(s, VARIANT_NAME[v])) return v; exit(2); }
static int parse_model(const char *s) { return s[1] - '0'; }

static void random_key(int ks, uint64_t *rng, uint16_t k[8], uint64_t rk[28]) {
    for (int j = 0; j < 8; j++) k[j] = (uint16_t)sm64(rng);
    if (ks == 96) { k[6] = k[7] = 0; dipper_expand_96(k, rk); } else dipper_expand_128(k, rk);
}

static int explore(int argc, char **argv) {
    if (argc < 9) return 2;
    int v = parse_variant(argv[2]), ks = atoi(argv[3] + 2), model = parse_model(argv[4]);
    int fr = atoi(argv[5]), trials = atoi(argv[6]), nf = atoi(argv[7]);
    uint64_t seed = strtoull(argv[8], 0, 0), rng = seed;
    long long cap = argc > 9 ? atoll(argv[9]) : 400000000LL;
    int T = fr + 1;
    printf("# explore variant=%s ks=%d model=M%d fault_round=%d target=rk%d seed=0x%llX node_cap=%lld\n",
           VARIANT_NAME[v], ks, model, fr, T, (unsigned long long)seed, cap);
    static gpair_t gp[2][DFA_MAXP];
    gres_t res; uint32_t *cbuf = malloc(sizeof(uint32_t) << 20);
    for (int t = 0; t < trials; t++) {
        uint16_t k[8]; uint64_t rk[28];
        random_key(ks, &rng, k, rk);
        uint64_t kap = perm_inv(rk[T]);
        uint32_t truek[2] = {(uint32_t)(kap >> 32), (uint32_t)kap};
        int n[2] = {0, 0};
        long long cnt[2] = {1LL << 32, 1LL << 32};
        printf("trial %d rk%d=%016llX\n", t, T, (unsigned long long)rk[T]);
        for (int f = 0; f < nf; f++) {
            uint64_t p = sm64(&rng), m = fault_mask(model, &rng);
            uint64_t c = encrypt_v(p, rk, v), cf = encrypt_fault(p, rk, v, fr, m);
            uint64_t w = peel(c, rk, T, v), wf = peel(cf, rk, T, v);
            gpair_t g1; int g = to_gpair(w, wf, &g1);
            if (g < 0) { printf("  fault %2d mask=%016llX BOTH GROUPS ACTIVE\n", f + 1, (unsigned long long)m); continue; }
            gp[g][n[g]++] = g1;
            res.cand = cbuf; res.cand_cap = 1 << 20;
            dfa_group(gp[g], n[g], g, v, model, cap, &res);
            cnt[g] = res.leaves;
            int in = 0;
            long long lim = res.leaves < res.cand_cap ? res.leaves : res.cand_cap;
            for (long long q = 0; q < lim; q++) if (cbuf[q] == truek[g]) in = 1;
            printf("  fault %2d mask=%016llX g=%d n=(%d,%d) cnt=(%lld%s,%lld) nodes=%lld lvlmax=%lld true_in=%d",
                   f + 1, (unsigned long long)m, g, n[0], n[1], cnt[0], res.capped && g == 0 ? "+" : "", cnt[1],
                   res.nodes, res.level_max, res.leaves > res.cand_cap ? -1 : in);
            if (res.leaves <= 8 && !res.capped) { printf(" cands:"); for (long long q = 0; q < res.leaves; q++) printf(" %08X", cbuf[q]); }
            printf("\n");
        }
        printf("  true kappa groups: %08X %08X\n", truek[0], truek[1]);
    }
    return 0;
}

/* direct fault-model check on the full state, independent of the DFS code */
static int direct_ok(uint64_t d, int model) {
    if (!d) return 0;
    if (model == M2) return __builtin_popcountll(d) == 1;
    unsigned act = 0;
    for (int t = 0; t < 16; t++) if ((d >> (4 * t)) & 0xF) act |= 1u << t;
    if (model == M1) return (act & (act - 1)) == 0;
    for (int b = 0; b < 8; b++) if ((act & ~(3u << (2 * b))) == 0) return 1;
    return 0;
}
static int cmp32(const void *a, const void *b) { uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b; return x < y ? -1 : x > y; }

/* dfa verify <variant> <M1|M2|M3> <fault_round> <npairs_per_group> <trials> <seed> <random_guesses>
 * Near filter only. For each group: (a) every DFS survivor passes the direct check,
 * (b) random guesses (other group = true key): direct pass <=> DFS survivor. */
static int verify(int argc, char **argv) {
    if (argc < 9) return 2;
    int v = parse_variant(argv[2]), model = parse_model(argv[3]), fr = atoi(argv[4]), np = atoi(argv[5]), trials = atoi(argv[6]);
    uint64_t seed = strtoull(argv[7], 0, 0), rng = seed; long R = atol(argv[8]);
    int T = fr + 1;
    long long cap = 1LL << 28; long long ccap = 1LL << 24;
    uint32_t *cbuf = malloc(sizeof(uint32_t) * ccap);
    static gpair_t gp[2][DFA_MAXP]; static uint64_t W[2][DFA_MAXP][2];
    long bad_a = 0, bad_b = 0, checked_a = 0, checked_b = 0, passed_b = 0, capped = 0;
    printf("# verify variant=%s model=M%d fault_round=%d pairs/group=%d trials=%d seed=0x%llX guesses=%ld\n",
           VARIANT_NAME[v], model, fr, np, trials, (unsigned long long)seed, R);
    for (int t = 0; t < trials; t++) {
        uint16_t k[8]; uint64_t rk[28];
        random_key(96, &rng, k, rk);
        int n[2] = {0, 0};
        while (n[0] < np || n[1] < np) {
            uint64_t p = sm64(&rng), m = fault_mask(model, &rng);
            uint64_t w = peel(encrypt_v(p, rk, v), rk, T, v), wf = peel(encrypt_fault(p, rk, v, fr, m), rk, T, v);
            gpair_t g1; int g = to_gpair(w, wf, &g1);
            if (g < 0 || n[g] >= np) continue;
            W[g][n[g]][0] = w; W[g][n[g]][1] = wf; gp[g][n[g]++] = g1;
        }
        uint64_t kap = perm_inv(rk[T]);
        for (int g = 0; g < 2; g++) {
            gres_t res; res.cand = cbuf; res.cand_cap = ccap;
            dfa_group(gp[g], np, g, v, model, cap, &res);
            int full = !res.capped && res.leaves <= ccap;
            if (!full) capped++;
            long long L = full ? res.leaves : 0;
            if (full) qsort(cbuf, (size_t)L, sizeof(uint32_t), cmp32);
            /* (a) */
            for (long long q = 0; q < L; q++) {
                uint64_t kk = g == 0 ? ((uint64_t)cbuf[q] << 32 | (uint32_t)kap) : ((kap & 0xFFFFFFFF00000000ULL) | cbuf[q]);
                uint64_t K = perm(kk); int ok = 1;
                for (int j = 0; j < np && ok; j++) ok = direct_ok(Finv(W[g][j][0] ^ K, v) ^ Finv(W[g][j][1] ^ K, v), model);
                checked_a++; if (!ok) bad_a++;
            }
            /* (b) */
            for (long r = 0; r < R; r++) {
                uint32_t gk = (uint32_t)sm64(&rng);
                uint64_t kk = g == 0 ? ((uint64_t)gk << 32 | (uint32_t)kap) : ((kap & 0xFFFFFFFF00000000ULL) | gk);
                uint64_t K = perm(kk); int ok = 1;
                for (int j = 0; j < np && ok; j++) ok = direct_ok(Finv(W[g][j][0] ^ K, v) ^ Finv(W[g][j][1] ^ K, v), model);
                passed_b += ok; checked_b++;
                if (full) { int in = bsearch(&gk, cbuf, (size_t)L, sizeof(uint32_t), cmp32) != 0; if (in != ok) bad_b++; }
            }
        }
    }
    printf("(a) DFS survivors checked %ld, failing direct check %ld\n", checked_a, bad_a);
    printf("(b) random guesses %ld, passing direct check %ld (%.6f), disagreements with DFS %ld\n", checked_b, passed_b, (double)passed_b / checked_b, bad_b);
    printf("groups where DFS hit the cap (not compared in (b)): %ld of %d\n", capped, 2 * trials);
    return bad_a || bad_b;
}

typedef struct {
    attack_cfg_t cfg;
    int ks, opt, trials;
    uint64_t seed;
    int next; pthread_mutex_t mu;
} job_t;

static void one_trial(job_t *J, int t, FILE *o) {
    const attack_cfg_t *C = &J->cfg;
    uint64_t rng = J->seed ^ (0xD1B54A32D192ED03ULL * (uint64_t)(t + 1));
    sm64(&rng);
    uint16_t k[8]; uint64_t rk[28];
    random_key(J->ks, &rng, k, rk);
    int nst = J->ks == 96 ? 2 : (J->opt == 'A' ? 3 : 2);
    static __thread prefix_t *A, *B;
    if (!A) { A = calloc(MAXPREF, sizeof(prefix_t)); B = calloc(MAXPREF, sizeof(prefix_t)); }
    int na = 1; memset(A[0].rk, 0, sizeof(A[0].rk)); A[0].alive = 1;
    static __thread stage_t st[3];
    int ok = 1, s;
    double t0 = tcpu();
    for (s = 0; s < nst && ok; s++) {
        int nb;
        ok = run_stage(C, 27 - s, rk, &rng, A, na, B, &nb, &st[s]);
        prefix_t *tmp = A; A = B; B = tmp; na = nb;
    }
    /* master-key candidates, checked against one known plaintext/ciphertext pair */
    uint64_t p0 = sm64(&rng), c0 = encrypt_v(p0, rk, C->v);
    long long masters = 0, match = 0; int true_match = 0;
    if (ok && !(J->ks == 128 && J->opt == 'B')) {
        for (int q = 0; q < na; q++) {
            uint16_t m[8] = {0}; uint64_t rr[28];
            if (J->ks == 96) { ks96_master_from_rk(A[q].rk[26], A[q].rk[27], m); dipper_expand_96(m, rr); }
            else { ks128_master_from_rk(A[q].rk[25], A[q].rk[26], A[q].rk[27], m); dipper_expand_128(m, rr); }
            masters++;
            if (encrypt_v(p0, rr, C->v) == c0) {
                match++;
                int same = 1; for (int j = 0; j < (J->ks == 96 ? 6 : 8); j++) same &= m[j] == k[j];
                true_match |= same;
            }
        }
    }
    int true_tuple = 0;   /* 128B: is (rk26, rk27) true among the final tuples */
    if (ok && J->ks == 128 && J->opt == 'B')
        for (int q = 0; q < na; q++) true_tuple |= A[q].rk[26] == rk[26] && A[q].rk[27] == rk[27];
    double cpu = tcpu() - t0;
    int total = 0; for (int i = 0; i < s; i++) total += st[i].faults;
    pthread_mutex_lock(&J->mu);
    fprintf(o, "{\"trial\":%d,\"variant\":\"%s\",\"ks\":%d,\"opt\":\"%c\",\"model\":%d,\"mode\":\"%s\",\"seed\":\"0x%llX\",\"floor\":%d,\"theta\":%g,\"node_cap\":%lld,"
               "\"ok\":%d,\"total_faults\":%d,\"tuples_final\":%d,\"masters\":%lld,\"pc_match\":%lld,\"success\":%d,\"true_tuple\":%d,\"cpu\":%.4f,\"stages\":[",
            t, VARIANT_NAME[C->v], J->ks, J->opt ? J->opt : '-', C->model, C->deep ? "deep" : "near", (unsigned long long)J->seed, C->floor_, C->theta, C->cap,
            ok, total, na, masters, match, true_match && match == 1, true_tuple, cpu);
    for (int i = 0; i < s; i++) {
        stage_t *S = &st[i];
        fprintf(o, "%s{\"target\":%d,\"fault_round\":%d,\"faults\":%d,\"faults_g\":[%d,%d],\"reached\":%d,\"prefixes_in\":%d,\"live_end\":%d,\"cands_out\":%lld,"
                   "\"true_kept\":%d,\"nodes\":%lld,\"level_max\":%lld,\"cpu\":%.4f,\"log2_surv\":[",
                i ? "," : "", 27 - i, 27 - i - (C->deep ? 2 : 1), S->faults, S->faults_g[0], S->faults_g[1], S->reached, S->prefixes_in, S->live_end,
                S->cands_out, S->true_kept, S->nodes, S->level_max, S->cpu);
        int nf = S->faults < MAXFAULTS ? S->faults : MAXFAULTS;
        for (int f = 0; f < nf; f++) fprintf(o, "%s%.3f", f ? "," : "", S->log2_after[f]);
        fprintf(o, "],\"capped\":[");   /* 1 = value is a lower bound (node cap hit) */
        for (int f = 0; f < nf; f++) fprintf(o, "%s%d", f ? "," : "", S->capped_after[f]);
        fprintf(o, "]}");
    }
    fprintf(o, "]}\n"); fflush(o);
    pthread_mutex_unlock(&J->mu);
}

static void *worker(void *arg) {
    job_t *J = arg;
    for (;;) {
        pthread_mutex_lock(&J->mu); int t = J->next++; pthread_mutex_unlock(&J->mu);
        if (t >= J->trials) break;
        one_trial(J, t, stdout);
    }
    return 0;
}

/* dfa attack <variant> <ks96|ks128A|ks128B> <M1|M2|M3> <near|deep> <trials> <seed> <floor> <theta> <node_cap> <threads> [maxfaults] */
static int attack(int argc, char **argv) {
    if (argc < 12) { fprintf(stderr, "attack: bad args\n"); return 2; }
    static job_t J; static hyp_t H;
    memset(&J, 0, sizeof(J));
    J.cfg.v = parse_variant(argv[2]);
    J.ks = atoi(argv[3] + 2); J.opt = J.ks == 128 ? argv[3][5] : 0;
    J.cfg.model = parse_model(argv[4]);
    J.cfg.deep = !strcmp(argv[5], "deep");
    J.trials = atoi(argv[6]); J.seed = strtoull(argv[7], 0, 0);
    J.cfg.floor_ = atoi(argv[8]); J.cfg.theta = atof(argv[9]); J.cfg.cap = atoll(argv[10]);
    int th = atoi(argv[11]); J.cfg.maxfaults = argc > 12 ? atoi(argv[12]) : 1000;
    if (J.cfg.maxfaults > MAXFAULTS) J.cfg.maxfaults = MAXFAULTS;
    if (J.cfg.deep) {
        if (J.cfg.v == V_DIPPER) { fprintf(stderr, "deep filter needs a linear mixing layer (xor/none)\n"); return 2; }
        build_hyp(&H, J.cfg.v, J.cfg.model); J.cfg.H = &H;
    }
    pthread_mutex_init(&J.mu, 0);
    pthread_t tid[64];
    for (int i = 0; i < th; i++) pthread_create(&tid[i], 0, worker, &J);
    for (int i = 0; i < th; i++) pthread_join(tid[i], 0);
    return 0;
}

int main(int argc, char **argv) {
    cipher_init();
    if (argc > 1 && !strcmp(argv[1], "explore")) return explore(argc, argv);
    if (argc > 1 && !strcmp(argv[1], "attack")) return attack(argc, argv);
    if (argc > 1 && !strcmp(argv[1], "verify")) return verify(argc, argv);
    fprintf(stderr, "usage: see header\n");
    return 2;
}
