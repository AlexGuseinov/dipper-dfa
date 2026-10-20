/*
 * Dipper key-schedule inversion (written for this project; not part of the
 * Dipper repository). Uses the same update rule as ref/dipper.c.
 *
 * State convention: K[0..5] (96) / K[0..7] (128), round key rk_i =
 * K3||K2||K1||K0 taken from the state after i updates.
 */
#ifndef DFA_KS_INV_H
#define DFA_KS_INV_H
#include <stdint.h>
#include <string.h>

#define KS_ROUNDS 28
static const uint8_t KS_S[16]  = {0x1,0xA,0x4,0xC,0x6,0xF,0x3,0x9,0x2,0xD,0xB,0x7,0x5,0x0,0x8,0xE};
static const uint8_t KS_SI[16] = {0xD,0x0,0x8,0x6,0x2,0xC,0x4,0xB,0xE,0x7,0x1,0xA,0x3,0x9,0xF,0x5};

static inline uint16_t ks_rotr(uint16_t x, int r) { return (uint16_t)((x >> r) | (x << (16 - r))); }
static inline uint16_t ks_rotl(uint16_t x, int r) { return (uint16_t)((x << r) | (x >> (16 - r))); }
static inline uint16_t s_top(uint16_t x, const uint8_t *t)  { return (uint16_t)((x & 0x0FFF) | (t[(x >> 12) & 0xF] << 12)); }
static inline uint16_t s_7_4(uint16_t x, const uint8_t *t)  { return (uint16_t)((x & 0xFF0F) | (t[(x >> 4) & 0xF] << 4)); }

static inline uint8_t ks_lfsr(int i) { /* round constant used in update i */
    uint8_t l = 1;
    for (int t = 0; t < i; t++) l = (uint8_t)(((l << 1) | (((l >> 4) ^ (l >> 1)) & 1)) & 0x1F);
    return l;
}

/* forward updates (copies of the rule in ref/dipper.c) */
static inline void ks_update_96(uint16_t K[6], uint8_t rc) {
    uint16_t t1 = ks_rotr(K[1], 2), t0 = ks_rotr(K[0], 12);
    uint16_t n5 = K[3], n4 = K[2], n3 = t1, n2 = t0, n1 = K[5], n0 = K[4];
    K[5] = s_top(n5, KS_S); K[4] = s_7_4(n4, KS_S); K[3] = (uint16_t)(n3 ^ rc);
    K[2] = s_top(n2, KS_S); K[1] = s_7_4(n1, KS_S); K[0] = n0;
}
static inline void ks_update_128(uint16_t K[8], uint8_t rc) {
    uint16_t t1 = ks_rotr(K[1], 2), t0 = ks_rotr(K[0], 12);
    uint16_t n7 = K[3], n6 = K[2], n5 = K[7], n4 = K[6], n3 = K[5], n2 = K[4], n1 = t1, n0 = t0;
    K[7] = s_top(n7, KS_S); K[6] = n6; K[5] = n5; K[4] = (uint16_t)(n4 ^ rc);
    K[3] = s_top(n3, KS_S); K[2] = n2; K[1] = s_top(n1, KS_S); K[0] = n0;
}
/* inverse updates */
static inline void ks_invupdate_96(uint16_t K[6], uint8_t rc) {
    uint16_t o[6];
    o[4] = K[0];
    o[5] = s_7_4(K[1], KS_SI);
    o[0] = ks_rotl(s_top(K[2], KS_SI), 12);
    o[1] = ks_rotl((uint16_t)(K[3] ^ rc), 2);
    o[2] = s_7_4(K[4], KS_SI);
    o[3] = s_top(K[5], KS_SI);
    memcpy(K, o, sizeof(o));
}
static inline void ks_invupdate_128(uint16_t K[8], uint8_t rc) {
    uint16_t o[8];
    o[0] = ks_rotl(K[0], 12);
    o[1] = ks_rotl(s_top(K[1], KS_SI), 2);
    o[4] = K[2];
    o[5] = s_top(K[3], KS_SI);
    o[6] = (uint16_t)(K[4] ^ rc);
    o[7] = K[5];
    o[2] = K[6];
    o[3] = s_top(K[7], KS_SI);
    memcpy(K, o, sizeof(o));
}

static inline void words4(uint64_t rk, uint16_t w[4]) {
    for (int j = 0; j < 4; j++) w[j] = (uint16_t)(rk >> (16 * j));
}

/* 64/96: key state at round 26 from rk26, rk27 (fact 2), then back to master key */
static inline void ks96_master_from_rk(uint64_t rk26, uint64_t rk27, uint16_t master[6]) {
    uint16_t a[4], b[4], K[6];
    words4(rk26, a); words4(rk27, b);
    K[0] = a[0]; K[1] = a[1]; K[2] = a[2]; K[3] = a[3];
    K[4] = b[0]; K[5] = s_7_4(b[1], KS_SI);
    for (int i = 25; i >= 0; i--) ks_invupdate_96(K, ks_lfsr(i));
    memcpy(master, K, sizeof(K));
}
/* 64/128: state at round 26 from rk25, rk26, rk27 */
static inline void ks128_master_from_rk(uint64_t rk25, uint64_t rk26, uint64_t rk27, uint16_t master[8]) {
    uint16_t a[4], b[4], c[4], K[8];
    words4(rk26, a); words4(rk27, b); words4(rk25, c);
    K[0] = a[0]; K[1] = a[1]; K[2] = a[2]; K[3] = a[3];
    K[4] = b[2]; K[5] = s_top(b[3], KS_SI);
    K[6] = c[2]; K[7] = s_top(c[3], KS_S);
    for (int i = 25; i >= 0; i--) ks_invupdate_128(K, ks_lfsr(i));
    memcpy(master, K, sizeof(K));
}
/* 64/128 with only rk26, rk27: the free 32 bits are K6||K7 of the round-26 state */
static inline void ks128_master_from_rk_k67(uint64_t rk26, uint64_t rk27, uint16_t k6, uint16_t k7, uint16_t master[8]) {
    uint16_t a[4], b[4], K[8];
    words4(rk26, a); words4(rk27, b);
    K[0] = a[0]; K[1] = a[1]; K[2] = a[2]; K[3] = a[3];
    K[4] = b[2]; K[5] = s_top(b[3], KS_SI); K[6] = k6; K[7] = k7;
    for (int i = 25; i >= 0; i--) ks_invupdate_128(K, ks_lfsr(i));
    memcpy(master, K, sizeof(K));
}
#endif
