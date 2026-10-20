/*
 * Dipper round function with a selectable mixing layer.
 *
 *   V_DIPPER : A2 = A1 + B1, C2 = C1 + D1 (mod 2^16)  -- the real cipher
 *   V_XOR    : A2 = A1 ^ B1, C2 = C1 ^ D1             -- analysis-only variant
 *   V_NONE   : A2 = A1,      C2 = C1                  -- analysis-only variant
 *
 * The xor and none variants exist only to measure the effect of the modular
 * addition on the fault attack. They are NOT proposed as ciphers.
 *
 * Round i: s ^= rk[i]; s = S(s); rotations; mix; s = P(s).
 * Key schedules are taken unchanged from ref/dipper.c.
 */
#ifndef DFA_CIPHER_H
#define DFA_CIPHER_H
#include <stdint.h>

#define ROUNDS 28
enum { V_DIPPER = 0, V_XOR = 1, V_NONE = 2 };
static const char *const VARIANT_NAME[3] = {"dipper", "xor", "none"};

static const uint8_t SB[16]  = {0x1,0xA,0x4,0xC,0x6,0xF,0x3,0x9,0x2,0xD,0xB,0x7,0x5,0x0,0x8,0xE};
static const uint8_t SBI[16] = {0xD,0x0,0x8,0x6,0x2,0xC,0x4,0xB,0xE,0x7,0x1,0xA,0x3,0x9,0xF,0x5};

/* rotation amounts of words A,B,C,D (A = bits 63..48) */
static const int ROT[4] = {1, 4, 7, 11};

/* bit permutation (GIFT-64), same formula as ref/dipper.c */
static uint8_t PB[64], PBI[64];
static uint64_t PT[8][256], PTI[8][256];
static uint16_t ST[65536], STI[65536];

static inline uint16_t rotl16(uint16_t x, int r) { r &= 15; return (uint16_t)((x << r) | (x >> ((16 - r) & 15))); }
static inline uint16_t rotr16(uint16_t x, int r) { r &= 15; return (uint16_t)((x >> r) | (x << ((16 - r) & 15))); }

static void cipher_init(void) {
    static int ready = 0;
    if (ready) return;
    for (int i = 0; i < 64; i++) {
        int p = 4 * (i / 16) + 16 * ((3 * ((i % 16) / 4) + (i % 4)) % 4) + (i % 4);
        PB[i] = (uint8_t)p; PBI[p] = (uint8_t)i;
    }
    for (int b = 0; b < 8; b++)
        for (int v = 0; v < 256; v++) {
            uint64_t o = 0, oi = 0;
            for (int t = 0; t < 8; t++)
                if ((v >> t) & 1) { o |= 1ULL << PB[8 * b + t]; oi |= 1ULL << PBI[8 * b + t]; }
            PT[b][v] = o; PTI[b][v] = oi;
        }
    for (int v = 0; v < 65536; v++) {
        uint16_t o = 0, oi = 0;
        for (int j = 0; j < 4; j++) {
            o  |= (uint16_t)(SB[(v >> (4 * j)) & 0xF]  << (4 * j));
            oi |= (uint16_t)(SBI[(v >> (4 * j)) & 0xF] << (4 * j));
        }
        ST[v] = o; STI[v] = oi;
    }
    ready = 1;
}

static inline uint64_t perm(uint64_t s) {
    uint64_t o = 0;
    for (int b = 0; b < 8; b++) o |= PT[b][(s >> (8 * b)) & 0xFF];
    return o;
}
static inline uint64_t perm_inv(uint64_t s) {
    uint64_t o = 0;
    for (int b = 0; b < 8; b++) o |= PTI[b][(s >> (8 * b)) & 0xFF];
    return o;
}
static inline uint64_t sub(uint64_t s) {
    return (uint64_t)ST[s & 0xFFFF] | (uint64_t)ST[(s >> 16) & 0xFFFF] << 16 |
           (uint64_t)ST[(s >> 32) & 0xFFFF] << 32 | (uint64_t)ST[s >> 48] << 48;
}
static inline uint64_t sub_inv(uint64_t s) {
    return (uint64_t)STI[s & 0xFFFF] | (uint64_t)STI[(s >> 16) & 0xFFFF] << 16 |
           (uint64_t)STI[(s >> 32) & 0xFFFF] << 32 | (uint64_t)STI[s >> 48] << 48;
}

static inline uint16_t mixop(uint16_t x, uint16_t y, int v) {
    return v == V_DIPPER ? (uint16_t)(x + y) : v == V_XOR ? (uint16_t)(x ^ y) : x;
}
static inline uint16_t mixop_inv(uint16_t x, uint16_t y, int v) {
    return v == V_DIPPER ? (uint16_t)(x - y) : v == V_XOR ? (uint16_t)(x ^ y) : x;
}

/* rotations + mixing, on the S-box output */
static inline uint64_t arx(uint64_t s, int v) {
    uint16_t A = rotl16((uint16_t)(s >> 48), ROT[0]), B = rotl16((uint16_t)(s >> 32), ROT[1]);
    uint16_t C = rotl16((uint16_t)(s >> 16), ROT[2]), D = rotl16((uint16_t)s, ROT[3]);
    return (uint64_t)mixop(A, B, v) << 48 | (uint64_t)B << 32 | (uint64_t)mixop(C, D, v) << 16 | D;
}
static inline uint64_t arx_inv(uint64_t s, int v) {
    uint16_t A2 = (uint16_t)(s >> 48), B1 = (uint16_t)(s >> 32), C2 = (uint16_t)(s >> 16), D1 = (uint16_t)s;
    uint16_t A = rotr16(mixop_inv(A2, B1, v), ROT[0]), B = rotr16(B1, ROT[1]);
    uint16_t C = rotr16(mixop_inv(C2, D1, v), ROT[2]), D = rotr16(D1, ROT[3]);
    return (uint64_t)A << 48 | (uint64_t)B << 32 | (uint64_t)C << 16 | D;
}

/* keyless round part F = P o ARX o S and its inverse */
static inline uint64_t Fwd(uint64_t s, int v) { return perm(arx(sub(s), v)); }
static inline uint64_t Finv(uint64_t s, int v) { return sub_inv(arx_inv(perm_inv(s), v)); }

/* Encrypt; if fround >= 0, XOR fmask into the S-box input of round fround. */
static inline uint64_t encrypt_fault(uint64_t p, const uint64_t rk[ROUNDS], int v, int fround, uint64_t fmask) {
    uint64_t s = p;
    for (int i = 0; i < ROUNDS; i++) {
        s ^= rk[i];
        if (i == fround) s ^= fmask;
        s = Fwd(s, v);
    }
    return s;
}
static inline uint64_t encrypt_v(uint64_t p, const uint64_t rk[ROUNDS], int v) {
    return encrypt_fault(p, rk, v, -1, 0);
}
static inline uint64_t decrypt_v(uint64_t c, const uint64_t rk[ROUNDS], int v) {
    uint64_t s = c;
    for (int i = ROUNDS - 1; i >= 0; i--) s = Finv(s, v) ^ rk[i];
    return s;
}

/* splitmix64: fixed-seed RNG used everywhere */
static inline uint64_t sm64(uint64_t *x) {
    uint64_t z = (*x += 0x9E3779B97F4A7C15ULL);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
    return z ^ (z >> 31);
}
#endif
