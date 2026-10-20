/*
 * Software fault simulation. A fault is an XOR mask applied to the S-box input
 * of one round (see encrypt_fault in variants/cipher.h).
 *   M1: one random nibble, random non-zero value
 *   M2: one random bit
 *   M3: one random aligned byte (two adjacent nibbles), random non-zero value
 * Location and value are unknown to the attacker.
 */
#ifndef DFA_FAULT_H
#define DFA_FAULT_H
#include "../variants/cipher.h"
#include "../attack/dfa.h"

static inline uint64_t fault_mask(int model, uint64_t *rng) {
    uint64_t r = sm64(rng);
    if (model == M1) return (uint64_t)(1 + (r >> 8) % 15) << (4 * (r & 15));
    if (model == M2) return 1ULL << (r & 63);
    return (uint64_t)(1 + (r >> 8) % 255) << (8 * (r & 7));
}

/* y_T (S-box input of round T, key added) from a ciphertext, given rk[T+1..27] */
static inline uint64_t peel(uint64_t c, const uint64_t *rk, int T, int v) {
    uint64_t s = Finv(c, v);                 /* = y_27 (fact 1) */
    for (int r = 27; r > T; r--) s = Finv(s ^ rk[r], v);
    return s;
}
#endif
