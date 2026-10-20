/*
 * Step-0 checks.
 *  T1  variants/cipher.h (V_DIPPER) == ref/dipper.c, TV1-TV4 and random keys
 *  T2  fact 1: Finv(C) == x27 ^ rk27 for random keys and plaintexts
 *  T3  fact 2: rk26,rk27 (and rk25 for 128) -> round-26 state -> master key
 *  T4  forward key-schedule copy in ks_inv.h == ref expansion
 */
#include <stdio.h>
#include <stdlib.h>
#include "../variants/cipher.h"
#include "ks_inv.h"

void dipper_expand_96(const uint16_t k[6], uint64_t rk[28]);
void dipper_expand_128(const uint16_t k[8], uint64_t rk[28]);
uint64_t dipper_encrypt_block(uint64_t p, const uint64_t rk[28]);

int main(int argc, char **argv) {
    long N = argc > 1 ? atol(argv[1]) : 10000;
    uint64_t seed = argc > 2 ? strtoull(argv[2], 0, 0) : 0x5EED0001ULL;
    uint64_t rng = seed;
    cipher_init();
    int fail = 0;
    uint64_t rk[28];

    /* T1: test vectors through the variant code */
    {
        uint16_t k6[6] = {0xAABB, 0x8899, 0x6677, 0x4455, 0x2233, 0x0011};
        dipper_expand_96(k6, rk);
        uint64_t c = encrypt_v(0x0123456789ABCDEFULL, rk, V_DIPPER);
        int ok = c == 0x5F189202D3152B8FULL && decrypt_v(c, rk, V_DIPPER) == 0x0123456789ABCDEFULL;
        printf("T1 TV1 96  %016llX %s\n", (unsigned long long)c, ok ? "OK" : "FAIL"); fail |= !ok;
        uint16_t z6[6] = {0};
        dipper_expand_96(z6, rk);
        c = encrypt_v(0, rk, V_DIPPER); ok = c == 0xD873355EC63B1B4BULL;
        printf("T1 TV2 96  %016llX %s\n", (unsigned long long)c, ok ? "OK" : "FAIL"); fail |= !ok;
        uint16_t k8[8] = {0x0E0F, 0x0C0D, 0x0A0B, 0x0809, 0x0607, 0x0405, 0x0203, 0x0001};
        dipper_expand_128(k8, rk);
        c = encrypt_v(0x0123456789ABCDEFULL, rk, V_DIPPER); ok = c == 0x4B46284387969060ULL;
        printf("T1 TV3 128 %016llX %s\n", (unsigned long long)c, ok ? "OK" : "FAIL"); fail |= !ok;
        uint16_t f8[8]; for (int j = 0; j < 8; j++) f8[j] = 0xFFFF;
        dipper_expand_128(f8, rk);
        c = encrypt_v(~0ULL, rk, V_DIPPER); ok = c == 0x6ABB4518063706B0ULL;
        printf("T1 TV4 128 %016llX %s\n", (unsigned long long)c, ok ? "OK" : "FAIL"); fail |= !ok;
    }
    long bad1 = 0, bad2 = 0, bad3 = 0, bad4 = 0, badv = 0;
    for (long t = 0; t < N; t++) {
        for (int ks = 0; ks < 2; ks++) {
            uint16_t k[8];
            for (int j = 0; j < 8; j++) k[j] = (uint16_t)sm64(&rng);
            if (ks == 0) dipper_expand_96(k, rk); else dipper_expand_128(k, rk);
            uint64_t p = sm64(&rng);
            uint64_t c = encrypt_v(p, rk, V_DIPPER);
            if (c != dipper_encrypt_block(p, rk)) bad1++;
            for (int v = 1; v < 3; v++) if (decrypt_v(encrypt_v(p, rk, v), rk, v) != p) badv++;
            /* T2 */
            uint64_t s = p;
            for (int i = 0; i < 27; i++) s = Fwd(s ^ rk[i], V_DIPPER);
            if (Finv(c, V_DIPPER) != (s ^ rk[27])) bad2++;
            /* T3 */
            uint16_t m[8];
            if (ks == 0) {
                ks96_master_from_rk(rk[26], rk[27], m);
                for (int j = 0; j < 6; j++) if (m[j] != k[j]) { bad3++; break; }
            } else {
                ks128_master_from_rk(rk[25], rk[26], rk[27], m);
                for (int j = 0; j < 8; j++) if (m[j] != k[j]) { bad3++; break; }
            }
            /* T4 */
            uint16_t K[8];
            for (int j = 0; j < 8; j++) K[j] = k[j];
            for (int i = 0; i < 28; i++) {
                uint64_t r = (uint64_t)K[3] << 48 | (uint64_t)K[2] << 32 | (uint64_t)K[1] << 16 | K[0];
                if (r != rk[i]) { bad4++; break; }
                if (ks == 0) ks_update_96(K, ks_lfsr(i)); else ks_update_128(K, ks_lfsr(i));
            }
        }
    }
    printf("random keys per key size: %ld, seed 0x%llX\n", N, (unsigned long long)seed);
    printf("T1 variant==ref mismatches     : %ld\n", bad1);
    printf("T1 xor/none dec(enc(p))!=p     : %ld\n", badv);
    printf("T2 Finv(C)!=x27^rk27            : %ld\n", bad2);
    printf("T3 master-key recovery failures : %ld\n", bad3);
    printf("T4 forward KS copy mismatches   : %ld\n", bad4);
    fail |= bad1 || bad2 || bad3 || bad4 || badv;
    printf(fail ? "STEP-0 CHECKS FAILED\n" : "ALL STEP-0 CHECKS PASSED\n");
    return fail;
}
