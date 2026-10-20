#include <stdio.h>
#include <stdint.h>
#define DIPPER_ROUNDS 28
void dipper_expand_96(const uint16_t k[6], uint64_t rk[DIPPER_ROUNDS]);
void dipper_expand_128(const uint16_t k[8], uint64_t rk[DIPPER_ROUNDS]);
uint64_t dipper_encrypt_block(uint64_t p, const uint64_t rk[DIPPER_ROUNDS]);
uint64_t dipper_decrypt_block(uint64_t c, const uint64_t rk[DIPPER_ROUNDS]);

static void k96(uint64_t hi32, uint64_t lo64, uint16_t k[6]){
    /* master key = 96 bits: hi32 = k5||k4 (32 bit), lo64 = k3..k0 */
    k[5]=(uint16_t)(hi32>>16); k[4]=(uint16_t)hi32;
    k[3]=(uint16_t)(lo64>>48); k[2]=(uint16_t)(lo64>>32);
    k[1]=(uint16_t)(lo64>>16); k[0]=(uint16_t)lo64;
}
static void k128(uint64_t hi, uint64_t lo, uint16_t k[8]){
    k[7]=(uint16_t)(hi>>48);k[6]=(uint16_t)(hi>>32);k[5]=(uint16_t)(hi>>16);k[4]=(uint16_t)hi;
    k[3]=(uint16_t)(lo>>48);k[2]=(uint16_t)(lo>>32);k[1]=(uint16_t)(lo>>16);k[0]=(uint16_t)lo;
}
int main(void){
    int fail=0;
    uint64_t rk[DIPPER_ROUNDS]; uint16_t k6[6]; uint16_t k8[8];
    /* TV1 96 */
    k96(0x00112233ULL, 0x445566778899AABBULL, k6);
    dipper_expand_96(k6,rk);
    uint64_t c=dipper_encrypt_block(0x0123456789ABCDEFULL,rk);
    printf("TV1 96 : C=%016llX  (exp 5F189202D3152B8F) %s\n",(unsigned long long)c, c==0x5F189202D3152B8FULL?"OK":"FAIL");
    fail |= (c!=0x5F189202D3152B8FULL);
    uint64_t d=dipper_decrypt_block(c,rk);
    printf("TV1 dec: P=%016llX  %s\n",(unsigned long long)d, d==0x0123456789ABCDEFULL?"OK":"FAIL");
    fail |= (d!=0x0123456789ABCDEFULL);
    /* TV2 96 zeros */
    k96(0,0,k6); dipper_expand_96(k6,rk);
    c=dipper_encrypt_block(0,rk);
    printf("TV2 96 : C=%016llX  (exp D873355EC63B1B4B) %s\n",(unsigned long long)c, c==0xD873355EC63B1B4BULL?"OK":"FAIL");
    fail |= (c!=0xD873355EC63B1B4BULL);
    /* TV3 128 */
    k128(0x0001020304050607ULL,0x08090A0B0C0D0E0FULL,k8); dipper_expand_128(k8,rk);
    c=dipper_encrypt_block(0x0123456789ABCDEFULL,rk);
    printf("TV3 128: C=%016llX  (exp 4B46284387969060) %s\n",(unsigned long long)c, c==0x4B46284387969060ULL?"OK":"FAIL");
    fail |= (c!=0x4B46284387969060ULL);
    d=dipper_decrypt_block(c,rk);
    printf("TV3 dec: P=%016llX  %s\n",(unsigned long long)d, d==0x0123456789ABCDEFULL?"OK":"FAIL");
    fail |= (d!=0x0123456789ABCDEFULL);
    /* TV4 128 ones */
    k128(0xFFFFFFFFFFFFFFFFULL,0xFFFFFFFFFFFFFFFFULL,k8); dipper_expand_128(k8,rk);
    c=dipper_encrypt_block(0xFFFFFFFFFFFFFFFFULL,rk);
    printf("TV4 128: C=%016llX  (exp 6ABB4518063706B0) %s\n",(unsigned long long)c, c==0x6ABB4518063706B0ULL?"OK":"FAIL");
    fail |= (c!=0x6ABB4518063706B0ULL);
    printf(fail?"\nSELF-TEST FAILED\n":"\nALL SELF-TESTS PASSED\n");
    return fail;
}
