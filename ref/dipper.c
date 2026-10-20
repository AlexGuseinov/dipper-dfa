/*
 * Dipper block cipher - portable C99 implementation (Spec v1.1)
 * 64-bit block, 96/128-bit key, 28 rounds.
 * Round keys are precomputed (standard practice for benchmarking).
 * Reference use; not hardened against side channels.
 */
#include <stdint.h>
#include <string.h>

#define DIPPER_ROUNDS 28

static const uint8_t S[16]  = {0x1,0xA,0x4,0xC,0x6,0xF,0x3,0x9,0x2,0xD,0xB,0x7,0x5,0x0,0x8,0xE};
static const uint8_t SI[16] = {0xD,0x0,0x8,0x6,0x2,0xC,0x4,0xB,0xE,0x7,0x1,0xA,0x3,0x9,0xF,0x5}; /* S^-1 */

static uint8_t P[64], PI[64];
static int tables_ready = 0;

static void init_tables(void) {
    if (tables_ready) return;
    for (int i = 0; i < 64; i++) {
        int p = 4*(i/16) + 16*((3*((i%16)/4) + (i%4)) % 4) + (i%4);
        P[i] = (uint8_t)p; PI[p] = (uint8_t)i;
    }
    tables_ready = 1;
}

static inline uint16_t rotl16(uint16_t x, int r){ r&=15; return (uint16_t)((x<<r)|(x>>(16-r))); }
static inline uint16_t rotr16(uint16_t x, int r){ r&=15; return (uint16_t)((x>>r)|(x<<(16-r))); }

static inline uint64_t sub_cells(uint64_t s){
    uint64_t o=0; for(int j=0;j<16;j++) o |= (uint64_t)S[(s>>(4*j))&0xF]<<(4*j); return o;
}
static inline uint64_t sub_cells_inv(uint64_t s){
    uint64_t o=0; for(int j=0;j<16;j++) o |= (uint64_t)SI[(s>>(4*j))&0xF]<<(4*j); return o;
}
static inline uint64_t apply_perm(uint64_t s){
    uint64_t o=0; for(int i=0;i<64;i++) o |= ((s>>i)&1ULL)<<P[i]; return o;
}
static inline uint64_t apply_perm_inv(uint64_t s){
    uint64_t o=0; for(int i=0;i<64;i++) o |= ((s>>i)&1ULL)<<PI[i]; return o;
}

static inline uint64_t round_enc(uint64_t s, uint64_t rk){
    s ^= rk;
    s  = sub_cells(s);
    uint16_t A=(uint16_t)(s>>48), B=(uint16_t)(s>>32), C=(uint16_t)(s>>16), D=(uint16_t)s;
    uint16_t A1=rotl16(A,1), B1=rotl16(B,4), C1=rotl16(C,7), D1=rotl16(D,11);
    uint16_t A2=(uint16_t)(A1+B1), C2=(uint16_t)(C1+D1);
    s = ((uint64_t)A2<<48)|((uint64_t)B1<<32)|((uint64_t)C2<<16)|D1;
    return apply_perm(s);
}
static inline uint64_t round_dec(uint64_t s, uint64_t rk){
    s = apply_perm_inv(s);
    uint16_t A2=(uint16_t)(s>>48), B1=(uint16_t)(s>>32), C2=(uint16_t)(s>>16), D1=(uint16_t)s;
    uint16_t A1=(uint16_t)(A2-B1), C1=(uint16_t)(C2-D1);
    uint16_t A=rotr16(A1,1), B=rotr16(B1,4), C=rotr16(C1,7), D=rotr16(D1,11);
    s = ((uint64_t)A<<48)|((uint64_t)B<<32)|((uint64_t)C<<16)|D;
    s = sub_cells_inv(s);
    return s ^ rk;
}

/* ---- key schedules: expand all round keys up front ---- */
static inline uint8_t lfsr_step(uint8_t l){
    uint8_t nb = (uint8_t)(((l>>4)^(l>>1))&1);
    return (uint8_t)(((l<<1)|nb)&0x1F);
}
typedef struct { uint16_t w[8]; } key_t_; /* w[0]=k0 ... w[7]=k7 */

void dipper_expand_96(const uint16_t k[6], uint64_t rk[DIPPER_ROUNDS]){
    init_tables();
    uint16_t K[6]; memcpy(K,k,sizeof(K)); /* K[0]=k0..K[5]=k5 */
    uint8_t lfsr=0x01;
    for(int i=0;i<DIPPER_ROUNDS;i++){
        rk[i]=((uint64_t)K[3]<<48)|((uint64_t)K[2]<<32)|((uint64_t)K[1]<<16)|K[0];
        uint16_t t1=rotr16(K[1],2), t0=rotr16(K[0],12);
        uint16_t n5=K[3],n4=K[2],n3=t1,n2=t0,n1=K[5],n0=K[4];
        K[5]=n5;K[4]=n4;K[3]=n3;K[2]=n2;K[1]=n1;K[0]=n0;
        /* S-boxes at bit positions 92,68,44,20 => top nibble of k5,k4(?)... map: pos=16*w+off */
        /* 92 = 16*5+12 -> top nibble of K[5]; 68 = 16*4+4 -> K[4] bits[7:4];
           44 = 16*2+12 -> K[2] top nibble; 20 = 16*1+4 -> K[1] bits[7:4] */
        K[5]=(uint16_t)((K[5]&0x0FFF)|((uint16_t)S[(K[5]>>12)&0xF]<<12));
        K[4]=(uint16_t)((K[4]&0xFF0F)|((uint16_t)S[(K[4]>>4)&0xF]<<4));
        K[2]=(uint16_t)((K[2]&0x0FFF)|((uint16_t)S[(K[2]>>12)&0xF]<<12));
        K[1]=(uint16_t)((K[1]&0xFF0F)|((uint16_t)S[(K[1]>>4)&0xF]<<4));
        /* RC at bits 52..48 -> K[3] low 5 bits */
        K[3]^=(uint16_t)(lfsr&0x1F);
        lfsr=lfsr_step(lfsr);
    }
}
void dipper_expand_128(const uint16_t k[8], uint64_t rk[DIPPER_ROUNDS]){
    init_tables();
    uint16_t K[8]; memcpy(K,k,sizeof(K));
    uint8_t lfsr=0x01;
    for(int i=0;i<DIPPER_ROUNDS;i++){
        rk[i]=((uint64_t)K[3]<<48)|((uint64_t)K[2]<<32)|((uint64_t)K[1]<<16)|K[0];
        uint16_t t1=rotr16(K[1],2), t0=rotr16(K[0],12);
        uint16_t n7=K[3],n6=K[2],n5=K[7],n4=K[6],n3=K[5],n2=K[4],n1=t1,n0=t0;
        K[7]=n7;K[6]=n6;K[5]=n5;K[4]=n4;K[3]=n3;K[2]=n2;K[1]=n1;K[0]=n0;
        /* S-boxes at 124(K7 top),60(K3 top),28(K1 top) */
        K[7]=(uint16_t)((K[7]&0x0FFF)|((uint16_t)S[(K[7]>>12)&0xF]<<12));
        K[3]=(uint16_t)((K[3]&0x0FFF)|((uint16_t)S[(K[3]>>12)&0xF]<<12));
        K[1]=(uint16_t)((K[1]&0x0FFF)|((uint16_t)S[(K[1]>>12)&0xF]<<12));
        /* RC at bits 68..64 -> K[4] low 5 bits */
        K[4]^=(uint16_t)(lfsr&0x1F);
        lfsr=lfsr_step(lfsr);
    }
}

uint64_t dipper_encrypt_block(uint64_t p, const uint64_t rk[DIPPER_ROUNDS]){
    uint64_t s=p;
    for(int i=0;i<DIPPER_ROUNDS;i++) s=round_enc(s,rk[i]);
    return s;
}
uint64_t dipper_decrypt_block(uint64_t c, const uint64_t rk[DIPPER_ROUNDS]){
    uint64_t s=c;
    for(int i=DIPPER_ROUNDS-1;i>=0;i--) s=round_dec(s,rk[i]);
    return s;
}
