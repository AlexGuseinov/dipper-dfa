# Dipper — Lightweight Block Cipher Specification v1.1

**Authors:** Ali Huseynli (Azerbaijan Technical University)
**Date:** April 2026
**Status:** Design specification (reference implementation verified)

---

## 1. Overview

Dipper is a lightweight block cipher designed for resource-constrained IoT environments. It introduces a hybrid design combining SPN architecture with partial ARX (Addition-Rotation-XOR) operations, providing dual-source nonlinearity through both S-box substitution and modular arithmetic.

### 1.1 Key features

- Hybrid SPN + partial ARX structure (novel approach)
- Proven GIFT S-box (re-used component)
- 64-bit block size
- Two key-size variants: 96-bit and 128-bit
- Target area: < 1900 GE (64/96), ≤ 2040 GE (64/128) in Nangate45
- 28 rounds for both variants

### 1.2 Design philosophy

Dipper follows the "small-area, balanced-security" approach:
- Reuse the heavily-analyzed GIFT S-box (no new S-box design)
- Add minimal arithmetic nonlinearity (2 × 16-bit modular additions per round)
- Use word rotations for 0-cost mixing
- Conservative key schedule with distributed S-box applications

---

## 2. Parameters

| Parameter | Value |
|---|---|
| Block size | 64 bits |
| Key size | 96 bits (Dipper-64/96) or 128 bits (Dipper-64/128) |
| Number of rounds | 28 |
| S-box | GIFT S-box (4-bit, BOGI-compatible) |
| Round function type | Hybrid SPN + partial ARX |
| Architecture target | Round-based parallel |

---

## 3. State representation

The 64-bit internal state is viewed as four 16-bit words:

```
state = A || B || C || D
```

Where:
- A = state[63:48]
- B = state[47:32]
- C = state[31:16]
- D = state[15:0]

For S-box application, state is viewed as 16 nibbles (4-bit each).

---

## 4. GIFT S-box

Dipper uses the GIFT S-box without modification:

```
Input:  0 1 2 3 4 5 6 7 8 9 A B C D E F
Output: 1 A 4 C 6 F 3 9 2 D B 7 5 0 8 E
```

**Hardware cost:** ~16 GE per S-box unit (area-optimized implementation: 4 NAND + 6 XOR).

---

## 5. Round function

Each round consists of five steps applied in order:

```
1. AddRoundKey
2. SubCells (16 × GIFT S-box)
3. Word Rotations
4. ARX Addition Layer
5. Bit Permutation
```

### 5.1 Step 1 — AddRoundKey

Round key RK_i (64 bits) is XORed to the full state:

```
state ← state ⊕ RK_i
```

**Note:** Full-state addition is used (not half-state as in GIFT) to maximize key influence per round and compensate for the reduced number of S-boxes in the key schedule.

**Cost:** 64 XOR gates ≈ 170 GE.

### 5.2 Step 2 — SubCells

GIFT S-box is applied to all 16 nibbles in parallel:

```
for j = 0 to 15:
    state[4j+3:4j] ← SBOX(state[4j+3:4j])
```

**Cost:** 16 × 16 GE = ~263 GE.

### 5.3 Step 3 — Word Rotations

After SubCells, each 16-bit word is rotated left by a distinct fixed amount:

```
A1 = ROTL16(A, 1)
B1 = ROTL16(B, 4)
C1 = ROTL16(C, 7)
D1 = ROTL16(D, 11)
```

**Rotation constants:** (1, 4, 7, 11)
- Distinct values spanning small-to-medium range
- Three of four (1, 7, 11) are coprime with 16
- Selected to maximize per-round diffusion prior to ARX step

**Cost:** 0 GE (pure wire routing).

**Rationale:** The rotations distribute S-box output bits to different positions within each word before modular addition, ensuring that the ARX step operates on well-mixed inputs.

### 5.4 Step 4 — ARX Addition Layer

Two modular additions are performed between word pairs:

```
A2 = (A1 + B1) mod 2^16
C2 = (C1 + D1) mod 2^16
B2 = B1    (unchanged)
D2 = D1    (unchanged)
```

**Design choice — half-state ARX:**
- Only A and C are updated via addition
- B and D pass through unchanged
- Partial branch update preserves simple invertibility structure

**Nonlinearity source:** Modular addition mod 2^16 provides GF(2)-nonlinear mixing distinct from the GIFT S-box, giving the cipher dual-source nonlinearity.

**Cost:** 2 × 16-bit ripple-carry adder ≈ 280 GE.

### 5.5 Step 5 — Bit Permutation

State after ARX is:
```
state_after_ARX = A2 || B2 || C2 || D2
```

Apply GIFT-64 bit permutation P:
```
for i = 0 to 63:
    new_state[P(i)] ← state[i]
```

Where P is the standard GIFT-64 BOGI permutation:
```
P(i) = 4⌊i/16⌋ + 16((3⌊(i mod 16)/4⌋ + (i mod 4)) mod 4) + (i mod 4)
```

**Cost:** 0 GE (pure wire routing).

**Rationale:** GIFT BOGI permutation is retained because it is specifically designed to work with the GIFT S-box. Replacing it would require re-analysis of differential bounds.

---

## 6. Key schedule

Dipper employs different key schedules for the 96-bit and 128-bit variants.

### 6.1 Dipper-64/96 key schedule

Master key MK (96 bits) is held in key register K. K is viewed as six 16-bit words:
```
K = k5 || k4 || k3 || k2 || k1 || k0
```

**Round key extraction:**
```
RK_i = k3 || k2 || k1 || k0    // 64 bits (lower 64 bits of K)
```

**Key state update (after each round):**

```
Step 1: Word rotation (following GIFT approach)
   temp_k1 = ROTR16(k1, 2)
   temp_k0 = ROTR16(k0, 12)

   New key state:
   (k5, k4, k3, k2, k1, k0) ← (k3, k2, temp_k1, temp_k0, k5, k4)

Step 2: Distributed S-box application (4 S-boxes)
   K[95:92] ← SBOX(K[95:92])      // in k5 top nibble
   K[71:68] ← SBOX(K[71:68])      // in k4 top nibble
   K[47:44] ← SBOX(K[47:44])      // in k2 top nibble
   K[23:20] ← SBOX(K[23:20])      // in k1 top nibble

Step 3: Round constant injection
   K[52:48] ← K[52:48] ⊕ RC_i     // 5-bit XOR
```

**Cost breakdown:**
- Word rotations: 0 GE
- 4 × S-box: ~64 GE
- RC XOR: ~13 GE
- Total: ~77 GE

### 6.2 Dipper-64/128 key schedule

Master key MK (128 bits) is held in key register K (eight 16-bit words):
```
K = k7 || k6 || k5 || k4 || k3 || k2 || k1 || k0
```

**Round key extraction:**
```
RK_i = k3 || k2 || k1 || k0
```

**Key state update:**

```
Step 1: Word rotation
   temp_k1 = ROTR16(k1, 2)
   temp_k0 = ROTR16(k0, 12)

   (k7, ..., k0) ← (k3, k2, k7, k6, k5, k4, temp_k1, temp_k0)

Step 2: Distributed S-box application (3 S-boxes)
   K[127:124] ← SBOX(K[127:124])  // in k7 top nibble
   K[63:60]   ← SBOX(K[63:60])    // in k3 top nibble
   K[31:28]   ← SBOX(K[31:28])    // in k1 top nibble

Step 3: Round constant injection
   K[68:64] ← K[68:64] ⊕ RC_i
```

**Cost breakdown:**
- Word rotations: 0 GE
- 3 × S-box: ~48 GE
- RC XOR: ~13 GE
- Total: ~61 GE

**Rationale:** 128-bit variant uses 3 S-boxes instead of 4 to stay within 2040 GE target, since the larger key register itself adds ~192 GE.

---

## 7. Round constants

Round constants RC_i are generated by a 5-bit LFSR with polynomial x^5 + x^2 + 1:

```
Initial state: LFSR = 0x01

LFSR step (used to advance state between rounds):
    bit_new = LFSR[4] XOR LFSR[1]
    LFSR ← (LFSR << 1) | bit_new, truncated to 5 bits

RC_i = LFSR value used in round i  (5-bit value)
```

**Period:** 31 (maximal-length sequence over the 5 non-zero states; 0x00 is excluded from the cycle as is standard for LFSRs).

**Sequence (first 28 values, generated by the rule above starting from 0x01):**

```
RC_1  = 0x01    RC_8  = 0x0E    RC_15 = 0x03    RC_22 = 0x13
RC_2  = 0x02    RC_9  = 0x1D    RC_16 = 0x07    RC_23 = 0x06
RC_3  = 0x05    RC_10 = 0x1B    RC_17 = 0x0F    RC_24 = 0x0D
RC_4  = 0x0A    RC_11 = 0x16    RC_18 = 0x1F    RC_25 = 0x1A
RC_5  = 0x15    RC_12 = 0x0C    RC_19 = 0x1E    RC_26 = 0x14
RC_6  = 0x0B    RC_13 = 0x18    RC_20 = 0x1C    RC_27 = 0x09
RC_7  = 0x17    RC_14 = 0x11    RC_21 = 0x19    RC_28 = 0x12
```

> **Note (changed in v1.1):** The RC table in v1.0 contained transcription errors and did not match the LFSR formula. The LFSR formula is authoritative; the table above is the formula's actual output and supersedes the v1.0 table.

**Cost:** 5-bit LFSR register + XOR feedback ≈ 22 GE.

---

## 8. Encryption algorithm

```
INPUT:  plaintext P (64 bits), master key MK (96 or 128 bits)
OUTPUT: ciphertext C (64 bits)

1. state ← P
2. K ← MK
3. LFSR ← 0x01      // RC_1 is the initial value (use-then-step)

4. For i = 1 to 28:

   // Step 1: Extract round key (lower 64 bits of K)
   RK_i ← K mod 2^64

   // Step 2: AddRoundKey (full state)
   state ← state ⊕ RK_i

   // Step 3: SubCells (16 parallel S-boxes)
   for j = 0 to 15:
       state[4j+3:4j] ← SBOX(state[4j+3:4j])

   // Step 4: Word Rotations
   (A, B, C, D) ← split16(state)
   A1 ← ROTL16(A, 1)
   B1 ← ROTL16(B, 4)
   C1 ← ROTL16(C, 7)
   D1 ← ROTL16(D, 11)

   // Step 5: ARX Addition (half-state)
   A2 ← (A1 + B1) mod 2^16
   C2 ← (C1 + D1) mod 2^16
   state ← A2 || B1 || C2 || D1

   // Step 6: Bit Permutation
   temp ← 0
   for b = 0 to 63:                 // (loop variable renamed from i to avoid shadowing)
       temp[P(b)] ← state[b]
   state ← temp

   // Step 7: Key schedule update with current RC, then advance LFSR
   RC_i ← LFSR
   K ← KeyScheduleUpdate(K, RC_i)
   LFSR ← LFSR_step(LFSR)

5. C ← state
6. return C
```

> **Note (clarified in v1.1):** RC ordering is "use-then-step": round 1 uses RC_1 = 0x01 (the initial LFSR value), then the LFSR is advanced. This matches the table in Section 7.

---

## 9. Design rationale

### 9.1 Why partial ARX (not full ARX)

- Full ARX on all 64 bits would require 4 × 16-bit additions = ~560 GE
- Partial ARX (2 additions) keeps cost manageable (~280 GE)
- Half-state update simplifies inverse round construction
- Combined with S-box nonlinearity, provides defense-in-depth

### 9.2 Why rotation constants (1, 4, 7, 11)

- Pairwise distinct (each word rotated differently)
- Distributed across small-to-medium range
- 1, 7, 11 are coprime to 16; 4 is not but provides a complementary mixing profile
- Empirical analysis showed good per-round diffusion

**Note:** Final rotation constants may be adjusted based on MILP analysis of active S-box bounds.

### 9.3 Why GIFT bit permutation (not custom)

- GIFT permutation is specifically designed for GIFT S-box (BOGI property)
- Reusing avoids need for new permutation analysis
- 0 GE cost (pure wiring)
- Allows re-use of GIFT MILP models as starting point

### 9.4 Why 28 rounds

- Matches GIFT-64 round count
- Provides ~4× security margin based on preliminary differential analysis
- Conservative choice pending full MILP analysis

### 9.5 Why 4 S-boxes in 96-bit key schedule

- AES precedent: strong key schedule considered best practice
- 4 S-boxes cover all top nibbles of active key words
- Cost: +64 GE (3.5% of total area)
- Improves related-key resistance

### 9.6 Why 3 S-boxes in 128-bit key schedule

- Area budget is tighter (larger key register adds ~192 GE)
- 3 S-boxes still provide adequate key schedule nonlinearity
- Keeps total area ≤ 2040 GE target

---

## 10. Expected hardware cost (Nangate45, NAND2 = 0.798 μm²)

### 10.1 Dipper-64/96

| Component | Gates | GE estimate |
|---|---|---|
| State register (64-bit scan FF) | 64 | ~385 |
| Key register (96-bit scan FF) | 96 | ~576 |
| AddRoundKey (64 XOR) | 64 | ~170 |
| S-box layer (16 × GIFT) | - | ~263 |
| Word rotations | - | 0 |
| 2 × 16-bit adders | - | ~280 |
| Bit permutation | - | 0 |
| Key schedule (rotation + 4 S-box + RC XOR) | - | ~77 |
| LFSR | - | ~22 |
| Controller + MUX | - | ~120 |
| **TOTAL** | | **~1850–1950 GE** |

### 10.2 Dipper-64/128

| Component | GE estimate |
|---|---|
| State register | ~385 |
| Key register (128-bit) | ~768 |
| AddRoundKey | ~170 |
| S-box layer | ~263 |
| ARX adders | ~280 |
| Key schedule (3 S-box) | ~61 |
| LFSR | ~22 |
| Controller + MUX | ~130 |
| **TOTAL** | **~2000–2150 GE** |

**Note:** These are design-time estimates. Actual synthesized values may vary by ±10-15%.

---

## 11. Security considerations (preliminary)

### 11.1 Differential cryptanalysis

- Minimum 18 active S-boxes expected at 9 rounds (to be verified by MILP)
- Maximum differential probability per S-box: 2^(-1.415)
- Estimated 9-round differential probability: ~2^(-25) to 2^(-30)
- Full 28-round differential probability: << 2^(-64)

### 11.2 Linear cryptanalysis

- GIFT S-box maximum linear bias: 2^(-2)
- Additional mixing from ARX step degrades linear approximations
- 28 rounds provide strong margin

### 11.3 ARX-specific attacks

- Modular additions introduce arithmetic nonlinearity
- Difference propagation through ADD is well-studied (SPECK analysis)
- Combined with S-box, rotational attacks become difficult

### 11.4 Integral attacks

- Bit permutation + rotation combination disrupts integral properties
- GIFT-64 has 9-round integral distinguishers; Dipper expected to be shorter

### 11.5 Related-key attacks

- 4 S-boxes in key schedule (96-bit variant) disrupt linear key differences
- Distributed S-box placement prevents trivial related-key trails

**Full security analysis requires:**
- MILP-based active S-box bounds (all round counts)
- Differential trail search with constraints on ARX transitions
- Impossible differential search
- Meet-in-the-middle attack analysis

---

## 12. Open items (for full paper)

1. **MILP analysis** — formal bounds on active S-boxes for 4-9 rounds
2. **Empirical differential/linear search** — best trails for up to 15 rounds
3. **NIST SP 800-22 statistical tests** — randomness verification
4. **Avalanche/SAC/BIC analysis** — empirical diffusion properties
5. **Verilog implementation** — scan FF architecture
6. **Yosys synthesis** — actual GE measurement on Nangate45
7. **Comparison tables** — vs. GIFT, PRESENT, SIMON, SPECK, SKINNY
8. **Decryption algorithm** — if full encrypt/decrypt variant is needed
9. **Rotation constant optimization** — MILP-based selection of (r1, r2, r3, r4)
10. **Round count justification** — possibility of reducing to 24 rounds with formal bounds

---

## 13. Test vectors

The following test vectors were generated by the Python reference implementation
(`dipper_reference.py`) and shall be used as conformance targets for any other
implementation of Dipper.

```
Dipper-64/96:

  TV1 (spec example):
    Plaintext  : 0x0123456789ABCDEF
    Master key : 0x00112233445566778899AABB
    Ciphertext : 0x5F189202D3152B8F

  TV2 (all-zeros):
    Plaintext  : 0x0000000000000000
    Master key : 0x000000000000000000000000
    Ciphertext : 0xD873355EC63B1B4B

Dipper-64/128:

  TV3 (spec example):
    Plaintext  : 0x0123456789ABCDEF
    Master key : 0x000102030405060708090A0B0C0D0E0F
    Ciphertext : 0x4B46284387969060

  TV4 (all-ones):
    Plaintext  : 0xFFFFFFFFFFFFFFFF
    Master key : 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF
    Ciphertext : 0x6ABB4518063706B0
```

> **Status:** These vectors are derived from the v1.1 specification (full-state
> AddRoundKey, half-state ARX, RC sequence per Section 7). They will be re-verified
> against the Verilog reference once hardware implementation is complete.

---

## 14. Naming rationale

"Dipper" refers to the Big Dipper constellation — a small, identifiable pattern of stars that serves as a navigational reference. The cipher aims to be similarly compact yet reliable, providing navigation-quality security in resource-constrained environments.

---

## 15. Change log

- **v1.1 (April 2026):** Reference implementation completed and verified.
  - Section 7: RC table replaced with the actual LFSR output (v1.0 table contained transcription errors and was inconsistent with the formula). Period clarified as 31.
  - Section 8: RC ordering clarified ("use-then-step", RC_1 = 0x01); inner loop variable renamed from `i` to `b` to avoid shadowing the round index.
  - Section 9.2: Removed inaccurate "pairwise coprime with 16" claim; corrected to note that 1, 7, 11 are coprime to 16 while 4 is not.
  - Section 13: Added four test vectors generated by the reference implementation.
- **v1.0 (April 2026):** Initial specification based on design discussions. Renamed from NORTH v3.0.

---

## 16. References (to be completed)

1. Banik et al., "GIFT: A Small Present," CHES 2017.
2. Bogdanov et al., "PRESENT: An Ultra-Lightweight Block Cipher," CHES 2007.
3. Beaulieu et al., "The SIMON and SPECK Families of Lightweight Block Ciphers," 2013.
4. Beierle et al., "The SKINNY Family of Block Ciphers," CRYPTO 2016.
5. Yu and Aagaard, "Benchmarking and Optimizing AES for Lightweight Cryptography on ASICs," 2019.


## 17. Repository structure

```text
.
├── avalanche/              # Avalanche and round-by-round diffusion tests
├── sac/                    # Strict Avalanche Criterion tests
├── bic/                    # Bit Independence Criterion tests
├── nist/                   # NIST SP 800-22 test artifacts
├── yosys synthesis/        # Verilog RTL and Yosys/Nangate45 synthesis results
│   ├── Dipper_verilog/
│   ├── GIFT_verilog/
│   ├── PRESENT_verilog/
│   └── SIMON_verilog/
├── dipper_reference.py     # Python reference implementation
├── Dipper_Specification_v1.1.md
└── Dipper_GE_Benchmarking_Documentation.md
