"""
Dipper Reference Implementation (Python)
Based on Dipper Specification v1.0 (April 2026)
Author: Ali Huseynli, Azerbaijan Technical University

This is a reference implementation for spec validation and test vector
generation. It is NOT constant-time and NOT optimized for performance;
it is intended for cryptanalytic verification only.

Supports:
- Dipper-64/96  (64-bit block, 96-bit key)
- Dipper-64/128 (64-bit block, 128-bit key)
- 28 rounds
"""

# ============================================================
# Constants
# ============================================================

# GIFT 4-bit S-box (Section 4)
# Input:  0 1 2 3 4 5 6 7 8 9 A B C D E F
# Output: 1 A 4 C 6 F 3 9 2 D B 7 5 0 8 E
GIFT_SBOX = [0x1, 0xA, 0x4, 0xC, 0x6, 0xF, 0x3, 0x9,
             0x2, 0xD, 0xB, 0x7, 0x5, 0x0, 0x8, 0xE]


# ============================================================
# Helper functions
# ============================================================

def rotl16(x, r):
    """Left rotation of a 16-bit value by r bits."""
    r = r % 16
    return ((x << r) | (x >> (16 - r))) & 0xFFFF


def rotr16(x, r):
    """Right rotation of a 16-bit value by r bits."""
    r = r % 16
    return ((x >> r) | (x << (16 - r))) & 0xFFFF


def gift_permutation_p(i):
    """GIFT-64 bit permutation P(i): position i moves to position P(i)."""
    return 4 * (i // 16) + 16 * ((3 * ((i % 16) // 4) + (i % 4)) % 4) + (i % 4)


def apply_permutation(state):
    """Apply GIFT-64 bit permutation P to a 64-bit state."""
    new_state = 0
    for i in range(64):
        bit = (state >> i) & 1
        new_state |= (bit << gift_permutation_p(i))
    return new_state


def sub_cells(state):
    """Apply GIFT S-box to all 16 nibbles of a 64-bit state in parallel."""
    new_state = 0
    for j in range(16):
        nibble = (state >> (4 * j)) & 0xF
        new_state |= GIFT_SBOX[nibble] << (4 * j)
    return new_state


def lfsr_step(lfsr):
    """5-bit LFSR step per spec Section 7:
       bit_new = LFSR[4] XOR LFSR[1]
       LFSR = (LFSR << 1) | bit_new, truncated to 5 bits.
       (Polynomial nominally x^5 + x^2 + 1.)
    """
    bit_new = ((lfsr >> 4) & 1) ^ ((lfsr >> 1) & 1)
    return ((lfsr << 1) | bit_new) & 0x1F


# ============================================================
# Round function (Section 5)
# ============================================================

def round_function(state, RK_i):
    """One round of Dipper. Steps:
       1. AddRoundKey (full 64-bit XOR)
       2. SubCells (16 parallel GIFT S-boxes)
       3. Word rotations (1, 4, 7, 11)
       4. ARX additions (A+B, C+D mod 2^16)
       5. Bit permutation (GIFT-64 P)
    """
    # Step 1: AddRoundKey
    state ^= RK_i

    # Step 2: SubCells
    state = sub_cells(state)

    # Step 3: Word rotations
    A = (state >> 48) & 0xFFFF
    B = (state >> 32) & 0xFFFF
    C = (state >> 16) & 0xFFFF
    D = state & 0xFFFF

    A1 = rotl16(A, 1)
    B1 = rotl16(B, 4)
    C1 = rotl16(C, 7)
    D1 = rotl16(D, 11)

    # Step 4: ARX addition (half-state update)
    A2 = (A1 + B1) & 0xFFFF
    C2 = (C1 + D1) & 0xFFFF

    state = (A2 << 48) | (B1 << 32) | (C2 << 16) | D1

    # Step 5: Bit permutation
    state = apply_permutation(state)

    return state


# ============================================================
# Key schedules (Section 6)
# ============================================================

def key_schedule_update_96(K, RC_i):
    """Key schedule update for Dipper-64/96 (Section 6.1).

       K = k5 || k4 || k3 || k2 || k1 || k0  (96 bits, k5 = MSB)

       Step 1: temp_k1 = ROTR16(k1, 2); temp_k0 = ROTR16(k0, 12)
               (k5,k4,k3,k2,k1,k0) <- (k3, k2, temp_k1, temp_k0, k5, k4)
       Step 2: 4 S-boxes at K[95:92], K[71:68], K[47:44], K[23:20]
       Step 3: 5-bit RC XOR at K[52:48]
    """
    k5 = (K >> 80) & 0xFFFF
    k4 = (K >> 64) & 0xFFFF
    k3 = (K >> 48) & 0xFFFF
    k2 = (K >> 32) & 0xFFFF
    k1 = (K >> 16) & 0xFFFF
    k0 = K & 0xFFFF

    temp_k1 = rotr16(k1, 2)
    temp_k0 = rotr16(k0, 12)

    new_k5, new_k4 = k3, k2
    new_k3, new_k2 = temp_k1, temp_k0
    new_k1, new_k0 = k5, k4

    K_new = ((new_k5 << 80) | (new_k4 << 64) | (new_k3 << 48) |
             (new_k2 << 32) | (new_k1 << 16) | new_k0)

    # 4 S-boxes at top nibbles of (new) k5, k4, k2, k1
    for pos in [92, 68, 44, 20]:
        nibble = (K_new >> pos) & 0xF
        K_new = (K_new & ~(0xF << pos)) | (GIFT_SBOX[nibble] << pos)

    # 5-bit round constant XOR (RC_i is 5 bits)
    K_new ^= (RC_i & 0x1F) << 48

    return K_new


def key_schedule_update_128(K, RC_i):
    """Key schedule update for Dipper-64/128 (Section 6.2).

       K = k7 || k6 || ... || k0  (128 bits, k7 = MSB)

       Step 1: temp_k1 = ROTR16(k1, 2); temp_k0 = ROTR16(k0, 12)
               (k7,...,k0) <- (k3, k2, k7, k6, k5, k4, temp_k1, temp_k0)
       Step 2: 3 S-boxes at K[127:124], K[63:60], K[31:28]
       Step 3: 5-bit RC XOR at K[68:64]
    """
    k7 = (K >> 112) & 0xFFFF
    k6 = (K >> 96) & 0xFFFF
    k5 = (K >> 80) & 0xFFFF
    k4 = (K >> 64) & 0xFFFF
    k3 = (K >> 48) & 0xFFFF
    k2 = (K >> 32) & 0xFFFF
    k1 = (K >> 16) & 0xFFFF
    k0 = K & 0xFFFF

    temp_k1 = rotr16(k1, 2)
    temp_k0 = rotr16(k0, 12)

    new_k7, new_k6 = k3, k2
    new_k5, new_k4 = k7, k6
    new_k3, new_k2 = k5, k4
    new_k1, new_k0 = temp_k1, temp_k0

    K_new = ((new_k7 << 112) | (new_k6 << 96) | (new_k5 << 80) | (new_k4 << 64) |
             (new_k3 << 48) | (new_k2 << 32) | (new_k1 << 16) | new_k0)

    # 3 S-boxes at top nibbles of (new) k7, k3, k1
    for pos in [124, 60, 28]:
        nibble = (K_new >> pos) & 0xF
        K_new = (K_new & ~(0xF << pos)) | (GIFT_SBOX[nibble] << pos)

    # 5-bit round constant XOR
    K_new ^= (RC_i & 0x1F) << 64

    return K_new


def extract_round_key(K):
    """Round key = lower 64 bits of K (= k3 || k2 || k1 || k0)."""
    return K & 0xFFFFFFFFFFFFFFFF


# ============================================================
# Encryption
# ============================================================

def encrypt(plaintext, master_key, key_size=96, num_rounds=28, verbose=False):
    """Encrypt a 64-bit plaintext with the given master key.

       Args:
           plaintext: 64-bit integer
           master_key: 96-bit or 128-bit integer
           key_size: 96 or 128
           num_rounds: 28 by default
           verbose: print intermediate state

       Returns:
           64-bit ciphertext
    """
    if key_size == 96:
        ks_update = key_schedule_update_96
    elif key_size == 128:
        ks_update = key_schedule_update_128
    else:
        raise ValueError(f"Unsupported key size: {key_size}")

    state = plaintext & 0xFFFFFFFFFFFFFFFF
    K = master_key
    lfsr = 0x01  # initial LFSR state, also RC_1

    for i in range(1, num_rounds + 1):
        RK_i = extract_round_key(K)
        if verbose:
            print(f"  R{i:2d}: state_in =0x{state:016X}, RK=0x{RK_i:016X}, RC=0x{lfsr:02X}")
        state = round_function(state, RK_i)
        # Use current LFSR as RC, then step (per spec Section 7 RC table starting at 0x01)
        K = ks_update(K, lfsr)
        lfsr = lfsr_step(lfsr)

    return state


# ============================================================
# Test / verification
# ============================================================

def generate_rc_sequence(n=28):
    """Generate first n LFSR values starting from initial state 0x01."""
    seq = []
    lfsr = 0x01
    for _ in range(n):
        seq.append(lfsr)
        lfsr = lfsr_step(lfsr)
    return seq


def main():
    print("=" * 64)
    print("Dipper Reference Implementation - Self-Test")
    print("=" * 64)

    # ---- Verify GIFT permutation against known values ----
    expected_p = {0: 0, 1: 17, 2: 34, 3: 51, 4: 48, 5: 1, 6: 18, 7: 35,
                  8: 32, 9: 49, 10: 2, 11: 19, 12: 16, 13: 33, 14: 50, 15: 3}
    for i, exp in expected_p.items():
        got = gift_permutation_p(i)
        assert got == exp, f"P({i}) = {got}, expected {exp}"
    print("[OK]   GIFT permutation P verified for first 16 inputs")

    # ---- Verify GIFT S-box is bijective ----
    assert sorted(GIFT_SBOX) == list(range(16)), "S-box not a permutation"
    print("[OK]   GIFT S-box is a valid permutation")

    # ---- Generate RC sequence and compare to spec table ----
    print("\n" + "-" * 64)
    print("Round Constant Sequence (LFSR per spec Section 7)")
    print("-" * 64)
    rc = generate_rc_sequence(28)

    # Spec-stated values from Section 7 of Dipper_Specification_v1.0.md
    spec_rc = {
        1:  0x01, 2:  0x02, 3:  0x05, 4:  0x0B, 5:  0x16, 6:  0x0C, 7:  0x19,
        8:  0x09, 9:  0x13, 10: 0x07, 11: 0x0F, 12: 0x1F, 13: 0x1E, 14: 0x1D,
        15: 0x17, 16: 0x0E, 17: 0x1C, 18: 0x19, 19: 0x12, 20: 0x05, 21: 0x0B,
        22: 0x04, 23: 0x08, 24: 0x11, 25: 0x03, 26: 0x06, 27: 0x0D, 28: 0x1B
    }

    mismatches = []
    print(f"  {'i':>3} | {'computed':>9} | {'spec':>6} | match?")
    print(f"  {'-'*3}-+-{'-'*9}-+-{'-'*6}-+--------")
    for i, val in enumerate(rc, 1):
        sv = spec_rc[i]
        ok = (val == sv)
        if not ok:
            mismatches.append((i, val, sv))
        mark = "OK" if ok else "MISMATCH"
        print(f"  {i:>3} |   0x{val:02X}    | 0x{sv:02X}   | {mark}")

    if mismatches:
        print(f"\n[WARN] {len(mismatches)}/28 RC values do NOT match spec table.")
    else:
        print("\n[OK]   All 28 RC values match the spec table.")

    # ---- Test vectors ----
    print("\n" + "=" * 64)
    print("Test Vectors")
    print("=" * 64)

    tvs = [
        ("TV1: Dipper-64/96  (spec example)",
         96,  0x0123456789ABCDEF, 0x00112233445566778899AABB),
        ("TV2: Dipper-64/96  (all-zeros)",
         96,  0x0000000000000000, 0x000000000000000000000000),
        ("TV3: Dipper-64/128 (spec example)",
         128, 0x0123456789ABCDEF, 0x000102030405060708090A0B0C0D0E0F),
        ("TV4: Dipper-64/128 (all-ones)",
         128, 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF),
    ]

    for name, ks, P, K in tvs:
        C = encrypt(P, K, key_size=ks)
        kw = ks // 4  # hex digits in master key
        print(f"\n{name}")
        print(f"  Plaintext : 0x{P:016X}")
        print(f"  Master key: 0x{K:0{kw}X}")
        print(f"  Ciphertext: 0x{C:016X}")


if __name__ == "__main__":
    main()
