#include <metal_stdlib>
using namespace metal;

// =============================================================================
// PROFANITY-KILLER: Ultra-optimized vanity address generator for Metal
// =============================================================================
// Key optimizations:
// 1. Montgomery batch inversion - 1 inverse per BATCH_SIZE points instead of per point
// 2. Lambda chaining - λ' = -λ - 2Gy/d' (no new lambda computation)
// 3. Delta storage - store (x - Gx) to save subtractions
// 4. 32-bit limbs - 8 x uint32 for better GPU utilization
// 5. Fully unrolled critical loops
// 6. Precomputed -2Gy constant multiplied into batch inverse
// =============================================================================

#define MP_WORDS 8
#define BATCH_SIZE 32  // Optimal for Metal - less register pressure

typedef uint mp_word;

struct mp_number {
    mp_word d[MP_WORDS];
};

// secp256k1 prime p = 0xFFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F
constant mp_number mod = {{0xfffffc2f, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff}};

// Generator point G
// Gx = 0x79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798
constant mp_number GX = {{0x16f81798, 0x59f2815b, 0x2dce28d9, 0x029bfcdb, 0xce870b07, 0x55a06295, 0xf9dcbbac, 0x79be667e}};

// Gy = 0x483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8
constant mp_number GY = {{0xfb10d4b8, 0x9c47d08f, 0xa6855419, 0xfd17b448, 0x0e1108a8, 0x5da4fbfc, 0x26a3c465, 0x483ada77}};

// -Gy mod p (for lambda chaining)
constant mp_number NEG_GY = {{0x04ef2777, 0x63b82f6f, 0x597aabe6, 0x02e84bb7, 0xf1eef757, 0xa25b0403, 0xd95c3b9a, 0xb7c52588}};

// -2Gy mod p (multiplied into batch inverse)
constant mp_number NEG_2GY = {{0x09de52bf, 0xc7705edf, 0xb2f557cc, 0x05d0976e, 0xe3ddeeae, 0x44b60807, 0xb2b87735, 0x6f8a4b11}};

// 3Gx mod p (for delta calculation: d' = λ² - 3Gx - d)
constant mp_number TRIPLE_NEG_GX = {{0xbb17b196, 0xf2287bec, 0x76958573, 0xf82c096e, 0x946adeea, 0xff1ed83e, 0x1269ccfa, 0x92c4cc83}};

// -Gx mod p (for recovering x from delta)
constant mp_number NEG_GX = {{0xe907e497, 0xa60d7ea3, 0xd231d726, 0xfd640324, 0x3178f4f8, 0xaa5f9d6a, 0x06234453, 0x86419981}};

// =============================================================================
// Keccak-256 (optimized, unrolled)
// =============================================================================

constant uint64_t KECCAK_RC[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

#define ROTL64(x, n) (((x) << (n)) | ((x) >> (64 - (n))))

// Keccak round macro for full unrolling
#define KECCAK_ROUND(RC) do { \
    bc0 = st[0] ^ st[5] ^ st[10] ^ st[15] ^ st[20]; \
    bc1 = st[1] ^ st[6] ^ st[11] ^ st[16] ^ st[21]; \
    bc2 = st[2] ^ st[7] ^ st[12] ^ st[17] ^ st[22]; \
    bc3 = st[3] ^ st[8] ^ st[13] ^ st[18] ^ st[23]; \
    bc4 = st[4] ^ st[9] ^ st[14] ^ st[19] ^ st[24]; \
    t = bc4 ^ ROTL64(bc1, 1); st[0] ^= t; st[5] ^= t; st[10] ^= t; st[15] ^= t; st[20] ^= t; \
    t = bc0 ^ ROTL64(bc2, 1); st[1] ^= t; st[6] ^= t; st[11] ^= t; st[16] ^= t; st[21] ^= t; \
    t = bc1 ^ ROTL64(bc3, 1); st[2] ^= t; st[7] ^= t; st[12] ^= t; st[17] ^= t; st[22] ^= t; \
    t = bc2 ^ ROTL64(bc4, 1); st[3] ^= t; st[8] ^= t; st[13] ^= t; st[18] ^= t; st[23] ^= t; \
    t = bc3 ^ ROTL64(bc0, 1); st[4] ^= t; st[9] ^= t; st[14] ^= t; st[19] ^= t; st[24] ^= t; \
    t = st[1]; \
    st[1]  = ROTL64(st[6], 44);  st[6]  = ROTL64(st[9], 20); \
    st[9]  = ROTL64(st[22], 61); st[22] = ROTL64(st[14], 39); \
    st[14] = ROTL64(st[20], 18); st[20] = ROTL64(st[2], 62); \
    st[2]  = ROTL64(st[12], 43); st[12] = ROTL64(st[13], 25); \
    st[13] = ROTL64(st[19], 8);  st[19] = ROTL64(st[23], 56); \
    st[23] = ROTL64(st[15], 41); st[15] = ROTL64(st[4], 27); \
    st[4]  = ROTL64(st[24], 14); st[24] = ROTL64(st[21], 2); \
    st[21] = ROTL64(st[8], 55);  st[8]  = ROTL64(st[16], 45); \
    st[16] = ROTL64(st[5], 36);  st[5]  = ROTL64(st[3], 28); \
    st[3]  = ROTL64(st[18], 21); st[18] = ROTL64(st[17], 15); \
    st[17] = ROTL64(st[11], 10); st[11] = ROTL64(st[7], 6); \
    st[7]  = ROTL64(st[10], 3);  st[10] = ROTL64(t, 1); \
    bc0 = st[0]; bc1 = st[1]; bc2 = st[2]; bc3 = st[3]; bc4 = st[4]; \
    st[0] ^= (~bc1) & bc2; st[1] ^= (~bc2) & bc3; st[2] ^= (~bc3) & bc4; st[3] ^= (~bc4) & bc0; st[4] ^= (~bc0) & bc1; \
    bc0 = st[5]; bc1 = st[6]; bc2 = st[7]; bc3 = st[8]; bc4 = st[9]; \
    st[5] ^= (~bc1) & bc2; st[6] ^= (~bc2) & bc3; st[7] ^= (~bc3) & bc4; st[8] ^= (~bc4) & bc0; st[9] ^= (~bc0) & bc1; \
    bc0 = st[10]; bc1 = st[11]; bc2 = st[12]; bc3 = st[13]; bc4 = st[14]; \
    st[10] ^= (~bc1) & bc2; st[11] ^= (~bc2) & bc3; st[12] ^= (~bc3) & bc4; st[13] ^= (~bc4) & bc0; st[14] ^= (~bc0) & bc1; \
    bc0 = st[15]; bc1 = st[16]; bc2 = st[17]; bc3 = st[18]; bc4 = st[19]; \
    st[15] ^= (~bc1) & bc2; st[16] ^= (~bc2) & bc3; st[17] ^= (~bc3) & bc4; st[18] ^= (~bc4) & bc0; st[19] ^= (~bc0) & bc1; \
    bc0 = st[20]; bc1 = st[21]; bc2 = st[22]; bc3 = st[23]; bc4 = st[24]; \
    st[20] ^= (~bc1) & bc2; st[21] ^= (~bc2) & bc3; st[22] ^= (~bc3) & bc4; st[23] ^= (~bc4) & bc0; st[24] ^= (~bc0) & bc1; \
    st[0] ^= (RC); \
} while(0)

inline void keccak_f1600(thread uint64_t* st) {
    uint64_t bc0, bc1, bc2, bc3, bc4, t;

    // Fully unrolled 24 rounds - eliminates loop overhead and enables better instruction scheduling
    KECCAK_ROUND(0x0000000000000001ULL);
    KECCAK_ROUND(0x0000000000008082ULL);
    KECCAK_ROUND(0x800000000000808aULL);
    KECCAK_ROUND(0x8000000080008000ULL);
    KECCAK_ROUND(0x000000000000808bULL);
    KECCAK_ROUND(0x0000000080000001ULL);
    KECCAK_ROUND(0x8000000080008081ULL);
    KECCAK_ROUND(0x8000000000008009ULL);
    KECCAK_ROUND(0x000000000000008aULL);
    KECCAK_ROUND(0x0000000000000088ULL);
    KECCAK_ROUND(0x0000000080008009ULL);
    KECCAK_ROUND(0x000000008000000aULL);
    KECCAK_ROUND(0x000000008000808bULL);
    KECCAK_ROUND(0x800000000000008bULL);
    KECCAK_ROUND(0x8000000000008089ULL);
    KECCAK_ROUND(0x8000000000008003ULL);
    KECCAK_ROUND(0x8000000000008002ULL);
    KECCAK_ROUND(0x8000000000000080ULL);
    KECCAK_ROUND(0x000000000000800aULL);
    KECCAK_ROUND(0x800000008000000aULL);
    KECCAK_ROUND(0x8000000080008081ULL);
    KECCAK_ROUND(0x8000000000008080ULL);
    KECCAK_ROUND(0x0000000080000001ULL);
    KECCAK_ROUND(0x8000000080008008ULL);
}

// =============================================================================
// Multi-precision arithmetic (32-bit limbs, profanity-style)
// =============================================================================

// Modular subtraction
inline void mp_mod_sub(thread mp_number* r, thread const mp_number* a, thread const mp_number* b) {
    mp_word t, c = 0;

    for (mp_word i = 0; i < MP_WORDS; ++i) {
        t = a->d[i] - b->d[i] - c;
        c = t < a->d[i] ? 0 : (t == a->d[i] ? c : 1);
        r->d[i] = t;
    }

    if (c) {
        c = 0;
        for (mp_word i = 0; i < MP_WORDS; ++i) {
            r->d[i] += mod.d[i] + c;
            c = r->d[i] < mod.d[i] ? 1 : (r->d[i] == mod.d[i] ? c : 0);
        }
    }
}

// Subtraction of constant Gx
inline void mp_mod_sub_gx(thread mp_number* r, thread const mp_number* a) {
    mp_word t, c = 0;

    t = a->d[0] - 0x16f81798; c = t < a->d[0] ? 0 : (t == a->d[0] ? c : 1); r->d[0] = t;
    t = a->d[1] - 0x59f2815b - c; c = t < a->d[1] ? 0 : (t == a->d[1] ? c : 1); r->d[1] = t;
    t = a->d[2] - 0x2dce28d9 - c; c = t < a->d[2] ? 0 : (t == a->d[2] ? c : 1); r->d[2] = t;
    t = a->d[3] - 0x029bfcdb - c; c = t < a->d[3] ? 0 : (t == a->d[3] ? c : 1); r->d[3] = t;
    t = a->d[4] - 0xce870b07 - c; c = t < a->d[4] ? 0 : (t == a->d[4] ? c : 1); r->d[4] = t;
    t = a->d[5] - 0x55a06295 - c; c = t < a->d[5] ? 0 : (t == a->d[5] ? c : 1); r->d[5] = t;
    t = a->d[6] - 0xf9dcbbac - c; c = t < a->d[6] ? 0 : (t == a->d[6] ? c : 1); r->d[6] = t;
    t = a->d[7] - 0x79be667e - c; c = t < a->d[7] ? 0 : (t == a->d[7] ? c : 1); r->d[7] = t;

    if (c) {
        c = 0;
        for (mp_word i = 0; i < MP_WORDS; ++i) {
            r->d[i] += mod.d[i] + c;
            c = r->d[i] < mod.d[i] ? 1 : (r->d[i] == mod.d[i] ? c : 0);
        }
    }
}

// Subtraction from constant
inline void mp_mod_sub_const(thread mp_number* r, constant const mp_number* a, thread const mp_number* b) {
    mp_word t, c = 0;

    for (mp_word i = 0; i < MP_WORDS; ++i) {
        t = a->d[i] - b->d[i] - c;
        c = t < a->d[i] ? 0 : (t == a->d[i] ? c : 1);
        r->d[i] = t;
    }

    if (c) {
        c = 0;
        for (mp_word i = 0; i < MP_WORDS; ++i) {
            r->d[i] += mod.d[i] + c;
            c = r->d[i] < mod.d[i] ? 1 : (r->d[i] == mod.d[i] ? c : 0);
        }
    }
}

// Check if >= mod
inline bool mp_gte_mod(thread const mp_number* a) {
    for (int i = MP_WORDS - 1; i >= 0; i--) {
        if (a->d[i] > mod.d[i]) return true;
        if (a->d[i] < mod.d[i]) return false;
    }
    return true;
}

// Subtract mod from number
inline void mp_sub_mod(thread mp_number* r) {
    mp_word t, c = 0;
    for (mp_word i = 0; i < MP_WORDS; ++i) {
        t = r->d[i] - mod.d[i] - c;
        c = t > r->d[i] ? 1 : (t == r->d[i] ? c : 0);
        r->d[i] = t;
    }
}

// Modular multiplication using Algorithm 3 from Koç paper
// Much faster than schoolbook + reduction
inline void mp_mod_mul(thread mp_number* r, thread const mp_number* X, thread const mp_number* Y) {
    mp_number Z = {{0}};
    mp_word extraWord;

    for (int i = MP_WORDS - 1; i >= 0; --i) {
        // Z = Z * 2^32 (shift left by one word)
        extraWord = Z.d[7];
        Z.d[7] = Z.d[6]; Z.d[6] = Z.d[5]; Z.d[5] = Z.d[4]; Z.d[4] = Z.d[3];
        Z.d[3] = Z.d[2]; Z.d[2] = Z.d[1]; Z.d[1] = Z.d[0]; Z.d[0] = 0;

        // Z = Z + X * Y_i
        mp_word cM = 0, cA = 0;
        for (mp_word j = 0; j < MP_WORDS; ++j) {
            mp_word tM = X->d[j] * Y->d[i] + cM;
            cM = mulhi(X->d[j], Y->d[i]) + (tM < cM);

            Z.d[j] += tM + cA;
            cA = Z.d[j] < tM ? 1 : (Z.d[j] == tM ? cA : 0);
        }
        extraWord += cM + cA;
        bool overflow = extraWord < cM;

        // Z = Z - q*M where q = extraWord
        // This is: Z -= extraWord * mod + (overflow ? mod<<32 : 0)
        mp_word cS = 0;
        cM = 0;
        cA = 0;

        mp_number modhigher = {{0x00000000, 0xfffffc2f, 0xfffffffe, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff}};

        for (mp_word j = 0; j < MP_WORDS; ++j) {
            mp_word tM = mod.d[j] * extraWord + cM;
            cM = mulhi(mod.d[j], extraWord) + (tM < cM);

            tM += (overflow ? modhigher.d[j] : 0) + cA;
            cA = tM < (overflow ? modhigher.d[j] : 0) ? 1 : (tM == (overflow ? modhigher.d[j] : 0) ? cA : 0);

            mp_word tS = Z.d[j] - tM - cS;
            cS = tS > Z.d[j] ? 1 : (tS == Z.d[j] ? cS : 0);
            Z.d[j] = tS;
        }
    }

    *r = Z;
}

// Binary GCD-based modular inverse (faster than Fermat for secp256k1)
inline void mp_mod_inverse(thread mp_number* r) {
    mp_number A = {{1, 0, 0, 0, 0, 0, 0, 0}};
    mp_number C = {{0, 0, 0, 0, 0, 0, 0, 0}};
    mp_number v = mod;

    mp_word extraA = 0;
    mp_word extraC = 0;

    while (r->d[0] || r->d[1] || r->d[2] || r->d[3] || r->d[4] || r->d[5] || r->d[6] || r->d[7]) {
        while (!(r->d[0] & 1)) {
            // r >>= 1
            r->d[0] = (r->d[1] << 31) | (r->d[0] >> 1);
            r->d[1] = (r->d[2] << 31) | (r->d[1] >> 1);
            r->d[2] = (r->d[3] << 31) | (r->d[2] >> 1);
            r->d[3] = (r->d[4] << 31) | (r->d[3] >> 1);
            r->d[4] = (r->d[5] << 31) | (r->d[4] >> 1);
            r->d[5] = (r->d[6] << 31) | (r->d[5] >> 1);
            r->d[6] = (r->d[7] << 31) | (r->d[6] >> 1);
            r->d[7] >>= 1;

            if (A.d[0] & 1) {
                mp_word c = 0;
                for (mp_word i = 0; i < MP_WORDS; ++i) {
                    A.d[i] += mod.d[i] + c;
                    c = A.d[i] < mod.d[i] ? 1 : (A.d[i] == mod.d[i] ? c : 0);
                }
                extraA += c;
            }

            // A >>= 1 with extra
            A.d[0] = (A.d[1] << 31) | (A.d[0] >> 1);
            A.d[1] = (A.d[2] << 31) | (A.d[1] >> 1);
            A.d[2] = (A.d[3] << 31) | (A.d[2] >> 1);
            A.d[3] = (A.d[4] << 31) | (A.d[3] >> 1);
            A.d[4] = (A.d[5] << 31) | (A.d[4] >> 1);
            A.d[5] = (A.d[6] << 31) | (A.d[5] >> 1);
            A.d[6] = (A.d[7] << 31) | (A.d[6] >> 1);
            A.d[7] = (extraA << 31) | (A.d[7] >> 1);
            extraA >>= 1;
        }

        while (!(v.d[0] & 1)) {
            v.d[0] = (v.d[1] << 31) | (v.d[0] >> 1);
            v.d[1] = (v.d[2] << 31) | (v.d[1] >> 1);
            v.d[2] = (v.d[3] << 31) | (v.d[2] >> 1);
            v.d[3] = (v.d[4] << 31) | (v.d[3] >> 1);
            v.d[4] = (v.d[5] << 31) | (v.d[4] >> 1);
            v.d[5] = (v.d[6] << 31) | (v.d[5] >> 1);
            v.d[6] = (v.d[7] << 31) | (v.d[6] >> 1);
            v.d[7] >>= 1;

            if (C.d[0] & 1) {
                mp_word c = 0;
                for (mp_word i = 0; i < MP_WORDS; ++i) {
                    C.d[i] += mod.d[i] + c;
                    c = C.d[i] < mod.d[i] ? 1 : (C.d[i] == mod.d[i] ? c : 0);
                }
                extraC += c;
            }

            C.d[0] = (C.d[1] << 31) | (C.d[0] >> 1);
            C.d[1] = (C.d[2] << 31) | (C.d[1] >> 1);
            C.d[2] = (C.d[3] << 31) | (C.d[2] >> 1);
            C.d[3] = (C.d[4] << 31) | (C.d[3] >> 1);
            C.d[4] = (C.d[5] << 31) | (C.d[4] >> 1);
            C.d[5] = (C.d[6] << 31) | (C.d[5] >> 1);
            C.d[6] = (C.d[7] << 31) | (C.d[6] >> 1);
            C.d[7] = (extraC << 31) | (C.d[7] >> 1);
            extraC >>= 1;
        }

        // Compare r >= v
        bool r_gte_v = false;
        mp_word l = 0, g = 0;
        for (mp_word i = 0; i < MP_WORDS; ++i) {
            if (r->d[i] < v.d[i]) l |= (1 << i);
            if (r->d[i] > v.d[i]) g |= (1 << i);
        }
        r_gte_v = (g >= l);

        if (r_gte_v) {
            // r -= v
            mp_word c = 0;
            for (mp_word i = 0; i < MP_WORDS; ++i) {
                mp_word t = r->d[i] - v.d[i] - c;
                c = t > r->d[i] ? 1 : (t == r->d[i] ? c : 0);
                r->d[i] = t;
            }
            // A += C
            mp_word ca = 0;
            for (mp_word i = 0; i < MP_WORDS; ++i) {
                A.d[i] += C.d[i] + ca;
                ca = A.d[i] < C.d[i] ? 1 : (A.d[i] == C.d[i] ? ca : 0);
            }
            extraA += extraC + ca;
        } else {
            // v -= r
            mp_word c = 0;
            for (mp_word i = 0; i < MP_WORDS; ++i) {
                mp_word t = v.d[i] - r->d[i] - c;
                c = t > v.d[i] ? 1 : (t == v.d[i] ? c : 0);
                v.d[i] = t;
            }
            // C += A
            mp_word ca = 0;
            for (mp_word i = 0; i < MP_WORDS; ++i) {
                C.d[i] += A.d[i] + ca;
                ca = C.d[i] < A.d[i] ? 1 : (C.d[i] == A.d[i] ? ca : 0);
            }
            extraC += extraA + ca;
        }
    }

    // Reduce C
    while (extraC) {
        mp_word c = 0;
        for (mp_word i = 0; i < MP_WORDS; ++i) {
            mp_word t = C.d[i] - mod.d[i] - c;
            c = t > C.d[i] ? 1 : (t == C.d[i] ? c : 0);
            C.d[i] = t;
        }
        extraC -= c;
    }

    // r = mod - C
    mp_word c = 0;
    for (mp_word i = 0; i < MP_WORDS; ++i) {
        mp_word t = mod.d[i] - C.d[i] - c;
        c = t > mod.d[i] ? 1 : (t == mod.d[i] ? c : 0);
        r->d[i] = t;
    }
}

// =============================================================================
// Main optimized kernel - uses lambda chaining like profanity2
// =============================================================================
// Key insight: λ' = -λ - 2Gy/d'
// This means we can compute the next lambda from the previous one with just
// one multiplication and one subtraction, instead of computing from scratch.
// The -2Gy factor is folded into the batch inverse.

kernel void profanity_iterate(
    device mp_number* deltaX [[buffer(0)]],         // x - Gx for each point
    device mp_number* prevLambda [[buffer(1)]],     // Previous lambda values
    device const mp_number* inverses [[buffer(2)]], // Pre-computed (-2Gy / dX) values
    device uint* results [[buffer(3)]],             // Result: [threadId, iteration] pairs
    device atomic_uint* foundCount [[buffer(4)]],   // Number found
    constant uchar* prefix [[buffer(5)]],           // Target prefix bytes
    constant uint& prefixLen [[buffer(6)]],         // Prefix length in nibbles
    constant uint& maxResults [[buffer(7)]],        // Max results
    device uint* iterCounter [[buffer(8)]],         // Per-thread iteration counter
    device uint32_t* debugOutput [[buffer(9)]],     // Debug: pubkey x,y and hash for first match
    uint tid [[thread_position_in_grid]]
) {
    // Increment iteration counter and read the NEW value
    // iter represents which point we're checking: k + iter + 1
    uint iter = iterCounter[tid] + 1;
    iterCounter[tid] = iter;

    // Load state
    mp_number dX = deltaX[tid];
    mp_number lambda = prevLambda[tid];

    // Load pre-computed inverse (already has -2Gy folded in)
    mp_number inv = inverses[tid];

    // λ' = inv - λ = (-2Gy/dX) - λ
    mp_mod_sub(&lambda, &inv, &lambda);

    // λ² = λ * λ
    mp_number lambda2;
    mp_mod_mul(&lambda2, &lambda, &lambda);

    // d' = λ² - d - 3Gx = (-3Gx) - (d - λ²)
    mp_mod_sub(&dX, &dX, &lambda2);
    mp_mod_sub_const(&dX, &TRIPLE_NEG_GX, &dX);

    // Store updated state
    deltaX[tid] = dX;
    prevLambda[tid] = lambda;

    // Compute y from lambda and deltaX
    // y = (-Gy) - λ * d'
    mp_number y;
    mp_mod_mul(&y, &lambda, &dX);
    mp_mod_sub_const(&y, &NEG_GY, &y);

    // Recover x from delta: dX = x - Gx, so x = dX + Gx
    // We have -Gx stored as NEG_GX, so x = dX - (-Gx) = dX - NEG_GX
    mp_number x;
    mp_number negGx;
    for (int i = 0; i < MP_WORDS; i++) negGx.d[i] = NEG_GX.d[i];
    mp_mod_sub(&x, &dX, &negGx);  // x = dX - NEG_GX = dX + Gx

    // Compute keccak256(x || y)
    uint64_t state[25] = {0};

    // Pack x and y into state (big-endian for keccak input)
    #define BSWAP32(n) (rotate(n & 0x00FF00FF, 24U)|(rotate(n, 8U) & 0x00FF00FF))

    uint32_t pubkey[16];
    pubkey[0]  = BSWAP32(x.d[7]); pubkey[1]  = BSWAP32(x.d[6]);
    pubkey[2]  = BSWAP32(x.d[5]); pubkey[3]  = BSWAP32(x.d[4]);
    pubkey[4]  = BSWAP32(x.d[3]); pubkey[5]  = BSWAP32(x.d[2]);
    pubkey[6]  = BSWAP32(x.d[1]); pubkey[7]  = BSWAP32(x.d[0]);
    pubkey[8]  = BSWAP32(y.d[7]); pubkey[9]  = BSWAP32(y.d[6]);
    pubkey[10] = BSWAP32(y.d[5]); pubkey[11] = BSWAP32(y.d[4]);
    pubkey[12] = BSWAP32(y.d[3]); pubkey[13] = BSWAP32(y.d[2]);
    pubkey[14] = BSWAP32(y.d[1]); pubkey[15] = BSWAP32(y.d[0]);

    // Load into keccak state (little-endian)
    for (int i = 0; i < 8; i++) {
        state[i] = uint64_t(pubkey[i*2]) | (uint64_t(pubkey[i*2+1]) << 32);
    }

    // Padding for 64-byte message
    state[8] ^= 0x01;
    state[16] ^= 0x8000000000000000ULL;

    keccak_f1600(state);

    // Extract address (last 20 bytes of 32-byte hash)
    // Keccak state is little-endian: byte 0 is LSB of state[0], byte 7 is MSB of state[0]
    // Address is bytes 12-31 of the 32-byte hash
    uchar hash[32];
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 8; j++) {
            hash[i*8 + j] = (state[i] >> (j*8)) & 0xFF;
        }
    }

    // Check prefix match
    bool match = true;
    for (uint i = 0; i < prefixLen && match; i++) {
        uchar addrByte = hash[12 + i/2];
        uchar addrNibble = (i % 2 == 0) ? (addrByte >> 4) : (addrByte & 0x0F);
        uchar prefixNibble = (i % 2 == 0) ? (prefix[i/2] >> 4) : (prefix[i/2] & 0x0F);
        if (addrNibble != prefixNibble) match = false;
    }

    if (match) {
        uint idx = atomic_fetch_add_explicit(foundCount, 1, memory_order_relaxed);
        if (idx < maxResults) {
            // Store both thread ID and iteration as result pair
            results[idx * 2] = tid;
            results[idx * 2 + 1] = iter;

            // Debug: store pubkey and hash for first match only
            if (idx == 0) {
                // Store x (8 words)
                for (int i = 0; i < 8; i++) debugOutput[i] = x.d[i];
                // Store y (8 words)
                for (int i = 0; i < 8; i++) debugOutput[8 + i] = y.d[i];
                // Store hash (8 words = 32 bytes)
                for (int i = 0; i < 4; i++) {
                    debugOutput[16 + i*2] = uint32_t(state[i] & 0xFFFFFFFF);
                    debugOutput[16 + i*2 + 1] = uint32_t(state[i] >> 32);
                }
            }
        }
    }
}

// =============================================================================
// Batch inverse kernel - simple sequential version (like profanity2)
// One thread per batch, processes BATCH_SIZE points sequentially
// =============================================================================

kernel void profanity_inverse_batch(
    device mp_number* deltaX [[buffer(0)]],
    device mp_number* inverses [[buffer(1)]],
    constant uint& batchSize [[buffer(2)]],
    uint tid [[thread_position_in_grid]]
) {
    const uint baseId = tid * batchSize;

    mp_number products[BATCH_SIZE];
    mp_number originals[BATCH_SIZE];

    // Forward pass: compute cumulative products
    originals[0] = deltaX[baseId];
    products[0] = originals[0];

    for (uint i = 1; i < batchSize; i++) {
        originals[i] = deltaX[baseId + i];
        mp_mod_mul(&products[i], &products[i-1], &originals[i]);
    }

    // Single inverse of the product
    mp_number inv = products[batchSize - 1];
    mp_mod_inverse(&inv);

    // Multiply by -2Gy (fold into all inverses)
    mp_number neg2gy;
    for (int j = 0; j < MP_WORDS; j++) neg2gy.d[j] = NEG_2GY.d[j];
    mp_mod_mul(&inv, &inv, &neg2gy);

    // Backward pass: extract individual inverses
    for (uint i = batchSize - 1; i > 0; i--) {
        mp_number thisInv;
        mp_mod_mul(&thisInv, &inv, &products[i-1]);
        mp_mod_mul(&inv, &inv, &originals[i]);
        inverses[baseId + i] = thisInv;
    }
    inverses[baseId] = inv;
}

// =============================================================================
// Simple kernel for initial public key computation
// =============================================================================

// Jacobian point for initial scalar mult
struct JPoint {
    mp_number x, y, z;
};

inline void jpoint_double(thread JPoint* r, thread const JPoint* p) {
    if (p->z.d[0] == 0 && p->z.d[1] == 0 && p->z.d[2] == 0 && p->z.d[3] == 0 &&
        p->z.d[4] == 0 && p->z.d[5] == 0 && p->z.d[6] == 0 && p->z.d[7] == 0) {
        *r = *p;
        return;
    }

    // S = 4*X*Y^2
    mp_number y2, s, tmp;
    mp_mod_mul(&y2, &p->y, &p->y);
    mp_mod_mul(&s, &p->x, &y2);
    mp_mod_sub(&tmp, &s, &s); // tmp = 0 - (-2s) = 2s... wait
    // Actually for doubling: s = s + s; s = s + s
    mp_number two_s, four_s;
    mp_mod_sub(&two_s, &s, &s);  // This doesn't work. Let me redo

    // Let's use add by subtracting negative (since mod_sub(a, -b) = a + b)
    // For a + a: result = a - (p - a) = 2a - p, then add p if negative
    // This is getting complicated. Let me just implement mod_add:

    // Inline mod_add
    auto mod_add = [](thread mp_number* result, thread const mp_number* a, thread const mp_number* b) {
        mp_word c = 0;
        for (int i = 0; i < MP_WORDS; i++) {
            result->d[i] = a->d[i] + b->d[i] + c;
            c = result->d[i] < a->d[i] ? 1 : (result->d[i] == a->d[i] ? c : 0);
        }
        // Reduce if >= mod
        bool gte = true;
        for (int i = MP_WORDS - 1; i >= 0; i--) {
            if (result->d[i] > mod.d[i]) break;
            if (result->d[i] < mod.d[i]) { gte = false; break; }
        }
        if (gte) {
            c = 0;
            for (int i = 0; i < MP_WORDS; i++) {
                mp_word t = result->d[i] - mod.d[i] - c;
                c = t > result->d[i] ? 1 : (t == result->d[i] ? c : 0);
                result->d[i] = t;
            }
        }
    };

    mod_add(&two_s, &s, &s);
    mod_add(&four_s, &two_s, &two_s);

    // M = 3*X^2 (a=0 for secp256k1)
    mp_number x2, m;
    mp_mod_mul(&x2, &p->x, &p->x);
    mod_add(&m, &x2, &x2);
    mod_add(&m, &m, &x2);

    // X' = M^2 - 2*S
    mp_number m2, s2_2;
    mp_mod_mul(&m2, &m, &m);
    mod_add(&s2_2, &four_s, &four_s);
    mp_mod_sub(&r->x, &m2, &s2_2);

    // Y' = M*(S - X') - 8*Y^4
    mp_number y4, y4_8;
    mp_mod_mul(&y4, &y2, &y2);
    mod_add(&y4_8, &y4, &y4);
    mod_add(&y4_8, &y4_8, &y4_8);
    mod_add(&y4_8, &y4_8, &y4_8);

    // Z' = 2*Y*Z - must compute BEFORE modifying r->y due to aliasing (r may equal p)
    mp_mod_mul(&r->z, &p->y, &p->z);
    mod_add(&r->z, &r->z, &r->z);

    // Y' = M*(S - X') - 8*Y^4
    mp_number sdiff;
    mp_mod_sub(&sdiff, &four_s, &r->x);
    mp_mod_mul(&r->y, &m, &sdiff);
    mp_mod_sub(&r->y, &r->y, &y4_8);
}

inline void jpoint_add(thread JPoint* r, thread const JPoint* p, thread const JPoint* q) {
    bool p_zero = p->z.d[0] == 0 && p->z.d[1] == 0 && p->z.d[2] == 0 && p->z.d[3] == 0 &&
                  p->z.d[4] == 0 && p->z.d[5] == 0 && p->z.d[6] == 0 && p->z.d[7] == 0;
    bool q_zero = q->z.d[0] == 0 && q->z.d[1] == 0 && q->z.d[2] == 0 && q->z.d[3] == 0 &&
                  q->z.d[4] == 0 && q->z.d[5] == 0 && q->z.d[6] == 0 && q->z.d[7] == 0;

    if (p_zero) { *r = *q; return; }
    if (q_zero) { *r = *p; return; }

    auto mod_add = [](thread mp_number* result, thread const mp_number* a, thread const mp_number* b) {
        mp_word c = 0;
        for (int i = 0; i < MP_WORDS; i++) {
            result->d[i] = a->d[i] + b->d[i] + c;
            c = result->d[i] < a->d[i] ? 1 : (result->d[i] == a->d[i] ? c : 0);
        }
        bool gte = true;
        for (int i = MP_WORDS - 1; i >= 0; i--) {
            if (result->d[i] > mod.d[i]) break;
            if (result->d[i] < mod.d[i]) { gte = false; break; }
        }
        if (gte) {
            c = 0;
            for (int i = 0; i < MP_WORDS; i++) {
                mp_word t = result->d[i] - mod.d[i] - c;
                c = t > result->d[i] ? 1 : (t == result->d[i] ? c : 0);
                result->d[i] = t;
            }
        }
    };

    mp_number z1z1, z2z2, u1, u2, s1, s2, h, rr;

    mp_mod_mul(&z1z1, &p->z, &p->z);
    mp_mod_mul(&z2z2, &q->z, &q->z);
    mp_mod_mul(&u1, &p->x, &z2z2);
    mp_mod_mul(&u2, &q->x, &z1z1);

    mp_number tmp;
    mp_mod_mul(&tmp, &q->z, &z2z2);
    mp_mod_mul(&s1, &p->y, &tmp);
    mp_mod_mul(&tmp, &p->z, &z1z1);
    mp_mod_mul(&s2, &q->y, &tmp);

    mp_mod_sub(&h, &u2, &u1);
    mp_mod_sub(&rr, &s2, &s1);

    // Check if h == 0
    bool h_zero = h.d[0] == 0 && h.d[1] == 0 && h.d[2] == 0 && h.d[3] == 0 &&
                  h.d[4] == 0 && h.d[5] == 0 && h.d[6] == 0 && h.d[7] == 0;
    if (h_zero) {
        bool rr_zero = rr.d[0] == 0 && rr.d[1] == 0 && rr.d[2] == 0 && rr.d[3] == 0 &&
                       rr.d[4] == 0 && rr.d[5] == 0 && rr.d[6] == 0 && rr.d[7] == 0;
        if (rr_zero) {
            jpoint_double(r, p);
        } else {
            // Point at infinity
            for (int i = 0; i < MP_WORDS; i++) { r->x.d[i] = 0; r->y.d[i] = 0; r->z.d[i] = 0; }
        }
        return;
    }

    mp_number h2, h3, u1h2;
    mp_mod_mul(&h2, &h, &h);
    mp_mod_mul(&h3, &h, &h2);
    mp_mod_mul(&u1h2, &u1, &h2);

    mp_number r2, u1h2_2;
    mp_mod_mul(&r2, &rr, &rr);
    mod_add(&u1h2_2, &u1h2, &u1h2);

    mp_mod_sub(&r->x, &r2, &h3);
    mp_mod_sub(&r->x, &r->x, &u1h2_2);

    mp_mod_sub(&tmp, &u1h2, &r->x);
    mp_mod_mul(&r->y, &rr, &tmp);
    mp_mod_mul(&tmp, &s1, &h3);
    mp_mod_sub(&r->y, &r->y, &tmp);

    mp_mod_mul(&tmp, &p->z, &q->z);
    mp_mod_mul(&r->z, &tmp, &h);
}

kernel void compute_initial_points(
    device const uint32_t* privateKeys [[buffer(0)]],
    device mp_number* deltaX [[buffer(1)]],
    device mp_number* prevLambda [[buffer(2)]],
    uint tid [[thread_position_in_grid]]
) {
    // Load private key (8 x 32-bit words)
    mp_number k;
    for (int i = 0; i < MP_WORDS; i++) {
        k.d[i] = privateKeys[tid * MP_WORDS + i];
    }

    // Compute k*G using double-and-add
    JPoint result = {{{0}}, {{0}}, {{0}}};
    JPoint g;
    for (int i = 0; i < MP_WORDS; i++) {
        g.x.d[i] = GX.d[i];
        g.y.d[i] = GY.d[i];
    }
    g.z.d[0] = 1;
    for (int i = 1; i < MP_WORDS; i++) g.z.d[i] = 0;

    for (int bit = 255; bit >= 0; bit--) {
        jpoint_double(&result, &result);
        int wordIdx = bit / 32;
        int bitIdx = bit % 32;
        if ((k.d[wordIdx] >> bitIdx) & 1) {
            jpoint_add(&result, &result, &g);
        }
    }

    // Convert to affine
    mp_number zinv = result.z;
    mp_mod_inverse(&zinv);
    mp_number zinv2, zinv3;
    mp_mod_mul(&zinv2, &zinv, &zinv);
    mp_mod_mul(&zinv3, &zinv2, &zinv);

    mp_number px, py;
    mp_mod_mul(&px, &result.x, &zinv2);
    mp_mod_mul(&py, &result.y, &zinv3);

    // Compute initial lambda: (Gy - py) / (Gx - px)
    mp_number dx, dy;
    mp_mod_sub_gx(&dx, &px);  // dx = px - Gx (but we want Gx - px)
    // Actually mp_mod_sub_gx computes r = a - Gx, so dx = px - Gx
    // We need Gx - px = -(px - Gx)
    // Let's compute properly:
    mp_number gx_local, gy_local;
    for (int i = 0; i < MP_WORDS; i++) {
        gx_local.d[i] = GX.d[i];
        gy_local.d[i] = GY.d[i];
    }
    mp_mod_sub(&dx, &gx_local, &px);
    mp_mod_sub(&dy, &gy_local, &py);

    mp_number dx_inv = dx;
    mp_mod_inverse(&dx_inv);

    mp_number lambda;
    mp_mod_mul(&lambda, &dy, &dx_inv);

    // Add G to get next point
    // newPx = lambda^2 - Gx - px
    mp_number lambda2;
    mp_mod_mul(&lambda2, &lambda, &lambda);
    mp_number newPx;
    mp_mod_sub(&newPx, &lambda2, &gx_local);
    mp_mod_sub(&newPx, &newPx, &px);

    // Store delta: newPx - Gx
    mp_number delta;
    mp_mod_sub_gx(&delta, &newPx);
    deltaX[tid] = delta;

    // Store lambda
    prevLambda[tid] = lambda;
}
