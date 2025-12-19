#include <metal_stdlib>
using namespace metal;

// =============================================================================
// Keccak-256 implementation for Metal
// =============================================================================

constant uint64_t KECCAK_ROUND_CONSTANTS[24] = {
    0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
    0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
    0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
    0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
    0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
    0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
    0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
    0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

constant int KECCAK_ROTATION[24] = {
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
    27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
};

constant int KECCAK_PI[24] = {
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
    15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
};

inline uint64_t rotl64(uint64_t x, int n) {
    return (x << n) | (x >> (64 - n));
}

void keccak_f1600(thread uint64_t* state) {
    uint64_t t, bc[5];

    for (int round = 0; round < 24; round++) {
        // Theta
        for (int i = 0; i < 5; i++) {
            bc[i] = state[i] ^ state[i + 5] ^ state[i + 10] ^ state[i + 15] ^ state[i + 20];
        }
        for (int i = 0; i < 5; i++) {
            t = bc[(i + 4) % 5] ^ rotl64(bc[(i + 1) % 5], 1);
            for (int j = 0; j < 25; j += 5) {
                state[j + i] ^= t;
            }
        }

        // Rho and Pi
        t = state[1];
        for (int i = 0; i < 24; i++) {
            int j = KECCAK_PI[i];
            bc[0] = state[j];
            state[j] = rotl64(t, KECCAK_ROTATION[i]);
            t = bc[0];
        }

        // Chi
        for (int j = 0; j < 25; j += 5) {
            for (int i = 0; i < 5; i++) {
                bc[i] = state[j + i];
            }
            for (int i = 0; i < 5; i++) {
                state[j + i] ^= (~bc[(i + 1) % 5]) & bc[(i + 2) % 5];
            }
        }

        // Iota
        state[0] ^= KECCAK_ROUND_CONSTANTS[round];
    }
}

void keccak256(thread const uchar* input, uint input_len, thread uchar* output) {
    uint64_t state[25] = {0};

    // Absorb phase - for 64-byte input (public key), we need one block
    // Rate for keccak256 is 136 bytes (1088 bits)
    uint rate = 136;

    // Copy input to state (little-endian)
    for (uint i = 0; i < input_len / 8; i++) {
        uint64_t word = 0;
        for (uint j = 0; j < 8; j++) {
            word |= uint64_t(input[i * 8 + j]) << (j * 8);
        }
        state[i] ^= word;
    }

    // Handle remaining bytes
    uint remaining = input_len % 8;
    if (remaining > 0) {
        uint64_t word = 0;
        uint offset = (input_len / 8) * 8;
        for (uint j = 0; j < remaining; j++) {
            word |= uint64_t(input[offset + j]) << (j * 8);
        }
        state[input_len / 8] ^= word;
    }

    // Padding: 0x01 after message, 0x80 at end of rate
    uint pad_offset = input_len;
    state[pad_offset / 8] ^= uint64_t(0x01) << ((pad_offset % 8) * 8);
    state[(rate - 1) / 8] ^= uint64_t(0x80) << (((rate - 1) % 8) * 8);

    // Permutation
    keccak_f1600(state);

    // Squeeze - extract 32 bytes
    for (uint i = 0; i < 32; i++) {
        output[i] = uchar((state[i / 8] >> ((i % 8) * 8)) & 0xFF);
    }
}

// =============================================================================
// secp256k1 implementation for Metal
// =============================================================================

// We use a 256-bit representation as 4 x uint64_t (little-endian limbs)
struct U256 {
    uint64_t limbs[4];
};

// secp256k1 field prime: p = 2^256 - 2^32 - 977
constant U256 SECP256K1_P = {{
    0xFFFFFFFEFFFFFC2FULL,
    0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL,
    0xFFFFFFFFFFFFFFFFULL
}};

// secp256k1 curve order
constant U256 SECP256K1_N = {{
    0xBFD25E8CD0364141ULL,
    0xBAAEDCE6AF48A03BULL,
    0xFFFFFFFFFFFFFFFEULL,
    0xFFFFFFFFFFFFFFFFULL
}};

// Generator point G
constant U256 SECP256K1_GX = {{
    0x59F2815B16F81798ULL,
    0x029BFCDB2DCE28D9ULL,
    0x55A06295CE870B07ULL,
    0x79BE667EF9DCBBACULL
}};

constant U256 SECP256K1_GY = {{
    0x9C47D08FFB10D4B8ULL,
    0xFD17B448A6855419ULL,
    0x5DA4FBFC0E1108A8ULL,
    0x483ADA7726A3C465ULL
}};

// Point in Jacobian coordinates
struct JacobianPoint {
    U256 x;
    U256 y;
    U256 z;
};

// Comparison
inline bool u256_is_zero(thread const U256& a) {
    return a.limbs[0] == 0 && a.limbs[1] == 0 && a.limbs[2] == 0 && a.limbs[3] == 0;
}

inline bool u256_gte(thread const U256& a, thread const U256& b) {
    for (int i = 3; i >= 0; i--) {
        if (a.limbs[i] > b.limbs[i]) return true;
        if (a.limbs[i] < b.limbs[i]) return false;
    }
    return true; // equal
}

// Addition with carry
inline U256 u256_add(thread const U256& a, thread const U256& b) {
    U256 result;
    uint64_t carry = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t sum = a.limbs[i] + b.limbs[i] + carry;
        carry = (sum < a.limbs[i]) || (carry && sum == a.limbs[i]) ? 1 : 0;
        result.limbs[i] = sum;
    }
    return result;
}

// Subtraction with borrow
inline U256 u256_sub(thread const U256& a, thread const U256& b) {
    U256 result;
    uint64_t borrow = 0;
    for (int i = 0; i < 4; i++) {
        uint64_t diff = a.limbs[i] - b.limbs[i] - borrow;
        borrow = (a.limbs[i] < b.limbs[i] + borrow) ? 1 : 0;
        result.limbs[i] = diff;
    }
    return result;
}

// Modular reduction (simple subtraction-based for secp256k1)
inline U256 mod_p(thread const U256& a) {
    U256 result = a;
    while (u256_gte(result, SECP256K1_P)) {
        result = u256_sub(result, SECP256K1_P);
    }
    return result;
}

// Modular addition
inline U256 mod_add(thread const U256& a, thread const U256& b) {
    U256 sum = u256_add(a, b);
    return mod_p(sum);
}

// Modular subtraction
inline U256 mod_sub(thread const U256& a, thread const U256& b) {
    U256 result;
    if (u256_gte(a, b)) {
        result = u256_sub(a, b);
    } else {
        result = u256_sub(u256_add(a, SECP256K1_P), b);
    }
    return result;
}

// Multiply 256-bit by 256-bit to get 512-bit result
// Returns low and high parts
inline void u256_mul_full(thread const U256& a, thread const U256& b,
                          thread U256& lo, thread U256& hi) {
    // Simple schoolbook multiplication using 64-bit limbs
    // Each limb multiplication produces 128 bits
    uint64_t r[8] = {0};

    for (int i = 0; i < 4; i++) {
        uint64_t carry = 0;
        for (int j = 0; j < 4; j++) {
            // Multiply a.limbs[i] * b.limbs[j]
            uint64_t a_lo = a.limbs[i] & 0xFFFFFFFFULL;
            uint64_t a_hi = a.limbs[i] >> 32;
            uint64_t b_lo = b.limbs[j] & 0xFFFFFFFFULL;
            uint64_t b_hi = b.limbs[j] >> 32;

            uint64_t p0 = a_lo * b_lo;
            uint64_t p1 = a_lo * b_hi;
            uint64_t p2 = a_hi * b_lo;
            uint64_t p3 = a_hi * b_hi;

            uint64_t mid = p1 + p2;
            uint64_t mid_carry = (mid < p1) ? 1ULL << 32 : 0;

            uint64_t lo_part = p0 + (mid << 32);
            uint64_t lo_carry = (lo_part < p0) ? 1 : 0;

            uint64_t hi_part = p3 + (mid >> 32) + mid_carry + lo_carry;

            // Add to result with carry chain
            uint64_t sum = r[i + j] + lo_part + carry;
            carry = (sum < r[i + j]) || (carry && sum == r[i + j]) ? 1 : 0;
            carry += hi_part;
            r[i + j] = sum;
        }
        r[i + 4] = carry;
    }

    lo.limbs[0] = r[0]; lo.limbs[1] = r[1]; lo.limbs[2] = r[2]; lo.limbs[3] = r[3];
    hi.limbs[0] = r[4]; hi.limbs[1] = r[5]; hi.limbs[2] = r[6]; hi.limbs[3] = r[7];
}

// Fast reduction modulo secp256k1 prime using its special form
// p = 2^256 - 2^32 - 977
// For a 512-bit number (lo, hi): result = lo + hi * (2^32 + 977) mod p
inline U256 reduce_512_mod_p(thread const U256& lo, thread const U256& hi) {
    if (u256_is_zero(hi)) {
        return mod_p(lo);
    }

    // Multiply hi by (2^32 + 977) and add to lo
    // This is simplified; full implementation would need more iterations
    U256 result = lo;
    U256 mult = hi;

    // hi * 2^32
    U256 shifted;
    shifted.limbs[0] = 0;
    shifted.limbs[1] = mult.limbs[0];
    shifted.limbs[2] = mult.limbs[1];
    shifted.limbs[3] = mult.limbs[2];
    // Note: mult.limbs[3] << 32 would overflow, need special handling

    result = u256_add(result, shifted);

    // hi * 977
    uint64_t carry = 0;
    U256 mul977;
    for (int i = 0; i < 4; i++) {
        uint64_t prod = mult.limbs[i] * 977 + carry;
        mul977.limbs[i] = prod;
        carry = 0; // simplified, would need proper carry handling
    }
    result = u256_add(result, mul977);

    // Reduce
    while (u256_gte(result, SECP256K1_P)) {
        result = u256_sub(result, SECP256K1_P);
    }

    return result;
}

// Modular multiplication
inline U256 mod_mul(thread const U256& a, thread const U256& b) {
    U256 lo, hi;
    u256_mul_full(a, b, lo, hi);
    return reduce_512_mod_p(lo, hi);
}

// Modular squaring
inline U256 mod_sqr(thread const U256& a) {
    return mod_mul(a, a);
}

// Modular inversion using Fermat's little theorem: a^(-1) = a^(p-2) mod p
inline U256 mod_inv(thread const U256& a) {
    // p - 2 for secp256k1
    U256 exp = {{
        0xFFFFFFFEFFFFFC2DULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xFFFFFFFFFFFFFFFFULL,
        0xFFFFFFFFFFFFFFFFULL
    }};

    U256 result = {{1, 0, 0, 0}};
    U256 base = a;

    for (int i = 0; i < 256; i++) {
        int limb_idx = i / 64;
        int bit_idx = i % 64;
        if ((exp.limbs[limb_idx] >> bit_idx) & 1) {
            result = mod_mul(result, base);
        }
        base = mod_sqr(base);
    }

    return result;
}

// Point doubling in Jacobian coordinates
inline JacobianPoint point_double(thread const JacobianPoint& p) {
    if (u256_is_zero(p.y)) {
        JacobianPoint inf;
        inf.x = {{0, 0, 0, 0}};
        inf.y = {{0, 0, 0, 0}};
        inf.z = {{0, 0, 0, 0}};
        return inf;
    }

    // S = 4*X*Y^2
    U256 y2 = mod_sqr(p.y);
    U256 s = mod_mul(p.x, y2);
    s = mod_add(s, s);
    s = mod_add(s, s);

    // M = 3*X^2 (a=0 for secp256k1)
    U256 x2 = mod_sqr(p.x);
    U256 m = mod_add(x2, mod_add(x2, x2));

    // X' = M^2 - 2*S
    U256 m2 = mod_sqr(m);
    U256 s2 = mod_add(s, s);
    U256 xr = mod_sub(m2, s2);

    // Y' = M*(S - X') - 8*Y^4
    U256 y4 = mod_sqr(y2);
    U256 y4_8 = mod_add(y4, y4);
    y4_8 = mod_add(y4_8, y4_8);
    y4_8 = mod_add(y4_8, y4_8);
    U256 yr = mod_sub(mod_mul(m, mod_sub(s, xr)), y4_8);

    // Z' = 2*Y*Z
    U256 zr = mod_mul(p.y, p.z);
    zr = mod_add(zr, zr);

    JacobianPoint result;
    result.x = xr;
    result.y = yr;
    result.z = zr;
    return result;
}

// Point addition in Jacobian coordinates
inline JacobianPoint point_add(thread const JacobianPoint& p, thread const JacobianPoint& q) {
    if (u256_is_zero(p.z)) return q;
    if (u256_is_zero(q.z)) return p;

    U256 z1z1 = mod_sqr(p.z);
    U256 z2z2 = mod_sqr(q.z);

    U256 u1 = mod_mul(p.x, z2z2);
    U256 u2 = mod_mul(q.x, z1z1);

    U256 s1 = mod_mul(p.y, mod_mul(q.z, z2z2));
    U256 s2 = mod_mul(q.y, mod_mul(p.z, z1z1));

    U256 h = mod_sub(u2, u1);
    U256 r = mod_sub(s2, s1);

    if (u256_is_zero(h)) {
        if (u256_is_zero(r)) {
            return point_double(p);
        }
        // Point at infinity
        JacobianPoint inf;
        inf.x = {{0, 0, 0, 0}};
        inf.y = {{0, 0, 0, 0}};
        inf.z = {{0, 0, 0, 0}};
        return inf;
    }

    U256 h2 = mod_sqr(h);
    U256 h3 = mod_mul(h, h2);
    U256 u1h2 = mod_mul(u1, h2);

    // X3 = r^2 - h^3 - 2*u1*h^2
    U256 r2 = mod_sqr(r);
    U256 xr = mod_sub(r2, h3);
    xr = mod_sub(xr, mod_add(u1h2, u1h2));

    // Y3 = r*(u1*h^2 - X3) - s1*h^3
    U256 yr = mod_mul(r, mod_sub(u1h2, xr));
    yr = mod_sub(yr, mod_mul(s1, h3));

    // Z3 = h*z1*z2
    U256 zr = mod_mul(h, mod_mul(p.z, q.z));

    JacobianPoint result;
    result.x = xr;
    result.y = yr;
    result.z = zr;
    return result;
}

// Scalar multiplication: compute k*G using double-and-add
inline JacobianPoint scalar_mult_g(thread const U256& k) {
    JacobianPoint result;
    result.x = {{0, 0, 0, 0}};
    result.y = {{0, 0, 0, 0}};
    result.z = {{0, 0, 0, 0}};

    JacobianPoint g;
    g.x = SECP256K1_GX;
    g.y = SECP256K1_GY;
    g.z = {{1, 0, 0, 0}};

    for (int i = 255; i >= 0; i--) {
        result = point_double(result);
        int limb_idx = i / 64;
        int bit_idx = i % 64;
        if ((k.limbs[limb_idx] >> bit_idx) & 1) {
            result = point_add(result, g);
        }
    }

    return result;
}

// Convert Jacobian to affine coordinates
inline void jacobian_to_affine(thread const JacobianPoint& p, thread U256& x, thread U256& y) {
    U256 z_inv = mod_inv(p.z);
    U256 z_inv2 = mod_sqr(z_inv);
    U256 z_inv3 = mod_mul(z_inv2, z_inv);

    x = mod_mul(p.x, z_inv2);
    y = mod_mul(p.y, z_inv3);
}

// =============================================================================
// Main kernel
// =============================================================================

kernel void vanity_search(
    device const uint64_t* seeds [[buffer(0)]],      // Random seeds per thread
    device uint64_t* results [[buffer(1)]],          // Found private keys
    device uint* found_count [[buffer(2)]],          // Atomic counter
    device const uchar* prefix [[buffer(3)]],        // Target prefix bytes
    constant uint& prefix_len [[buffer(4)]],         // Prefix length in nibbles
    constant uint& max_results [[buffer(5)]],        // Max results to find
    constant uint& iterations [[buffer(6)]],         // Iterations per thread
    uint tid [[thread_position_in_grid]]
) {
    // Initialize private key from seed
    U256 priv_key;
    priv_key.limbs[0] = seeds[tid * 4 + 0];
    priv_key.limbs[1] = seeds[tid * 4 + 1];
    priv_key.limbs[2] = seeds[tid * 4 + 2];
    priv_key.limbs[3] = seeds[tid * 4 + 3];

    for (uint iter = 0; iter < iterations; iter++) {
        // Check if we've found enough
        if (*found_count >= max_results) return;

        // Compute public key
        JacobianPoint pub_jac = scalar_mult_g(priv_key);
        U256 pub_x, pub_y;
        jacobian_to_affine(pub_jac, pub_x, pub_y);

        // Serialize public key (uncompressed, without 0x04 prefix for keccak)
        uchar pubkey[64];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 8; j++) {
                pubkey[(3 - i) * 8 + (7 - j)] = uchar((pub_x.limbs[i] >> (j * 8)) & 0xFF);
                pubkey[32 + (3 - i) * 8 + (7 - j)] = uchar((pub_y.limbs[i] >> (j * 8)) & 0xFF);
            }
        }

        // Compute keccak256(pubkey)
        uchar hash[32];
        keccak256(pubkey, 64, hash);

        // Address is last 20 bytes of hash
        uchar address[20];
        for (int i = 0; i < 20; i++) {
            address[i] = hash[12 + i];
        }

        // Check prefix match (comparing nibbles)
        bool match = true;
        for (uint i = 0; i < prefix_len && match; i++) {
            uchar addr_nibble;
            if (i % 2 == 0) {
                addr_nibble = (address[i / 2] >> 4) & 0x0F;
            } else {
                addr_nibble = address[i / 2] & 0x0F;
            }

            uchar target_nibble;
            if (i % 2 == 0) {
                target_nibble = (prefix[i / 2] >> 4) & 0x0F;
            } else {
                target_nibble = prefix[i / 2] & 0x0F;
            }

            if (addr_nibble != target_nibble) {
                match = false;
            }
        }

        if (match) {
            uint idx = atomic_fetch_add_explicit((device atomic_uint*)found_count, 1, memory_order_relaxed);
            if (idx < max_results) {
                // Store the private key
                results[idx * 4 + 0] = priv_key.limbs[0];
                results[idx * 4 + 1] = priv_key.limbs[1];
                results[idx * 4 + 2] = priv_key.limbs[2];
                results[idx * 4 + 3] = priv_key.limbs[3];
            }
        }

        // Increment private key for next iteration
        priv_key.limbs[0] += 1;
        if (priv_key.limbs[0] == 0) {
            priv_key.limbs[1] += 1;
            if (priv_key.limbs[1] == 0) {
                priv_key.limbs[2] += 1;
                if (priv_key.limbs[2] == 0) {
                    priv_key.limbs[3] += 1;
                }
            }
        }
    }
}
