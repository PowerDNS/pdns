/**
 * Untrinsics - Header-only portable implementations of common Intel intrinsics
 * for cryptographic implementations.
 * https://github.com/jedisct1/untrinsics
 * (C) 2025 Frank Denis <j [at] pureftpd.org> - Public Domain.
 */

#ifndef untrinsics_H
#define untrinsics_H

#define __untrinsics__ 1

#include <stdint.h>
#include <string.h>

#ifndef __has_attribute
#    define __has_attribute(x) 0
#endif
#if !(__has_attribute(aligned) || defined(__GNUC__) || defined(__clang__) || defined(__attribute__))
#    define __attribute__(x)
#endif

typedef union {
    uint8_t  b[16];
    uint32_t w[4];
    uint64_t q[2];
} __m128i __attribute__((aligned(16)));

/* clang-format off */

static const uint8_t UNTRINSICS_SBOX[256] __attribute__((aligned(64))) = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static const uint8_t UNTRINSICS_INV_SBOX[256] __attribute__((aligned(64))) = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

/* clang-format on */

static volatile uint8_t  untrinsics_optblocker_u8;
static volatile uint32_t untrinsics_optblocker_u32;
static volatile uint64_t untrinsics_optblocker_u64;

#ifdef UNTRINSICS_MITIGATE
static inline uint8_t
untrinsics_sbox(const uint8_t x)
{
    uint32_t optblocker_u32 = untrinsics_optblocker_u32;
    uint8_t  result         = 0;

    for (int i = 0; i < 256; i++) {
        uint32_t diff = (uint32_t) (i ^ x);
        uint32_t mask = (((diff - 1) >> 29) ^ optblocker_u32) >> 2;
        result |= UNTRINSICS_SBOX[i] & -(uint8_t) mask;
    }
    return result;
}

static inline uint8_t
untrinsics_inv_sbox(const uint8_t x)
{
    uint32_t optblocker_u32 = untrinsics_optblocker_u32;
    uint8_t  result         = 0;

    for (int i = 0; i < 256; i++) {
        uint32_t diff = (uint32_t) (i ^ x);
        uint32_t mask = (((diff - 1) >> 29) ^ optblocker_u32) >> 2;
        result |= UNTRINSICS_INV_SBOX[i] & -(uint8_t) mask;
    }
    return result;
}
#else
#    define untrinsics_sbox(x)     UNTRINSICS_SBOX[x]
#    define untrinsics_inv_sbox(x) UNTRINSICS_INV_SBOX[x]
#endif

/* Multiply by x in GF(2^8) using the AES polynomial (usually compiled to branchless code) */
static inline uint8_t
untrinsics_xtime(uint8_t x)
{
    return (uint8_t) ((x << 1) ^ ((x & 0x80) ? 0x1B : 0));
}

/* Multiply by 2 (MixColumns) */
static inline uint8_t
untrinsics_mul2(uint8_t x)
{
    return untrinsics_xtime(x);
}

/* Multiply by 3 (MixColumns) */
static inline uint8_t
untrinsics_mul3(uint8_t x)
{
    return (uint8_t) (untrinsics_xtime(x) ^ x);
}

/* Multiply by 9 (InvMixColumns) */
static inline uint8_t
untrinsics_mul9(uint8_t x)
{
    uint8_t t2 = untrinsics_xtime(x);
    uint8_t t4 = untrinsics_xtime(t2);
    uint8_t t8 = untrinsics_xtime(t4);
    return (uint8_t) (t8 ^ x);
}

/* Multiply by 0x0B (InvMixColumns) */
static inline uint8_t
untrinsics_mul0b(uint8_t x)
{
    uint8_t t2 = untrinsics_xtime(x);
    uint8_t t4 = untrinsics_xtime(t2);
    uint8_t t8 = untrinsics_xtime(t4);
    return (uint8_t) (t8 ^ t2 ^ x);
}

/* Multiply by 0x0D (InvMixColumns) */
static inline uint8_t
untrinsics_mul0d(uint8_t x)
{
    uint8_t t2 = untrinsics_xtime(x);
    uint8_t t4 = untrinsics_xtime(t2);
    uint8_t t8 = untrinsics_xtime(t4);
    return (uint8_t) (t8 ^ t4 ^ x);
}

/* Multiply by 0x0E (InvMixColumns) */
static inline uint8_t
untrinsics_mul0e(uint8_t x)
{
    uint8_t t2 = untrinsics_xtime(x);
    uint8_t t4 = untrinsics_xtime(t2);
    uint8_t t8 = untrinsics_xtime(t4);
    return (uint8_t) (t8 ^ t4 ^ t2);
}

/* Combine SubBytes and ShiftRows (forward) */
static inline void
untrinsics_sub_shiftrows(uint8_t s[16])
{
    uint8_t tmp[16];
    tmp[0]  = untrinsics_sbox(s[0]);
    tmp[1]  = untrinsics_sbox(s[5]);
    tmp[2]  = untrinsics_sbox(s[10]);
    tmp[3]  = untrinsics_sbox(s[15]);
    tmp[4]  = untrinsics_sbox(s[4]);
    tmp[5]  = untrinsics_sbox(s[9]);
    tmp[6]  = untrinsics_sbox(s[14]);
    tmp[7]  = untrinsics_sbox(s[3]);
    tmp[8]  = untrinsics_sbox(s[8]);
    tmp[9]  = untrinsics_sbox(s[13]);
    tmp[10] = untrinsics_sbox(s[2]);
    tmp[11] = untrinsics_sbox(s[7]);
    tmp[12] = untrinsics_sbox(s[12]);
    tmp[13] = untrinsics_sbox(s[1]);
    tmp[14] = untrinsics_sbox(s[6]);
    tmp[15] = untrinsics_sbox(s[11]);
    memcpy(s, tmp, 16);
}

/* Combine InvSubBytes and InvShiftRows */
static inline void
untrinsics_invsub_shiftrows(uint8_t s[16])
{
    uint8_t tmp[16];
    tmp[0]  = untrinsics_inv_sbox(s[0]);
    tmp[1]  = untrinsics_inv_sbox(s[13]);
    tmp[2]  = untrinsics_inv_sbox(s[10]);
    tmp[3]  = untrinsics_inv_sbox(s[7]);
    tmp[4]  = untrinsics_inv_sbox(s[4]);
    tmp[5]  = untrinsics_inv_sbox(s[1]);
    tmp[6]  = untrinsics_inv_sbox(s[14]);
    tmp[7]  = untrinsics_inv_sbox(s[11]);
    tmp[8]  = untrinsics_inv_sbox(s[8]);
    tmp[9]  = untrinsics_inv_sbox(s[5]);
    tmp[10] = untrinsics_inv_sbox(s[2]);
    tmp[11] = untrinsics_inv_sbox(s[15]);
    tmp[12] = untrinsics_inv_sbox(s[12]);
    tmp[13] = untrinsics_inv_sbox(s[9]);
    tmp[14] = untrinsics_inv_sbox(s[6]);
    tmp[15] = untrinsics_inv_sbox(s[3]);
    memcpy(s, tmp, 16);
}

/* MixColumns transformation (forward) */
static inline void
untrinsics_mixcolumns(uint8_t s[16])
{
    for (int c = 0; c < 4; c++) {
        int     i  = 4 * c;
        uint8_t a0 = s[i], a1 = s[i + 1], a2 = s[i + 2], a3 = s[i + 3];
        s[i]     = (uint8_t) (untrinsics_mul2(a0) ^ untrinsics_mul3(a1) ^ a2 ^ a3);
        s[i + 1] = (uint8_t) (a0 ^ untrinsics_mul2(a1) ^ untrinsics_mul3(a2) ^ a3);
        s[i + 2] = (uint8_t) (a0 ^ a1 ^ untrinsics_mul2(a2) ^ untrinsics_mul3(a3));
        s[i + 3] = (uint8_t) (untrinsics_mul3(a0) ^ a1 ^ a2 ^ untrinsics_mul2(a3));
    }
}

/* InvMixColumns transformation */
static inline void
untrinsics_inv_mixcolumns(uint8_t s[16])
{
    for (int c = 0; c < 4; c++) {
        int     i  = 4 * c;
        uint8_t a0 = s[i], a1 = s[i + 1], a2 = s[i + 2], a3 = s[i + 3];
        s[i]     = (uint8_t) (untrinsics_mul0e(a0) ^ untrinsics_mul0b(a1) ^ untrinsics_mul0d(a2) ^
                          untrinsics_mul9(a3));
        s[i + 1] = (uint8_t) (untrinsics_mul9(a0) ^ untrinsics_mul0e(a1) ^ untrinsics_mul0b(a2) ^
                              untrinsics_mul0d(a3));
        s[i + 2] = (uint8_t) (untrinsics_mul0d(a0) ^ untrinsics_mul9(a1) ^ untrinsics_mul0e(a2) ^
                              untrinsics_mul0b(a3));
        s[i + 3] = (uint8_t) (untrinsics_mul0b(a0) ^ untrinsics_mul0d(a1) ^ untrinsics_mul9(a2) ^
                              untrinsics_mul0e(a3));
    }
}

/* Rotate a 32-bit word right by 8 bits */
static inline uint32_t
untrinsics_rot_word(const uint32_t x)
{
    return (x >> 8) | (x << 24);
}

/* Apply S-box to each byte in a 32-bit word */
static inline uint32_t
untrinsics_sub_word(const uint32_t x)
{
    return ((uint32_t) untrinsics_sbox((x >> 24) & 0xff) << 24) |
           ((uint32_t) untrinsics_sbox((x >> 16) & 0xff) << 16) |
           ((uint32_t) untrinsics_sbox((x >> 8) & 0xff) << 8) |
           ((uint32_t) untrinsics_sbox(x & 0xff));
}

/* Copy __m128i value */
static inline __m128i
untrinsics_copy(const __m128i a)
{
    __m128i r;
    memcpy(r.b, a.b, 16);
    return r;
}

/* AES encryption round */
static inline __m128i
_mm_aesenc_si128(const __m128i a_, const __m128i rk)
{
    __m128i a = untrinsics_copy(a_);
    untrinsics_sub_shiftrows(a.b);
    untrinsics_mixcolumns(a.b);
    for (int i = 0; i < 16; i++)
        a.b[i] ^= rk.b[i];
    return a;
}

/* Final AES encryption round */
static inline __m128i
_mm_aesenclast_si128(const __m128i a_, const __m128i rk)
{
    __m128i a = untrinsics_copy(a_);
    untrinsics_sub_shiftrows(a.b);
    for (int i = 0; i < 16; i++)
        a.b[i] ^= rk.b[i];
    return a;
}

/* AES decryption round */
static inline __m128i
_mm_aesdec_si128(const __m128i a_, const __m128i rk)
{
    __m128i a = untrinsics_copy(a_);
    untrinsics_invsub_shiftrows(a.b);
    untrinsics_inv_mixcolumns(a.b);
    for (int i = 0; i < 16; i++)
        a.b[i] ^= rk.b[i];
    return a;
}

/* Final AES decryption round */
static inline __m128i
_mm_aesdeclast_si128(const __m128i a_, const __m128i rk)
{
    __m128i a = untrinsics_copy(a_);
    untrinsics_invsub_shiftrows(a.b);
    for (int i = 0; i < 16; i++)
        a.b[i] ^= rk.b[i];
    return a;
}

/* Transform encryption round key to decryption key */
static inline __m128i
_mm_aesimc_si128(const __m128i a_)
{
    __m128i a = untrinsics_copy(a_);
    untrinsics_inv_mixcolumns(a.b);
    return a;
}

/* Key expansion assist */
static inline __m128i
_mm_aeskeygenassist_si128(const __m128i a, const uint8_t rcon)
{
    __m128i        dst;
    const uint32_t x1  = a.w[1];
    const uint32_t x3  = a.w[3];
    const uint32_t sx1 = untrinsics_sub_word(x1);
    const uint32_t sx3 = untrinsics_sub_word(x3);

    dst.w[0] = sx1;
    dst.w[1] = untrinsics_rot_word(sx1) ^ rcon;
    dst.w[2] = sx3;
    dst.w[3] = untrinsics_rot_word(sx3) ^ rcon;
    return dst;
}

/* Carry-less multiplication of selected 64-bit lanes.
   imm: bit 0x01 selects lane from a, 0x10 from b.
*/
static inline __m128i
_mm_clmulepi64_si128(const __m128i a, const __m128i b, const int imm)
{
    __m128i  r;
    uint64_t x    = (imm & 1) ? a.q[1] : a.q[0];
    uint64_t y    = (imm & 0x10) ? b.q[1] : b.q[0];
    uint64_t r_lo = 0, r_hi = 0;
    {
        uint64_t bit  = y & 1ULL;
        uint64_t mask = 0ULL - bit;
        r_lo ^= x & mask;
    }
    for (int i = 1; i < 64; i++) {
        uint64_t bit  = (y >> i) & 1ULL;
        uint64_t mask = 0ULL - bit;
        r_lo ^= (x << i) & mask;
        r_hi ^= (x >> (64 - i)) & mask;
    }
    r.q[0] = r_lo;
    r.q[1] = r_hi;
    return r;
}

/* Load 128 bits from unaligned memory */
static inline __m128i
_mm_loadu_si128(const void* const p)
{
    __m128i r;
    memcpy(r.b, p, 16);
    return r;
}

/* Store 128 bits to unaligned memory */
static inline void
_mm_storeu_si128(void* const p, const __m128i a)
{
    memcpy(p, a.b, 16);
}

/* Bitwise XOR of 128-bit values */
static inline __m128i
_mm_xor_si128(const __m128i a, const __m128i b)
{
    __m128i r;
    for (int i = 0; i < 16; i++)
        r.b[i] = (uint8_t) (a.b[i] ^ b.b[i]);
    return r;
}

/* Bitwise OR of 128-bit values */
static inline __m128i
_mm_or_si128(const __m128i a, const __m128i b)
{
    __m128i r;
    for (int i = 0; i < 16; i++)
        r.b[i] = (uint8_t) (a.b[i] | b.b[i]);
    return r;
}

/* Bitwise AND of 128-bit values */
static inline __m128i
_mm_and_si128(const __m128i a, const __m128i b)
{
    __m128i r;
    for (int i = 0; i < 16; i++)
        r.b[i] = (uint8_t) (a.b[i] & b.b[i]);
    return r;
}

/* Set __m128i from two 64-bit integers (high, low) */
static inline __m128i
_mm_set_epi64x(const long long high, const long long low)
{
    __m128i r;
    r.q[0] = (uint64_t) low;
    r.q[1] = (uint64_t) high;
    return r;
}

/* Shift left by imm bytes (zero-fill) */
static inline __m128i
_mm_slli_si128(const __m128i a, const int imm)
{
    __m128i r;
    if (imm <= 0)
        return a;
    if (imm >= 16) {
        memset(r.b, 0, 16);
        return r;
    }
    memset(r.b, 0, imm);
    memcpy(r.b + imm, a.b, 16 - imm);
    return r;
}

/* Shift right by imm bytes (zero-fill) */
static inline __m128i
_mm_srli_si128(const __m128i a, const int imm)
{
    __m128i r;
    if (imm <= 0)
        return a;
    if (imm >= 16) {
        memset(r.b, 0, 16);
        return r;
    }
    memcpy(r.b, a.b + imm, 16 - imm);
    memset(r.b + (16 - imm), 0, imm);
    return r;
}

#ifndef _MM_SHUFFLE
#    define _MM_SHUFFLE(z, y, x, w) (((z & 3) << 6) | ((y & 3) << 4) | ((x & 3) << 2) | (w & 3))
#endif

/* Shuffle 32-bit words */
static inline __m128i
_mm_shuffle_epi32(const __m128i a, const int imm)
{
    __m128i r;
    int     w0 = imm & 0x3;
    int     w1 = (imm >> 2) & 0x3;
    int     w2 = (imm >> 4) & 0x3;
    int     w3 = (imm >> 6) & 0x3;
    r.w[0]     = a.w[w0];
    r.w[1]     = a.w[w1];
    r.w[2]     = a.w[w2];
    r.w[3]     = a.w[w3];
    return r;
}

/* Shuffle bytes using a mask; if mask bit 7 is set, output zero */
static inline __m128i
_mm_shuffle_epi8(const __m128i a, const __m128i b)
{
    __m128i r;
    for (int i = 0; i < 16; i++) {
        uint8_t index = b.b[i] & 0x0F;
        uint8_t mask  = b.b[i] & 0x80;
        r.b[i]        = mask ? 0 : a.b[index];
    }
    return r;
}

/* Load 64 bits from unaligned memory; zero upper half */
static inline __m128i
_mm_loadu_si64(const void* const mem_addr)
{
    __m128i  r;
    uint64_t tmp;
    memcpy(&tmp, mem_addr, 8);
    r.q[0] = tmp;
    r.q[1] = 0;
    return r;
}

/* Set __m128i from 16 int8_t values */
static inline __m128i
_mm_setr_epi8(const int8_t b0, const int8_t b1, const int8_t b2, const int8_t b3, const int8_t b4,
              const int8_t b5, const int8_t b6, const int8_t b7, const int8_t b8, const int8_t b9,
              const int8_t b10, const int8_t b11, const int8_t b12, const int8_t b13,
              const int8_t b14, const int8_t b15)
{
    __m128i r;
    r.b[0]  = b0;
    r.b[1]  = b1;
    r.b[2]  = b2;
    r.b[3]  = b3;
    r.b[4]  = b4;
    r.b[5]  = b5;
    r.b[6]  = b6;
    r.b[7]  = b7;
    r.b[8]  = b8;
    r.b[9]  = b9;
    r.b[10] = b10;
    r.b[11] = b11;
    r.b[12] = b12;
    r.b[13] = b13;
    r.b[14] = b14;
    r.b[15] = b15;
    return r;
}

/* Set __m128i from 16 int values */
static inline __m128i
_mm_setr_epi32(const int e0, const int e1, const int e2, const int e3)
{
    __m128i v;
    v.w[0] = (uint32_t) e0;
    v.w[1] = (uint32_t) e1;
    v.w[2] = (uint32_t) e2;
    v.w[3] = (uint32_t) e3;
    return v;
}

/* Logical right shift each 32-bit lane by imm8 */
static inline __m128i
_mm_srli_epi32(const __m128i v, const int imm8)
{
    __m128i r;
    r.w[0] = v.w[0] >> imm8;
    r.w[1] = v.w[1] >> imm8;
    r.w[2] = v.w[2] >> imm8;
    r.w[3] = v.w[3] >> imm8;
    return r;
}

/* Logical left shift each 32-bit lane by imm8 */
static inline __m128i
_mm_slli_epi32(const __m128i v, const int imm8)
{
    __m128i r;
    r.w[0] = v.w[0] << imm8;
    r.w[1] = v.w[1] << imm8;
    r.w[2] = v.w[2] << imm8;
    r.w[3] = v.w[3] << imm8;
    return r;
}

/* Logical right shift each 16-bit lane by imm8 */
static inline __m128i
_mm_srli_epi16(const __m128i v, const int imm8)
{
    __m128i r;
    for (int i = 0; i < 8; i++) {
        uint16_t val = (uint16_t)v.b[i * 2] | ((uint16_t)v.b[i * 2 + 1] << 8);
        val >>= imm8;
        r.b[i * 2] = (uint8_t)(val & 0xff);
        r.b[i * 2 + 1] = (uint8_t)(val >> 8);
    }
    return r;
}

/* Logical left shift each 16-bit lane by imm8 */
static inline __m128i
_mm_slli_epi16(const __m128i v, const int imm8)
{
    __m128i r;
    for (int i = 0; i < 8; i++) {
        uint16_t val = (uint16_t)v.b[i * 2] | ((uint16_t)v.b[i * 2 + 1] << 8);
        val <<= imm8;
        r.b[i * 2] = (uint8_t)(val & 0xff);
        r.b[i * 2 + 1] = (uint8_t)(val >> 8);
    }
    return r;
}

/* Logical right shift each 64-bit lane by imm8 */
static inline __m128i
_mm_srli_epi64(const __m128i v, const int imm8)
{
    __m128i r;
    r.q[0] = v.q[0] >> imm8;
    r.q[1] = v.q[1] >> imm8;
    return r;
}

/* Logical left shift each 64-bit lane by imm8 */
static inline __m128i
_mm_slli_epi64(const __m128i v, const int imm8)
{
    __m128i r;
    r.q[0] = v.q[0] << imm8;
    r.q[1] = v.q[1] << imm8;
    return r;
}

/* Set __m128i to zero */
static inline __m128i
_mm_setzero_si128(void)
{
    __m128i r;
    memset(r.b, 0, 16);
    return r;
}

/* Set all 16 bytes to the same 8-bit value */
static inline __m128i
_mm_set1_epi8(const int8_t a)
{
    __m128i r;
    for (int i = 0; i < 16; i++)
        r.b[i] = (uint8_t) a;
    return r;
}

/* Add 8-bit integers in two __m128i values */
static inline __m128i
_mm_add_epi8(const __m128i a, const __m128i b)
{
    __m128i r;
    for (int i = 0; i < 16; i++)
        r.b[i] = (uint8_t) (a.b[i] + b.b[i]);
    return r;
}

/* Subtract 8-bit integers in two __m128i values */
static inline __m128i
_mm_sub_epi8(const __m128i a, const __m128i b)
{
    __m128i r;
    for (int i = 0; i < 16; i++)
        r.b[i] = (uint8_t) (a.b[i] - b.b[i]);
    return r;
}

/* Add 64-bit integers in two __m128i values */
static inline __m128i
_mm_add_epi64(const __m128i a, const __m128i b)
{
    __m128i r;
    r.q[0] = a.q[0] + b.q[0];
    r.q[1] = a.q[1] + b.q[1];
    return r;
}

/* Subtract 64-bit integers in two __m128i values */
static inline __m128i
_mm_sub_epi64(const __m128i a, const __m128i b)
{
    __m128i r;
    r.q[0] = a.q[0] - b.q[0];
    r.q[1] = a.q[1] - b.q[1];
    return r;
}

/* Compare 16 bytes for equality; result byte is 0xFF if equal, else 0x00 */
static inline __m128i
_mm_cmpeq_epi8(const __m128i a, const __m128i b)
{
    __m128i  r;
    uint64_t optblocker_u8 = untrinsics_optblocker_u8;
    for (int i = 0; i < 16; i++) {
        uint8_t diff = a.b[i] ^ b.b[i];
        uint8_t t    = ((diff | (uint8_t) (-diff)) >> 5 ^ optblocker_u8) >> 2;
        r.b[i]       = -(t ^ 1);
    }
    return r;
}

/* Compare 16 bytes for less than; result byte is 0xFF if a < b, else 0x00 */
#define _mm_test_all_zeros(M, V) _mm_testz_si128((M), (V))

/* _mm_testz_si128: Returns 1 if (a & b) is all zeros, 0 otherwise. */
static inline int
_mm_testz_si128(const __m128i a, const __m128i b)
{
    uint64_t optblocker_u64 = untrinsics_optblocker_u64;
    uint64_t x              = (a.q[0] & b.q[0]) | (a.q[1] & b.q[1]);
    return (int) (((((x | (optblocker_u64 ^ -x)) >> 61) ^ optblocker_u64) >> 2) ^ 1);
}

/* _mm_test_all_ones: Returns 1 if all bits of a are 1, 0 otherwise. */
static inline int
_mm_test_all_ones(const __m128i a)
{
    uint64_t optblocker_u64 = untrinsics_optblocker_u64;
    uint64_t t              = (a.q[0] ^ ~0ULL) | (a.q[1] ^ ~0ULL);
    return (int) (((((t | (optblocker_u64 ^ -t)) >> 61) ^ optblocker_u64) >> 2) ^ 1);
}

#endif /* UNTRINSICS_H */
