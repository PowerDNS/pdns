/**
 * IPCrypt2: Lightweight IP Address Encryption Library
 *
 * IPCrypt2 provides simple and efficient encryption and decryption of IP addresses (IPv4 & IPv6).
 * Designed for privacy-preserving network applications, it supports four encryption modes:
 *
 * 1. **Format-Preserving AES Encryption**
 *    - Transforms an IP address into another valid IP address of the same size.
 *    - Useful for logs or systems that expect syntactically correct IPs.
 *
 * 2. **Prefix-Preserving AES Encryption (PFX)**
 *    - IP addresses with the same prefix produce encrypted IP addresses with the same prefix.
 *    - The prefix can be of any length.
 *    - Useful for maintaining network structure while anonymizing individual hosts.
 *    - Format-preserving: output remains a valid IP address.
 *
 * 3. **Non-Deterministic AES Encryption (KIASU-BC)**
 *    - Introduces a 64-bit tweak, producing different ciphertexts for the same IP.
 *    - Useful when repeated IPs must remain unlinkable. This mode is not format-preserving.
 *
 * 4. **NDX Mode: Non-Deterministic AES Encryption with Extended Tweaks (AES-XTX)**
 *    - Introduces a 128-bit tweak, producing different ciphertexts for the same IP.
 *    - Useful when repeated IPs must remain unlinkable. This mode is not format-preserving.
 *    - Higher usage limits than KIASU-BC, but half the performance and larger ciphertexts.
 *
 * Additional Features:
 * - Built-in string/binary IP conversion helpers.
 * - Optimized for x86_64 and ARM (aarch64) with AES hardware acceleration.
 * - Minimal external dependencies; just compile and link.
 *
 * Limitations:
 * - Not intended for general-purpose encryption — IP address only.
 * - Ensure keys are secret and tweak values are random or unique per encryption.
 */

#include <stdint.h>
#include <string.h>

#include <sys/types.h>
#ifdef _WIN32
#    include <ws2tcpip.h>
#else
#    include <arpa/inet.h>
#    include <netinet/in.h>
#    include <sys/socket.h>
#endif

#include "include/ipcrypt2.h"

/** Number of AES rounds. For AES-128, this is 10. */
#define ROUNDS 10

#define COMPILER_ASSERT(X) (void) sizeof(char[(X) ? 1 : -1])

#if !defined(_MSC_VER) || _MSC_VER < 1800
#    define __vectorcall
#endif

#ifdef __aarch64__
#    ifndef __ARM_FEATURE_CRYPTO
#        define __ARM_FEATURE_CRYPTO 1
#    endif
#    ifndef __ARM_FEATURE_AES
#        define __ARM_FEATURE_AES 1
#    endif

#    if defined(_MSC_VER) && defined(_M_ARM64)
#        include <arm64_neon.h>
#    else
#        include <arm_neon.h>
#    endif

#    ifdef __clang__
/**
 * Enable AES instructions when compiling with Clang.
 */
#        pragma clang attribute push(__attribute__((target("neon,crypto,aes"))), \
                                     apply_to = function)
#    elif defined(__GNUC__)
/**
 * Enable AES and crypto instructions when compiling with GCC.
 */
#        pragma GCC target("+simd+crypto")
#    endif

/**
 * For AArch64, we represent AES blocks using a 128-bit NEON register (uint64x2_t).
 */
typedef uint64x2_t BlockVec;

/**
 * Load 16 bytes from memory into a NEON register.
 */
#    define LOAD128(a) vld1q_u64((const uint64_t *) (const void *) (a))
/**
 * Store 16 bytes from a NEON register into memory.
 */
#    define STORE128(a, b) vst1q_u64((uint64_t *) (void *) (a), (b))
/**
 * Perform one round of AES encryption (no final round) on block_vec with rkey.
 */
#    define AES_XENCRYPT(block_vec, rkey) \
        vreinterpretq_u64_u8(vaesmcq_u8(vaeseq_u8(rkey, vreinterpretq_u8_u64(block_vec))))
/**
 * Perform the final AES encryption round on block_vec with rkey.
 * The final round excludes the MixColumns step.
 */
#    define AES_XENCRYPTLAST(block_vec, rkey) \
        vreinterpretq_u64_u8(vaeseq_u8(rkey, vreinterpretq_u8_u64(block_vec)))
/**
 * Perform one round of AES decryption (no final round) on block_vec with rkey.
 */
#    define AES_XDECRYPT(block_vec, rkey) \
        vreinterpretq_u64_u8(vaesimcq_u8(vaesdq_u8(rkey, vreinterpretq_u8_u64(block_vec))))
/**
 * Perform the final AES decryption round on block_vec with rkey.
 * The final round excludes the InverseMixColumns step.
 */
#    define AES_XDECRYPTLAST(block_vec, rkey) \
        vreinterpretq_u64_u8(vaesdq_u8(rkey, vreinterpretq_u8_u64(block_vec)))
/**
 * XOR two 128-bit blocks.
 */
#    define XOR128(a, b) veorq_u64((a), (b))
/**
 * XOR three 128-bit blocks.
 */
#    define XOR128_3(a, b, c) veorq_u64(veorq_u64((a), (b)), c)
/**
 * Create a 128-bit register by combining two 64-bit values.
 */
#    define SET64x2(a, b) vsetq_lane_u64((uint64_t) (a), vmovq_n_u64((uint64_t) (b)), 1)
/**
 * Shift left a 128-bit register by b bytes (zero-filling from the right).
 */
#    define BYTESHL128(a, b) vreinterpretq_u64_u8(vextq_s8(vdupq_n_s8(0), (uint8x16_t) a, 16 - (b)))
/**
 * Reorder 32-bit lanes in a 128-bit register according to the indices (a, b, c, d).
 */
#    define SHUFFLE32x4(x, a, b, c, d)                 \
        vreinterpretq_u64_u32(__builtin_shufflevector( \
            vreinterpretq_u32_u64(x), vreinterpretq_u32_u64(x), (a), (b), (c), (d)))
/**
 * Invert an AES round key for decryption.
 */
#    define RKINVERT(rkey) vaesimcq_u8(rkey)
/**
 * Expand the 8-byte tweak into a 128-bit NEON register.
 */
#    define TWEAK_EXPAND(tweak) \
        vreinterpretq_u8_u32(vmovl_u16(vld1_u16((const uint16_t *) (tweak))));

/**
 * Shift an entire 128-bit block left by 1 bit.
 */
static inline BlockVec
SHL1_128(const BlockVec a)
{
    const BlockVec shl     = vshlq_n_u8(a, 1);
    const BlockVec msb     = vshrq_n_u8(a, 7);
    const BlockVec zero    = vdupq_n_u8(0);
    const BlockVec carries = vextq_u8(msb, zero, 1);
    return vorrq_u8(shl, carries);
}

/**
 * Internal function for deriving a subkey using AES key generation instructions.
 * block_vec: the current AES round key block.
 * rc: the round constant.
 */
static inline BlockVec
AES_KEYGEN(BlockVec block_vec, const int rc)
{
    // Perform an AES single round encryption on block_vec with a zero key.
    // This extracts the needed transformation for generating a new round key.
    uint8x16_t a = vaeseq_u8(vreinterpretq_u8_u64(block_vec), vmovq_n_u8(0));
    // Shuffle for the key expansion rotation.
    const uint8x16_t b =
        __builtin_shufflevector(a, a, 4, 1, 14, 11, 1, 14, 11, 4, 12, 9, 6, 3, 9, 6, 3, 12);
    // Combine with round constant.
    const uint64x2_t c = SET64x2((uint64_t) rc << 32, (uint64_t) rc << 32);
    return XOR128(b, c);
}

#else

#    if defined(__x86_64__) || defined(__i386__) || defined(_M_X64) || defined(_M_IX86)

#        ifdef __clang__
/**
 * Enable AES/SSE4.1 instructions when compiling with Clang.
 */
#            pragma clang attribute push(__attribute__((target("aes,sse4.1"))), apply_to = function)
#        elif defined(__GNUC__)
/**
 * Enable AES/SSE4.1 instructions when compiling with GCC.
 */
#            pragma GCC target("aes,sse4.1")
#        elif defined(_MSC_VER)
#            include <intrin.h>
#            pragma intrinsic(_mm_aesenc_si128)
#            pragma intrinsic(_mm_aesenclast_si128)
#            pragma intrinsic(_mm_aesdec_si128)
#            pragma intrinsic(_mm_aesdeclast_si128)
#            pragma intrinsic(_mm_aesimc_si128)
#            pragma intrinsic(_mm_aeskeygenassist_si128)
#        endif

#        include <smmintrin.h>
#        include <tmmintrin.h>
#        include <wmmintrin.h>

#    else
#        ifdef __clang__
#            pragma clang attribute push(__attribute__((target(""))), apply_to = function)
#        elif defined(__GNUC__)
#            pragma GCC target("")
#        endif
#        include "softaes/untrinsics.h"
#    endif

/**
 * On x86_64, we represent AES blocks using __m128i.
 */
typedef __m128i BlockVec;

/**
 * Load 16 bytes from memory into an __m128i.
 */
#    define LOAD128(a)                       _mm_loadu_si128((const BlockVec *) (a))
/**
 * Store 16 bytes from an __m128i into memory.
 */
#    define STORE128(a, b)                   _mm_storeu_si128((BlockVec *) (a), (b))
/**
 * Perform a standard AES round (no final) on block_vec with rkey.
 */
#    define AES_ENCRYPT(block_vec, rkey)     _mm_aesenc_si128((block_vec), (rkey))
/**
 * Perform the final AES round (excludes MixColumns) on block_vec with rkey.
 */
#    define AES_ENCRYPTLAST(block_vec, rkey) _mm_aesenclast_si128((block_vec), (rkey))
/**
 * Perform a standard AES decryption round on block_vec with rkey.
 */
#    define AES_DECRYPT(block_vec, rkey)     _mm_aesdec_si128((block_vec), (rkey))
/**
 * Perform the final AES decryption round (excludes InverseMixColumns) on block_vec with rkey.
 */
#    define AES_DECRYPTLAST(block_vec, rkey) _mm_aesdeclast_si128((block_vec), (rkey))
/**
 * Generate an AES subkey for key expansion.
 */
#    define AES_KEYGEN(block_vec, rc)        _mm_aeskeygenassist_si128((block_vec), (rc))
/**
 * XOR two 128-bit blocks.
 */
#    define XOR128(a, b)                     _mm_xor_si128((a), (b))
/**
 * XOR three 128-bit blocks.
 */
#    define XOR128_3(a, b, c)                _mm_xor_si128(_mm_xor_si128((a), (b)), (c))
/**
 * Construct a 128-bit block from two 64-bit values.
 */
#    define SET64x2(a, b)                    _mm_set_epi64x((uint64_t) (a), (uint64_t) (b))
/**
 * Shift a 128-bit block left by b bytes.
 */
#    define BYTESHL128(a, b)                 _mm_slli_si128(a, b)
/**
 * Reorder 32-bit lanes in a 128-bit block.
 */
#    define SHUFFLE32x4(x, a, b, c, d)       _mm_shuffle_epi32((x), _MM_SHUFFLE((d), (c), (b), (a)))
/**
 * Invert an AES round key for decryption.
 */
#    define RKINVERT(rkey)                   _mm_aesimc_si128(rkey)
/**
 * Expand an 8-byte tweak into a 128-bit register.
 */
#    define TWEAK_EXPAND(tweak)                                                                    \
        _mm_shuffle_epi8(_mm_loadu_si64((const void *) tweak),                                     \
                         _mm_setr_epi8(0x00, 0x01, 0x80, 0x80, 0x02, 0x03, 0x80, 0x80, 0x04, 0x05, \
                                       0x80, 0x80, 0x06, 0x07, 0x80, 0x80))

/**
 * Shift an entire 128-bit block left by 1 bit.
 */
static inline BlockVec
SHL1_128(const BlockVec a)
{
    const BlockVec shl     = _mm_add_epi8(a, a);
    const BlockVec msb     = _mm_and_si128(_mm_srli_epi16(a, 7), _mm_set1_epi8(0x01));
    const BlockVec carries = _mm_srli_si128(msb, 1);
    return _mm_or_si128(shl, carries);
}
#endif

/**
 * KeySchedule is an array of 1 + ROUNDS 128-bit blocks.
 * The first block is the initial round key, followed by ROUNDS subkeys.
 */
typedef BlockVec KeySchedule[1 + ROUNDS];

/**
 * Inverse key schedule for decryption.
 */
typedef BlockVec InvKeySchedule[ROUNDS - 1];

/**
 * AesState holds the expanded round keys for encryption/decryption.
 */
typedef struct AesState {
    KeySchedule rkeys;
} AesState;

/**
 * NDXState holds the expanded tweak round keys and encryption round keys for encryption/decryption.
 */
typedef struct NDXState {
    KeySchedule tkeys;
    KeySchedule rkeys;
} NDXState;

/**
 * PFXState holds the expanded tweak round keys and encryption round keys for encryption/decryption.
 */
typedef struct PFXState {
    KeySchedule k1keys;
    KeySchedule k2keys;
} PFXState;

/**
 * expand_key expands a 16-byte AES key into a full set of round keys.
 * st: the AesState structure to be populated.
 * key: a 16-byte AES key.
 */
static void __vectorcall
expand_key(KeySchedule rkeys, const unsigned char key[IPCRYPT_KEYBYTES])
{
    BlockVec t, s;
    size_t   i = 0;

#define EXPAND_KEY(RC)                        \
    rkeys[i++] = t;                           \
    s          = AES_KEYGEN(t, RC);           \
    t          = XOR128(t, BYTESHL128(t, 4)); \
    t          = XOR128(t, BYTESHL128(t, 8)); \
    t          = XOR128(t, SHUFFLE32x4(s, 3, 3, 3, 3));

    // Load the initial 128-bit key from memory.
    t = LOAD128(key);
    // Repeatedly generate the next round key.
    EXPAND_KEY(0x01);
    EXPAND_KEY(0x02);
    EXPAND_KEY(0x04);
    EXPAND_KEY(0x08);
    EXPAND_KEY(0x10);
    EXPAND_KEY(0x20);
    EXPAND_KEY(0x40);
    EXPAND_KEY(0x80);
    EXPAND_KEY(0x1b);
    EXPAND_KEY(0x36);
    // Store the final key.
    rkeys[i++] = t;
}

/**
 * aes_encrypt encrypts a 16-byte block x in-place using the expanded keys in st.
 */
static void
aes_encrypt(uint8_t x[16], const AesState *st)
{
    const BlockVec *rkeys = st->rkeys;
    BlockVec        t;
    size_t          i;

#ifdef AES_XENCRYPT
    // For AArch64 with AES_XENCRYPT macros.
    t = AES_XENCRYPT(LOAD128(x), rkeys[0]);
    for (i = 1; i < ROUNDS - 1; i++) {
        t = AES_XENCRYPT(t, rkeys[i]);
    }
    t = AES_XENCRYPTLAST(t, rkeys[i]);
    t = XOR128(t, rkeys[ROUNDS]);
#else
    // For x86_64 or a fallback.
    t = XOR128(LOAD128(x), rkeys[0]);
    for (i = 1; i < ROUNDS; i++) {
        t = AES_ENCRYPT(t, rkeys[i]);
    }
    t = AES_ENCRYPTLAST(t, rkeys[ROUNDS]);
#endif
    STORE128(x, t);
}

/**
 * aes_decrypt decrypts a 16-byte block x in-place using the expanded keys in st.
 */
static void
aes_decrypt(uint8_t x[16], const AesState *st)
{
    const BlockVec *rkeys = st->rkeys;
    InvKeySchedule  rkeys_inv;
    BlockVec        t;
    size_t          i;

    // Given the purpose of this library, we assume that decryption is not a frequent operation.
    for (i = 0; i < ROUNDS - 1; i++) {
        rkeys_inv[i] = RKINVERT(rkeys[ROUNDS - 1 - i]);
    }
#ifdef AES_XENCRYPT
    // AArch64 path with AES_XDECRYPT.
    t = AES_XDECRYPT(LOAD128(x), rkeys[ROUNDS]);
    for (i = 0; i < ROUNDS - 2; i++) {
        t = AES_XDECRYPT(t, rkeys_inv[i]);
    }
    t = AES_XDECRYPTLAST(t, rkeys_inv[i]);
    t = XOR128(t, rkeys[0]);
#else
    // x86_64 path using AES_DECRYPT.
    t = XOR128(LOAD128(x), rkeys[ROUNDS]);
    for (i = 0; i < ROUNDS - 1; i++) {
        t = AES_DECRYPT(t, rkeys_inv[i]);
    }
    t = AES_DECRYPTLAST(t, rkeys[0]);
#endif
    STORE128(x, t);
}

/**
 * aes_encrypt_with_tweak encrypts a 16-byte block x with an additional 8-byte tweak.
 * The tweak is XORed with each round key.
 */
static void
aes_encrypt_with_tweak(uint8_t x[16], const AesState *st, const uint8_t tweak[IPCRYPT_TWEAKBYTES])
{
    const BlockVec *rkeys       = st->rkeys;
    const BlockVec  tweak_block = TWEAK_EXPAND(tweak);
    BlockVec        t;
    size_t          i;

#ifdef AES_XENCRYPT
    // AArch64 path.
    t = AES_XENCRYPT(LOAD128(x), XOR128(tweak_block, rkeys[0]));
    for (i = 1; i < ROUNDS - 1; i++) {
        t = AES_XENCRYPT(t, XOR128(tweak_block, rkeys[i]));
    }
    t = AES_XENCRYPTLAST(t, XOR128(tweak_block, rkeys[i]));
    t = XOR128(t, XOR128(tweak_block, rkeys[ROUNDS]));
#else
    // x86_64 path.
    t = XOR128_3(LOAD128(x), tweak_block, rkeys[0]);
    for (i = 1; i < ROUNDS; i++) {
        t = AES_ENCRYPT(t, XOR128(tweak_block, rkeys[i]));
    }
    t = AES_ENCRYPTLAST(t, XOR128(tweak_block, rkeys[ROUNDS]));
#endif
    STORE128(x, t);
}

/**
 * aes_decrypt_with_tweak decrypts a 16-byte block x with an additional 8-byte tweak.
 * The same tweak used during encryption must be provided.
 */
static void
aes_decrypt_with_tweak(uint8_t x[16], const AesState *st, const uint8_t tweak[IPCRYPT_TWEAKBYTES])
{
    const BlockVec *rkeys = st->rkeys;
    InvKeySchedule  rkeys_inv;
    const BlockVec  tweak_block     = TWEAK_EXPAND(tweak);
    const BlockVec  tweak_block_inv = RKINVERT(tweak_block);
    BlockVec        t;
    size_t          i;

    // Given the purpose of this library, we assume that decryption is not a frequent operation.
    for (i = 0; i < ROUNDS - 1; i++) {
        rkeys_inv[i] = RKINVERT(rkeys[ROUNDS - 1 - i]);
    }
#ifdef AES_XENCRYPT
    t = AES_XDECRYPT(LOAD128(x), XOR128(tweak_block, rkeys[ROUNDS]));
    for (i = 0; i < ROUNDS - 2; i++) {
        t = AES_XDECRYPT(t, XOR128(tweak_block_inv, rkeys_inv[i]));
    }
    t = AES_XDECRYPTLAST(t, XOR128(tweak_block_inv, rkeys_inv[i]));
    t = XOR128(t, XOR128(tweak_block, rkeys[0]));
#else
    t = XOR128_3(LOAD128(x), tweak_block, rkeys[ROUNDS]);
    for (i = 0; i < ROUNDS - 1; i++) {
        t = AES_DECRYPT(t, XOR128(tweak_block_inv, rkeys_inv[i]));
    }
    t = AES_DECRYPTLAST(t, XOR128(tweak_block, rkeys[0]));
#endif
    STORE128(x, t);
}

static BlockVec
aes_xex_tweak(const NDXState *st, const uint8_t tweak[IPCRYPT_NDX_TWEAKBYTES])
{
    const BlockVec *tkeys = st->tkeys;
    BlockVec        tt;
    size_t          i;

    COMPILER_ASSERT(IPCRYPT_NDX_TWEAKBYTES == 16);

#ifdef AES_XENCRYPT
    // AArch64 path.
    tt = AES_XENCRYPT(LOAD128(tweak), tkeys[0]);
    for (i = 1; i < ROUNDS - 1; i++) {
        tt = AES_XENCRYPT(tt, tkeys[i]);
    }
    tt = AES_XENCRYPTLAST(tt, tkeys[i]);
    tt = XOR128(tt, tkeys[ROUNDS]);
#else
    // x86_64 path.
    tt = XOR128(LOAD128(tweak), tkeys[0]);
    for (i = 1; i < ROUNDS; i++) {
        tt = AES_ENCRYPT(tt, tkeys[i]);
    }
    tt = AES_ENCRYPTLAST(tt, tkeys[ROUNDS]);
#endif
    return tt;
}

static void
aes_xex_encrypt(uint8_t x[16], const NDXState *st, const uint8_t tweak[IPCRYPT_NDX_TWEAKBYTES])
{
    const BlockVec  tt    = aes_xex_tweak(st, tweak);
    const BlockVec *rkeys = st->rkeys;
    BlockVec        t;
    size_t          i;

    COMPILER_ASSERT(IPCRYPT_NDX_TWEAKBYTES == 16);

#ifdef AES_XENCRYPT
    // For AArch64 with AES_XENCRYPT macros.
    t = AES_XENCRYPT(XOR128(LOAD128(x), tt), rkeys[0]);
    for (i = 1; i < ROUNDS - 1; i++) {
        t = AES_XENCRYPT(t, rkeys[i]);
    }
    t = AES_XENCRYPTLAST(t, rkeys[i]);
    t = XOR128_3(t, rkeys[ROUNDS], tt);
#else
    // For x86_64 or a fallback.
    t = XOR128(XOR128(LOAD128(x), tt), rkeys[0]);
    for (i = 1; i < ROUNDS; i++) {
        t = AES_ENCRYPT(t, rkeys[i]);
    }
    t = AES_ENCRYPTLAST(t, XOR128(rkeys[ROUNDS], tt));
#endif
    STORE128(x, t);
}

static void
aes_ndx_decrypt(uint8_t x[16], const NDXState *st, const uint8_t tweak[IPCRYPT_NDX_TWEAKBYTES])
{

    const BlockVec  tt    = aes_xex_tweak(st, tweak);
    const BlockVec *rkeys = st->rkeys;
    BlockVec        t;
    size_t          i;

#ifdef AES_XENCRYPT
    // AArch64 path with AES_XDECRYPT.
    t = AES_XDECRYPT(XOR128(LOAD128(x), tt), rkeys[ROUNDS]);
    for (i = ROUNDS - 1; i > 1; i--) {
        t = AES_XDECRYPT(t, RKINVERT(rkeys[i]));
    }
    t = AES_XDECRYPTLAST(t, RKINVERT(rkeys[1]));
    t = XOR128_3(t, rkeys[0], tt);
#else
    // x86_64 path using AES_DECRYPT.
    t = XOR128(XOR128(LOAD128(x), tt), rkeys[ROUNDS]);
    for (i = ROUNDS - 1; i > 0; i--) {
        t = AES_DECRYPT(t, RKINVERT(rkeys[i]));
    }
    t = AES_DECRYPTLAST(t, XOR128(rkeys[0], tt));
#endif
    STORE128(x, t);
}

/**
 * bin2hex converts a binary buffer into a lowercase hex string.
 * hex: the destination buffer.
 * hex_maxlen: maximum capacity of hex.
 * bin: source buffer.
 * bin_len: length of bin.
 * Returns NULL on error, or hex on success.
 */
static char *
bin2hex(char *hex, size_t hex_maxlen, const uint8_t *bin, size_t bin_len)
{
    size_t       i = (size_t) 0U;
    unsigned int x;
    int          b;
    int          c;

    // Check buffer limits.
    if (bin_len >= SIZE_MAX / 2 || hex_maxlen <= bin_len * 2U) {
        return NULL;
    }
    // Convert each byte to two hex characters.
    while (i < bin_len) {
        c = bin[i] & 0xf;
        b = bin[i] >> 4;
        x = (unsigned char) (87U + c + (((c - 10U) >> 8) & ~38U)) << 8 |
            (unsigned char) (87U + b + (((b - 10U) >> 8) & ~38U));
        hex[i * 2U] = (char) x;
        x >>= 8;
        hex[i * 2U + 1U] = (char) x;
        i++;
    }
    // Null-terminate the string.
    hex[i * 2U] = 0U;

    return hex;
}

/**
 * hex2bin converts a hex string into a binary buffer.
 * bin: destination buffer.
 * bin_maxlen: capacity of bin.
 * hex: source string.
 * hex_len: length of the hex string.
 * Returns the number of bytes written on success, or 0 on error.
 */
static size_t
hex2bin(uint8_t *bin, size_t bin_maxlen, const char *hex, size_t hex_len)
{
    const size_t bin_len = hex_len / 2U;
    size_t       i;

    // Must have an even length and fit the destination.
    if (hex_len % 2U != 0 || bin_len > bin_maxlen) {
        return 0U;
    }
    for (i = 0; i < bin_len; i++) {
        unsigned char c = (unsigned char) hex[i * 2U];
        unsigned char b = (unsigned char) hex[i * 2U + 1U];
        // Convert from ASCII to nibble.
        if (c >= '0' && c <= '9') {
            c -= '0';
        } else if (c >= 'a' && c <= 'f') {
            c -= 'a' - 10;
        } else {
            return 0U;
        }
        if (b >= '0' && b <= '9') {
            b -= '0';
        } else if (b >= 'a' && b <= 'f') {
            b -= 'a' - 10;
        } else {
            return 0U;
        }
        bin[i] = ((uint8_t) c << 4) | b;
    }
    return bin_len;
}

/**
 * Convert a hexadecimal string to a secret key.
 *
 * The input string must be exactly 32 or 64 characters long (IPCRYPT_KEYBYTES or
 * IPCRYPT_NDX_KEYBYTES bytes in hex). Returns 0 on success, or -1 if the input string is invalid or
 * conversion fails.
 */
int
ipcrypt_key_from_hex(uint8_t *key, size_t key_len, const char *hex, size_t hex_len)
{
    if (hex_len != 2 * IPCRYPT_KEYBYTES && hex_len != 2 * IPCRYPT_NDX_KEYBYTES) {
        return -1;
    }
    if (hex2bin(key, key_len, hex, hex_len) != key_len) {
        return -1;
    }
    return 0;
}

/**
 * Convert a hexadecimal string to an ipcrypt-nd ciphertext.
 *
 * The input string must be exactly 48 characters long (IPCRYPT_NDIP_BYTES bytes in hex).
 * Returns 0 on success, or -1 if the input string is invalid or conversion fails.
 */
int
ipcrypt_ndip_from_hex(uint8_t ndip[IPCRYPT_NDIP_BYTES], const char *hex, size_t hex_len)
{
    if (hex_len != 2 * IPCRYPT_NDIP_BYTES) {
        return -1;
    }
    if (hex2bin(ndip, IPCRYPT_NDIP_BYTES, hex, hex_len) != IPCRYPT_NDIP_BYTES) {
        return -1;
    }
    return 0;
}

/**
 * Convert a hexadecimal string to an ipcrypt-ndx ciphertext.
 *
 * The input string must be exactly 64 characters long (IPCRYPT_NDX_NDIP_BYTES bytes in hex).
 * Returns 0 on success, or -1 if the input string is invalid or conversion fails.
 */
int
ipcrypt_ndx_ndip_from_hex(uint8_t ndip[IPCRYPT_NDX_NDIP_BYTES], const char *hex, size_t hex_len)
{
    if (hex_len != 2 * IPCRYPT_NDX_NDIP_BYTES) {
        return -1;
    }
    if (hex2bin(ndip, IPCRYPT_NDX_NDIP_BYTES, hex, hex_len) != IPCRYPT_NDX_NDIP_BYTES) {
        return -1;
    }
    return 0;
}

/**
 * ipcrypt_str_to_ip16 parses an IP address string (IPv4 or IPv6) into a 16-byte buffer ip16.
 * If it detects an IPv4 address, it is stored as an IPv4-mapped IPv6 address.
 * Returns 0 on success, or -1 on failure.
 */
int
ipcrypt_str_to_ip16(uint8_t ip16[16], const char *ip_str)
{
    struct in6_addr addr6;
    struct in_addr  addr4;

    // Try parsing as IPv6.
    if (inet_pton(AF_INET6, ip_str, &addr6) == 1) {
        memcpy(ip16, &addr6, 16);
        return 0;
    }
    // Try parsing as IPv4.
    if (inet_pton(AF_INET, ip_str, &addr4) == 1) {
        memset(ip16, 0, 16);
        ip16[10] = 0xff;
        ip16[11] = 0xff;
        memcpy(ip16 + 12, &addr4, 4);
        return 0;
    }
    return -1; // Parsing failed.
}

/**
 * ipcrypt_ip16_to_str converts a 16-byte buffer ip16 into its string representation (IPv4 or IPv6).
 * If the buffer holds an IPv4-mapped address, it returns an IPv4 string.
 * Returns the length of the resulting string on success, or 0 on error.
 */
size_t
ipcrypt_ip16_to_str(char ip_str[IPCRYPT_MAX_IP_STR_BYTES], const uint8_t ip16[16])
{
    int    is_ipv4_mapped = 1;
    size_t i;

    COMPILER_ASSERT(IPCRYPT_MAX_IP_STR_BYTES >= 46U);

    // Check whether it's an IPv4-mapped IPv6 address (::ffff:x.x.x.x).
    for (i = 0; i < 10; i++) {
        if (ip16[i] != 0) {
            is_ipv4_mapped = 0;
            break;
        }
    }
    if (is_ipv4_mapped && (ip16[10] != 0xff || ip16[11] != 0xff)) {
        is_ipv4_mapped = 0;
    }
    // If IPv4-mapped, convert to IPv4 string.
    if (is_ipv4_mapped) {
        struct in_addr addr4;
        memcpy(&addr4, ip16 + 12, 4);
        if (inet_ntop(AF_INET, &addr4, ip_str, INET_ADDRSTRLEN) == NULL) {
            return 0;
        }
    } else {
        // Otherwise, treat as IPv6.
        struct in6_addr addr6;
        memcpy(&addr6, ip16, 16);
        if (inet_ntop(AF_INET6, &addr6, ip_str, INET6_ADDRSTRLEN) == NULL) {
            return 0;
        }
    }
    return strlen(ip_str);
}

/**
 * Convert a socket address structure to a 16-byte binary IP representation.
 *
 * Supports both IPv4 (AF_INET) and IPv6 (AF_INET6) socket addresses.
 * For IPv4 addresses, they are converted to IPv4-mapped IPv6 format.
 *
 * Returns 0 on success, or -1 if the address family is not supported.
 */
int
ipcrypt_sockaddr_to_ip16(uint8_t ip16[16], const struct sockaddr *sa)
{
    if (sa->sa_family == AF_INET) {
        const struct sockaddr_in *s = (const struct sockaddr_in *) sa;
        memset(ip16, 0, 10);
        ip16[10] = 0xff;
        ip16[11] = 0xff;
        memcpy(ip16 + 12, &s->sin_addr, 4);
        return 0;
    } else if (sa->sa_family == AF_INET6) {
        const struct sockaddr_in6 *s = (const struct sockaddr_in6 *) sa;
        memcpy(ip16, &s->sin6_addr, 16);
        return 0;
    }
    return -1;
}

/**
 * Convert a 16-byte binary IP address to a socket address structure.
 *
 * The socket address structure is populated based on the IP format:
 * - For IPv4-mapped IPv6 addresses, an IPv4 socket address is created
 * - For other IPv6 addresses, an IPv6 socket address is created
 *
 * The provided sockaddr_storage structure is guaranteed to be large enough
 * to hold any socket address type.
 */
void
ipcrypt_ip16_to_sockaddr(struct sockaddr_storage *sa, const uint8_t ip16[16])
{
    const uint8_t ipv4_mapped[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };

    memset(sa, 0, sizeof *sa);
    if (memcmp(ip16, ipv4_mapped, sizeof ipv4_mapped) == 0) {
        struct sockaddr_in *s = (struct sockaddr_in *) sa;
        s->sin_family         = AF_INET;
        memcpy(&s->sin_addr, ip16 + 12, 4);
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || \
    defined(__DragonFly__)
        s->sin_len = sizeof *s;
#endif
    } else {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *) sa;
        s->sin6_family         = AF_INET6;
        memcpy(&s->sin6_addr, ip16, 16);
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || \
    defined(__DragonFly__)
        s->sin6_len = sizeof *s;
#endif
    }
}

/**
 * ipcrypt_init initializes an IPCrypt context with a 16-byte key.
 * Expands the key into round keys and stores them in ipcrypt->opaque.
 */
void
ipcrypt_init(IPCrypt *ipcrypt, const uint8_t key[IPCRYPT_KEYBYTES])
{
    AesState st;

    expand_key(st.rkeys, key);
    COMPILER_ASSERT(sizeof ipcrypt->opaque >= sizeof st);
    memcpy(ipcrypt->opaque, &st, sizeof st);
}

/**
 * ipcrypt_deinit clears the IPCrypt context to wipe sensitive data from memory.
 */
void
ipcrypt_deinit(IPCrypt *ipcrypt)
{
#ifdef _MSC_VER
    SecureZeroMemory(ipcrypt, sizeof *ipcrypt);
#elif defined(__STDC_LIB_EXT1__)
    memset_s(ipcrypt, sizeof *ipcrypt, 0, sizeof *ipcrypt);
#else
    memset(ipcrypt, 0, sizeof *ipcrypt);
// Compiler barrier to prevent optimizations from removing memset.
#    if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(ipcrypt) : "memory");
#    endif
#endif
}

/**
 * ipcrypt_pfx_init initializes the IPCryptPFX context with a 32-byte secret key.
 * This prepares the context for prefix-preserving IP address encryption operations.
 */
void
ipcrypt_pfx_init(IPCryptPFX *ipcrypt, const uint8_t key[IPCRYPT_PFX_KEYBYTES])
{
    PFXState st;

    expand_key(st.k1keys, key);
    expand_key(st.k2keys, key + 16);
    COMPILER_ASSERT(sizeof ipcrypt->opaque >= sizeof st);
    memcpy(ipcrypt->opaque, &st, sizeof st);
}

/**
 * ipcrypt_pfx_deinit securely clears and deinitializes the IPCryptPFX context.
 * This ensures that secret key material is wiped from memory.
 */
void
ipcrypt_pfx_deinit(IPCryptPFX *ipcrypt)
{
#ifdef _MSC_VER
    SecureZeroMemory(ipcrypt, sizeof *ipcrypt);
#elif defined(__STDC_LIB_EXT1__)
    memset_s(ipcrypt, sizeof *ipcrypt, 0, sizeof *ipcrypt);
#else
    memset(ipcrypt, 0, sizeof *ipcrypt);
// Compiler barrier to prevent optimizations from removing memset.
#    if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(ipcrypt) : "memory");
#    endif
#endif
}

static int
ipcrypt_is_mapped_ipv4(const uint8_t ip16[16])
{
    static const uint8_t ipv4_mapped[12] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff };
    return memcmp(ip16, ipv4_mapped, sizeof ipv4_mapped) == 0;
}

static void
ipcrypt_pfx_pad_prefix(uint8_t padded_prefix[16], unsigned int prefix_len_bits)
{
    memset(padded_prefix, 0, 16);
    if (prefix_len_bits == 0) {
        padded_prefix[15] = 0x01;
    } else {
        padded_prefix[3]  = 0x01;
        padded_prefix[14] = 0xff;
        padded_prefix[15] = 0xff;
    }
}

static uint8_t
ipcrypt_pfx_get_bit(const uint8_t ip16[16], const unsigned int bit_index)
{
    return (ip16[15 - bit_index / 8] >> (bit_index % 8)) & 1;
}

static void
ipcrypt_pfx_set_bit(uint8_t ip16[16], const unsigned int bit_index, const uint8_t bit_value)
{
    if (bit_value) {
        ip16[15 - bit_index / 8] |= (1 << (bit_index % 8));
    } else {
        ip16[15 - bit_index / 8] &= ~(1 << (bit_index % 8));
    }
}

static void
ipcrypt_pfx_shift_left(uint8_t ip16[16])
{
#ifdef STANDARD
    size_t i;

    for (i = 0; i < 15; i++) {
        ip16[i] = (ip16[i] << 1) | (ip16[i + 1] >> 7);
    }
    ip16[15] <<= 1;
#else
    BlockVec v = LOAD128(ip16);
    v          = SHL1_128(v);
    STORE128(ip16, v);
#endif
}

/**
 * ipcrypt_pfx_encrypt_ip16 encrypts a 16-byte IP address in-place with prefix preservation.
 * IP addresses with the same prefix produce encrypted IP addresses with the same prefix.
 * The prefix can be of any length. For IPv4 addresses (stored as IPv4-mapped IPv6),
 * this preserves the IPv4 prefix structure.
 */
void
ipcrypt_pfx_encrypt_ip16(const IPCryptPFX *ipcrypt, uint8_t ip16[16])
{
    PFXState     st;
    BlockVec     e1_0, e2_0, e_0, e1_1, e2_1, e_1;
    uint8_t      encrypted_ip[16];
    uint8_t      padded_prefix_0[16], padded_prefix_1[16];
    uint8_t      t_0[16], t_1[16];
    size_t       i;
    unsigned int bit_pos_0, bit_pos_1;
    unsigned int prefix_start = 0;
    unsigned int prefix_len_bits;
    uint8_t      cipher_bit_0, cipher_bit_1;
    uint8_t      original_bit_0, original_bit_1;

    memcpy(&st, ipcrypt->opaque, sizeof st);
    if (ipcrypt_is_mapped_ipv4(ip16)) {
        prefix_start = 96;
    }

    ipcrypt_pfx_pad_prefix(padded_prefix_0, prefix_start);

    memset(encrypted_ip, 0, 16);
    if (prefix_start == 96) {
        encrypted_ip[10] = 0xff;
        encrypted_ip[11] = 0xff;
    }

    // Process two bits per iteration for better parallelism
    for (prefix_len_bits = prefix_start; prefix_len_bits < 128; prefix_len_bits += 2) {
        // Prepare padded_prefix_1 for the second iteration
        memcpy(padded_prefix_1, padded_prefix_0, 16);
        bit_pos_0      = 127 - prefix_len_bits;
        original_bit_0 = ipcrypt_pfx_get_bit(ip16, bit_pos_0);
        ipcrypt_pfx_shift_left(padded_prefix_1);
        ipcrypt_pfx_set_bit(padded_prefix_1, 0, original_bit_0);

#ifdef AES_XENCRYPT
        // For AArch64 with AES_XENCRYPT macros - process two encryptions in parallel
        e1_0 = AES_XENCRYPT(LOAD128(padded_prefix_0), st.k1keys[0]);
        e2_0 = AES_XENCRYPT(LOAD128(padded_prefix_0), st.k2keys[0]);
        e1_1 = AES_XENCRYPT(LOAD128(padded_prefix_1), st.k1keys[0]);
        e2_1 = AES_XENCRYPT(LOAD128(padded_prefix_1), st.k2keys[0]);

        for (i = 1; i < ROUNDS - 1; i++) {
            e1_0 = AES_XENCRYPT(e1_0, st.k1keys[i]);
            e2_0 = AES_XENCRYPT(e2_0, st.k2keys[i]);
            e1_1 = AES_XENCRYPT(e1_1, st.k1keys[i]);
            e2_1 = AES_XENCRYPT(e2_1, st.k2keys[i]);
        }

        e1_0 = AES_XENCRYPTLAST(e1_0, st.k1keys[i]);
        e2_0 = AES_XENCRYPTLAST(e2_0, st.k2keys[i]);
        e1_1 = AES_XENCRYPTLAST(e1_1, st.k1keys[i]);
        e2_1 = AES_XENCRYPTLAST(e2_1, st.k2keys[i]);

        e1_0 = XOR128(e1_0, st.k1keys[ROUNDS]);
        e2_0 = XOR128(e2_0, st.k2keys[ROUNDS]);
        e1_1 = XOR128(e1_1, st.k1keys[ROUNDS]);
        e2_1 = XOR128(e2_1, st.k2keys[ROUNDS]);
#else
        // For x86_64 or a fallback - process two encryptions in parallel
        e1_0 = XOR128(LOAD128(padded_prefix_0), st.k1keys[0]);
        e2_0 = XOR128(LOAD128(padded_prefix_0), st.k2keys[0]);
        e1_1 = XOR128(LOAD128(padded_prefix_1), st.k1keys[0]);
        e2_1 = XOR128(LOAD128(padded_prefix_1), st.k2keys[0]);

        for (i = 1; i < ROUNDS; i++) {
            e1_0 = AES_ENCRYPT(e1_0, st.k1keys[i]);
            e2_0 = AES_ENCRYPT(e2_0, st.k2keys[i]);
            e1_1 = AES_ENCRYPT(e1_1, st.k1keys[i]);
            e2_1 = AES_ENCRYPT(e2_1, st.k2keys[i]);
        }

        e1_0 = AES_ENCRYPTLAST(e1_0, st.k1keys[ROUNDS]);
        e2_0 = AES_ENCRYPTLAST(e2_0, st.k2keys[ROUNDS]);
        e1_1 = AES_ENCRYPTLAST(e1_1, st.k1keys[ROUNDS]);
        e2_1 = AES_ENCRYPTLAST(e2_1, st.k2keys[ROUNDS]);
#endif

        // Process results for first bit
        e_0 = XOR128(e1_0, e2_0);
        STORE128(t_0, e_0);
        cipher_bit_0 = t_0[15] & 1;

        // Process results for second bit
        e_1 = XOR128(e1_1, e2_1);
        STORE128(t_1, e_1);
        cipher_bit_1   = t_1[15] & 1;
        bit_pos_1      = bit_pos_0 - 1;
        original_bit_1 = ipcrypt_pfx_get_bit(ip16, bit_pos_1);

        ipcrypt_pfx_set_bit(encrypted_ip, bit_pos_0, original_bit_0 ^ cipher_bit_0);
        ipcrypt_pfx_set_bit(encrypted_ip, bit_pos_1, original_bit_1 ^ cipher_bit_1);

        // Update padded_prefix_0 for next iteration
        ipcrypt_pfx_shift_left(padded_prefix_1);
        ipcrypt_pfx_set_bit(padded_prefix_1, 0, original_bit_1);
        memcpy(padded_prefix_0, padded_prefix_1, 16);
    }
    memcpy(ip16, encrypted_ip, 16);
}

/**
 * ipcrypt_pfx_decrypt_ip16 decrypts a 16-byte IP address in-place with prefix preservation.
 * This reverses the encryption performed by ipcrypt_pfx_encrypt_ip16, recovering the original IP
 * address.
 */
void
ipcrypt_pfx_decrypt_ip16(const IPCryptPFX *ipcrypt, uint8_t ip16[16])
{
    PFXState     st;
    BlockVec     e1, e2, e;
    uint8_t      original_ip[16];
    uint8_t      padded_prefix[16];
    uint8_t      t[16];
    size_t       i;
    unsigned int bit_pos;
    unsigned int prefix_start = 0;
    unsigned int prefix_len_bits;
    uint8_t      cipher_bit;
    uint8_t      encrypted_bit;
    uint8_t      original_bit;

    memcpy(&st, ipcrypt->opaque, sizeof st);
    if (ipcrypt_is_mapped_ipv4(ip16)) {
        prefix_start = 96;
    }

    ipcrypt_pfx_pad_prefix(padded_prefix, prefix_start);

    memset(original_ip, 0, 16);
    if (prefix_start == 96) {
        original_ip[10] = 0xff;
        original_ip[11] = 0xff;
    }

    for (prefix_len_bits = prefix_start; prefix_len_bits < 128; prefix_len_bits++) {
#ifdef AES_XENCRYPT
        // For AArch64 with AES_XENCRYPT macros.
        e1 = AES_XENCRYPT(LOAD128(padded_prefix), st.k1keys[0]);
        e2 = AES_XENCRYPT(LOAD128(padded_prefix), st.k2keys[0]);
        for (i = 1; i < ROUNDS - 1; i++) {
            e1 = AES_XENCRYPT(e1, st.k1keys[i]);
            e2 = AES_XENCRYPT(e2, st.k2keys[i]);
        }
        e1 = AES_XENCRYPTLAST(e1, st.k1keys[i]);
        e2 = AES_XENCRYPTLAST(e2, st.k2keys[i]);
        e1 = XOR128(e1, st.k1keys[ROUNDS]);
        e2 = XOR128(e2, st.k2keys[ROUNDS]);
#else
        // For x86_64 or a fallback.
        e1 = XOR128(LOAD128(padded_prefix), st.k1keys[0]);
        e2 = XOR128(LOAD128(padded_prefix), st.k2keys[0]);
        for (i = 1; i < ROUNDS; i++) {
            e1 = AES_ENCRYPT(e1, st.k1keys[i]);
            e2 = AES_ENCRYPT(e2, st.k2keys[i]);
        }
        e1 = AES_ENCRYPTLAST(e1, st.k1keys[ROUNDS]);
        e2 = AES_ENCRYPTLAST(e2, st.k2keys[ROUNDS]);
#endif
        e = XOR128(e1, e2);
        STORE128(t, e);
        cipher_bit    = t[15] & 1;
        bit_pos       = 127 - prefix_len_bits;
        encrypted_bit = ipcrypt_pfx_get_bit(ip16, bit_pos);
        original_bit  = encrypted_bit ^ cipher_bit;
        ipcrypt_pfx_set_bit(original_ip, bit_pos, original_bit);
        ipcrypt_pfx_shift_left(padded_prefix);
        ipcrypt_pfx_set_bit(padded_prefix, 0, original_bit);
    }
    memcpy(ip16, original_ip, 16);
}

/**
 * ipcrypt_pfx_encrypt_ip_str encrypts an IP address string (IPv4 or IPv6) with prefix preservation.
 * The result is another valid IP address string.
 * Returns the length of the encrypted string or 0 on error.
 */
size_t
ipcrypt_pfx_encrypt_ip_str(const IPCryptPFX *ipcrypt,
                           char              encrypted_ip_str[IPCRYPT_MAX_IP_STR_BYTES],
                           const char       *ip_str)
{
    uint8_t ip16[16];

    if (ipcrypt_str_to_ip16(ip16, ip_str) != 0) {
        return 0;
    }
    ipcrypt_pfx_encrypt_ip16(ipcrypt, ip16);
    return ipcrypt_ip16_to_str(encrypted_ip_str, ip16);
}

/**
 * ipcrypt_pfx_decrypt_ip_str decrypts an encrypted IP address string with prefix preservation.
 * Returns the length of the decrypted string or 0 on error.
 */
size_t
ipcrypt_pfx_decrypt_ip_str(const IPCryptPFX *ipcrypt,
                           char              ip_str[IPCRYPT_MAX_IP_STR_BYTES],
                           const char       *encrypted_ip_str)
{
    uint8_t ip16[16];

    memset(ip_str, 0, IPCRYPT_MAX_IP_STR_BYTES);
    if (ipcrypt_str_to_ip16(ip16, encrypted_ip_str) != 0) {
        return 0;
    }
    ipcrypt_pfx_decrypt_ip16(ipcrypt, ip16);
    return ipcrypt_ip16_to_str(ip_str, ip16);
}

/**
 * ipcrypt_init initializes an IPCrypt context with a 16-byte key.
 * Expands the key into round keys and stores them in ipcrypt->opaque.
 */
void
ipcrypt_ndx_init(IPCryptNDX *ipcrypt, const uint8_t key[IPCRYPT_NDX_KEYBYTES])
{
    NDXState st;

    expand_key(st.tkeys, key + 16);
    expand_key(st.rkeys, key);
    COMPILER_ASSERT(sizeof ipcrypt->opaque >= sizeof st);
    memcpy(ipcrypt->opaque, &st, sizeof st);
}

/**
 * ipcrypt_deinit clears the IPCrypt context to wipe sensitive data from memory.
 */
void
ipcrypt_ndx_deinit(IPCryptNDX *ipcrypt)
{
#ifdef _MSC_VER
    SecureZeroMemory(ipcrypt, sizeof *ipcrypt);
#elif defined(__STDC_LIB_EXT1__)
    memset_s(ipcrypt, sizeof *ipcrypt, 0, sizeof *ipcrypt);
#else
    memset(ipcrypt, 0, sizeof *ipcrypt);
// Compiler barrier to prevent optimizations from removing memset.
#    if defined(__GNUC__) || defined(__clang__)
    __asm__ __volatile__("" : : "r"(ipcrypt) : "memory");
#    endif
#endif
}

/**
 * ipcrypt_encrypt_ip16 performs format-preserving encryption on a 16-byte IP buffer.
 * Encrypted data is stored in-place.
 */
void
ipcrypt_encrypt_ip16(const IPCrypt *ipcrypt, uint8_t ip16[16])
{
    AesState st;
    memcpy(&st, ipcrypt->opaque, sizeof st);
    aes_encrypt(ip16, &st);
}

/**
 * ipcrypt_decrypt_ip16 performs format-preserving decryption on a 16-byte IP buffer.
 * Decrypted data is stored in-place.
 */
void
ipcrypt_decrypt_ip16(const IPCrypt *ipcrypt, uint8_t ip16[16])
{
    AesState st;
    memcpy(&st, ipcrypt->opaque, sizeof st);
    aes_decrypt(ip16, &st);
}

/**
 * ipcrypt_encrypt_ip_str encrypts an IP address string (IPv4 or IPv6) in a format-preserving way.
 * The result is another valid IP address string.
 * Returns the length of the encrypted string or 0 on error.
 */
size_t
ipcrypt_encrypt_ip_str(const IPCrypt *ipcrypt, char encrypted_ip_str[IPCRYPT_MAX_IP_STR_BYTES],
                       const char *ip_str)
{
    uint8_t ip16[16];

    if (ipcrypt_str_to_ip16(ip16, ip_str) != 0) {
        return 0;
    }
    ipcrypt_encrypt_ip16(ipcrypt, ip16);
    return ipcrypt_ip16_to_str(encrypted_ip_str, ip16);
}

/**
 * ipcrypt_decrypt_ip_str decrypts an encrypted IP address string and restores the original address.
 * Returns the length of the decrypted string or 0 on error.
 */
size_t
ipcrypt_decrypt_ip_str(const IPCrypt *ipcrypt, char ip_str[IPCRYPT_MAX_IP_STR_BYTES],
                       const char *encrypted_ip_str)
{
    uint8_t ip16[16];

    memset(ip_str, 0, IPCRYPT_MAX_IP_STR_BYTES);
    if (ipcrypt_str_to_ip16(ip16, encrypted_ip_str) != 0) {
        return 0;
    }
    ipcrypt_decrypt_ip16(ipcrypt, ip16);
    return ipcrypt_ip16_to_str(ip_str, ip16);
}

/**
 * ipcrypt_nd_encrypt_ip16 performs non-deterministic encryption of a 16-byte IP.
 * A random 8-byte tweak (random) must be provided.
 * Output is 24 bytes: the tweak + the encrypted IP.
 */
void
ipcrypt_nd_encrypt_ip16(const IPCrypt *ipcrypt, uint8_t ndip[IPCRYPT_NDIP_BYTES],
                        const uint8_t ip16[16], const uint8_t random[IPCRYPT_TWEAKBYTES])
{
    AesState st;

    COMPILER_ASSERT(IPCRYPT_NDIP_BYTES == 16 + IPCRYPT_TWEAKBYTES);
    memcpy(&st, ipcrypt->opaque, sizeof st);
    // Copy the tweak into the first 8 bytes.
    memcpy(ndip, random, IPCRYPT_TWEAKBYTES);
    // Copy the IP into the next 16 bytes.
    memcpy(ndip + IPCRYPT_TWEAKBYTES, ip16, 16);
    // Encrypt the IP portion with the tweak.
    aes_encrypt_with_tweak(ndip + IPCRYPT_TWEAKBYTES, &st, random);
}

/**
 * ipcrypt_nd_decrypt_ip16 decrypts a 24-byte (tweak + IP) buffer produced by
 * ipcrypt_nd_encrypt_ip16. The original IP is restored in ip16.
 */
void
ipcrypt_nd_decrypt_ip16(const IPCrypt *ipcrypt, uint8_t ip16[16],
                        const uint8_t ndip[IPCRYPT_NDIP_BYTES])
{
    AesState st;

    COMPILER_ASSERT(IPCRYPT_NDIP_BYTES == 16 + IPCRYPT_TWEAKBYTES);
    memcpy(&st, ipcrypt->opaque, sizeof st);
    // Copy the IP portion from ndip.
    memcpy(ip16, ndip + IPCRYPT_TWEAKBYTES, 16);
    // Decrypt using the tweak from the first 8 bytes.
    aes_decrypt_with_tweak(ip16, &st, ndip);
}

/**
 * ipcrypt_nd_encrypt_ip_str encrypts an IP address string in non-deterministic mode.
 * The output is a hex-encoded string of length IPCRYPT_NDIP_STR_BYTES (48 hex chars + null
 * terminator). random must be an 8-byte random value.
 */
size_t
ipcrypt_nd_encrypt_ip_str(const IPCrypt *ipcrypt, char encrypted_ip_str[IPCRYPT_NDIP_STR_BYTES],
                          const char *ip_str, const uint8_t random[IPCRYPT_TWEAKBYTES])
{
    uint8_t ip16[16];
    uint8_t ndip[IPCRYPT_NDIP_BYTES];

    COMPILER_ASSERT(IPCRYPT_NDIP_STR_BYTES == IPCRYPT_NDIP_BYTES * 2 + 1);
    // Convert to 16-byte IP.
    ipcrypt_str_to_ip16(ip16, ip_str);
    // Perform non-deterministic encryption.
    ipcrypt_nd_encrypt_ip16(ipcrypt, ndip, ip16, random);
    // Convert the 24-byte ndip to a hex string.
    bin2hex(encrypted_ip_str, IPCRYPT_NDIP_STR_BYTES, ndip, IPCRYPT_NDIP_BYTES);

    return IPCRYPT_NDIP_STR_BYTES - 1;
}

/**
 * ipcrypt_nd_decrypt_ip_str decrypts a hex-encoded string produced by ipcrypt_nd_encrypt_ip_str.
 * The original IP address string is written to ip_str.
 * Returns the length of the resulting IP string on success, or 0 on error.
 */
size_t
ipcrypt_nd_decrypt_ip_str(const IPCrypt *ipcrypt, char ip_str[IPCRYPT_MAX_IP_STR_BYTES],
                          const char *encrypted_ip_str)
{
    uint8_t ip16[16];
    uint8_t ndip[IPCRYPT_NDIP_BYTES];
    memset(ip_str, 0, IPCRYPT_MAX_IP_STR_BYTES);
    // Convert the hex string back to a 24-byte buffer.
    if (hex2bin(ndip, sizeof ndip, encrypted_ip_str, strlen(encrypted_ip_str)) != sizeof ndip) {
        return 0;
    }
    // Decrypt the IP.
    ipcrypt_nd_decrypt_ip16(ipcrypt, ip16, ndip);
    // Convert binary IP to string.
    return ipcrypt_ip16_to_str(ip_str, ip16);
}

/**
 * ipcrypt_ndx_encrypt_ip16 performs non-deterministic encryption of a 16-byte IP.
 * A random 16-byte tweak (random) must be provided.
 * Output is 32 bytes: the tweak + the encrypted IP.
 */
void
ipcrypt_ndx_encrypt_ip16(const IPCryptNDX *ipcrypt, uint8_t ndip[IPCRYPT_NDX_NDIP_BYTES],
                         const uint8_t ip16[16], const uint8_t random[IPCRYPT_NDX_TWEAKBYTES])
{
    NDXState st;

    COMPILER_ASSERT(IPCRYPT_NDX_NDIP_BYTES == 16 + IPCRYPT_NDX_TWEAKBYTES);
    memcpy(&st, ipcrypt->opaque, sizeof st);
    // Copy the tweak into the first 8 bytes.
    memcpy(ndip, random, IPCRYPT_NDX_TWEAKBYTES);
    // Copy the IP into the next 16 bytes.
    memcpy(ndip + IPCRYPT_NDX_TWEAKBYTES, ip16, 16);
    // Encrypt the IP portion with the tweak.
    aes_xex_encrypt(ndip + IPCRYPT_NDX_TWEAKBYTES, &st, random);
}

/**
 * ipcrypt_ndx_decrypt_ip16 decrypts a 32 byte (tweak + IP) buffer produced by
 * ipcrypt_ndx_encrypt_ip16. The original IP is restored in ip16.
 */
void
ipcrypt_ndx_decrypt_ip16(const IPCryptNDX *ipcrypt, uint8_t ip16[16],
                         const uint8_t ndip[IPCRYPT_NDX_NDIP_BYTES])
{
    NDXState st;

    COMPILER_ASSERT(IPCRYPT_NDX_NDIP_BYTES == 16 + IPCRYPT_NDX_TWEAKBYTES);
    memcpy(&st, ipcrypt->opaque, sizeof st);
    // Copy the IP portion from ndip.
    memcpy(ip16, ndip + IPCRYPT_NDX_TWEAKBYTES, 16);
    // Decrypt using the tweak from the first 16 bytes.
    aes_ndx_decrypt(ip16, &st, ndip);
}

/**
 * ipcrypt_ndx_encrypt_ip_str encrypts an IP address string in NDX mode.
 * The output is a hex-encoded string of length IPCRYPT_NDIP_STR_BYTES (64 hex chars + null
 * terminator). random must be an 8-byte random value.
 */
size_t
ipcrypt_ndx_encrypt_ip_str(const IPCryptNDX *ipcrypt,
                           char encrypted_ip_str[IPCRYPT_NDX_NDIP_STR_BYTES], const char *ip_str,
                           const uint8_t random[IPCRYPT_NDX_TWEAKBYTES])
{
    uint8_t ip16[16];
    uint8_t ndip[IPCRYPT_NDX_NDIP_BYTES];

    COMPILER_ASSERT(IPCRYPT_NDX_NDIP_STR_BYTES == IPCRYPT_NDX_NDIP_BYTES * 2 + 1);
    // Convert to 16-byte IP.
    ipcrypt_str_to_ip16(ip16, ip_str);
    // Perform non-deterministic encryption.
    ipcrypt_ndx_encrypt_ip16(ipcrypt, ndip, ip16, random);
    // Convert the 32-byte ndip to a hex string.
    bin2hex(encrypted_ip_str, IPCRYPT_NDX_NDIP_STR_BYTES, ndip, IPCRYPT_NDX_NDIP_BYTES);

    return IPCRYPT_NDX_NDIP_STR_BYTES - 1;
}

/**
 * ipcrypt_ndx_decrypt_ip_str decrypts a hex-encoded string produced by ipcrypt_ndx_encrypt_ip_str.
 * The original IP address string is written to ip_str.
 * Returns the length of the resulting IP string on success, or 0 on error.
 */
size_t
ipcrypt_ndx_decrypt_ip_str(const IPCryptNDX *ipcrypt, char ip_str[IPCRYPT_MAX_IP_STR_BYTES],
                           const char *encrypted_ip_str)
{
    uint8_t ip16[16];
    uint8_t ndip[IPCRYPT_NDX_NDIP_BYTES];
    memset(ip_str, 0, IPCRYPT_MAX_IP_STR_BYTES);
    // Convert the hex string back to a 24-byte buffer.
    if (hex2bin(ndip, sizeof ndip, encrypted_ip_str, strlen(encrypted_ip_str)) != sizeof ndip) {
        return 0;
    }
    // Decrypt the IP.
    ipcrypt_ndx_decrypt_ip16(ipcrypt, ip16, ndip);
    // Convert binary IP to string.
    return ipcrypt_ip16_to_str(ip_str, ip16);
}

#ifdef __clang__
#    pragma clang attribute pop
#endif
