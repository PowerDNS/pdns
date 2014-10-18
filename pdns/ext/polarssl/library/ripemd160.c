/*
 *  RIPE MD-160 implementation
 *
 *  Copyright (C) 2014-2014, Brainspark B.V.
 *
 *  This file is part of PolarSSL (http://www.polarssl.org)
 *  Lead Maintainer: Paul Bakker <polarssl_maintainer at polarssl.org>
 *
 *  All rights reserved.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 *  The RIPEMD-160 algorithm was designed by RIPE in 1996
 *  http://homes.esat.kuleuven.be/~bosselae/ripemd160.html
 *  http://ehash.iaik.tugraz.at/wiki/RIPEMD-160
 */

#if !defined(POLARSSL_CONFIG_FILE)
#include "polarssl/config.h"
#else
#include POLARSSL_CONFIG_FILE
#endif

#if defined(POLARSSL_RIPEMD160_C)

#include "polarssl/ripemd160.h"

#if defined(POLARSSL_FS_IO) || defined(POLARSSL_SELF_TEST)
#include <stdio.h>
#endif

#if defined(POLARSSL_SELF_TEST)
#include <string.h>
#endif

#if defined(POLARSSL_PLATFORM_C)
#include "polarssl/platform.h"
#else
#define polarssl_printf printf
#endif

/*
 * 32-bit integer manipulation macros (little endian)
 */
#ifndef GET_UINT32_LE
#define GET_UINT32_LE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ]       )             \
        | ( (uint32_t) (b)[(i) + 1] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 2] << 16 )             \
        | ( (uint32_t) (b)[(i) + 3] << 24 );            \
}
#endif

#ifndef PUT_UINT32_LE
#define PUT_UINT32_LE(n,b,i)                            \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n)       );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 3] = (unsigned char) ( (n) >> 24 );       \
}
#endif

/* Implementation that should never be optimized out by the compiler */
static void polarssl_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}

void ripemd160_init( ripemd160_context *ctx )
{
    memset( ctx, 0, sizeof( ripemd160_context ) );
}

void ripemd160_free( ripemd160_context *ctx )
{
    if( ctx == NULL )
        return;

    polarssl_zeroize( ctx, sizeof( ripemd160_context ) );
}

/*
 * RIPEMD-160 context setup
 */
void ripemd160_starts( ripemd160_context *ctx )
{
    ctx->total[0] = 0;
    ctx->total[1] = 0;

    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xEFCDAB89;
    ctx->state[2] = 0x98BADCFE;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xC3D2E1F0;
}

/*
 * Process one block
 */
void ripemd160_process( ripemd160_context *ctx, const unsigned char data[64] )
{
    uint32_t A, B, C, D, E, Ap, Bp, Cp, Dp, Ep, X[16];

    GET_UINT32_LE( X[ 0], data,  0 );
    GET_UINT32_LE( X[ 1], data,  4 );
    GET_UINT32_LE( X[ 2], data,  8 );
    GET_UINT32_LE( X[ 3], data, 12 );
    GET_UINT32_LE( X[ 4], data, 16 );
    GET_UINT32_LE( X[ 5], data, 20 );
    GET_UINT32_LE( X[ 6], data, 24 );
    GET_UINT32_LE( X[ 7], data, 28 );
    GET_UINT32_LE( X[ 8], data, 32 );
    GET_UINT32_LE( X[ 9], data, 36 );
    GET_UINT32_LE( X[10], data, 40 );
    GET_UINT32_LE( X[11], data, 44 );
    GET_UINT32_LE( X[12], data, 48 );
    GET_UINT32_LE( X[13], data, 52 );
    GET_UINT32_LE( X[14], data, 56 );
    GET_UINT32_LE( X[15], data, 60 );

    A = Ap = ctx->state[0];
    B = Bp = ctx->state[1];
    C = Cp = ctx->state[2];
    D = Dp = ctx->state[3];
    E = Ep = ctx->state[4];

#define F1( x, y, z )   ( x ^ y ^ z )
#define F2( x, y, z )   ( ( x & y ) | ( ~x & z ) )
#define F3( x, y, z )   ( ( x | ~y ) ^ z )
#define F4( x, y, z )   ( ( x & z ) | ( y & ~z ) )
#define F5( x, y, z )   ( x ^ ( y | ~z ) )

#define S( x, n ) ( ( x << n ) | ( x >> (32 - n) ) )

#define P( a, b, c, d, e, r, s, f, k )      \
    a += f( b, c, d ) + X[r] + k;           \
    a = S( a, s ) + e;                      \
    c = S( c, 10 );

#define P2( a, b, c, d, e, r, s, rp, sp )   \
    P( a, b, c, d, e, r, s, F, K );         \
    P( a ## p, b ## p, c ## p, d ## p, e ## p, rp, sp, Fp, Kp );

#define F   F1
#define K   0x00000000
#define Fp  F5
#define Kp  0x50A28BE6
    P2( A, B, C, D, E,  0, 11,  5,  8 );
    P2( E, A, B, C, D,  1, 14, 14,  9 );
    P2( D, E, A, B, C,  2, 15,  7,  9 );
    P2( C, D, E, A, B,  3, 12,  0, 11 );
    P2( B, C, D, E, A,  4,  5,  9, 13 );
    P2( A, B, C, D, E,  5,  8,  2, 15 );
    P2( E, A, B, C, D,  6,  7, 11, 15 );
    P2( D, E, A, B, C,  7,  9,  4,  5 );
    P2( C, D, E, A, B,  8, 11, 13,  7 );
    P2( B, C, D, E, A,  9, 13,  6,  7 );
    P2( A, B, C, D, E, 10, 14, 15,  8 );
    P2( E, A, B, C, D, 11, 15,  8, 11 );
    P2( D, E, A, B, C, 12,  6,  1, 14 );
    P2( C, D, E, A, B, 13,  7, 10, 14 );
    P2( B, C, D, E, A, 14,  9,  3, 12 );
    P2( A, B, C, D, E, 15,  8, 12,  6 );
#undef F
#undef K
#undef Fp
#undef Kp

#define F   F2
#define K   0x5A827999
#define Fp  F4
#define Kp  0x5C4DD124
    P2( E, A, B, C, D,  7,  7,  6,  9 );
    P2( D, E, A, B, C,  4,  6, 11, 13 );
    P2( C, D, E, A, B, 13,  8,  3, 15 );
    P2( B, C, D, E, A,  1, 13,  7,  7 );
    P2( A, B, C, D, E, 10, 11,  0, 12 );
    P2( E, A, B, C, D,  6,  9, 13,  8 );
    P2( D, E, A, B, C, 15,  7,  5,  9 );
    P2( C, D, E, A, B,  3, 15, 10, 11 );
    P2( B, C, D, E, A, 12,  7, 14,  7 );
    P2( A, B, C, D, E,  0, 12, 15,  7 );
    P2( E, A, B, C, D,  9, 15,  8, 12 );
    P2( D, E, A, B, C,  5,  9, 12,  7 );
    P2( C, D, E, A, B,  2, 11,  4,  6 );
    P2( B, C, D, E, A, 14,  7,  9, 15 );
    P2( A, B, C, D, E, 11, 13,  1, 13 );
    P2( E, A, B, C, D,  8, 12,  2, 11 );
#undef F
#undef K
#undef Fp
#undef Kp

#define F   F3
#define K   0x6ED9EBA1
#define Fp  F3
#define Kp  0x6D703EF3
    P2( D, E, A, B, C,  3, 11, 15,  9 );
    P2( C, D, E, A, B, 10, 13,  5,  7 );
    P2( B, C, D, E, A, 14,  6,  1, 15 );
    P2( A, B, C, D, E,  4,  7,  3, 11 );
    P2( E, A, B, C, D,  9, 14,  7,  8 );
    P2( D, E, A, B, C, 15,  9, 14,  6 );
    P2( C, D, E, A, B,  8, 13,  6,  6 );
    P2( B, C, D, E, A,  1, 15,  9, 14 );
    P2( A, B, C, D, E,  2, 14, 11, 12 );
    P2( E, A, B, C, D,  7,  8,  8, 13 );
    P2( D, E, A, B, C,  0, 13, 12,  5 );
    P2( C, D, E, A, B,  6,  6,  2, 14 );
    P2( B, C, D, E, A, 13,  5, 10, 13 );
    P2( A, B, C, D, E, 11, 12,  0, 13 );
    P2( E, A, B, C, D,  5,  7,  4,  7 );
    P2( D, E, A, B, C, 12,  5, 13,  5 );
#undef F
#undef K
#undef Fp
#undef Kp

#define F   F4
#define K   0x8F1BBCDC
#define Fp  F2
#define Kp  0x7A6D76E9
    P2( C, D, E, A, B,  1, 11,  8, 15 );
    P2( B, C, D, E, A,  9, 12,  6,  5 );
    P2( A, B, C, D, E, 11, 14,  4,  8 );
    P2( E, A, B, C, D, 10, 15,  1, 11 );
    P2( D, E, A, B, C,  0, 14,  3, 14 );
    P2( C, D, E, A, B,  8, 15, 11, 14 );
    P2( B, C, D, E, A, 12,  9, 15,  6 );
    P2( A, B, C, D, E,  4,  8,  0, 14 );
    P2( E, A, B, C, D, 13,  9,  5,  6 );
    P2( D, E, A, B, C,  3, 14, 12,  9 );
    P2( C, D, E, A, B,  7,  5,  2, 12 );
    P2( B, C, D, E, A, 15,  6, 13,  9 );
    P2( A, B, C, D, E, 14,  8,  9, 12 );
    P2( E, A, B, C, D,  5,  6,  7,  5 );
    P2( D, E, A, B, C,  6,  5, 10, 15 );
    P2( C, D, E, A, B,  2, 12, 14,  8 );
#undef F
#undef K
#undef Fp
#undef Kp

#define F   F5
#define K   0xA953FD4E
#define Fp  F1
#define Kp  0x00000000
    P2( B, C, D, E, A,  4,  9, 12,  8 );
    P2( A, B, C, D, E,  0, 15, 15,  5 );
    P2( E, A, B, C, D,  5,  5, 10, 12 );
    P2( D, E, A, B, C,  9, 11,  4,  9 );
    P2( C, D, E, A, B,  7,  6,  1, 12 );
    P2( B, C, D, E, A, 12,  8,  5,  5 );
    P2( A, B, C, D, E,  2, 13,  8, 14 );
    P2( E, A, B, C, D, 10, 12,  7,  6 );
    P2( D, E, A, B, C, 14,  5,  6,  8 );
    P2( C, D, E, A, B,  1, 12,  2, 13 );
    P2( B, C, D, E, A,  3, 13, 13,  6 );
    P2( A, B, C, D, E,  8, 14, 14,  5 );
    P2( E, A, B, C, D, 11, 11,  0, 15 );
    P2( D, E, A, B, C,  6,  8,  3, 13 );
    P2( C, D, E, A, B, 15,  5,  9, 11 );
    P2( B, C, D, E, A, 13,  6, 11, 11 );
#undef F
#undef K
#undef Fp
#undef Kp

    C             = ctx->state[1] + C + Dp;
    ctx->state[1] = ctx->state[2] + D + Ep;
    ctx->state[2] = ctx->state[3] + E + Ap;
    ctx->state[3] = ctx->state[4] + A + Bp;
    ctx->state[4] = ctx->state[0] + B + Cp;
    ctx->state[0] = C;
}

/*
 * RIPEMD-160 process buffer
 */
void ripemd160_update( ripemd160_context *ctx,
                       const unsigned char *input, size_t ilen )
{
    size_t fill;
    uint32_t left;

    if( ilen == 0 )
        return;

    left = ctx->total[0] & 0x3F;
    fill = 64 - left;

    ctx->total[0] += (uint32_t) ilen;
    ctx->total[0] &= 0xFFFFFFFF;

    if( ctx->total[0] < (uint32_t) ilen )
        ctx->total[1]++;

    if( left && ilen >= fill )
    {
        memcpy( (void *) (ctx->buffer + left), input, fill );
        ripemd160_process( ctx, ctx->buffer );
        input += fill;
        ilen  -= fill;
        left = 0;
    }

    while( ilen >= 64 )
    {
        ripemd160_process( ctx, input );
        input += 64;
        ilen  -= 64;
    }

    if( ilen > 0 )
    {
        memcpy( (void *) (ctx->buffer + left), input, ilen );
    }
}

static const unsigned char ripemd160_padding[64] =
{
 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * RIPEMD-160 final digest
 */
void ripemd160_finish( ripemd160_context *ctx, unsigned char output[20] )
{
    uint32_t last, padn;
    uint32_t high, low;
    unsigned char msglen[8];

    high = ( ctx->total[0] >> 29 )
         | ( ctx->total[1] <<  3 );
    low  = ( ctx->total[0] <<  3 );

    PUT_UINT32_LE( low,  msglen, 0 );
    PUT_UINT32_LE( high, msglen, 4 );

    last = ctx->total[0] & 0x3F;
    padn = ( last < 56 ) ? ( 56 - last ) : ( 120 - last );

    ripemd160_update( ctx, ripemd160_padding, padn );
    ripemd160_update( ctx, msglen, 8 );

    PUT_UINT32_LE( ctx->state[0], output,  0 );
    PUT_UINT32_LE( ctx->state[1], output,  4 );
    PUT_UINT32_LE( ctx->state[2], output,  8 );
    PUT_UINT32_LE( ctx->state[3], output, 12 );
    PUT_UINT32_LE( ctx->state[4], output, 16 );
}

/*
 * output = RIPEMD-160( input buffer )
 */
void ripemd160( const unsigned char *input, size_t ilen,
                unsigned char output[20] )
{
    ripemd160_context ctx;

    ripemd160_init( &ctx );
    ripemd160_starts( &ctx );
    ripemd160_update( &ctx, input, ilen );
    ripemd160_finish( &ctx, output );
    ripemd160_free( &ctx );
}

#if defined(POLARSSL_FS_IO)
/*
 * output = RIPEMD-160( file contents )
 */
int ripemd160_file( const char *path, unsigned char output[20] )
{
    FILE *f;
    size_t n;
    ripemd160_context ctx;
    unsigned char buf[1024];

    if( ( f = fopen( path, "rb" ) ) == NULL )
        return( POLARSSL_ERR_RIPEMD160_FILE_IO_ERROR );

    ripemd160_init( &ctx );
    ripemd160_starts( &ctx );

    while( ( n = fread( buf, 1, sizeof( buf ), f ) ) > 0 )
        ripemd160_update( &ctx, buf, n );

    ripemd160_finish( &ctx, output );
    ripemd160_free( &ctx );

    if( ferror( f ) != 0 )
    {
        fclose( f );
        return( POLARSSL_ERR_RIPEMD160_FILE_IO_ERROR );
    }

    fclose( f );
    return( 0 );
}
#endif /* POLARSSL_FS_IO */

/*
 * RIPEMD-160 HMAC context setup
 */
void ripemd160_hmac_starts( ripemd160_context *ctx,
                            const unsigned char *key, size_t keylen )
{
    size_t i;
    unsigned char sum[20];

    if( keylen > 64 )
    {
        ripemd160( key, keylen, sum );
        keylen = 20;
        key = sum;
    }

    memset( ctx->ipad, 0x36, 64 );
    memset( ctx->opad, 0x5C, 64 );

    for( i = 0; i < keylen; i++ )
    {
        ctx->ipad[i] = (unsigned char)( ctx->ipad[i] ^ key[i] );
        ctx->opad[i] = (unsigned char)( ctx->opad[i] ^ key[i] );
    }

    ripemd160_starts( ctx );
    ripemd160_update( ctx, ctx->ipad, 64 );

    polarssl_zeroize( sum, sizeof( sum ) );
}

/*
 * RIPEMD-160 HMAC process buffer
 */
void ripemd160_hmac_update( ripemd160_context *ctx,
                            const unsigned char *input, size_t ilen )
{
    ripemd160_update( ctx, input, ilen );
}

/*
 * RIPEMD-160 HMAC final digest
 */
void ripemd160_hmac_finish( ripemd160_context *ctx, unsigned char output[20] )
{
    unsigned char tmpbuf[20];

    ripemd160_finish( ctx, tmpbuf );
    ripemd160_starts( ctx );
    ripemd160_update( ctx, ctx->opad, 64 );
    ripemd160_update( ctx, tmpbuf, 20 );
    ripemd160_finish( ctx, output );

    polarssl_zeroize( tmpbuf, sizeof( tmpbuf ) );
}

/*
 * RIPEMD-160 HMAC context reset
 */
void ripemd160_hmac_reset( ripemd160_context *ctx )
{
    ripemd160_starts( ctx );
    ripemd160_update( ctx, ctx->ipad, 64 );
}

/*
 * output = HMAC-RIPEMD-160( hmac key, input buffer )
 */
void ripemd160_hmac( const unsigned char *key, size_t keylen,
                     const unsigned char *input, size_t ilen,
                     unsigned char output[20] )
{
    ripemd160_context ctx;

    ripemd160_init( &ctx );
    ripemd160_hmac_starts( &ctx, key, keylen );
    ripemd160_hmac_update( &ctx, input, ilen );
    ripemd160_hmac_finish( &ctx, output );
    ripemd160_free( &ctx );
}


#if defined(POLARSSL_SELF_TEST)
/*
 * Test vectors from the RIPEMD-160 paper and
 * http://homes.esat.kuleuven.be/~bosselae/ripemd160.html#HMAC
 */
#define TESTS   8
#define KEYS    2
static const char *ripemd160_test_input[TESTS] =
{
    "",
    "a",
    "abc",
    "message digest",
    "abcdefghijklmnopqrstuvwxyz",
    "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "1234567890123456789012345678901234567890"
        "1234567890123456789012345678901234567890",
};

static const unsigned char ripemd160_test_md[TESTS][20] =
{
    { 0x9c, 0x11, 0x85, 0xa5, 0xc5, 0xe9, 0xfc, 0x54, 0x61, 0x28,
      0x08, 0x97, 0x7e, 0xe8, 0xf5, 0x48, 0xb2, 0x25, 0x8d, 0x31 },
    { 0x0b, 0xdc, 0x9d, 0x2d, 0x25, 0x6b, 0x3e, 0xe9, 0xda, 0xae,
      0x34, 0x7b, 0xe6, 0xf4, 0xdc, 0x83, 0x5a, 0x46, 0x7f, 0xfe },
    { 0x8e, 0xb2, 0x08, 0xf7, 0xe0, 0x5d, 0x98, 0x7a, 0x9b, 0x04,
      0x4a, 0x8e, 0x98, 0xc6, 0xb0, 0x87, 0xf1, 0x5a, 0x0b, 0xfc },
    { 0x5d, 0x06, 0x89, 0xef, 0x49, 0xd2, 0xfa, 0xe5, 0x72, 0xb8,
      0x81, 0xb1, 0x23, 0xa8, 0x5f, 0xfa, 0x21, 0x59, 0x5f, 0x36 },
    { 0xf7, 0x1c, 0x27, 0x10, 0x9c, 0x69, 0x2c, 0x1b, 0x56, 0xbb,
      0xdc, 0xeb, 0x5b, 0x9d, 0x28, 0x65, 0xb3, 0x70, 0x8d, 0xbc },
    { 0x12, 0xa0, 0x53, 0x38, 0x4a, 0x9c, 0x0c, 0x88, 0xe4, 0x05,
      0xa0, 0x6c, 0x27, 0xdc, 0xf4, 0x9a, 0xda, 0x62, 0xeb, 0x2b },
    { 0xb0, 0xe2, 0x0b, 0x6e, 0x31, 0x16, 0x64, 0x02, 0x86, 0xed,
      0x3a, 0x87, 0xa5, 0x71, 0x30, 0x79, 0xb2, 0x1f, 0x51, 0x89 },
    { 0x9b, 0x75, 0x2e, 0x45, 0x57, 0x3d, 0x4b, 0x39, 0xf4, 0xdb,
      0xd3, 0x32, 0x3c, 0xab, 0x82, 0xbf, 0x63, 0x32, 0x6b, 0xfb },
};

static const unsigned char ripemd160_test_hmac[KEYS][TESTS][20] =
{
  {
    { 0xcf, 0x38, 0x76, 0x77, 0xbf, 0xda, 0x84, 0x83, 0xe6, 0x3b,
      0x57, 0xe0, 0x6c, 0x3b, 0x5e, 0xcd, 0x8b, 0x7f, 0xc0, 0x55 },
    { 0x0d, 0x35, 0x1d, 0x71, 0xb7, 0x8e, 0x36, 0xdb, 0xb7, 0x39,
      0x1c, 0x81, 0x0a, 0x0d, 0x2b, 0x62, 0x40, 0xdd, 0xba, 0xfc },
    { 0xf7, 0xef, 0x28, 0x8c, 0xb1, 0xbb, 0xcc, 0x61, 0x60, 0xd7,
      0x65, 0x07, 0xe0, 0xa3, 0xbb, 0xf7, 0x12, 0xfb, 0x67, 0xd6 },
    { 0xf8, 0x36, 0x62, 0xcc, 0x8d, 0x33, 0x9c, 0x22, 0x7e, 0x60,
      0x0f, 0xcd, 0x63, 0x6c, 0x57, 0xd2, 0x57, 0x1b, 0x1c, 0x34 },
    { 0x84, 0x3d, 0x1c, 0x4e, 0xb8, 0x80, 0xac, 0x8a, 0xc0, 0xc9,
      0xc9, 0x56, 0x96, 0x50, 0x79, 0x57, 0xd0, 0x15, 0x5d, 0xdb },
    { 0x60, 0xf5, 0xef, 0x19, 0x8a, 0x2d, 0xd5, 0x74, 0x55, 0x45,
      0xc1, 0xf0, 0xc4, 0x7a, 0xa3, 0xfb, 0x57, 0x76, 0xf8, 0x81 },
    { 0xe4, 0x9c, 0x13, 0x6a, 0x9e, 0x56, 0x27, 0xe0, 0x68, 0x1b,
      0x80, 0x8a, 0x3b, 0x97, 0xe6, 0xa6, 0xe6, 0x61, 0xae, 0x79 },
    { 0x31, 0xbe, 0x3c, 0xc9, 0x8c, 0xee, 0x37, 0xb7, 0x9b, 0x06,
      0x19, 0xe3, 0xe1, 0xc2, 0xbe, 0x4f, 0x1a, 0xa5, 0x6e, 0x6c },
  },
  {
    { 0xfe, 0x69, 0xa6, 0x6c, 0x74, 0x23, 0xee, 0xa9, 0xc8, 0xfa,
      0x2e, 0xff, 0x8d, 0x9d, 0xaf, 0xb4, 0xf1, 0x7a, 0x62, 0xf5 },
    { 0x85, 0x74, 0x3e, 0x89, 0x9b, 0xc8, 0x2d, 0xbf, 0xa3, 0x6f,
      0xaa, 0xa7, 0xa2, 0x5b, 0x7c, 0xfd, 0x37, 0x24, 0x32, 0xcd },
    { 0x6e, 0x4a, 0xfd, 0x50, 0x1f, 0xa6, 0xb4, 0xa1, 0x82, 0x3c,
      0xa3, 0xb1, 0x0b, 0xd9, 0xaa, 0x0b, 0xa9, 0x7b, 0xa1, 0x82 },
    { 0x2e, 0x06, 0x6e, 0x62, 0x4b, 0xad, 0xb7, 0x6a, 0x18, 0x4c,
      0x8f, 0x90, 0xfb, 0xa0, 0x53, 0x33, 0x0e, 0x65, 0x0e, 0x92 },
    { 0x07, 0xe9, 0x42, 0xaa, 0x4e, 0x3c, 0xd7, 0xc0, 0x4d, 0xed,
      0xc1, 0xd4, 0x6e, 0x2e, 0x8c, 0xc4, 0xc7, 0x41, 0xb3, 0xd9 },
    { 0xb6, 0x58, 0x23, 0x18, 0xdd, 0xcf, 0xb6, 0x7a, 0x53, 0xa6,
      0x7d, 0x67, 0x6b, 0x8a, 0xd8, 0x69, 0xad, 0xed, 0x62, 0x9a },
    { 0xf1, 0xbe, 0x3e, 0xe8, 0x77, 0x70, 0x31, 0x40, 0xd3, 0x4f,
      0x97, 0xea, 0x1a, 0xb3, 0xa0, 0x7c, 0x14, 0x13, 0x33, 0xe2 },
    { 0x85, 0xf1, 0x64, 0x70, 0x3e, 0x61, 0xa6, 0x31, 0x31, 0xbe,
      0x7e, 0x45, 0x95, 0x8e, 0x07, 0x94, 0x12, 0x39, 0x04, 0xf9 },
  },
};

static const unsigned char ripemd160_test_key[KEYS][20] =
{
    { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
      0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x23, 0x45, 0x67 },
    { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc,
      0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x00, 0x11, 0x22, 0x33 },
};

/*
 * Checkup routine
 */
int ripemd160_self_test( int verbose )
{
    int i, j;
    unsigned char output[20];

    memset( output, 0, sizeof output );

    for( i = 0; i < TESTS; i++ )
    {
        if( verbose != 0 )
            polarssl_printf( "  RIPEMD-160 test #%d: ", i + 1 );

        ripemd160( (const unsigned char *) ripemd160_test_input[i],
                   strlen( ripemd160_test_input[i] ),
                   output );

        if( memcmp( output, ripemd160_test_md[i], 20 ) != 0 )
        {
            if( verbose != 0 )
                polarssl_printf( "failed\n" );

            return( 1 );
        }

        if( verbose != 0 )
            polarssl_printf( "passed\n" );

        for( j = 0; j < KEYS; j++ )
        {
            if( verbose != 0 )
                polarssl_printf( "  HMAC-RIPEMD-160 test #%d, key #%d: ",
                                 i + 1, j + 1 );

            ripemd160_hmac( ripemd160_test_key[j], 20,
                            (const unsigned char *) ripemd160_test_input[i],
                            strlen( ripemd160_test_input[i] ),
                            output );

            if( memcmp( output, ripemd160_test_hmac[j][i], 20 ) != 0 )
            {
                if( verbose != 0 )
                    polarssl_printf( "failed\n" );

                return( 1 );
            }

            if( verbose != 0 )
                polarssl_printf( "passed\n" );
        }

        if( verbose != 0 )
            polarssl_printf( "\n" );
    }

    return( 0 );
}

#endif /* POLARSSL_SELF_TEST */

#endif /* POLARSSL_RIPEMD160_C */
