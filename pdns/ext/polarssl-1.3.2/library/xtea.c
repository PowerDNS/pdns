/*
 *  An 32-bit implementation of the XTEA algorithm
 *
 *  Copyright (C) 2006-2013, Brainspark B.V.
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

#include "polarssl/config.h"

#if defined(POLARSSL_XTEA_C)

#include "polarssl/xtea.h"

#if !defined(POLARSSL_XTEA_ALT)

/*
 * 32-bit integer manipulation macros (big endian)
 */
#ifndef GET_UINT32_BE
#define GET_UINT32_BE(n,b,i)                            \
{                                                       \
    (n) = ( (uint32_t) (b)[(i)    ] << 24 )             \
        | ( (uint32_t) (b)[(i) + 1] << 16 )             \
        | ( (uint32_t) (b)[(i) + 2] <<  8 )             \
        | ( (uint32_t) (b)[(i) + 3]       );            \
}
#endif

#ifndef PUT_UINT32_BE
#define PUT_UINT32_BE(n,b,i)                            \
{                                                       \
    (b)[(i)    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[(i) + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[(i) + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[(i) + 3] = (unsigned char) ( (n)       );       \
}
#endif

/*
 * XTEA key schedule
 */
void xtea_setup( xtea_context *ctx, const unsigned char key[16] )
{
    int i;

    memset(ctx, 0, sizeof(xtea_context));

    for( i = 0; i < 4; i++ )
    {
        GET_UINT32_BE( ctx->k[i], key, i << 2 );
    }
}

/*
 * XTEA encrypt function
 */
int xtea_crypt_ecb( xtea_context *ctx, int mode,
                    const unsigned char input[8], unsigned char output[8])
{
    uint32_t *k, v0, v1, i;

    k = ctx->k;

    GET_UINT32_BE( v0, input, 0 );
    GET_UINT32_BE( v1, input, 4 );

    if( mode == XTEA_ENCRYPT )
    {
        uint32_t sum = 0, delta = 0x9E3779B9;

        for( i = 0; i < 32; i++ )
        {
            v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
            sum += delta;
            v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum>>11) & 3]);
        }
    }
    else /* XTEA_DECRYPT */
    {
        uint32_t delta = 0x9E3779B9, sum = delta * 32;

        for( i = 0; i < 32; i++ )
        {
            v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum>>11) & 3]);
            sum -= delta;
            v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum & 3]);
        }
    }

    PUT_UINT32_BE( v0, output, 0 );
    PUT_UINT32_BE( v1, output, 4 );

    return( 0 );
}

#if defined(POLARSSL_CIPHER_MODE_CBC)
/*
 * XTEA-CBC buffer encryption/decryption
 */
int xtea_crypt_cbc( xtea_context *ctx, int mode, size_t length,
                    unsigned char iv[8], const unsigned char *input,
                    unsigned char *output)
{
    int i;
    unsigned char temp[8];

    if( length % 8 )
        return( POLARSSL_ERR_XTEA_INVALID_INPUT_LENGTH );

    if( mode == XTEA_DECRYPT )
    {
        while( length > 0 )
        {
            memcpy( temp, input, 8 );
            xtea_crypt_ecb( ctx, mode, input, output );

            for(i = 0; i < 8; i++)
                output[i] = (unsigned char)( output[i] ^ iv[i] );

            memcpy( iv, temp, 8 );

            input  += 8;
            output += 8;
            length -= 8;
        }
    }
    else
    {
        while( length > 0 )
        {
            for( i = 0; i < 8; i++ )
                output[i] = (unsigned char)( input[i] ^ iv[i] );

            xtea_crypt_ecb( ctx, mode, output, output );
            memcpy( iv, output, 8 );

            input  += 8;
            output += 8;
            length -= 8;
        }
    }

    return( 0 );
}
#endif /* POLARSSL_CIPHER_MODE_CBC */
#endif /* !POLARSSL_XTEA_ALT */

#if defined(POLARSSL_SELF_TEST)

#include <string.h>
#include <stdio.h>

/*
 * XTEA tests vectors (non-official)
 */

static const unsigned char xtea_test_key[6][16] =
{
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
     0x0c, 0x0d, 0x0e, 0x0f },
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
     0x0c, 0x0d, 0x0e, 0x0f },
   { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
     0x0c, 0x0d, 0x0e, 0x0f },
   { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00 },
   { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00 },
   { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00 }
};

static const unsigned char xtea_test_pt[6][8] =
{
    { 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 },
    { 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41 },
    { 0x5a, 0x5b, 0x6e, 0x27, 0x89, 0x48, 0xd7, 0x7f },
    { 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48 },
    { 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41 },
    { 0x70, 0xe1, 0x22, 0x5d, 0x6e, 0x4e, 0x76, 0x55 }
};

static const unsigned char xtea_test_ct[6][8] =
{
    { 0x49, 0x7d, 0xf3, 0xd0, 0x72, 0x61, 0x2c, 0xb5 },
    { 0xe7, 0x8f, 0x2d, 0x13, 0x74, 0x43, 0x41, 0xd8 },
    { 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41 },
    { 0xa0, 0x39, 0x05, 0x89, 0xf8, 0xb8, 0xef, 0xa5 },
    { 0xed, 0x23, 0x37, 0x5a, 0x82, 0x1a, 0x8c, 0x2d },
    { 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41 }
};

/*
 * Checkup routine
 */
int xtea_self_test( int verbose )
{
    int i;
    unsigned char buf[8];
    xtea_context ctx;

    for( i = 0; i < 6; i++ )
    {
        if( verbose != 0 )
            printf( "  XTEA test #%d: ", i + 1 );

        memcpy( buf, xtea_test_pt[i], 8 );

        xtea_setup( &ctx, xtea_test_key[i] );
        xtea_crypt_ecb( &ctx, XTEA_ENCRYPT, buf, buf );

        if( memcmp( buf, xtea_test_ct[i], 8 ) != 0 )
        {
            if( verbose != 0 )
                printf( "failed\n" );

            return( 1 );
        }

        if( verbose != 0 )
            printf( "passed\n" );
    }

    if( verbose != 0 )
        printf( "\n" );

    return( 0 );
}

#endif

#endif
