/*
 *  Entropy accumulator implementation
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

#if defined(POLARSSL_ENTROPY_C)

#include "polarssl/entropy.h"
#include "polarssl/entropy_poll.h"

#if defined(POLARSSL_HAVEGE_C)
#include "polarssl/havege.h"
#endif

#define ENTROPY_MAX_LOOP    256     /**< Maximum amount to loop before error */

void entropy_init( entropy_context *ctx )
{
    memset( ctx, 0, sizeof(entropy_context) );

#if defined(POLARSSL_THREADING_C)
    polarssl_mutex_init( &ctx->mutex );
#endif

#if defined(POLARSSL_ENTROPY_SHA512_ACCUMULATOR)
    sha512_starts( &ctx->accumulator, 0 );
#else
    sha256_starts( &ctx->accumulator, 0 );
#endif
#if defined(POLARSSL_HAVEGE_C)
    havege_init( &ctx->havege_data );
#endif

#if !defined(POLARSSL_NO_DEFAULT_ENTROPY_SOURCES)
#if !defined(POLARSSL_NO_PLATFORM_ENTROPY)
    entropy_add_source( ctx, platform_entropy_poll, NULL,
                        ENTROPY_MIN_PLATFORM );
#endif
#if defined(POLARSSL_TIMING_C)
    entropy_add_source( ctx, hardclock_poll, NULL, ENTROPY_MIN_HARDCLOCK );
#endif
#if defined(POLARSSL_HAVEGE_C)
    entropy_add_source( ctx, havege_poll, &ctx->havege_data,
                        ENTROPY_MIN_HAVEGE );
#endif
#endif /* POLARSSL_NO_DEFAULT_ENTROPY_SOURCES */
}

void entropy_free( entropy_context *ctx )
{
    ((void) ctx);
#if defined(POLARSSL_THREADING_C)
    polarssl_mutex_free( &ctx->mutex );
#endif
}

int entropy_add_source( entropy_context *ctx,
                        f_source_ptr f_source, void *p_source,
                        size_t threshold )
{
    int index = ctx->source_count;

    if( index >= ENTROPY_MAX_SOURCES )
        return( POLARSSL_ERR_ENTROPY_MAX_SOURCES );

    ctx->source[index].f_source = f_source;
    ctx->source[index].p_source = p_source;
    ctx->source[index].threshold = threshold;

    ctx->source_count++;

    return( 0 );
}

/*
 * Entropy accumulator update
 */
static int entropy_update( entropy_context *ctx, unsigned char source_id,
                           const unsigned char *data, size_t len )
{
    unsigned char header[2];
    unsigned char tmp[ENTROPY_BLOCK_SIZE];
    size_t use_len = len;
    const unsigned char *p = data;

    if( use_len > ENTROPY_BLOCK_SIZE )
    {
#if defined(POLARSSL_ENTROPY_SHA512_ACCUMULATOR)
        sha512( data, len, tmp, 0 );
#else
        sha256( data, len, tmp, 0 );
#endif
        p = tmp;
        use_len = ENTROPY_BLOCK_SIZE;
    }

    header[0] = source_id;
    header[1] = use_len & 0xFF;

#if defined(POLARSSL_ENTROPY_SHA512_ACCUMULATOR)
    sha512_update( &ctx->accumulator, header, 2 );
    sha512_update( &ctx->accumulator, p, use_len );
#else
    sha256_update( &ctx->accumulator, header, 2 );
    sha256_update( &ctx->accumulator, p, use_len );
#endif

    return( 0 );
}

int entropy_update_manual( entropy_context *ctx,
                           const unsigned char *data, size_t len )
{
    return entropy_update( ctx, ENTROPY_SOURCE_MANUAL, data, len );
}

/*
 * Run through the different sources to add entropy to our accumulator
 */
int entropy_gather( entropy_context *ctx )
{
    int ret, i;
    unsigned char buf[ENTROPY_MAX_GATHER];
    size_t olen;
    
    if( ctx->source_count == 0 )
        return( POLARSSL_ERR_ENTROPY_NO_SOURCES_DEFINED );

    /*
     * Run through our entropy sources
     */
    for( i = 0; i < ctx->source_count; i++ )
    {
        olen = 0;
        if ( ( ret = ctx->source[i].f_source( ctx->source[i].p_source,
                        buf, ENTROPY_MAX_GATHER, &olen ) ) != 0 )
        {
            return( ret );
        }

        /*
         * Add if we actually gathered something
         */
        if( olen > 0 )
        {
            entropy_update( ctx, (unsigned char) i, buf, olen );
            ctx->source[i].size += olen;
        }
    }

    return( 0 );
}

int entropy_func( void *data, unsigned char *output, size_t len )
{
    int ret, count = 0, i, reached;
    entropy_context *ctx = (entropy_context *) data;
    unsigned char buf[ENTROPY_BLOCK_SIZE];

    if( len > ENTROPY_BLOCK_SIZE )
        return( POLARSSL_ERR_ENTROPY_SOURCE_FAILED );

#if defined(POLARSSL_THREADING_C)
    if( ( ret = polarssl_mutex_lock( &ctx->mutex ) ) != 0 )
        return( ret );
#endif

    /*
     * Always gather extra entropy before a call
     */
    do
    {
        if( count++ > ENTROPY_MAX_LOOP )
        {
            ret = POLARSSL_ERR_ENTROPY_SOURCE_FAILED;
            goto exit;
        }

        if( ( ret = entropy_gather( ctx ) ) != 0 )
            goto exit;

        reached = 0;

        for( i = 0; i < ctx->source_count; i++ )
            if( ctx->source[i].size >= ctx->source[i].threshold )
                reached++;
    }
    while( reached != ctx->source_count );

    memset( buf, 0, ENTROPY_BLOCK_SIZE );

#if defined(POLARSSL_ENTROPY_SHA512_ACCUMULATOR)
    sha512_finish( &ctx->accumulator, buf );

    /*
     * Perform second SHA-512 on entropy
     */
    sha512( buf, ENTROPY_BLOCK_SIZE, buf, 0 );

    /*
     * Reset accumulator and counters and recycle existing entropy
     */
    memset( &ctx->accumulator, 0, sizeof( sha512_context ) );
    sha512_starts( &ctx->accumulator, 0 );
    sha512_update( &ctx->accumulator, buf, ENTROPY_BLOCK_SIZE );
#else /* POLARSSL_ENTROPY_SHA512_ACCUMULATOR */
    sha256_finish( &ctx->accumulator, buf );

    /*
     * Perform second SHA-256 on entropy
     */
    sha256( buf, ENTROPY_BLOCK_SIZE, buf, 0 );

    /*
     * Reset accumulator and counters and recycle existing entropy
     */
    memset( &ctx->accumulator, 0, sizeof( sha256_context ) );
    sha256_starts( &ctx->accumulator, 0 );
    sha256_update( &ctx->accumulator, buf, ENTROPY_BLOCK_SIZE );
#endif /* POLARSSL_ENTROPY_SHA512_ACCUMULATOR */

    for( i = 0; i < ctx->source_count; i++ )
        ctx->source[i].size = 0;

    memcpy( output, buf, len );

    ret = 0;

exit:
#if defined(POLARSSL_THREADING_C)
    if( polarssl_mutex_unlock( &ctx->mutex ) != 0 )
        return( POLARSSL_ERR_THREADING_MUTEX_ERROR );
#endif

    return( ret );
}

#endif
