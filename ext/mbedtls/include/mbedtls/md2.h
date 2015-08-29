/**
 * \file mbedtls_md2.h
 *
 * \brief MD2 message digest algorithm (hash function)
 *
 *  Copyright (C) 2006-2014, ARM Limited, All Rights Reserved
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
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
#ifndef MBEDTLS_MD2_H
#define MBEDTLS_MD2_H

#if !defined(MBEDTLS_CONFIG_FILE)
#include "config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#include <stddef.h>

#if !defined(MBEDTLS_MD2_ALT)
// Regular implementation
//

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          MD2 context structure
 */
typedef struct
{
    unsigned char cksum[16];    /*!< checksum of the data block */
    unsigned char state[48];    /*!< intermediate digest state  */
    unsigned char buffer[16];   /*!< data block being processed */
    size_t left;                /*!< amount of data in buffer   */
}
mbedtls_md2_context;

/**
 * \brief          Initialize MD2 context
 *
 * \param ctx      MD2 context to be initialized
 */
void mbedtls_md2_init( mbedtls_md2_context *ctx );

/**
 * \brief          Clear MD2 context
 *
 * \param ctx      MD2 context to be cleared
 */
void mbedtls_md2_free( mbedtls_md2_context *ctx );

/**
 * \brief          Clone (the state of) an MD2 context
 *
 * \param dst      The destination context
 * \param src      The context to be cloned
 */
void mbedtls_md2_clone( mbedtls_md2_context *dst,
                        const mbedtls_md2_context *src );

/**
 * \brief          MD2 context setup
 *
 * \param ctx      context to be initialized
 */
void mbedtls_md2_starts( mbedtls_md2_context *ctx );

/**
 * \brief          MD2 process buffer
 *
 * \param ctx      MD2 context
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 */
void mbedtls_md2_update( mbedtls_md2_context *ctx, const unsigned char *input, size_t ilen );

/**
 * \brief          MD2 final digest
 *
 * \param ctx      MD2 context
 * \param output   MD2 checksum result
 */
void mbedtls_md2_finish( mbedtls_md2_context *ctx, unsigned char output[16] );

#ifdef __cplusplus
}
#endif

#else  /* MBEDTLS_MD2_ALT */
#include "md2_alt.h"
#endif /* MBEDTLS_MD2_ALT */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief          Output = MD2( input buffer )
 *
 * \param input    buffer holding the  data
 * \param ilen     length of the input data
 * \param output   MD2 checksum result
 */
void mbedtls_md2( const unsigned char *input, size_t ilen, unsigned char output[16] );

/**
 * \brief          Checkup routine
 *
 * \return         0 if successful, or 1 if the test failed
 */
int mbedtls_md2_self_test( int verbose );

/* Internal use */
void mbedtls_md2_process( mbedtls_md2_context *ctx );

#ifdef __cplusplus
}
#endif

#endif /* mbedtls_md2.h */
