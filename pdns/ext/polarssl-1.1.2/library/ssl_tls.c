/*
 *  SSLv3/TLSv1 shared functions
 *
 *  Copyright (C) 2006-2010, Brainspark B.V.
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
 *  The SSL 3.0 specification was drafted by Netscape in 1996,
 *  and became an IETF standard in 1999.
 *
 *  http://wp.netscape.com/eng/ssl3/
 *  http://www.ietf.org/rfc/rfc2246.txt
 *  http://www.ietf.org/rfc/rfc4346.txt
 */

#include "polarssl/config.h"

#if defined(POLARSSL_SSL_TLS_C)

#include "polarssl/aes.h"
#include "polarssl/arc4.h"
#include "polarssl/camellia.h"
#include "polarssl/des.h"
#include "polarssl/debug.h"
#include "polarssl/ssl.h"

#include <stdlib.h>
#include <time.h>

#if defined _MSC_VER && !defined strcasecmp
#define strcasecmp _stricmp
#endif

/*
 * Key material generation
 */
static int tls1_prf( unsigned char *secret, size_t slen, char *label,
                     unsigned char *random, size_t rlen,
                     unsigned char *dstbuf, size_t dlen )
{
    size_t nb, hs;
    size_t i, j, k;
    unsigned char *S1, *S2;
    unsigned char tmp[128];
    unsigned char h_i[20];

    if( sizeof( tmp ) < 20 + strlen( label ) + rlen )
        return( POLARSSL_ERR_SSL_BAD_INPUT_DATA );

    hs = ( slen + 1 ) / 2;
    S1 = secret;
    S2 = secret + slen - hs;

    nb = strlen( label );
    memcpy( tmp + 20, label, nb );
    memcpy( tmp + 20 + nb, random, rlen );
    nb += rlen;

    /*
     * First compute P_md5(secret,label+random)[0..dlen]
     */
    md5_hmac( S1, hs, tmp + 20, nb, 4 + tmp );

    for( i = 0; i < dlen; i += 16 )
    {
        md5_hmac( S1, hs, 4 + tmp, 16 + nb, h_i );
        md5_hmac( S1, hs, 4 + tmp, 16,  4 + tmp );

        k = ( i + 16 > dlen ) ? dlen % 16 : 16;

        for( j = 0; j < k; j++ )
            dstbuf[i + j]  = h_i[j];
    }

    /*
     * XOR out with P_sha1(secret,label+random)[0..dlen]
     */
    sha1_hmac( S2, hs, tmp + 20, nb, tmp );

    for( i = 0; i < dlen; i += 20 )
    {
        sha1_hmac( S2, hs, tmp, 20 + nb, h_i );
        sha1_hmac( S2, hs, tmp, 20,      tmp );

        k = ( i + 20 > dlen ) ? dlen % 20 : 20;

        for( j = 0; j < k; j++ )
            dstbuf[i + j] = (unsigned char)( dstbuf[i + j] ^ h_i[j] );
    }

    memset( tmp, 0, sizeof( tmp ) );
    memset( h_i, 0, sizeof( h_i ) );

    return( 0 );
}

int ssl_derive_keys( ssl_context *ssl )
{
    int i;
    md5_context md5;
    sha1_context sha1;
    unsigned char tmp[64];
    unsigned char padding[16];
    unsigned char sha1sum[20];
    unsigned char keyblk[256];
    unsigned char *key1;
    unsigned char *key2;

    SSL_DEBUG_MSG( 2, ( "=> derive keys" ) );

    /*
     * SSLv3:
     *   master =
     *     MD5( premaster + SHA1( 'A'   + premaster + randbytes ) ) +
     *     MD5( premaster + SHA1( 'BB'  + premaster + randbytes ) ) +
     *     MD5( premaster + SHA1( 'CCC' + premaster + randbytes ) )
     *
     * TLSv1:
     *   master = PRF( premaster, "master secret", randbytes )[0..47]
     */
    if( ssl->resume == 0 )
    {
        size_t len = ssl->pmslen;

        SSL_DEBUG_BUF( 3, "premaster secret", ssl->premaster, len );

        if( ssl->minor_ver == SSL_MINOR_VERSION_0 )
        {
            for( i = 0; i < 3; i++ )
            {
                memset( padding, 'A' + i, 1 + i );

                sha1_starts( &sha1 );
                sha1_update( &sha1, padding, 1 + i );
                sha1_update( &sha1, ssl->premaster, len );
                sha1_update( &sha1, ssl->randbytes,  64 );
                sha1_finish( &sha1, sha1sum );

                md5_starts( &md5 );
                md5_update( &md5, ssl->premaster, len );
                md5_update( &md5, sha1sum, 20 );
                md5_finish( &md5, ssl->session->master + i * 16 );
            }
        }
        else
            tls1_prf( ssl->premaster, len, "master secret",
                      ssl->randbytes, 64, ssl->session->master, 48 );

        memset( ssl->premaster, 0, sizeof( ssl->premaster ) );
    }
    else
        SSL_DEBUG_MSG( 3, ( "no premaster (session resumed)" ) );

    /*
     * Swap the client and server random values.
     */
    memcpy( tmp, ssl->randbytes, 64 );
    memcpy( ssl->randbytes, tmp + 32, 32 );
    memcpy( ssl->randbytes + 32, tmp, 32 );
    memset( tmp, 0, sizeof( tmp ) );

    /*
     *  SSLv3:
     *    key block =
     *      MD5( master + SHA1( 'A'    + master + randbytes ) ) +
     *      MD5( master + SHA1( 'BB'   + master + randbytes ) ) +
     *      MD5( master + SHA1( 'CCC'  + master + randbytes ) ) +
     *      MD5( master + SHA1( 'DDDD' + master + randbytes ) ) +
     *      ...
     *
     *  TLSv1:
     *    key block = PRF( master, "key expansion", randbytes )
     */
    if( ssl->minor_ver == SSL_MINOR_VERSION_0 )
    {
        for( i = 0; i < 16; i++ )
        {
            memset( padding, 'A' + i, 1 + i );

            sha1_starts( &sha1 );
            sha1_update( &sha1, padding, 1 + i );
            sha1_update( &sha1, ssl->session->master, 48 );
            sha1_update( &sha1, ssl->randbytes, 64 );
            sha1_finish( &sha1, sha1sum );

            md5_starts( &md5 );
            md5_update( &md5, ssl->session->master, 48 );
            md5_update( &md5, sha1sum, 20 );
            md5_finish( &md5, keyblk + i * 16 );
        }

        memset( &md5,  0, sizeof( md5  ) );
        memset( &sha1, 0, sizeof( sha1 ) );

        memset( padding, 0, sizeof( padding ) );
        memset( sha1sum, 0, sizeof( sha1sum ) );
    }
    else
        tls1_prf( ssl->session->master, 48, "key expansion",
                  ssl->randbytes, 64, keyblk, 256 );

    SSL_DEBUG_MSG( 3, ( "ciphersuite = %s", ssl_get_ciphersuite( ssl ) ) );
    SSL_DEBUG_BUF( 3, "master secret", ssl->session->master, 48 );
    SSL_DEBUG_BUF( 4, "random bytes", ssl->randbytes, 64 );
    SSL_DEBUG_BUF( 4, "key block", keyblk, 256 );

    memset( ssl->randbytes, 0, sizeof( ssl->randbytes ) );

    /*
     * Determine the appropriate key, IV and MAC length.
     */
    switch( ssl->session->ciphersuite )
    {
#if defined(POLARSSL_ARC4_C)
        case SSL_RSA_RC4_128_MD5:
            ssl->keylen = 16; ssl->minlen = 16;
            ssl->ivlen  =  0; ssl->maclen = 16;
            break;

        case SSL_RSA_RC4_128_SHA:
            ssl->keylen = 16; ssl->minlen = 20;
            ssl->ivlen  =  0; ssl->maclen = 20;
            break;
#endif

#if defined(POLARSSL_DES_C)
        case SSL_RSA_DES_168_SHA:
        case SSL_EDH_RSA_DES_168_SHA:
            ssl->keylen = 24; ssl->minlen = 24;
            ssl->ivlen  =  8; ssl->maclen = 20;
            break;
#endif

#if defined(POLARSSL_AES_C)
        case SSL_RSA_AES_128_SHA:
        case SSL_EDH_RSA_AES_128_SHA:
            ssl->keylen = 16; ssl->minlen = 32;
            ssl->ivlen  = 16; ssl->maclen = 20;
            break;

        case SSL_RSA_AES_256_SHA:
        case SSL_EDH_RSA_AES_256_SHA:
            ssl->keylen = 32; ssl->minlen = 32;
            ssl->ivlen  = 16; ssl->maclen = 20;
            break;
#endif

#if defined(POLARSSL_CAMELLIA_C)
        case SSL_RSA_CAMELLIA_128_SHA:
        case SSL_EDH_RSA_CAMELLIA_128_SHA:
            ssl->keylen = 16; ssl->minlen = 32;
            ssl->ivlen  = 16; ssl->maclen = 20;
            break;

        case SSL_RSA_CAMELLIA_256_SHA:
        case SSL_EDH_RSA_CAMELLIA_256_SHA:
            ssl->keylen = 32; ssl->minlen = 32;
            ssl->ivlen  = 16; ssl->maclen = 20;
            break;
#endif

        default:
            SSL_DEBUG_MSG( 1, ( "ciphersuite %s is not available",
                           ssl_get_ciphersuite( ssl ) ) );
            return( POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE );
    }

    SSL_DEBUG_MSG( 3, ( "keylen: %d, minlen: %d, ivlen: %d, maclen: %d",
                   ssl->keylen, ssl->minlen, ssl->ivlen, ssl->maclen ) );

    /*
     * Finally setup the cipher contexts, IVs and MAC secrets.
     */
    if( ssl->endpoint == SSL_IS_CLIENT )
    {
        key1 = keyblk + ssl->maclen * 2;
        key2 = keyblk + ssl->maclen * 2 + ssl->keylen;

        memcpy( ssl->mac_enc, keyblk,  ssl->maclen );
        memcpy( ssl->mac_dec, keyblk + ssl->maclen, ssl->maclen );

        /*
         * This is not used in TLS v1.1.
         */
        memcpy( ssl->iv_enc, key2 + ssl->keylen,  ssl->ivlen );
        memcpy( ssl->iv_dec, key2 + ssl->keylen + ssl->ivlen,
                ssl->ivlen );
    }
    else
    {
        key1 = keyblk + ssl->maclen * 2 + ssl->keylen;
        key2 = keyblk + ssl->maclen * 2;

        memcpy( ssl->mac_dec, keyblk,  ssl->maclen );
        memcpy( ssl->mac_enc, keyblk + ssl->maclen, ssl->maclen );

        /*
         * This is not used in TLS v1.1.
         */
        memcpy( ssl->iv_dec, key1 + ssl->keylen,  ssl->ivlen );
        memcpy( ssl->iv_enc, key1 + ssl->keylen + ssl->ivlen,
                ssl->ivlen );
    }

    switch( ssl->session->ciphersuite )
    {
#if defined(POLARSSL_ARC4_C)
        case SSL_RSA_RC4_128_MD5:
        case SSL_RSA_RC4_128_SHA:
            arc4_setup( (arc4_context *) ssl->ctx_enc, key1, ssl->keylen );
            arc4_setup( (arc4_context *) ssl->ctx_dec, key2, ssl->keylen );
            break;
#endif

#if defined(POLARSSL_DES_C)
        case SSL_RSA_DES_168_SHA:
        case SSL_EDH_RSA_DES_168_SHA:
            des3_set3key_enc( (des3_context *) ssl->ctx_enc, key1 );
            des3_set3key_dec( (des3_context *) ssl->ctx_dec, key2 );
            break;
#endif

#if defined(POLARSSL_AES_C)
        case SSL_RSA_AES_128_SHA:
        case SSL_EDH_RSA_AES_128_SHA:
            aes_setkey_enc( (aes_context *) ssl->ctx_enc, key1, 128 );
            aes_setkey_dec( (aes_context *) ssl->ctx_dec, key2, 128 );
            break;

        case SSL_RSA_AES_256_SHA:
        case SSL_EDH_RSA_AES_256_SHA:
            aes_setkey_enc( (aes_context *) ssl->ctx_enc, key1, 256 );
            aes_setkey_dec( (aes_context *) ssl->ctx_dec, key2, 256 );
            break;
#endif

#if defined(POLARSSL_CAMELLIA_C)
        case SSL_RSA_CAMELLIA_128_SHA:
        case SSL_EDH_RSA_CAMELLIA_128_SHA:
            camellia_setkey_enc( (camellia_context *) ssl->ctx_enc, key1, 128 );
            camellia_setkey_dec( (camellia_context *) ssl->ctx_dec, key2, 128 );
            break;

        case SSL_RSA_CAMELLIA_256_SHA:
        case SSL_EDH_RSA_CAMELLIA_256_SHA:
            camellia_setkey_enc( (camellia_context *) ssl->ctx_enc, key1, 256 );
            camellia_setkey_dec( (camellia_context *) ssl->ctx_dec, key2, 256 );
            break;
#endif

        default:
            return( POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE );
    }

    memset( keyblk, 0, sizeof( keyblk ) );

    SSL_DEBUG_MSG( 2, ( "<= derive keys" ) );

    return( 0 );
}

void ssl_calc_verify( ssl_context *ssl, unsigned char hash[36] )
{
    md5_context md5;
    sha1_context sha1;
    unsigned char pad_1[48];
    unsigned char pad_2[48];

    SSL_DEBUG_MSG( 2, ( "=> calc verify" ) );

    memcpy( &md5 , &ssl->fin_md5 , sizeof(  md5_context ) );
    memcpy( &sha1, &ssl->fin_sha1, sizeof( sha1_context ) );

    if( ssl->minor_ver == SSL_MINOR_VERSION_0 )
    {
        memset( pad_1, 0x36, 48 );
        memset( pad_2, 0x5C, 48 );

        md5_update( &md5, ssl->session->master, 48 );
        md5_update( &md5, pad_1, 48 );
        md5_finish( &md5, hash );

        md5_starts( &md5 );
        md5_update( &md5, ssl->session->master, 48 );
        md5_update( &md5, pad_2, 48 );
        md5_update( &md5, hash,  16 );
        md5_finish( &md5, hash );

        sha1_update( &sha1, ssl->session->master, 48 );
        sha1_update( &sha1, pad_1, 40 );
        sha1_finish( &sha1, hash + 16 );

        sha1_starts( &sha1 );
        sha1_update( &sha1, ssl->session->master, 48 );
        sha1_update( &sha1, pad_2, 40 );
        sha1_update( &sha1, hash + 16, 20 );
        sha1_finish( &sha1, hash + 16 );
    }
    else /* TLSv1 */
    {
         md5_finish( &md5,  hash );
        sha1_finish( &sha1, hash + 16 );
    }

    SSL_DEBUG_BUF( 3, "calculated verify result", hash, 36 );
    SSL_DEBUG_MSG( 2, ( "<= calc verify" ) );

    return;
}

/*
 * SSLv3.0 MAC functions
 */
static void ssl_mac_md5( unsigned char *secret,
                         unsigned char *buf, size_t len,
                         unsigned char *ctr, int type )
{
    unsigned char header[11];
    unsigned char padding[48];
    md5_context md5;

    memcpy( header, ctr, 8 );
    header[ 8] = (unsigned char)  type;
    header[ 9] = (unsigned char)( len >> 8 );
    header[10] = (unsigned char)( len      );

    memset( padding, 0x36, 48 );
    md5_starts( &md5 );
    md5_update( &md5, secret,  16 );
    md5_update( &md5, padding, 48 );
    md5_update( &md5, header,  11 );
    md5_update( &md5, buf,  len );
    md5_finish( &md5, buf + len );

    memset( padding, 0x5C, 48 );
    md5_starts( &md5 );
    md5_update( &md5, secret,  16 );
    md5_update( &md5, padding, 48 );
    md5_update( &md5, buf + len, 16 );
    md5_finish( &md5, buf + len );
}

static void ssl_mac_sha1( unsigned char *secret,
                          unsigned char *buf, size_t len,
                          unsigned char *ctr, int type )
{
    unsigned char header[11];
    unsigned char padding[40];
    sha1_context sha1;

    memcpy( header, ctr, 8 );
    header[ 8] = (unsigned char)  type;
    header[ 9] = (unsigned char)( len >> 8 );
    header[10] = (unsigned char)( len      );

    memset( padding, 0x36, 40 );
    sha1_starts( &sha1 );
    sha1_update( &sha1, secret,  20 );
    sha1_update( &sha1, padding, 40 );
    sha1_update( &sha1, header,  11 );
    sha1_update( &sha1, buf,  len );
    sha1_finish( &sha1, buf + len );

    memset( padding, 0x5C, 40 );
    sha1_starts( &sha1 );
    sha1_update( &sha1, secret,  20 );
    sha1_update( &sha1, padding, 40 );
    sha1_update( &sha1, buf + len, 20 );
    sha1_finish( &sha1, buf + len );
}

/*
 * Encryption/decryption functions
 */
static int ssl_encrypt_buf( ssl_context *ssl )
{
    size_t i, padlen;

    SSL_DEBUG_MSG( 2, ( "=> encrypt buf" ) );

    /*
     * Add MAC then encrypt
     */
    if( ssl->minor_ver == SSL_MINOR_VERSION_0 )
    {
        if( ssl->maclen == 16 )
             ssl_mac_md5( ssl->mac_enc,
                          ssl->out_msg, ssl->out_msglen,
                          ssl->out_ctr, ssl->out_msgtype );

        if( ssl->maclen == 20 )
            ssl_mac_sha1( ssl->mac_enc,
                          ssl->out_msg, ssl->out_msglen,
                          ssl->out_ctr, ssl->out_msgtype );
    }
    else
    {
        if( ssl->maclen == 16 )
             md5_hmac( ssl->mac_enc, 16,
                       ssl->out_ctr,  ssl->out_msglen + 13,
                       ssl->out_msg + ssl->out_msglen );

        if( ssl->maclen == 20 )
            sha1_hmac( ssl->mac_enc, 20,
                       ssl->out_ctr,  ssl->out_msglen + 13,
                       ssl->out_msg + ssl->out_msglen );
    }

    SSL_DEBUG_BUF( 4, "computed mac",
                   ssl->out_msg + ssl->out_msglen, ssl->maclen );

    ssl->out_msglen += ssl->maclen;

    for( i = 8; i > 0; i-- )
        if( ++ssl->out_ctr[i - 1] != 0 )
            break;

    if( ssl->ivlen == 0 )
    {
#if defined(POLARSSL_ARC4_C)
        padlen = 0;

        SSL_DEBUG_MSG( 3, ( "before encrypt: msglen = %d, "
                            "including %d bytes of padding",
                       ssl->out_msglen, 0 ) );

        SSL_DEBUG_BUF( 4, "before encrypt: output payload",
                       ssl->out_msg, ssl->out_msglen );

        arc4_crypt( (arc4_context *) ssl->ctx_enc,
                    ssl->out_msglen, ssl->out_msg,
                    ssl->out_msg );
#else
        return( POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE );
#endif
    }
    else
    {
        unsigned char *enc_msg;
        size_t enc_msglen;

        padlen = ssl->ivlen - ( ssl->out_msglen + 1 ) % ssl->ivlen;
        if( padlen == ssl->ivlen )
            padlen = 0;

        for( i = 0; i <= padlen; i++ )
            ssl->out_msg[ssl->out_msglen + i] = (unsigned char) padlen;

        ssl->out_msglen += padlen + 1;

        enc_msglen = ssl->out_msglen;
        enc_msg = ssl->out_msg;

        /*
         * Prepend per-record IV for block cipher in TLS v1.1 as per
         * Method 1 (6.2.3.2. in RFC4346)
         */
        if( ssl->minor_ver == SSL_MINOR_VERSION_2 )
        {
            /*
             * Generate IV
             */
            int ret = ssl->f_rng( ssl->p_rng, ssl->iv_enc, ssl->ivlen );
            if( ret != 0 )
                return( ret );

            /*
             * Shift message for ivlen bytes and prepend IV
             */
            memmove( ssl->out_msg + ssl->ivlen, ssl->out_msg, ssl->out_msglen );
            memcpy( ssl->out_msg, ssl->iv_enc, ssl->ivlen );

            /*
             * Fix pointer positions and message length with added IV
             */
            enc_msg = ssl->out_msg + ssl->ivlen;
            enc_msglen = ssl->out_msglen;
            ssl->out_msglen += ssl->ivlen;
        }

        SSL_DEBUG_MSG( 3, ( "before encrypt: msglen = %d, "
                            "including %d bytes of IV and %d bytes of padding",
                       ssl->out_msglen, ssl->ivlen, padlen + 1 ) );

        SSL_DEBUG_BUF( 4, "before encrypt: output payload",
                       ssl->out_msg, ssl->out_msglen );

        switch( ssl->ivlen )
        {
            case  8:
#if defined(POLARSSL_DES_C)
                des3_crypt_cbc( (des3_context *) ssl->ctx_enc,
                    DES_ENCRYPT, enc_msglen,
                    ssl->iv_enc, enc_msg, enc_msg );
                break;
#endif

            case 16:
#if defined(POLARSSL_AES_C)
        if ( ssl->session->ciphersuite == SSL_RSA_AES_128_SHA ||
             ssl->session->ciphersuite == SSL_EDH_RSA_AES_128_SHA ||
             ssl->session->ciphersuite == SSL_RSA_AES_256_SHA ||
             ssl->session->ciphersuite == SSL_EDH_RSA_AES_256_SHA)
        {
                    aes_crypt_cbc( (aes_context *) ssl->ctx_enc,
                        AES_ENCRYPT, enc_msglen,
                        ssl->iv_enc, enc_msg, enc_msg);
                    break;
        }
#endif

#if defined(POLARSSL_CAMELLIA_C)
        if ( ssl->session->ciphersuite == SSL_RSA_CAMELLIA_128_SHA ||
             ssl->session->ciphersuite == SSL_EDH_RSA_CAMELLIA_128_SHA ||
             ssl->session->ciphersuite == SSL_RSA_CAMELLIA_256_SHA ||
             ssl->session->ciphersuite == SSL_EDH_RSA_CAMELLIA_256_SHA)
        {
                    camellia_crypt_cbc( (camellia_context *) ssl->ctx_enc,
                        CAMELLIA_ENCRYPT, enc_msglen,
                        ssl->iv_enc, enc_msg, enc_msg );
                    break;
        }
#endif

            default:
                return( POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE );
        }
    }

    SSL_DEBUG_MSG( 2, ( "<= encrypt buf" ) );

    return( 0 );
}

static int ssl_decrypt_buf( ssl_context *ssl )
{
    size_t i, padlen;
    unsigned char tmp[20];

    SSL_DEBUG_MSG( 2, ( "=> decrypt buf" ) );

    if( ssl->in_msglen < ssl->minlen )
    {
        SSL_DEBUG_MSG( 1, ( "in_msglen (%d) < minlen (%d)",
                       ssl->in_msglen, ssl->minlen ) );
        return( POLARSSL_ERR_SSL_INVALID_MAC );
    }

    if( ssl->ivlen == 0 )
    {
#if defined(POLARSSL_ARC4_C)
        padlen = 0;
        arc4_crypt( (arc4_context *) ssl->ctx_dec,
                    ssl->in_msglen, ssl->in_msg,
                    ssl->in_msg );
#else
        return( POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE );
#endif
    }
    else
    {
        unsigned char *dec_msg;
        unsigned char *dec_msg_result;
        size_t dec_msglen;

        /*
         * Decrypt and check the padding
         */
        if( ssl->in_msglen % ssl->ivlen != 0 )
        {
            SSL_DEBUG_MSG( 1, ( "msglen (%d) %% ivlen (%d) != 0",
                           ssl->in_msglen, ssl->ivlen ) );
            return( POLARSSL_ERR_SSL_INVALID_MAC );
        }

        dec_msglen = ssl->in_msglen;
        dec_msg = ssl->in_msg;
        dec_msg_result = ssl->in_msg;

        /*
         * Initialize for prepended IV for block cipher in TLS v1.1
         */
        if( ssl->minor_ver == SSL_MINOR_VERSION_2 )
        {
            dec_msg += ssl->ivlen;
            dec_msglen -= ssl->ivlen;
            ssl->in_msglen -= ssl->ivlen;

            for( i = 0; i < ssl->ivlen; i++ )
                ssl->iv_dec[i] = ssl->in_msg[i];
        }

        switch( ssl->ivlen )
        {
#if defined(POLARSSL_DES_C)
            case  8:
                des3_crypt_cbc( (des3_context *) ssl->ctx_dec,
                    DES_DECRYPT, dec_msglen,
                    ssl->iv_dec, dec_msg, dec_msg_result );
                break;
#endif

            case 16:
#if defined(POLARSSL_AES_C)
        if ( ssl->session->ciphersuite == SSL_RSA_AES_128_SHA ||
             ssl->session->ciphersuite == SSL_EDH_RSA_AES_128_SHA ||
             ssl->session->ciphersuite == SSL_RSA_AES_256_SHA ||
             ssl->session->ciphersuite == SSL_EDH_RSA_AES_256_SHA)
        {
                    aes_crypt_cbc( (aes_context *) ssl->ctx_dec,
                       AES_DECRYPT, dec_msglen,
                       ssl->iv_dec, dec_msg, dec_msg_result );
                    break;
        }
#endif

#if defined(POLARSSL_CAMELLIA_C)
        if ( ssl->session->ciphersuite == SSL_RSA_CAMELLIA_128_SHA ||
             ssl->session->ciphersuite == SSL_EDH_RSA_CAMELLIA_128_SHA ||
             ssl->session->ciphersuite == SSL_RSA_CAMELLIA_256_SHA ||
             ssl->session->ciphersuite == SSL_EDH_RSA_CAMELLIA_256_SHA)
        {
                    camellia_crypt_cbc( (camellia_context *) ssl->ctx_dec,
                       CAMELLIA_DECRYPT, dec_msglen,
                       ssl->iv_dec, dec_msg, dec_msg_result );
                    break;
        }
#endif

            default:
                return( POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE );
        }

        padlen = 1 + ssl->in_msg[ssl->in_msglen - 1];

        if( ssl->minor_ver == SSL_MINOR_VERSION_0 )
        {
            if( padlen > ssl->ivlen )
            {
                SSL_DEBUG_MSG( 1, ( "bad padding length: is %d, "
                                    "should be no more than %d",
                               padlen, ssl->ivlen ) );
                padlen = 0;
            }
        }
        else
        {
            /*
             * TLSv1: always check the padding
             */
            for( i = 1; i <= padlen; i++ )
            {
                if( ssl->in_msg[ssl->in_msglen - i] != padlen - 1 )
                {
                    SSL_DEBUG_MSG( 1, ( "bad padding byte: should be "
                                        "%02x, but is %02x", padlen - 1,
                                   ssl->in_msg[ssl->in_msglen - i] ) );
                    padlen = 0;
                }
            }
        }
    }

    SSL_DEBUG_BUF( 4, "raw buffer after decryption",
                   ssl->in_msg, ssl->in_msglen );

    /*
     * Always compute the MAC (RFC4346, CBCTIME).
     */
    if( ssl->in_msglen <= ssl->maclen + padlen )
    {
        SSL_DEBUG_MSG( 1, ( "msglen (%d) < maclen (%d) + padlen (%d)",
                    ssl->in_msglen, ssl->maclen, padlen ) );
        return( POLARSSL_ERR_SSL_INVALID_MAC );
    }

    ssl->in_msglen -= ( ssl->maclen + padlen );

    ssl->in_hdr[3] = (unsigned char)( ssl->in_msglen >> 8 );
    ssl->in_hdr[4] = (unsigned char)( ssl->in_msglen      );

    memcpy( tmp, ssl->in_msg + ssl->in_msglen, 20 );

    if( ssl->minor_ver == SSL_MINOR_VERSION_0 )
    {
        if( ssl->maclen == 16 )
             ssl_mac_md5( ssl->mac_dec,
                          ssl->in_msg, ssl->in_msglen,
                          ssl->in_ctr, ssl->in_msgtype );
        else
            ssl_mac_sha1( ssl->mac_dec,
                          ssl->in_msg, ssl->in_msglen,
                          ssl->in_ctr, ssl->in_msgtype );
    }
    else
    {
        if( ssl->maclen == 16 )
             md5_hmac( ssl->mac_dec, 16,
                       ssl->in_ctr,  ssl->in_msglen + 13,
                       ssl->in_msg + ssl->in_msglen );
        else
            sha1_hmac( ssl->mac_dec, 20,
                       ssl->in_ctr,  ssl->in_msglen + 13,
                       ssl->in_msg + ssl->in_msglen );
    }

    SSL_DEBUG_BUF( 4, "message  mac", tmp, ssl->maclen );
    SSL_DEBUG_BUF( 4, "computed mac", ssl->in_msg + ssl->in_msglen,
                   ssl->maclen );

    if( memcmp( tmp, ssl->in_msg + ssl->in_msglen,
                     ssl->maclen ) != 0 )
    {
        SSL_DEBUG_MSG( 1, ( "message mac does not match" ) );
        return( POLARSSL_ERR_SSL_INVALID_MAC );
    }

    /*
     * Finally check the padding length; bad padding
     * will produce the same error as an invalid MAC.
     */
    if( ssl->ivlen != 0 && padlen == 0 )
        return( POLARSSL_ERR_SSL_INVALID_MAC );

    if( ssl->in_msglen == 0 )
    {
        ssl->nb_zero++;

        /*
         * Three or more empty messages may be a DoS attack
         * (excessive CPU consumption).
         */
        if( ssl->nb_zero > 3 )
        {
            SSL_DEBUG_MSG( 1, ( "received four consecutive empty "
                                "messages, possible DoS attack" ) );
            return( POLARSSL_ERR_SSL_INVALID_MAC );
        }
    }
    else
        ssl->nb_zero = 0;

    for( i = 8; i > 0; i-- )
        if( ++ssl->in_ctr[i - 1] != 0 )
            break;

    SSL_DEBUG_MSG( 2, ( "<= decrypt buf" ) );

    return( 0 );
}

/*
 * Fill the input message buffer
 */
int ssl_fetch_input( ssl_context *ssl, size_t nb_want )
{
    int ret;
    size_t len;

    SSL_DEBUG_MSG( 2, ( "=> fetch input" ) );

    while( ssl->in_left < nb_want )
    {
        len = nb_want - ssl->in_left;
        ret = ssl->f_recv( ssl->p_recv, ssl->in_hdr + ssl->in_left, len );

        SSL_DEBUG_MSG( 2, ( "in_left: %d, nb_want: %d",
                       ssl->in_left, nb_want ) );
        SSL_DEBUG_RET( 2, "ssl->f_recv", ret );

        if( ret == 0 )
            return( POLARSSL_ERR_SSL_CONN_EOF );

        if( ret < 0 )
            return( ret );

        ssl->in_left += ret;
    }

    SSL_DEBUG_MSG( 2, ( "<= fetch input" ) );

    return( 0 );
}

/*
 * Flush any data not yet written
 */
int ssl_flush_output( ssl_context *ssl )
{
    int ret;
    unsigned char *buf;

    SSL_DEBUG_MSG( 2, ( "=> flush output" ) );

    while( ssl->out_left > 0 )
    {
        SSL_DEBUG_MSG( 2, ( "message length: %d, out_left: %d",
                       5 + ssl->out_msglen, ssl->out_left ) );

        buf = ssl->out_hdr + 5 + ssl->out_msglen - ssl->out_left;
        ret = ssl->f_send( ssl->p_send, buf, ssl->out_left );
        SSL_DEBUG_RET( 2, "ssl->f_send", ret );

        if( ret <= 0 )
            return( ret );

        ssl->out_left -= ret;
    }

    SSL_DEBUG_MSG( 2, ( "<= flush output" ) );

    return( 0 );
}

/*
 * Record layer functions
 */
int ssl_write_record( ssl_context *ssl )
{
    int ret;
    size_t len = ssl->out_msglen;

    SSL_DEBUG_MSG( 2, ( "=> write record" ) );

    ssl->out_hdr[0] = (unsigned char) ssl->out_msgtype;
    ssl->out_hdr[1] = (unsigned char) ssl->major_ver;
    ssl->out_hdr[2] = (unsigned char) ssl->minor_ver;
    ssl->out_hdr[3] = (unsigned char)( len >> 8 );
    ssl->out_hdr[4] = (unsigned char)( len      );

    if( ssl->out_msgtype == SSL_MSG_HANDSHAKE )
    {
        ssl->out_msg[1] = (unsigned char)( ( len - 4 ) >> 16 );
        ssl->out_msg[2] = (unsigned char)( ( len - 4 ) >>  8 );
        ssl->out_msg[3] = (unsigned char)( ( len - 4 )       );

         md5_update( &ssl->fin_md5 , ssl->out_msg, len );
        sha1_update( &ssl->fin_sha1, ssl->out_msg, len );
    }

    if( ssl->do_crypt != 0 )
    {
        if( ( ret = ssl_encrypt_buf( ssl ) ) != 0 )
        {
            SSL_DEBUG_RET( 1, "ssl_encrypt_buf", ret );
            return( ret );
        }

        len = ssl->out_msglen;
        ssl->out_hdr[3] = (unsigned char)( len >> 8 );
        ssl->out_hdr[4] = (unsigned char)( len      );
    }

    ssl->out_left = 5 + ssl->out_msglen;

    SSL_DEBUG_MSG( 3, ( "output record: msgtype = %d, "
                        "version = [%d:%d], msglen = %d",
                   ssl->out_hdr[0], ssl->out_hdr[1], ssl->out_hdr[2],
                 ( ssl->out_hdr[3] << 8 ) | ssl->out_hdr[4] ) );

    SSL_DEBUG_BUF( 4, "output record sent to network",
                   ssl->out_hdr, 5 + ssl->out_msglen );

    if( ( ret = ssl_flush_output( ssl ) ) != 0 )
    {
        SSL_DEBUG_RET( 1, "ssl_flush_output", ret );
        return( ret );
    }

    SSL_DEBUG_MSG( 2, ( "<= write record" ) );

    return( 0 );
}

int ssl_read_record( ssl_context *ssl )
{
    int ret;

    SSL_DEBUG_MSG( 2, ( "=> read record" ) );

    if( ssl->in_hslen != 0 &&
        ssl->in_hslen < ssl->in_msglen )
    {
        /*
         * Get next Handshake message in the current record
         */
        ssl->in_msglen -= ssl->in_hslen;

        memmove( ssl->in_msg, ssl->in_msg + ssl->in_hslen,
                ssl->in_msglen );

        ssl->in_hslen  = 4;
        ssl->in_hslen += ( ssl->in_msg[2] << 8 ) | ssl->in_msg[3];

        SSL_DEBUG_MSG( 3, ( "handshake message: msglen ="
                            " %d, type = %d, hslen = %d",
                       ssl->in_msglen, ssl->in_msg[0], ssl->in_hslen ) );

        if( ssl->in_msglen < 4 || ssl->in_msg[1] != 0 )
        {
            SSL_DEBUG_MSG( 1, ( "bad handshake length" ) );
            return( POLARSSL_ERR_SSL_INVALID_RECORD );
        }

        if( ssl->in_msglen < ssl->in_hslen )
        {
            SSL_DEBUG_MSG( 1, ( "bad handshake length" ) );
            return( POLARSSL_ERR_SSL_INVALID_RECORD );
        }

         md5_update( &ssl->fin_md5 , ssl->in_msg, ssl->in_hslen );
        sha1_update( &ssl->fin_sha1, ssl->in_msg, ssl->in_hslen );

        return( 0 );
    }

    ssl->in_hslen = 0;

    /*
     * Read the record header and validate it
     */
    if( ( ret = ssl_fetch_input( ssl, 5 ) ) != 0 )
    {
        SSL_DEBUG_RET( 1, "ssl_fetch_input", ret );
        return( ret );
    }

    ssl->in_msgtype =  ssl->in_hdr[0];
    ssl->in_msglen = ( ssl->in_hdr[3] << 8 ) | ssl->in_hdr[4];

    SSL_DEBUG_MSG( 3, ( "input record: msgtype = %d, "
                        "version = [%d:%d], msglen = %d",
                     ssl->in_hdr[0], ssl->in_hdr[1], ssl->in_hdr[2],
                   ( ssl->in_hdr[3] << 8 ) | ssl->in_hdr[4] ) );

    if( ssl->in_hdr[1] != ssl->major_ver )
    {
        SSL_DEBUG_MSG( 1, ( "major version mismatch" ) );
        return( POLARSSL_ERR_SSL_INVALID_RECORD );
    }

    if( ssl->in_hdr[2] > ssl->max_minor_ver )
    {
        SSL_DEBUG_MSG( 1, ( "minor version mismatch" ) );
        return( POLARSSL_ERR_SSL_INVALID_RECORD );
    }

    /*
     * Make sure the message length is acceptable
     */
    if( ssl->do_crypt == 0 )
    {
        if( ssl->in_msglen < 1 ||
            ssl->in_msglen > SSL_MAX_CONTENT_LEN )
        {
            SSL_DEBUG_MSG( 1, ( "bad message length" ) );
            return( POLARSSL_ERR_SSL_INVALID_RECORD );
        }
    }
    else
    {
        if( ssl->in_msglen < ssl->minlen )
        {
            SSL_DEBUG_MSG( 1, ( "bad message length" ) );
            return( POLARSSL_ERR_SSL_INVALID_RECORD );
        }

        if( ssl->minor_ver == SSL_MINOR_VERSION_0 &&
            ssl->in_msglen > ssl->minlen + SSL_MAX_CONTENT_LEN )
        {
            SSL_DEBUG_MSG( 1, ( "bad message length" ) );
            return( POLARSSL_ERR_SSL_INVALID_RECORD );
        }

        /*
         * TLS encrypted messages can have up to 256 bytes of padding
         */
        if( ssl->minor_ver == SSL_MINOR_VERSION_1 &&
            ssl->in_msglen > ssl->minlen + SSL_MAX_CONTENT_LEN + 256 )
        {
            SSL_DEBUG_MSG( 1, ( "bad message length" ) );
            return( POLARSSL_ERR_SSL_INVALID_RECORD );
        }
    }

    /*
     * Read and optionally decrypt the message contents
     */
    if( ( ret = ssl_fetch_input( ssl, 5 + ssl->in_msglen ) ) != 0 )
    {
        SSL_DEBUG_RET( 1, "ssl_fetch_input", ret );
        return( ret );
    }

    SSL_DEBUG_BUF( 4, "input record from network",
                   ssl->in_hdr, 5 + ssl->in_msglen );

    if( ssl->do_crypt != 0 )
    {
        if( ( ret = ssl_decrypt_buf( ssl ) ) != 0 )
        {
            SSL_DEBUG_RET( 1, "ssl_decrypt_buf", ret );
            return( ret );
        }

        SSL_DEBUG_BUF( 4, "input payload after decrypt",
                       ssl->in_msg, ssl->in_msglen );

        if( ssl->in_msglen > SSL_MAX_CONTENT_LEN )
        {
            SSL_DEBUG_MSG( 1, ( "bad message length" ) );
            return( POLARSSL_ERR_SSL_INVALID_RECORD );
        }
    }

    if( ssl->in_msgtype == SSL_MSG_HANDSHAKE )
    {
        ssl->in_hslen  = 4;
        ssl->in_hslen += ( ssl->in_msg[2] << 8 ) | ssl->in_msg[3];

        SSL_DEBUG_MSG( 3, ( "handshake message: msglen ="
                            " %d, type = %d, hslen = %d",
                       ssl->in_msglen, ssl->in_msg[0], ssl->in_hslen ) );

        /*
         * Additional checks to validate the handshake header
         */
        if( ssl->in_msglen < 4 || ssl->in_msg[1] != 0 )
        {
            SSL_DEBUG_MSG( 1, ( "bad handshake length" ) );
            return( POLARSSL_ERR_SSL_INVALID_RECORD );
        }

        if( ssl->in_msglen < ssl->in_hslen )
        {
            SSL_DEBUG_MSG( 1, ( "bad handshake length" ) );
            return( POLARSSL_ERR_SSL_INVALID_RECORD );
        }

         md5_update( &ssl->fin_md5 , ssl->in_msg, ssl->in_hslen );
        sha1_update( &ssl->fin_sha1, ssl->in_msg, ssl->in_hslen );
    }

    if( ssl->in_msgtype == SSL_MSG_ALERT )
    {
        SSL_DEBUG_MSG( 2, ( "got an alert message, type: [%d:%d]",
                       ssl->in_msg[0], ssl->in_msg[1] ) );

        /*
         * Ignore non-fatal alerts, except close_notify
         */
        if( ssl->in_msg[0] == SSL_ALERT_LEVEL_FATAL )
        {
            SSL_DEBUG_MSG( 1, ( "is a fatal alert message" ) );
            /**
             * Subtract from error code as ssl->in_msg[1] is 7-bit positive
             * error identifier.
             */
            return( POLARSSL_ERR_SSL_FATAL_ALERT_MESSAGE - ssl->in_msg[1] );
        }

        if( ssl->in_msg[0] == SSL_ALERT_LEVEL_WARNING &&
            ssl->in_msg[1] == SSL_ALERT_MSG_CLOSE_NOTIFY )
        {
            SSL_DEBUG_MSG( 2, ( "is a close notify message" ) );
            return( POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY );
        }
    }

    ssl->in_left = 0;

    SSL_DEBUG_MSG( 2, ( "<= read record" ) );

    return( 0 );
}

/*
 * Handshake functions
 */
int ssl_write_certificate( ssl_context *ssl )
{
    int ret;
    size_t i, n;
    const x509_cert *crt;

    SSL_DEBUG_MSG( 2, ( "=> write certificate" ) );

    if( ssl->endpoint == SSL_IS_CLIENT )
    {
        if( ssl->client_auth == 0 )
        {
            SSL_DEBUG_MSG( 2, ( "<= skip write certificate" ) );
            ssl->state++;
            return( 0 );
        }

        /*
         * If using SSLv3 and got no cert, send an Alert message
         * (otherwise an empty Certificate message will be sent).
         */
        if( ssl->own_cert  == NULL &&
            ssl->minor_ver == SSL_MINOR_VERSION_0 )
        {
            ssl->out_msglen  = 2;
            ssl->out_msgtype = SSL_MSG_ALERT;
            ssl->out_msg[0]  = SSL_ALERT_LEVEL_WARNING;
            ssl->out_msg[1]  = SSL_ALERT_MSG_NO_CERT;

            SSL_DEBUG_MSG( 2, ( "got no certificate to send" ) );
            goto write_msg;
        }
    }
    else /* SSL_IS_SERVER */
    {
        if( ssl->own_cert == NULL )
        {
            SSL_DEBUG_MSG( 1, ( "got no certificate to send" ) );
            return( POLARSSL_ERR_SSL_CERTIFICATE_REQUIRED );
        }
    }

    SSL_DEBUG_CRT( 3, "own certificate", ssl->own_cert );

    /*
     *     0  .  0    handshake type
     *     1  .  3    handshake length
     *     4  .  6    length of all certs
     *     7  .  9    length of cert. 1
     *    10  . n-1   peer certificate
     *     n  . n+2   length of cert. 2
     *    n+3 . ...   upper level cert, etc.
     */
    i = 7;
    crt = ssl->own_cert;

    while( crt != NULL )
    {
        n = crt->raw.len;
        if( i + 3 + n > SSL_MAX_CONTENT_LEN )
        {
            SSL_DEBUG_MSG( 1, ( "certificate too large, %d > %d",
                           i + 3 + n, SSL_MAX_CONTENT_LEN ) );
            return( POLARSSL_ERR_SSL_CERTIFICATE_TOO_LARGE );
        }

        ssl->out_msg[i    ] = (unsigned char)( n >> 16 );
        ssl->out_msg[i + 1] = (unsigned char)( n >>  8 );
        ssl->out_msg[i + 2] = (unsigned char)( n       );

        i += 3; memcpy( ssl->out_msg + i, crt->raw.p, n );
        i += n; crt = crt->next;
    }

    ssl->out_msg[4]  = (unsigned char)( ( i - 7 ) >> 16 );
    ssl->out_msg[5]  = (unsigned char)( ( i - 7 ) >>  8 );
    ssl->out_msg[6]  = (unsigned char)( ( i - 7 )       );

    ssl->out_msglen  = i;
    ssl->out_msgtype = SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = SSL_HS_CERTIFICATE;

write_msg:

    ssl->state++;

    if( ( ret = ssl_write_record( ssl ) ) != 0 )
    {
        SSL_DEBUG_RET( 1, "ssl_write_record", ret );
        return( ret );
    }

    SSL_DEBUG_MSG( 2, ( "<= write certificate" ) );

    return( 0 );
}

int ssl_parse_certificate( ssl_context *ssl )
{
    int ret;
    size_t i, n;

    SSL_DEBUG_MSG( 2, ( "=> parse certificate" ) );

    if( ssl->endpoint == SSL_IS_SERVER &&
        ssl->authmode == SSL_VERIFY_NONE )
    {
        ssl->verify_result = BADCERT_SKIP_VERIFY;
        SSL_DEBUG_MSG( 2, ( "<= skip parse certificate" ) );
        ssl->state++;
        return( 0 );
    }

    if( ( ret = ssl_read_record( ssl ) ) != 0 )
    {
        SSL_DEBUG_RET( 1, "ssl_read_record", ret );
        return( ret );
    }

    ssl->state++;

    /*
     * Check if the client sent an empty certificate
     */
    if( ssl->endpoint  == SSL_IS_SERVER &&
        ssl->minor_ver == SSL_MINOR_VERSION_0 )
    {
        if( ssl->in_msglen  == 2                        &&
            ssl->in_msgtype == SSL_MSG_ALERT            &&
            ssl->in_msg[0]  == SSL_ALERT_LEVEL_WARNING  &&
            ssl->in_msg[1]  == SSL_ALERT_MSG_NO_CERT )
        {
            SSL_DEBUG_MSG( 1, ( "SSLv3 client has no certificate" ) );

            ssl->verify_result = BADCERT_MISSING;
            if( ssl->authmode == SSL_VERIFY_OPTIONAL )
                return( 0 );
            else
                return( POLARSSL_ERR_SSL_NO_CLIENT_CERTIFICATE );
        }
    }

    if( ssl->endpoint  == SSL_IS_SERVER &&
        ssl->minor_ver != SSL_MINOR_VERSION_0 )
    {
        if( ssl->in_hslen   == 7                    &&
            ssl->in_msgtype == SSL_MSG_HANDSHAKE    &&
            ssl->in_msg[0]  == SSL_HS_CERTIFICATE   &&
            memcmp( ssl->in_msg + 4, "\0\0\0", 3 ) == 0 )
        {
            SSL_DEBUG_MSG( 1, ( "TLSv1 client has no certificate" ) );

            ssl->verify_result = BADCERT_MISSING;
            if( ssl->authmode == SSL_VERIFY_REQUIRED )
                return( POLARSSL_ERR_SSL_NO_CLIENT_CERTIFICATE );
            else
                return( 0 );
        }
    }

    if( ssl->in_msgtype != SSL_MSG_HANDSHAKE )
    {
        SSL_DEBUG_MSG( 1, ( "bad certificate message" ) );
        return( POLARSSL_ERR_SSL_UNEXPECTED_MESSAGE );
    }

    if( ssl->in_msg[0] != SSL_HS_CERTIFICATE || ssl->in_hslen < 10 )
    {
        SSL_DEBUG_MSG( 1, ( "bad certificate message" ) );
        return( POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE );
    }

    /*
     * Same message structure as in ssl_write_certificate()
     */
    n = ( ssl->in_msg[5] << 8 ) | ssl->in_msg[6];

    if( ssl->in_msg[4] != 0 || ssl->in_hslen != 7 + n )
    {
        SSL_DEBUG_MSG( 1, ( "bad certificate message" ) );
        return( POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE );
    }

    if( ( ssl->peer_cert = (x509_cert *) malloc(
                    sizeof( x509_cert ) ) ) == NULL )
    {
        SSL_DEBUG_MSG( 1, ( "malloc(%d bytes) failed",
                       sizeof( x509_cert ) ) );
        return( POLARSSL_ERR_SSL_MALLOC_FAILED );
    }

    memset( ssl->peer_cert, 0, sizeof( x509_cert ) );

    i = 7;

    while( i < ssl->in_hslen )
    {
        if( ssl->in_msg[i] != 0 )
        {
            SSL_DEBUG_MSG( 1, ( "bad certificate message" ) );
            return( POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE );
        }

        n = ( (unsigned int) ssl->in_msg[i + 1] << 8 )
            | (unsigned int) ssl->in_msg[i + 2];
        i += 3;

        if( n < 128 || i + n > ssl->in_hslen )
        {
            SSL_DEBUG_MSG( 1, ( "bad certificate message" ) );
            return( POLARSSL_ERR_SSL_BAD_HS_CERTIFICATE );
        }

        ret = x509parse_crt( ssl->peer_cert, ssl->in_msg + i, n );
        if( ret != 0 )
        {
            SSL_DEBUG_RET( 1, " x509parse_crt", ret );
            return( ret );
        }

        i += n;
    }

    SSL_DEBUG_CRT( 3, "peer certificate", ssl->peer_cert );

    if( ssl->authmode != SSL_VERIFY_NONE )
    {
        if( ssl->ca_chain == NULL )
        {
            SSL_DEBUG_MSG( 1, ( "got no CA chain" ) );
            return( POLARSSL_ERR_SSL_CA_CHAIN_REQUIRED );
        }

        ret = x509parse_verify( ssl->peer_cert, ssl->ca_chain, ssl->ca_crl,
                                ssl->peer_cn,  &ssl->verify_result,
                                ssl->f_vrfy, ssl->p_vrfy );

        if( ret != 0 )
            SSL_DEBUG_RET( 1, "x509_verify_cert", ret );

        if( ssl->authmode != SSL_VERIFY_REQUIRED )
            ret = 0;
    }

    SSL_DEBUG_MSG( 2, ( "<= parse certificate" ) );

    return( ret );
}

int ssl_write_change_cipher_spec( ssl_context *ssl )
{
    int ret;

    SSL_DEBUG_MSG( 2, ( "=> write change cipher spec" ) );

    ssl->out_msgtype = SSL_MSG_CHANGE_CIPHER_SPEC;
    ssl->out_msglen  = 1;
    ssl->out_msg[0]  = 1;

    ssl->do_crypt = 0;
    ssl->state++;

    if( ( ret = ssl_write_record( ssl ) ) != 0 )
    {
        SSL_DEBUG_RET( 1, "ssl_write_record", ret );
        return( ret );
    }

    SSL_DEBUG_MSG( 2, ( "<= write change cipher spec" ) );

    return( 0 );
}

int ssl_parse_change_cipher_spec( ssl_context *ssl )
{
    int ret;

    SSL_DEBUG_MSG( 2, ( "=> parse change cipher spec" ) );

    ssl->do_crypt = 0;

    if( ( ret = ssl_read_record( ssl ) ) != 0 )
    {
        SSL_DEBUG_RET( 1, "ssl_read_record", ret );
        return( ret );
    }

    if( ssl->in_msgtype != SSL_MSG_CHANGE_CIPHER_SPEC )
    {
        SSL_DEBUG_MSG( 1, ( "bad change cipher spec message" ) );
        return( POLARSSL_ERR_SSL_UNEXPECTED_MESSAGE );
    }

    if( ssl->in_msglen != 1 || ssl->in_msg[0] != 1 )
    {
        SSL_DEBUG_MSG( 1, ( "bad change cipher spec message" ) );
        return( POLARSSL_ERR_SSL_BAD_HS_CHANGE_CIPHER_SPEC );
    }

    ssl->state++;

    SSL_DEBUG_MSG( 2, ( "<= parse change cipher spec" ) );

    return( 0 );
}

static void ssl_calc_finished(
                ssl_context *ssl, unsigned char *buf, int from,
                md5_context *md5, sha1_context *sha1 )
{
    int len = 12;
    char *sender;
    unsigned char padbuf[48];
    unsigned char md5sum[16];
    unsigned char sha1sum[20];

    SSL_DEBUG_MSG( 2, ( "=> calc  finished" ) );

    /*
     * SSLv3:
     *   hash =
     *      MD5( master + pad2 +
     *          MD5( handshake + sender + master + pad1 ) )
     *   + SHA1( master + pad2 +
     *         SHA1( handshake + sender + master + pad1 ) )
     *
     * TLSv1:
     *   hash = PRF( master, finished_label,
     *               MD5( handshake ) + SHA1( handshake ) )[0..11]
     */

    SSL_DEBUG_BUF( 4, "finished  md5 state", (unsigned char *)
                    md5->state, sizeof(  md5->state ) );

    SSL_DEBUG_BUF( 4, "finished sha1 state", (unsigned char *)
                   sha1->state, sizeof( sha1->state ) );

    if( ssl->minor_ver == SSL_MINOR_VERSION_0 )
    {
        sender = ( from == SSL_IS_CLIENT ) ? (char *) "CLNT"
                                           : (char *) "SRVR";

        memset( padbuf, 0x36, 48 );

        md5_update( md5, (unsigned char *) sender, 4 );
        md5_update( md5, ssl->session->master, 48 );
        md5_update( md5, padbuf, 48 );
        md5_finish( md5, md5sum );

        sha1_update( sha1, (unsigned char *) sender, 4 );
        sha1_update( sha1, ssl->session->master, 48 );
        sha1_update( sha1, padbuf, 40 );
        sha1_finish( sha1, sha1sum );

        memset( padbuf, 0x5C, 48 );

        md5_starts( md5 );
        md5_update( md5, ssl->session->master, 48 );
        md5_update( md5, padbuf, 48 );
        md5_update( md5, md5sum, 16 );
        md5_finish( md5, buf );

        sha1_starts( sha1 );
        sha1_update( sha1, ssl->session->master, 48 );
        sha1_update( sha1, padbuf , 40 );
        sha1_update( sha1, sha1sum, 20 );
        sha1_finish( sha1, buf + 16 );

        len += 24;
    }
    else
    {
        sender = ( from == SSL_IS_CLIENT )
                 ? (char *) "client finished"
                 : (char *) "server finished";

         md5_finish(  md5, padbuf );
        sha1_finish( sha1, padbuf + 16 );

        tls1_prf( ssl->session->master, 48, sender,
                  padbuf, 36, buf, len );
    }

    SSL_DEBUG_BUF( 3, "calc finished result", buf, len );

    memset(  md5, 0, sizeof(  md5_context ) );
    memset( sha1, 0, sizeof( sha1_context ) );

    memset(  padbuf, 0, sizeof(  padbuf ) );
    memset(  md5sum, 0, sizeof(  md5sum ) );
    memset( sha1sum, 0, sizeof( sha1sum ) );

    SSL_DEBUG_MSG( 2, ( "<= calc  finished" ) );
}

int ssl_write_finished( ssl_context *ssl )
{
    int ret, hash_len;
     md5_context  md5;
    sha1_context sha1;

    SSL_DEBUG_MSG( 2, ( "=> write finished" ) );

    memcpy( &md5 , &ssl->fin_md5 , sizeof(  md5_context ) );
    memcpy( &sha1, &ssl->fin_sha1, sizeof( sha1_context ) );

    ssl_calc_finished( ssl, ssl->out_msg + 4,
                       ssl->endpoint, &md5, &sha1 );

    hash_len = ( ssl->minor_ver == SSL_MINOR_VERSION_0 ) ? 36 : 12;

    ssl->out_msglen  = 4 + hash_len;
    ssl->out_msgtype = SSL_MSG_HANDSHAKE;
    ssl->out_msg[0]  = SSL_HS_FINISHED;

    /*
     * In case of session resuming, invert the client and server
     * ChangeCipherSpec messages order.
     */
    if( ssl->resume != 0 )
    {
        if( ssl->endpoint == SSL_IS_CLIENT )
            ssl->state = SSL_HANDSHAKE_OVER;
        else
            ssl->state = SSL_CLIENT_CHANGE_CIPHER_SPEC;
    }
    else
        ssl->state++;

    ssl->do_crypt = 1;

    if( ( ret = ssl_write_record( ssl ) ) != 0 )
    {
        SSL_DEBUG_RET( 1, "ssl_write_record", ret );
        return( ret );
    }

    SSL_DEBUG_MSG( 2, ( "<= write finished" ) );

    return( 0 );
}

int ssl_parse_finished( ssl_context *ssl )
{
    int ret;
    unsigned int hash_len;
    unsigned char buf[36];
    md5_context  md5;
    sha1_context sha1;

    SSL_DEBUG_MSG( 2, ( "=> parse finished" ) );

    memcpy( &md5 , &ssl->fin_md5 , sizeof(  md5_context ) );
    memcpy( &sha1, &ssl->fin_sha1, sizeof( sha1_context ) );

    ssl->do_crypt = 1;

    if( ( ret = ssl_read_record( ssl ) ) != 0 )
    {
        SSL_DEBUG_RET( 1, "ssl_read_record", ret );
        return( ret );
    }

    if( ssl->in_msgtype != SSL_MSG_HANDSHAKE )
    {
        SSL_DEBUG_MSG( 1, ( "bad finished message" ) );
        return( POLARSSL_ERR_SSL_UNEXPECTED_MESSAGE );
    }

    hash_len = ( ssl->minor_ver == SSL_MINOR_VERSION_0 ) ? 36 : 12;

    if( ssl->in_msg[0] != SSL_HS_FINISHED ||
        ssl->in_hslen  != 4 + hash_len )
    {
        SSL_DEBUG_MSG( 1, ( "bad finished message" ) );
        return( POLARSSL_ERR_SSL_BAD_HS_FINISHED );
    }

    ssl_calc_finished( ssl, buf, ssl->endpoint ^ 1, &md5, &sha1 );

    if( memcmp( ssl->in_msg + 4, buf, hash_len ) != 0 )
    {
        SSL_DEBUG_MSG( 1, ( "bad finished message" ) );
        return( POLARSSL_ERR_SSL_BAD_HS_FINISHED );
    }

    if( ssl->resume != 0 )
    {
        if( ssl->endpoint == SSL_IS_CLIENT )
            ssl->state = SSL_CLIENT_CHANGE_CIPHER_SPEC;

        if( ssl->endpoint == SSL_IS_SERVER )
            ssl->state = SSL_HANDSHAKE_OVER;
    }
    else
        ssl->state++;

    SSL_DEBUG_MSG( 2, ( "<= parse finished" ) );

    return( 0 );
}

/*
 * Initialize an SSL context
 */
int ssl_init( ssl_context *ssl )
{
    int len = SSL_BUFFER_LEN;

    memset( ssl, 0, sizeof( ssl_context ) );

    ssl->in_ctr = (unsigned char *) malloc( len );
    ssl->in_hdr = ssl->in_ctr +  8;
    ssl->in_msg = ssl->in_ctr + 13;

    if( ssl->in_ctr == NULL )
    {
        SSL_DEBUG_MSG( 1, ( "malloc(%d bytes) failed", len ) );
        return( POLARSSL_ERR_SSL_MALLOC_FAILED );
    }

    ssl->out_ctr = (unsigned char *) malloc( len );
    ssl->out_hdr = ssl->out_ctr +  8;
    ssl->out_msg = ssl->out_ctr + 13;

    if( ssl->out_ctr == NULL )
    {
        SSL_DEBUG_MSG( 1, ( "malloc(%d bytes) failed", len ) );
        free( ssl-> in_ctr );
        return( POLARSSL_ERR_SSL_MALLOC_FAILED );
    }

    memset( ssl-> in_ctr, 0, SSL_BUFFER_LEN );
    memset( ssl->out_ctr, 0, SSL_BUFFER_LEN );

    ssl->hostname = NULL;
    ssl->hostname_len = 0;

     md5_starts( &ssl->fin_md5  );
    sha1_starts( &ssl->fin_sha1 );

    return( 0 );
}

/*
 * Reset an initialized and used SSL context for re-use while retaining
 * all application-set variables, function pointers and data.
 */
void ssl_session_reset( ssl_context *ssl )
{
    ssl->state = SSL_HELLO_REQUEST;

    ssl->in_offt = NULL;

    ssl->in_msgtype = 0;
    ssl->in_msglen = 0;
    ssl->in_left = 0;

    ssl->in_hslen = 0;
    ssl->nb_zero = 0;

    ssl->out_msgtype = 0;
    ssl->out_msglen = 0;
    ssl->out_left = 0;

    ssl->do_crypt = 0;
    ssl->pmslen = 0;
    ssl->keylen = 0;
    ssl->minlen = 0;
    ssl->ivlen = 0;
    ssl->maclen = 0;

    memset( ssl->out_ctr, 0, SSL_BUFFER_LEN );
    memset( ssl->in_ctr, 0, SSL_BUFFER_LEN );
    memset( ssl->randbytes, 0, 64 );
    memset( ssl->premaster, 0, 256 );
    memset( ssl->iv_enc, 0, 16 );
    memset( ssl->iv_dec, 0, 16 );
    memset( ssl->mac_enc, 0, 32 );
    memset( ssl->mac_dec, 0, 32 );
    memset( ssl->ctx_enc, 0, 128 );
    memset( ssl->ctx_dec, 0, 128 );

     md5_starts( &ssl->fin_md5  );
    sha1_starts( &ssl->fin_sha1 );
}

/*
 * SSL set accessors
 */
void ssl_set_endpoint( ssl_context *ssl, int endpoint )
{
    ssl->endpoint   = endpoint;
}

void ssl_set_authmode( ssl_context *ssl, int authmode )
{
    ssl->authmode   = authmode;
}

void ssl_set_verify( ssl_context *ssl,
                     int (*f_vrfy)(void *, x509_cert *, int, int),
                     void *p_vrfy )
{
    ssl->f_vrfy      = f_vrfy;
    ssl->p_vrfy      = p_vrfy;
}

void ssl_set_rng( ssl_context *ssl,
                  int (*f_rng)(void *, unsigned char *, size_t),
                  void *p_rng )
{
    ssl->f_rng      = f_rng;
    ssl->p_rng      = p_rng;
}

void ssl_set_dbg( ssl_context *ssl,
                  void (*f_dbg)(void *, int, const char *),
                  void  *p_dbg )
{
    ssl->f_dbg      = f_dbg;
    ssl->p_dbg      = p_dbg;
}

void ssl_set_bio( ssl_context *ssl,
            int (*f_recv)(void *, unsigned char *, size_t), void *p_recv,
            int (*f_send)(void *, const unsigned char *, size_t), void *p_send )
{
    ssl->f_recv     = f_recv;
    ssl->f_send     = f_send;
    ssl->p_recv     = p_recv;
    ssl->p_send     = p_send;
}

void ssl_set_scb( ssl_context *ssl,
                  int (*s_get)(ssl_context *),
                  int (*s_set)(ssl_context *) )
{
    ssl->s_get      = s_get;
    ssl->s_set      = s_set;
}

void ssl_set_session( ssl_context *ssl, int resume, int timeout,
                      ssl_session *session )
{
    ssl->resume     = resume;
    ssl->timeout    = timeout;
    ssl->session    = session;
}

void ssl_set_ciphersuites( ssl_context *ssl, int *ciphersuites )
{
    ssl->ciphersuites    = ciphersuites;
}

void ssl_set_ca_chain( ssl_context *ssl, x509_cert *ca_chain,
                       x509_crl *ca_crl, const char *peer_cn )
{
    ssl->ca_chain   = ca_chain;
    ssl->ca_crl     = ca_crl;
    ssl->peer_cn    = peer_cn;
}

void ssl_set_own_cert( ssl_context *ssl, x509_cert *own_cert,
                       rsa_context *rsa_key )
{
    ssl->own_cert   = own_cert;
    ssl->rsa_key    = rsa_key;
}

#if defined(POLARSSL_PKCS11_C)
void ssl_set_own_cert_pkcs11( ssl_context *ssl, x509_cert *own_cert,
                       pkcs11_context *pkcs11_key )
{
    ssl->own_cert   = own_cert;
    ssl->pkcs11_key = pkcs11_key;
}
#endif

int ssl_set_dh_param( ssl_context *ssl, const char *dhm_P, const char *dhm_G )
{
    int ret;

    if( ( ret = mpi_read_string( &ssl->dhm_ctx.P, 16, dhm_P ) ) != 0 )
    {
        SSL_DEBUG_RET( 1, "mpi_read_string", ret );
        return( ret );
    }

    if( ( ret = mpi_read_string( &ssl->dhm_ctx.G, 16, dhm_G ) ) != 0 )
    {
        SSL_DEBUG_RET( 1, "mpi_read_string", ret );
        return( ret );
    }

    return( 0 );
}

int ssl_set_dh_param_ctx( ssl_context *ssl, dhm_context *dhm_ctx )
{
    int ret;

    if( ( ret = mpi_copy(&ssl->dhm_ctx.P, &dhm_ctx->P) ) != 0 )
    {
        SSL_DEBUG_RET( 1, "mpi_copy", ret );
        return( ret );
    }

    if( ( ret = mpi_copy(&ssl->dhm_ctx.G, &dhm_ctx->G) ) != 0 )
    {
        SSL_DEBUG_RET( 1, "mpi_copy", ret );
        return( ret );
    }

    return( 0 );
}

int ssl_set_hostname( ssl_context *ssl, const char *hostname )
{
    if( hostname == NULL )
        return( POLARSSL_ERR_SSL_BAD_INPUT_DATA );

    ssl->hostname_len = strlen( hostname );
    ssl->hostname = (unsigned char *) malloc( ssl->hostname_len + 1 );

    if( ssl->hostname == NULL )
        return( POLARSSL_ERR_SSL_MALLOC_FAILED );

    memcpy( ssl->hostname, (unsigned char *) hostname,
            ssl->hostname_len );

    ssl->hostname[ssl->hostname_len] = '\0';

    return( 0 );
}

void ssl_set_max_version( ssl_context *ssl, int major, int minor )
{
    ssl->max_major_ver = major;
    ssl->max_minor_ver = minor;
}

/*
 * SSL get accessors
 */
size_t ssl_get_bytes_avail( const ssl_context *ssl )
{
    return( ssl->in_offt == NULL ? 0 : ssl->in_msglen );
}

int ssl_get_verify_result( const ssl_context *ssl )
{
    return( ssl->verify_result );
}

const char *ssl_get_ciphersuite_name( const int ciphersuite_id )
{
    switch( ciphersuite_id )
    {
#if defined(POLARSSL_ARC4_C)
        case SSL_RSA_RC4_128_MD5:
            return( "SSL-RSA-RC4-128-MD5" );

        case SSL_RSA_RC4_128_SHA:
            return( "SSL-RSA-RC4-128-SHA" );
#endif

#if defined(POLARSSL_DES_C)
        case SSL_RSA_DES_168_SHA:
            return( "SSL-RSA-DES-168-SHA" );

        case SSL_EDH_RSA_DES_168_SHA:
            return( "SSL-EDH-RSA-DES-168-SHA" );
#endif

#if defined(POLARSSL_AES_C)
        case SSL_RSA_AES_128_SHA:
            return( "SSL-RSA-AES-128-SHA" );

        case SSL_EDH_RSA_AES_128_SHA:
            return( "SSL-EDH-RSA-AES-128-SHA" );

        case SSL_RSA_AES_256_SHA:
            return( "SSL-RSA-AES-256-SHA" );

        case SSL_EDH_RSA_AES_256_SHA:
            return( "SSL-EDH-RSA-AES-256-SHA" );
#endif

#if defined(POLARSSL_CAMELLIA_C)
        case SSL_RSA_CAMELLIA_128_SHA:
            return( "SSL-RSA-CAMELLIA-128-SHA" );

        case SSL_EDH_RSA_CAMELLIA_128_SHA:
            return( "SSL-EDH-RSA-CAMELLIA-128-SHA" );

        case SSL_RSA_CAMELLIA_256_SHA:
            return( "SSL-RSA-CAMELLIA-256-SHA" );

        case SSL_EDH_RSA_CAMELLIA_256_SHA:
            return( "SSL-EDH-RSA-CAMELLIA-256-SHA" );
#endif

    default:
        break;
    }

    return( "unknown" );
}

int ssl_get_ciphersuite_id( const char *ciphersuite_name )
{
#if defined(POLARSSL_ARC4_C)
    if (0 == strcasecmp(ciphersuite_name, "SSL-RSA-RC4-128-MD5"))
        return( SSL_RSA_RC4_128_MD5 );
    if (0 == strcasecmp(ciphersuite_name, "SSL-RSA-RC4-128-SHA"))
        return( SSL_RSA_RC4_128_SHA );
#endif

#if defined(POLARSSL_DES_C)
    if (0 == strcasecmp(ciphersuite_name, "SSL-RSA-DES-168-SHA"))
        return( SSL_RSA_DES_168_SHA );
    if (0 == strcasecmp(ciphersuite_name, "SSL-EDH-RSA-DES-168-SHA"))
        return( SSL_EDH_RSA_DES_168_SHA );
#endif

#if defined(POLARSSL_AES_C)
    if (0 == strcasecmp(ciphersuite_name, "SSL-RSA-AES-128-SHA"))
        return( SSL_RSA_AES_128_SHA );
    if (0 == strcasecmp(ciphersuite_name, "SSL-EDH-RSA-AES-128-SHA"))
        return( SSL_EDH_RSA_AES_128_SHA );
    if (0 == strcasecmp(ciphersuite_name, "SSL-RSA-AES-256-SHA"))
        return( SSL_RSA_AES_256_SHA );
    if (0 == strcasecmp(ciphersuite_name, "SSL-EDH-RSA-AES-256-SHA"))
        return( SSL_EDH_RSA_AES_256_SHA );
#endif

#if defined(POLARSSL_CAMELLIA_C)
    if (0 == strcasecmp(ciphersuite_name, "SSL-RSA-CAMELLIA-128-SHA"))
        return( SSL_RSA_CAMELLIA_128_SHA );
    if (0 == strcasecmp(ciphersuite_name, "SSL-EDH-RSA-CAMELLIA-128-SHA"))
        return( SSL_EDH_RSA_CAMELLIA_128_SHA );
    if (0 == strcasecmp(ciphersuite_name, "SSL-RSA-CAMELLIA-256-SHA"))
        return( SSL_RSA_CAMELLIA_256_SHA );
    if (0 == strcasecmp(ciphersuite_name, "SSL-EDH-RSA-CAMELLIA-256-SHA"))
        return( SSL_EDH_RSA_CAMELLIA_256_SHA );
#endif

    return( 0 );
}

const char *ssl_get_ciphersuite( const ssl_context *ssl )
{
    return ssl_get_ciphersuite_name( ssl->session->ciphersuite );
}

const char *ssl_get_version( const ssl_context *ssl )
{
    switch( ssl->minor_ver )
    {
        case SSL_MINOR_VERSION_0:
            return( "SSLv3.0" );

        case SSL_MINOR_VERSION_1:
            return( "TLSv1.0" );

        case SSL_MINOR_VERSION_2:
            return( "TLSv1.1" );

        default:
            break;
    }
    return( "unknown" );
}

int ssl_default_ciphersuites[] =
{
#if defined(POLARSSL_DHM_C)
#if defined(POLARSSL_AES_C)
    SSL_EDH_RSA_AES_128_SHA,
    SSL_EDH_RSA_AES_256_SHA,
#endif
#if defined(POLARSSL_CAMELLIA_C)
    SSL_EDH_RSA_CAMELLIA_128_SHA,
    SSL_EDH_RSA_CAMELLIA_256_SHA,
#endif
#if defined(POLARSSL_DES_C)
    SSL_EDH_RSA_DES_168_SHA,
#endif
#endif

#if defined(POLARSSL_AES_C)
    SSL_RSA_AES_256_SHA,
#endif
#if defined(POLARSSL_CAMELLIA_C)
    SSL_RSA_CAMELLIA_256_SHA,
#endif
#if defined(POLARSSL_AES_C)
    SSL_RSA_AES_128_SHA,
#endif
#if defined(POLARSSL_CAMELLIA_C)
    SSL_RSA_CAMELLIA_128_SHA,
#endif
#if defined(POLARSSL_DES_C)
    SSL_RSA_DES_168_SHA,
#endif
#if defined(POLARSSL_ARC4_C)
    SSL_RSA_RC4_128_SHA,
    SSL_RSA_RC4_128_MD5,
#endif
    0
};

/*
 * Perform the SSL handshake
 */
int ssl_handshake( ssl_context *ssl )
{
    int ret = POLARSSL_ERR_SSL_FEATURE_UNAVAILABLE;

    SSL_DEBUG_MSG( 2, ( "=> handshake" ) );

#if defined(POLARSSL_SSL_CLI_C)
    if( ssl->endpoint == SSL_IS_CLIENT )
        ret = ssl_handshake_client( ssl );
#endif

#if defined(POLARSSL_SSL_SRV_C)
    if( ssl->endpoint == SSL_IS_SERVER )
        ret = ssl_handshake_server( ssl );
#endif

    SSL_DEBUG_MSG( 2, ( "<= handshake" ) );

    return( ret );
}

/*
 * Receive application data decrypted from the SSL layer
 */
int ssl_read( ssl_context *ssl, unsigned char *buf, size_t len )
{
    int ret;
    size_t n;

    SSL_DEBUG_MSG( 2, ( "=> read" ) );

    if( ssl->state != SSL_HANDSHAKE_OVER )
    {
        if( ( ret = ssl_handshake( ssl ) ) != 0 )
        {
            SSL_DEBUG_RET( 1, "ssl_handshake", ret );
            return( ret );
        }
    }

    if( ssl->in_offt == NULL )
    {
        if( ( ret = ssl_read_record( ssl ) ) != 0 )
        {
            if( ret == POLARSSL_ERR_SSL_CONN_EOF )
                return( 0 );

            SSL_DEBUG_RET( 1, "ssl_read_record", ret );
            return( ret );
        }

        if( ssl->in_msglen  == 0 &&
            ssl->in_msgtype == SSL_MSG_APPLICATION_DATA )
        {
            /*
             * OpenSSL sends empty messages to randomize the IV
             */
            if( ( ret = ssl_read_record( ssl ) ) != 0 )
            {
                if( ret == POLARSSL_ERR_SSL_CONN_EOF )
                    return( 0 );

                SSL_DEBUG_RET( 1, "ssl_read_record", ret );
                return( ret );
            }
        }

        if( ssl->in_msgtype != SSL_MSG_APPLICATION_DATA )
        {
            SSL_DEBUG_MSG( 1, ( "bad application data message" ) );
            return( POLARSSL_ERR_SSL_UNEXPECTED_MESSAGE );
        }

        ssl->in_offt = ssl->in_msg;
    }

    n = ( len < ssl->in_msglen )
        ? len : ssl->in_msglen;

    memcpy( buf, ssl->in_offt, n );
    ssl->in_msglen -= n;

    if( ssl->in_msglen == 0 )
        /* all bytes consumed  */
        ssl->in_offt = NULL;
    else
        /* more data available */
        ssl->in_offt += n;

    SSL_DEBUG_MSG( 2, ( "<= read" ) );

    return( (int) n );
}

/*
 * Send application data to be encrypted by the SSL layer
 */
int ssl_write( ssl_context *ssl, const unsigned char *buf, size_t len )
{
    int ret;
    size_t n;

    SSL_DEBUG_MSG( 2, ( "=> write" ) );

    if( ssl->state != SSL_HANDSHAKE_OVER )
    {
        if( ( ret = ssl_handshake( ssl ) ) != 0 )
        {
            SSL_DEBUG_RET( 1, "ssl_handshake", ret );
            return( ret );
        }
    }

    n = ( len < SSL_MAX_CONTENT_LEN )
        ? len : SSL_MAX_CONTENT_LEN;

    if( ssl->out_left != 0 )
    {
        if( ( ret = ssl_flush_output( ssl ) ) != 0 )
        {
            SSL_DEBUG_RET( 1, "ssl_flush_output", ret );
            return( ret );
        }
    }
    else
    {
        ssl->out_msglen  = n;
        ssl->out_msgtype = SSL_MSG_APPLICATION_DATA;
        memcpy( ssl->out_msg, buf, n );

        if( ( ret = ssl_write_record( ssl ) ) != 0 )
        {
            SSL_DEBUG_RET( 1, "ssl_write_record", ret );
            return( ret );
        }
    }

    SSL_DEBUG_MSG( 2, ( "<= write" ) );

    return( (int) n );
}

/*
 * Notify the peer that the connection is being closed
 */
int ssl_close_notify( ssl_context *ssl )
{
    int ret;

    SSL_DEBUG_MSG( 2, ( "=> write close notify" ) );

    if( ( ret = ssl_flush_output( ssl ) ) != 0 )
    {
        SSL_DEBUG_RET( 1, "ssl_flush_output", ret );
        return( ret );
    }

    if( ssl->state == SSL_HANDSHAKE_OVER )
    {
        ssl->out_msgtype = SSL_MSG_ALERT;
        ssl->out_msglen  = 2;
        ssl->out_msg[0]  = SSL_ALERT_LEVEL_WARNING;
        ssl->out_msg[1]  = SSL_ALERT_MSG_CLOSE_NOTIFY;

        if( ( ret = ssl_write_record( ssl ) ) != 0 )
        {
            SSL_DEBUG_RET( 1, "ssl_write_record", ret );
            return( ret );
        }
    }

    SSL_DEBUG_MSG( 2, ( "<= write close notify" ) );

    return( ret );
}

/*
 * Free an SSL context
 */
void ssl_free( ssl_context *ssl )
{
    SSL_DEBUG_MSG( 2, ( "=> free" ) );

    if( ssl->peer_cert != NULL )
    {
        x509_free( ssl->peer_cert );
        memset( ssl->peer_cert, 0, sizeof( x509_cert ) );
          free( ssl->peer_cert );
    }

    if( ssl->out_ctr != NULL )
    {
        memset( ssl->out_ctr, 0, SSL_BUFFER_LEN );
          free( ssl->out_ctr );
    }

    if( ssl->in_ctr != NULL )
    {
        memset( ssl->in_ctr, 0, SSL_BUFFER_LEN );
          free( ssl->in_ctr );
    }

#if defined(POLARSSL_DHM_C)
    dhm_free( &ssl->dhm_ctx );
#endif

    if ( ssl->hostname != NULL)
    {
        memset( ssl->hostname, 0, ssl->hostname_len );
        free( ssl->hostname );
        ssl->hostname_len = 0;
    }

    SSL_DEBUG_MSG( 2, ( "<= free" ) );

    /* Actually free after last debug message */
    memset( ssl, 0, sizeof( ssl_context ) );
}

#endif
