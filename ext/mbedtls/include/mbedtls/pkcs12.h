/**
 * \file pkcs12.h
 *
 * \brief PKCS#12 Personal Information Exchange Syntax
 *
 *  Copyright (C) 2006-2013, ARM Limited, All Rights Reserved
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
#ifndef MBEDTLS_PKCS12_H
#define MBEDTLS_PKCS12_H

#include "md.h"
#include "cipher.h"
#include "asn1.h"

#include <stddef.h>

#define MBEDTLS_ERR_PKCS12_BAD_INPUT_DATA                 -0x1F80  /**< Bad input parameters to function. */
#define MBEDTLS_ERR_PKCS12_FEATURE_UNAVAILABLE            -0x1F00  /**< Feature not available, e.g. unsupported encryption scheme. */
#define MBEDTLS_ERR_PKCS12_PBE_INVALID_FORMAT             -0x1E80  /**< PBE ASN.1 data not as expected. */
#define MBEDTLS_ERR_PKCS12_PASSWORD_MISMATCH              -0x1E00  /**< Given private key password does not allow for correct decryption. */

#define MBEDTLS_PKCS12_DERIVE_KEY       1   /**< encryption/decryption key */
#define MBEDTLS_PKCS12_DERIVE_IV        2   /**< initialization vector     */
#define MBEDTLS_PKCS12_DERIVE_MAC_KEY   3   /**< integrity / MAC key       */

#define MBEDTLS_PKCS12_PBE_DECRYPT      0
#define MBEDTLS_PKCS12_PBE_ENCRYPT      1

#ifdef __cplusplus
extern "C" {
#endif

/**
 * \brief            PKCS12 Password Based function (encryption / decryption)
 *                   for pbeWithSHAAnd128BitRC4
 *
 * \param pbe_params an ASN1 buffer containing the pkcs-12PbeParams structure
 * \param mode       either MBEDTLS_PKCS12_PBE_ENCRYPT or MBEDTLS_PKCS12_PBE_DECRYPT
 * \param pwd        the password used (may be NULL if no password is used)
 * \param pwdlen     length of the password (may be 0)
 * \param input      the input data
 * \param len        data length
 * \param output     the output buffer
 *
 * \return           0 if successful, or a MBEDTLS_ERR_XXX code
 */
int mbedtls_pkcs12_pbe_sha1_rc4_128( mbedtls_asn1_buf *pbe_params, int mode,
                             const unsigned char *pwd,  size_t pwdlen,
                             const unsigned char *input, size_t len,
                             unsigned char *output );

/**
 * \brief            PKCS12 Password Based function (encryption / decryption)
 *                   for cipher-based and mbedtls_md-based PBE's
 *
 * \param pbe_params an ASN1 buffer containing the pkcs-12PbeParams structure
 * \param mode       either MBEDTLS_PKCS12_PBE_ENCRYPT or MBEDTLS_PKCS12_PBE_DECRYPT
 * \param cipher_type the cipher used
 * \param md_type     the mbedtls_md used
 * \param pwd        the password used (may be NULL if no password is used)
 * \param pwdlen     length of the password (may be 0)
 * \param input      the input data
 * \param len        data length
 * \param output     the output buffer
 *
 * \return           0 if successful, or a MBEDTLS_ERR_XXX code
 */
int mbedtls_pkcs12_pbe( mbedtls_asn1_buf *pbe_params, int mode,
                mbedtls_cipher_type_t cipher_type, mbedtls_md_type_t md_type,
                const unsigned char *pwd,  size_t pwdlen,
                const unsigned char *input, size_t len,
                unsigned char *output );

/**
 * \brief            The PKCS#12 derivation function uses a password and a salt
 *                   to produce pseudo-random bits for a particular "purpose".
 *
 *                   Depending on the given id, this function can produce an
 *                   encryption/decryption key, an nitialization vector or an
 *                   integrity key.
 *
 * \param data       buffer to store the derived data in
 * \param datalen    length to fill
 * \param pwd        password to use (may be NULL if no password is used)
 * \param pwdlen     length of the password (may be 0)
 * \param salt       salt buffer to use
 * \param saltlen    length of the salt
 * \param mbedtls_md         mbedtls_md type to use during the derivation
 * \param id         id that describes the purpose (can be MBEDTLS_PKCS12_DERIVE_KEY,
 *                   MBEDTLS_PKCS12_DERIVE_IV or MBEDTLS_PKCS12_DERIVE_MAC_KEY)
 * \param iterations number of iterations
 *
 * \return          0 if successful, or a MD, BIGNUM type error.
 */
int mbedtls_pkcs12_derivation( unsigned char *data, size_t datalen,
                       const unsigned char *pwd, size_t pwdlen,
                       const unsigned char *salt, size_t saltlen,
                       mbedtls_md_type_t mbedtls_md, int id, int iterations );

#ifdef __cplusplus
}
#endif

#endif /* pkcs12.h */
