/*
 *  X.509 Certificate Signing Request (CSR) parsing
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: GPL-2.0
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
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
/*
 *  The ITU-T X.509 standard defines a certificate format for PKI.
 *
 *  http://www.ietf.org/rfc/rfc5280.txt (Certificates and CRLs)
 *  http://www.ietf.org/rfc/rfc3279.txt (Alg IDs for CRLs)
 *  http://www.ietf.org/rfc/rfc2986.txt (CSRs, aka PKCS#10)
 *
 *  http://www.itu.int/ITU-T/studygroups/com17/languages/X.680-0207.pdf
 *  http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
 */

#if !defined(MBEDTLS_CONFIG_FILE)
#include "mbedtls/config.h"
#else
#include MBEDTLS_CONFIG_FILE
#endif

#if defined(MBEDTLS_X509_CSR_PARSE_C)

#include "mbedtls/x509_csr.h"
#include "mbedtls/oid.h"

#include <string.h>

#if defined(MBEDTLS_PEM_PARSE_C)
#include "mbedtls/pem.h"
#endif

#if defined(MBEDTLS_PLATFORM_C)
#include "mbedtls/platform.h"
#else
#include <stdlib.h>
#include <stdio.h>
#define mbedtls_free       free
#define mbedtls_calloc    calloc
#define mbedtls_snprintf   snprintf
#endif

#if defined(MBEDTLS_FS_IO) || defined(EFIX64) || defined(EFI32)
#include <stdio.h>
#endif

/* Implementation that should never be optimized out by the compiler */
static void mbedtls_zeroize( void *v, size_t n ) {
    volatile unsigned char *p = v; while( n-- ) *p++ = 0;
}

/*
 *  Version  ::=  INTEGER  {  v1(0)  }
 */
static int x509_csr_get_version( unsigned char **p,
                             const unsigned char *end,
                             int *ver )
{
    int ret;

    if( ( ret = mbedtls_asn1_get_int( p, end, ver ) ) != 0 )
    {
        if( ret == MBEDTLS_ERR_ASN1_UNEXPECTED_TAG )
        {
            *ver = 0;
            return( 0 );
        }

        return( MBEDTLS_ERR_X509_INVALID_VERSION + ret );
    }

    return( 0 );
}

/*
 * Parse a CSR in DER format
 */
int mbedtls_x509_csr_parse_der( mbedtls_x509_csr *csr,
                        const unsigned char *buf, size_t buflen )
{
    int ret;
    size_t len;
    unsigned char *p, *end;
    mbedtls_x509_buf sig_params;

    memset( &sig_params, 0, sizeof( mbedtls_x509_buf ) );

    /*
     * Check for valid input
     */
    if( csr == NULL || buf == NULL )
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

    mbedtls_x509_csr_init( csr );

    /*
     * first copy the raw DER data
     */
    p = mbedtls_calloc( 1, len = buflen );

    if( p == NULL )
        return( MBEDTLS_ERR_X509_ALLOC_FAILED );

    memcpy( p, buf, buflen );

    csr->raw.p = p;
    csr->raw.len = len;
    end = p + len;

    /*
     *  CertificationRequest ::= SEQUENCE {
     *       certificationRequestInfo CertificationRequestInfo,
     *       signatureAlgorithm AlgorithmIdentifier,
     *       signature          BIT STRING
     *  }
     */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT );
    }

    if( len != (size_t) ( end - p ) )
    {
        mbedtls_x509_csr_free( csr );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
    }

    /*
     *  CertificationRequestInfo ::= SEQUENCE {
     */
    csr->cri.p = p;

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    end = p + len;
    csr->cri.len = end - csr->cri.p;

    /*
     *  Version  ::=  INTEGER {  v1(0) }
     */
    if( ( ret = x509_csr_get_version( &p, end, &csr->version ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( ret );
    }

    csr->version++;

    if( csr->version != 1 )
    {
        mbedtls_x509_csr_free( csr );
        return( MBEDTLS_ERR_X509_UNKNOWN_VERSION );
    }

    /*
     *  subject               Name
     */
    csr->subject_raw.p = p;

    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }

    if( ( ret = mbedtls_x509_get_name( &p, p + len, &csr->subject ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( ret );
    }

    csr->subject_raw.len = p - csr->subject_raw.p;

    /*
     *  subjectPKInfo SubjectPublicKeyInfo
     */
    if( ( ret = mbedtls_pk_parse_subpubkey( &p, end, &csr->pk ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( ret );
    }

    /*
     *  attributes    [0] Attributes
     */
    if( ( ret = mbedtls_asn1_get_tag( &p, end, &len,
            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_CONTEXT_SPECIFIC ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT + ret );
    }
    // TODO Parse Attributes / extension requests

    p += len;

    end = csr->raw.p + csr->raw.len;

    /*
     *  signatureAlgorithm   AlgorithmIdentifier,
     *  signature            BIT STRING
     */
    if( ( ret = mbedtls_x509_get_alg( &p, end, &csr->sig_oid, &sig_params ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( ret );
    }

    if( ( ret = mbedtls_x509_get_sig_alg( &csr->sig_oid, &sig_params,
                                  &csr->sig_md, &csr->sig_pk,
                                  &csr->sig_opts ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( MBEDTLS_ERR_X509_UNKNOWN_SIG_ALG );
    }

    if( ( ret = mbedtls_x509_get_sig( &p, end, &csr->sig ) ) != 0 )
    {
        mbedtls_x509_csr_free( csr );
        return( ret );
    }

    if( p != end )
    {
        mbedtls_x509_csr_free( csr );
        return( MBEDTLS_ERR_X509_INVALID_FORMAT +
                MBEDTLS_ERR_ASN1_LENGTH_MISMATCH );
    }

    return( 0 );
}

/*
 * Parse a CSR, allowing for PEM or raw DER encoding
 */
int mbedtls_x509_csr_parse( mbedtls_x509_csr *csr, const unsigned char *buf, size_t buflen )
{
    int ret;
#if defined(MBEDTLS_PEM_PARSE_C)
    size_t use_len;
    mbedtls_pem_context pem;
#endif

    /*
     * Check for valid input
     */
    if( csr == NULL || buf == NULL )
        return( MBEDTLS_ERR_X509_BAD_INPUT_DATA );

#if defined(MBEDTLS_PEM_PARSE_C)
    mbedtls_pem_init( &pem );

    /* Avoid calling mbedtls_pem_read_buffer() on non-null-terminated string */
    if( buflen == 0 || buf[buflen - 1] != '\0' )
        ret = MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT;
    else
        ret = mbedtls_pem_read_buffer( &pem,
                               "-----BEGIN CERTIFICATE REQUEST-----",
                               "-----END CERTIFICATE REQUEST-----",
                               buf, NULL, 0, &use_len );

    if( ret == 0 )
    {
        /*
         * Was PEM encoded, parse the result
         */
        if( ( ret = mbedtls_x509_csr_parse_der( csr, pem.buf, pem.buflen ) ) != 0 )
            return( ret );

        mbedtls_pem_free( &pem );
        return( 0 );
    }
    else if( ret != MBEDTLS_ERR_PEM_NO_HEADER_FOOTER_PRESENT )
    {
        mbedtls_pem_free( &pem );
        return( ret );
    }
    else
#endif /* MBEDTLS_PEM_PARSE_C */
    return( mbedtls_x509_csr_parse_der( csr, buf, buflen ) );
}

#if defined(MBEDTLS_FS_IO)
/*
 * Load a CSR into the structure
 */
int mbedtls_x509_csr_parse_file( mbedtls_x509_csr *csr, const char *path )
{
    int ret;
    size_t n;
    unsigned char *buf;

    if( ( ret = mbedtls_pk_load_file( path, &buf, &n ) ) != 0 )
        return( ret );

    ret = mbedtls_x509_csr_parse( csr, buf, n );

    mbedtls_zeroize( buf, n );
    mbedtls_free( buf );

    return( ret );
}
#endif /* MBEDTLS_FS_IO */

#define BEFORE_COLON    14
#define BC              "14"
/*
 * Return an informational string about the CSR.
 */
int mbedtls_x509_csr_info( char *buf, size_t size, const char *prefix,
                   const mbedtls_x509_csr *csr )
{
    int ret;
    size_t n;
    char *p;
    char key_size_str[BEFORE_COLON];

    p = buf;
    n = size;

    ret = mbedtls_snprintf( p, n, "%sCSR version   : %d",
                               prefix, csr->version );
    MBEDTLS_X509_SAFE_SNPRINTF;

    ret = mbedtls_snprintf( p, n, "\n%ssubject name  : ", prefix );
    MBEDTLS_X509_SAFE_SNPRINTF;
    ret = mbedtls_x509_dn_gets( p, n, &csr->subject );
    MBEDTLS_X509_SAFE_SNPRINTF;

    ret = mbedtls_snprintf( p, n, "\n%ssigned using  : ", prefix );
    MBEDTLS_X509_SAFE_SNPRINTF;

    ret = mbedtls_x509_sig_alg_gets( p, n, &csr->sig_oid, csr->sig_pk, csr->sig_md,
                             csr->sig_opts );
    MBEDTLS_X509_SAFE_SNPRINTF;

    if( ( ret = mbedtls_x509_key_size_helper( key_size_str, BEFORE_COLON,
                                      mbedtls_pk_get_name( &csr->pk ) ) ) != 0 )
    {
        return( ret );
    }

    ret = mbedtls_snprintf( p, n, "\n%s%-" BC "s: %d bits\n", prefix, key_size_str,
                          (int) mbedtls_pk_get_bitlen( &csr->pk ) );
    MBEDTLS_X509_SAFE_SNPRINTF;

    return( (int) ( size - n ) );
}

/*
 * Initialize a CSR
 */
void mbedtls_x509_csr_init( mbedtls_x509_csr *csr )
{
    memset( csr, 0, sizeof(mbedtls_x509_csr) );
}

/*
 * Unallocate all CSR data
 */
void mbedtls_x509_csr_free( mbedtls_x509_csr *csr )
{
    mbedtls_x509_name *name_cur;
    mbedtls_x509_name *name_prv;

    if( csr == NULL )
        return;

    mbedtls_pk_free( &csr->pk );

#if defined(MBEDTLS_X509_RSASSA_PSS_SUPPORT)
    mbedtls_free( csr->sig_opts );
#endif

    name_cur = csr->subject.next;
    while( name_cur != NULL )
    {
        name_prv = name_cur;
        name_cur = name_cur->next;
        mbedtls_zeroize( name_prv, sizeof( mbedtls_x509_name ) );
        mbedtls_free( name_prv );
    }

    if( csr->raw.p != NULL )
    {
        mbedtls_zeroize( csr->raw.p, csr->raw.len );
        mbedtls_free( csr->raw.p );
    }

    mbedtls_zeroize( csr, sizeof( mbedtls_x509_csr ) );
}

#endif /* MBEDTLS_X509_CSR_PARSE_C */
