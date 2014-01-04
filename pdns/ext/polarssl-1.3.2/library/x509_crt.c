/*
 *  X.509 certificate and private key decoding
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
/*
 *  The ITU-T X.509 standard defines a certificate format for PKI.
 *
 *  http://www.ietf.org/rfc/rfc3279.txt
 *  http://www.ietf.org/rfc/rfc3280.txt
 *
 *  ftp://ftp.rsasecurity.com/pub/pkcs/ascii/pkcs-1v2.asc
 *
 *  http://www.itu.int/ITU-T/studygroups/com17/languages/X.680-0207.pdf
 *  http://www.itu.int/ITU-T/studygroups/com17/languages/X.690-0207.pdf
 */

#include "polarssl/config.h"

#if defined(POLARSSL_X509_CRT_PARSE_C)

#include "polarssl/x509_crt.h"
#include "polarssl/oid.h"
#if defined(POLARSSL_PEM_PARSE_C)
#include "polarssl/pem.h"
#endif

#if defined(POLARSSL_MEMORY_C)
#include "polarssl/memory.h"
#else
#define polarssl_malloc     malloc
#define polarssl_free       free
#endif

#include <string.h>
#include <stdlib.h>
#if defined(_WIN32) && !defined(EFIX64) && !defined(EFI32)
#include <windows.h>
#else
#include <time.h>
#endif

#if defined(EFIX64) || defined(EFI32)
#include <stdio.h>
#endif

#if defined(POLARSSL_FS_IO)
#include <stdio.h>
#if !defined(_WIN32)
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#endif
#endif

/*
 *  Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
 */
static int x509_get_version( unsigned char **p,
                             const unsigned char *end,
                             int *ver )
{
    int ret;
    size_t len;

    if( ( ret = asn1_get_tag( p, end, &len,
            ASN1_CONTEXT_SPECIFIC | ASN1_CONSTRUCTED | 0 ) ) != 0 )
    {
        if( ret == POLARSSL_ERR_ASN1_UNEXPECTED_TAG )
        {
            *ver = 0;
            return( 0 );
        }

        return( ret );
    }

    end = *p + len;

    if( ( ret = asn1_get_int( p, end, ver ) ) != 0 )
        return( POLARSSL_ERR_X509_INVALID_VERSION + ret );

    if( *p != end )
        return( POLARSSL_ERR_X509_INVALID_VERSION +
                POLARSSL_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

/*
 *  Validity ::= SEQUENCE {
 *       notBefore      Time,
 *       notAfter       Time }
 */
static int x509_get_dates( unsigned char **p,
                           const unsigned char *end,
                           x509_time *from,
                           x509_time *to )
{
    int ret;
    size_t len;

    if( ( ret = asn1_get_tag( p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
        return( POLARSSL_ERR_X509_INVALID_DATE + ret );

    end = *p + len;

    if( ( ret = x509_get_time( p, end, from ) ) != 0 )
        return( ret );

    if( ( ret = x509_get_time( p, end, to ) ) != 0 )
        return( ret );

    if( *p != end )
        return( POLARSSL_ERR_X509_INVALID_DATE +
                POLARSSL_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

/*
 * X.509 v2/v3 unique identifier (not parsed)
 */
static int x509_get_uid( unsigned char **p,
                         const unsigned char *end,
                         x509_buf *uid, int n )
{
    int ret;

    if( *p == end )
        return( 0 );

    uid->tag = **p;

    if( ( ret = asn1_get_tag( p, end, &uid->len,
            ASN1_CONTEXT_SPECIFIC | ASN1_CONSTRUCTED | n ) ) != 0 )
    {
        if( ret == POLARSSL_ERR_ASN1_UNEXPECTED_TAG )
            return( 0 );

        return( ret );
    }

    uid->p = *p;
    *p += uid->len;

    return( 0 );
}

static int x509_get_basic_constraints( unsigned char **p,
                                       const unsigned char *end,
                                       int *ca_istrue,
                                       int *max_pathlen )
{
    int ret;
    size_t len;

    /*
     * BasicConstraints ::= SEQUENCE {
     *      cA                      BOOLEAN DEFAULT FALSE,
     *      pathLenConstraint       INTEGER (0..MAX) OPTIONAL }
     */
    *ca_istrue = 0; /* DEFAULT FALSE */
    *max_pathlen = 0; /* endless */

    if( ( ret = asn1_get_tag( p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
        return( POLARSSL_ERR_X509_INVALID_EXTENSIONS + ret );

    if( *p == end )
        return 0;

    if( ( ret = asn1_get_bool( p, end, ca_istrue ) ) != 0 )
    {
        if( ret == POLARSSL_ERR_ASN1_UNEXPECTED_TAG )
            ret = asn1_get_int( p, end, ca_istrue );

        if( ret != 0 )
            return( POLARSSL_ERR_X509_INVALID_EXTENSIONS + ret );

        if( *ca_istrue != 0 )
            *ca_istrue = 1;
    }

    if( *p == end )
        return 0;

    if( ( ret = asn1_get_int( p, end, max_pathlen ) ) != 0 )
        return( POLARSSL_ERR_X509_INVALID_EXTENSIONS + ret );

    if( *p != end )
        return( POLARSSL_ERR_X509_INVALID_EXTENSIONS +
                POLARSSL_ERR_ASN1_LENGTH_MISMATCH );

    (*max_pathlen)++;

    return 0;
}

static int x509_get_ns_cert_type( unsigned char **p,
                                       const unsigned char *end,
                                       unsigned char *ns_cert_type)
{
    int ret;
    x509_bitstring bs = { 0, 0, NULL };

    if( ( ret = asn1_get_bitstring( p, end, &bs ) ) != 0 )
        return( POLARSSL_ERR_X509_INVALID_EXTENSIONS + ret );

    if( bs.len != 1 )
        return( POLARSSL_ERR_X509_INVALID_EXTENSIONS +
                POLARSSL_ERR_ASN1_INVALID_LENGTH );

    /* Get actual bitstring */
    *ns_cert_type = *bs.p;
    return 0;
}

static int x509_get_key_usage( unsigned char **p,
                               const unsigned char *end,
                               unsigned char *key_usage)
{
    int ret;
    x509_bitstring bs = { 0, 0, NULL };

    if( ( ret = asn1_get_bitstring( p, end, &bs ) ) != 0 )
        return( POLARSSL_ERR_X509_INVALID_EXTENSIONS + ret );

    if( bs.len < 1 )
        return( POLARSSL_ERR_X509_INVALID_EXTENSIONS +
                POLARSSL_ERR_ASN1_INVALID_LENGTH );

    /* Get actual bitstring */
    *key_usage = *bs.p;
    return 0;
}

/*
 * ExtKeyUsageSyntax ::= SEQUENCE SIZE (1..MAX) OF KeyPurposeId
 *
 * KeyPurposeId ::= OBJECT IDENTIFIER
 */
static int x509_get_ext_key_usage( unsigned char **p,
                               const unsigned char *end,
                               x509_sequence *ext_key_usage)
{
    int ret;

    if( ( ret = asn1_get_sequence_of( p, end, ext_key_usage, ASN1_OID ) ) != 0 )
        return( POLARSSL_ERR_X509_INVALID_EXTENSIONS + ret );

    /* Sequence length must be >= 1 */
    if( ext_key_usage->buf.p == NULL )
        return( POLARSSL_ERR_X509_INVALID_EXTENSIONS +
                POLARSSL_ERR_ASN1_INVALID_LENGTH );

    return 0;
}

/*
 * SubjectAltName ::= GeneralNames
 *
 * GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
 *
 * GeneralName ::= CHOICE {
 *      otherName                       [0]     OtherName,
 *      rfc822Name                      [1]     IA5String,
 *      dNSName                         [2]     IA5String,
 *      x400Address                     [3]     ORAddress,
 *      directoryName                   [4]     Name,
 *      ediPartyName                    [5]     EDIPartyName,
 *      uniformResourceIdentifier       [6]     IA5String,
 *      iPAddress                       [7]     OCTET STRING,
 *      registeredID                    [8]     OBJECT IDENTIFIER }
 *
 * OtherName ::= SEQUENCE {
 *      type-id    OBJECT IDENTIFIER,
 *      value      [0] EXPLICIT ANY DEFINED BY type-id }
 *
 * EDIPartyName ::= SEQUENCE {
 *      nameAssigner            [0]     DirectoryString OPTIONAL,
 *      partyName               [1]     DirectoryString }
 *
 * NOTE: PolarSSL only parses and uses dNSName at this point.
 */
static int x509_get_subject_alt_name( unsigned char **p,
                                      const unsigned char *end,
                                      x509_sequence *subject_alt_name )
{
    int ret;
    size_t len, tag_len;
    asn1_buf *buf;
    unsigned char tag;
    asn1_sequence *cur = subject_alt_name;

    /* Get main sequence tag */
    if( ( ret = asn1_get_tag( p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
        return( POLARSSL_ERR_X509_INVALID_EXTENSIONS + ret );

    if( *p + len != end )
        return( POLARSSL_ERR_X509_INVALID_EXTENSIONS +
                POLARSSL_ERR_ASN1_LENGTH_MISMATCH );

    while( *p < end )
    {
        if( ( end - *p ) < 1 )
            return( POLARSSL_ERR_X509_INVALID_EXTENSIONS +
                    POLARSSL_ERR_ASN1_OUT_OF_DATA );

        tag = **p;
        (*p)++;
        if( ( ret = asn1_get_len( p, end, &tag_len ) ) != 0 )
            return( POLARSSL_ERR_X509_INVALID_EXTENSIONS + ret );

        if( ( tag & ASN1_CONTEXT_SPECIFIC ) != ASN1_CONTEXT_SPECIFIC )
            return( POLARSSL_ERR_X509_INVALID_EXTENSIONS +
                    POLARSSL_ERR_ASN1_UNEXPECTED_TAG );

        if( tag != ( ASN1_CONTEXT_SPECIFIC | 2 ) )
        {
            *p += tag_len;
            continue;
        }

        buf = &(cur->buf);
        buf->tag = tag;
        buf->p = *p;
        buf->len = tag_len;
        *p += buf->len;

        /* Allocate and assign next pointer */
        if (*p < end)
        {
            cur->next = (asn1_sequence *) polarssl_malloc(
                 sizeof( asn1_sequence ) );

            if( cur->next == NULL )
                return( POLARSSL_ERR_X509_INVALID_EXTENSIONS +
                        POLARSSL_ERR_ASN1_MALLOC_FAILED );

            memset( cur->next, 0, sizeof( asn1_sequence ) );
            cur = cur->next;
        }
    }

    /* Set final sequence entry's next pointer to NULL */
    cur->next = NULL;

    if( *p != end )
        return( POLARSSL_ERR_X509_INVALID_EXTENSIONS +
                POLARSSL_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

/*
 * X.509 v3 extensions
 *
 * TODO: Perform all of the basic constraints tests required by the RFC
 * TODO: Set values for undetected extensions to a sane default?
 *
 */
static int x509_get_crt_ext( unsigned char **p,
                             const unsigned char *end,
                             x509_crt *crt )
{
    int ret;
    size_t len;
    unsigned char *end_ext_data, *end_ext_octet;

    if( ( ret = x509_get_ext( p, end, &crt->v3_ext, 3 ) ) != 0 )
    {
        if( ret == POLARSSL_ERR_ASN1_UNEXPECTED_TAG )
            return( 0 );

        return( ret );
    }

    while( *p < end )
    {
        /*
         * Extension  ::=  SEQUENCE  {
         *      extnID      OBJECT IDENTIFIER,
         *      critical    BOOLEAN DEFAULT FALSE,
         *      extnValue   OCTET STRING  }
         */
        x509_buf extn_oid = {0, 0, NULL};
        int is_critical = 0; /* DEFAULT FALSE */
        int ext_type = 0;

        if( ( ret = asn1_get_tag( p, end, &len,
                ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
            return( POLARSSL_ERR_X509_INVALID_EXTENSIONS + ret );

        end_ext_data = *p + len;

        /* Get extension ID */
        extn_oid.tag = **p;

        if( ( ret = asn1_get_tag( p, end, &extn_oid.len, ASN1_OID ) ) != 0 )
            return( POLARSSL_ERR_X509_INVALID_EXTENSIONS + ret );

        extn_oid.p = *p;
        *p += extn_oid.len;

        if( ( end - *p ) < 1 )
            return( POLARSSL_ERR_X509_INVALID_EXTENSIONS +
                    POLARSSL_ERR_ASN1_OUT_OF_DATA );

        /* Get optional critical */
        if( ( ret = asn1_get_bool( p, end_ext_data, &is_critical ) ) != 0 &&
            ( ret != POLARSSL_ERR_ASN1_UNEXPECTED_TAG ) )
            return( POLARSSL_ERR_X509_INVALID_EXTENSIONS + ret );

        /* Data should be octet string type */
        if( ( ret = asn1_get_tag( p, end_ext_data, &len,
                ASN1_OCTET_STRING ) ) != 0 )
            return( POLARSSL_ERR_X509_INVALID_EXTENSIONS + ret );

        end_ext_octet = *p + len;

        if( end_ext_octet != end_ext_data )
            return( POLARSSL_ERR_X509_INVALID_EXTENSIONS +
                    POLARSSL_ERR_ASN1_LENGTH_MISMATCH );

        /*
         * Detect supported extensions
         */
        ret = oid_get_x509_ext_type( &extn_oid, &ext_type );

        if( ret != 0 )
        {
            /* No parser found, skip extension */
            *p = end_ext_octet;

#if !defined(POLARSSL_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION)
            if( is_critical )
            {
                /* Data is marked as critical: fail */
                return ( POLARSSL_ERR_X509_INVALID_EXTENSIONS +
                        POLARSSL_ERR_ASN1_UNEXPECTED_TAG );
            }
#endif
            continue;
        }

        crt->ext_types |= ext_type;

        switch( ext_type )
        {
        case EXT_BASIC_CONSTRAINTS:
            /* Parse basic constraints */
            if( ( ret = x509_get_basic_constraints( p, end_ext_octet,
                    &crt->ca_istrue, &crt->max_pathlen ) ) != 0 )
                return ( ret );
            break;

        case EXT_KEY_USAGE:
            /* Parse key usage */
            if( ( ret = x509_get_key_usage( p, end_ext_octet,
                    &crt->key_usage ) ) != 0 )
                return ( ret );
            break;

        case EXT_EXTENDED_KEY_USAGE:
            /* Parse extended key usage */
            if( ( ret = x509_get_ext_key_usage( p, end_ext_octet,
                    &crt->ext_key_usage ) ) != 0 )
                return ( ret );
            break;

        case EXT_SUBJECT_ALT_NAME:
            /* Parse subject alt name */
            if( ( ret = x509_get_subject_alt_name( p, end_ext_octet,
                    &crt->subject_alt_names ) ) != 0 )
                return ( ret );
            break;

        case EXT_NS_CERT_TYPE:
            /* Parse netscape certificate type */
            if( ( ret = x509_get_ns_cert_type( p, end_ext_octet,
                    &crt->ns_cert_type ) ) != 0 )
                return ( ret );
            break;

        default:
            return( POLARSSL_ERR_X509_FEATURE_UNAVAILABLE );
        }
    }

    if( *p != end )
        return( POLARSSL_ERR_X509_INVALID_EXTENSIONS +
                POLARSSL_ERR_ASN1_LENGTH_MISMATCH );

    return( 0 );
}

/*
 * Parse and fill a single X.509 certificate in DER format
 */
static int x509_crt_parse_der_core( x509_crt *crt, const unsigned char *buf,
                                    size_t buflen )
{
    int ret;
    size_t len;
    unsigned char *p, *end, *crt_end;

    /*
     * Check for valid input
     */
    if( crt == NULL || buf == NULL )
        return( POLARSSL_ERR_X509_BAD_INPUT_DATA );

    p = (unsigned char *) polarssl_malloc( len = buflen );

    if( p == NULL )
        return( POLARSSL_ERR_X509_MALLOC_FAILED );

    memcpy( p, buf, buflen );

    buflen = 0;

    crt->raw.p = p;
    crt->raw.len = len;
    end = p + len;

    /*
     * Certificate  ::=  SEQUENCE  {
     *      tbsCertificate       TBSCertificate,
     *      signatureAlgorithm   AlgorithmIdentifier,
     *      signatureValue       BIT STRING  }
     */
    if( ( ret = asn1_get_tag( &p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
    {
        x509_crt_free( crt );
        return( POLARSSL_ERR_X509_INVALID_FORMAT );
    }

    if( len > (size_t) ( end - p ) )
    {
        x509_crt_free( crt );
        return( POLARSSL_ERR_X509_INVALID_FORMAT +
                POLARSSL_ERR_ASN1_LENGTH_MISMATCH );
    }
    crt_end = p + len;

    /*
     * TBSCertificate  ::=  SEQUENCE  {
     */
    crt->tbs.p = p;

    if( ( ret = asn1_get_tag( &p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
    {
        x509_crt_free( crt );
        return( POLARSSL_ERR_X509_INVALID_FORMAT + ret );
    }

    end = p + len;
    crt->tbs.len = end - crt->tbs.p;

    /*
     * Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
     *
     * CertificateSerialNumber  ::=  INTEGER
     *
     * signature            AlgorithmIdentifier
     */
    if( ( ret = x509_get_version(  &p, end, &crt->version  ) ) != 0 ||
        ( ret = x509_get_serial(   &p, end, &crt->serial   ) ) != 0 ||
        ( ret = x509_get_alg_null( &p, end, &crt->sig_oid1 ) ) != 0 )
    {
        x509_crt_free( crt );
        return( ret );
    }

    crt->version++;

    if( crt->version > 3 )
    {
        x509_crt_free( crt );
        return( POLARSSL_ERR_X509_UNKNOWN_VERSION );
    }

    if( ( ret = x509_get_sig_alg( &crt->sig_oid1, &crt->sig_md,
                                  &crt->sig_pk ) ) != 0 )
    {
        x509_crt_free( crt );
        return( ret );
    }

    /*
     * issuer               Name
     */
    crt->issuer_raw.p = p;

    if( ( ret = asn1_get_tag( &p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
    {
        x509_crt_free( crt );
        return( POLARSSL_ERR_X509_INVALID_FORMAT + ret );
    }

    if( ( ret = x509_get_name( &p, p + len, &crt->issuer ) ) != 0 )
    {
        x509_crt_free( crt );
        return( ret );
    }

    crt->issuer_raw.len = p - crt->issuer_raw.p;

    /*
     * Validity ::= SEQUENCE {
     *      notBefore      Time,
     *      notAfter       Time }
     *
     */
    if( ( ret = x509_get_dates( &p, end, &crt->valid_from,
                                         &crt->valid_to ) ) != 0 )
    {
        x509_crt_free( crt );
        return( ret );
    }

    /*
     * subject              Name
     */
    crt->subject_raw.p = p;

    if( ( ret = asn1_get_tag( &p, end, &len,
            ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
    {
        x509_crt_free( crt );
        return( POLARSSL_ERR_X509_INVALID_FORMAT + ret );
    }

    if( len && ( ret = x509_get_name( &p, p + len, &crt->subject ) ) != 0 )
    {
        x509_crt_free( crt );
        return( ret );
    }

    crt->subject_raw.len = p - crt->subject_raw.p;

    /*
     * SubjectPublicKeyInfo
     */
    if( ( ret = pk_parse_subpubkey( &p, end, &crt->pk ) ) != 0 )
    {
        x509_crt_free( crt );
        return( ret );
    }

    /*
     *  issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
     *                       -- If present, version shall be v2 or v3
     *  subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
     *                       -- If present, version shall be v2 or v3
     *  extensions      [3]  EXPLICIT Extensions OPTIONAL
     *                       -- If present, version shall be v3
     */
    if( crt->version == 2 || crt->version == 3 )
    {
        ret = x509_get_uid( &p, end, &crt->issuer_id,  1 );
        if( ret != 0 )
        {
            x509_crt_free( crt );
            return( ret );
        }
    }

    if( crt->version == 2 || crt->version == 3 )
    {
        ret = x509_get_uid( &p, end, &crt->subject_id,  2 );
        if( ret != 0 )
        {
            x509_crt_free( crt );
            return( ret );
        }
    }

#if !defined(POLARSSL_X509_ALLOW_EXTENSIONS_NON_V3)
    if( crt->version == 3 )
    {
#endif
        ret = x509_get_crt_ext( &p, end, crt);
        if( ret != 0 )
        {
            x509_crt_free( crt );
            return( ret );
        }
#if !defined(POLARSSL_X509_ALLOW_EXTENSIONS_NON_V3)
    }
#endif

    if( p != end )
    {
        x509_crt_free( crt );
        return( POLARSSL_ERR_X509_INVALID_FORMAT +
                POLARSSL_ERR_ASN1_LENGTH_MISMATCH );
    }

    end = crt_end;

    /*
     *  }
     *  -- end of TBSCertificate
     *
     *  signatureAlgorithm   AlgorithmIdentifier,
     *  signatureValue       BIT STRING
     */
    if( ( ret = x509_get_alg_null( &p, end, &crt->sig_oid2 ) ) != 0 )
    {
        x509_crt_free( crt );
        return( ret );
    }

    if( crt->sig_oid1.len != crt->sig_oid2.len ||
        memcmp( crt->sig_oid1.p, crt->sig_oid2.p, crt->sig_oid1.len ) != 0 )
    {
        x509_crt_free( crt );
        return( POLARSSL_ERR_X509_SIG_MISMATCH );
    }

    if( ( ret = x509_get_sig( &p, end, &crt->sig ) ) != 0 )
    {
        x509_crt_free( crt );
        return( ret );
    }

    if( p != end )
    {
        x509_crt_free( crt );
        return( POLARSSL_ERR_X509_INVALID_FORMAT +
                POLARSSL_ERR_ASN1_LENGTH_MISMATCH );
    }

    return( 0 );
}

/*
 * Parse one X.509 certificate in DER format from a buffer and add them to a
 * chained list
 */
int x509_crt_parse_der( x509_crt *chain, const unsigned char *buf,
                        size_t buflen )
{
    int ret;
    x509_crt *crt = chain, *prev = NULL;

    /*
     * Check for valid input
     */
    if( crt == NULL || buf == NULL )
        return( POLARSSL_ERR_X509_BAD_INPUT_DATA );

    while( crt->version != 0 && crt->next != NULL )
    {
        prev = crt;
        crt = crt->next;
    }

    /*
     * Add new certificate on the end of the chain if needed.
     */
    if ( crt->version != 0 && crt->next == NULL)
    {
        crt->next = (x509_crt *) polarssl_malloc( sizeof( x509_crt ) );

        if( crt->next == NULL )
            return( POLARSSL_ERR_X509_MALLOC_FAILED );

        prev = crt;
        crt = crt->next;
        x509_crt_init( crt );
    }

    if( ( ret = x509_crt_parse_der_core( crt, buf, buflen ) ) != 0 )
    {
        if( prev )
            prev->next = NULL;

        if( crt != chain )
            polarssl_free( crt );

        return( ret );
    }

    return( 0 );
}

/*
 * Parse one or more PEM certificates from a buffer and add them to the chained list
 */
int x509_crt_parse( x509_crt *chain, const unsigned char *buf, size_t buflen )
{
    int success = 0, first_error = 0, total_failed = 0;
    int buf_format = X509_FORMAT_DER;

    /*
     * Check for valid input
     */
    if( chain == NULL || buf == NULL )
        return( POLARSSL_ERR_X509_BAD_INPUT_DATA );

    /*
     * Determine buffer content. Buffer contains either one DER certificate or
     * one or more PEM certificates.
     */
#if defined(POLARSSL_PEM_PARSE_C)
    if( strstr( (const char *) buf, "-----BEGIN CERTIFICATE-----" ) != NULL )
        buf_format = X509_FORMAT_PEM;
#endif

    if( buf_format == X509_FORMAT_DER )
        return x509_crt_parse_der( chain, buf, buflen );

#if defined(POLARSSL_PEM_PARSE_C)
    if( buf_format == X509_FORMAT_PEM )
    {
        int ret;
        pem_context pem;

        while( buflen > 0 )
        {
            size_t use_len;
            pem_init( &pem );

            ret = pem_read_buffer( &pem,
                           "-----BEGIN CERTIFICATE-----",
                           "-----END CERTIFICATE-----",
                           buf, NULL, 0, &use_len );

            if( ret == 0 )
            {
                /*
                 * Was PEM encoded
                 */
                buflen -= use_len;
                buf += use_len;
            }
            else if( ret == POLARSSL_ERR_PEM_BAD_INPUT_DATA )
            {
                return( ret );
            }
            else if( ret != POLARSSL_ERR_PEM_NO_HEADER_FOOTER_PRESENT )
            {
                pem_free( &pem );

                /*
                 * PEM header and footer were found
                 */
                buflen -= use_len;
                buf += use_len;

                if( first_error == 0 )
                    first_error = ret;

                continue;
            }
            else
                break;

            ret = x509_crt_parse_der( chain, pem.buf, pem.buflen );

            pem_free( &pem );

            if( ret != 0 )
            {
                /*
                 * Quit parsing on a memory error
                 */
                if( ret == POLARSSL_ERR_X509_MALLOC_FAILED )
                    return( ret );

                if( first_error == 0 )
                    first_error = ret;

                total_failed++;
                continue;
            }

            success = 1;
        }
    }
#endif

    if( success )
        return( total_failed );
    else if( first_error )
        return( first_error );
    else
        return( POLARSSL_ERR_X509_CERT_UNKNOWN_FORMAT );
}

#if defined(POLARSSL_FS_IO)
/*
 * Load one or more certificates and add them to the chained list
 */
int x509_crt_parse_file( x509_crt *chain, const char *path )
{
    int ret;
    size_t n;
    unsigned char *buf;

    if ( ( ret = x509_load_file( path, &buf, &n ) ) != 0 )
        return( ret );

    ret = x509_crt_parse( chain, buf, n );

    memset( buf, 0, n + 1 );
    polarssl_free( buf );

    return( ret );
}

int x509_crt_parse_path( x509_crt *chain, const char *path )
{
    int ret = 0;
#if defined(_WIN32) && !defined(EFIX64) && !defined(EFI32)
    int w_ret;
    WCHAR szDir[MAX_PATH];
    char filename[MAX_PATH];
	char *p;
    int len = (int) strlen( path );

	WIN32_FIND_DATAW file_data;
    HANDLE hFind;

    if( len > MAX_PATH - 3 )
        return( POLARSSL_ERR_X509_BAD_INPUT_DATA );

	memset( szDir, 0, sizeof(szDir) );
	memset( filename, 0, MAX_PATH );
	memcpy( filename, path, len );
	filename[len++] = '\\';
	p = filename + len;
    filename[len++] = '*';

	w_ret = MultiByteToWideChar( CP_ACP, 0, path, len, szDir, MAX_PATH - 3 );

    hFind = FindFirstFileW( szDir, &file_data );
    if (hFind == INVALID_HANDLE_VALUE)
        return( POLARSSL_ERR_X509_FILE_IO_ERROR );

    len = MAX_PATH - len;
    do
    {
		memset( p, 0, len );

        if( file_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY )
            continue;

		w_ret = WideCharToMultiByte( CP_ACP, 0, file_data.cFileName,
									 lstrlenW(file_data.cFileName),
									 p, len - 1,
									 NULL, NULL );

        w_ret = x509_crt_parse_file( chain, filename );
        if( w_ret < 0 )
            ret++;
        else
            ret += w_ret;
    }
    while( FindNextFileW( hFind, &file_data ) != 0 );

    if (GetLastError() != ERROR_NO_MORE_FILES)
        ret = POLARSSL_ERR_X509_FILE_IO_ERROR;

    FindClose( hFind );
#else /* _WIN32 */
#if defined(POLARSSL_HAVE_READDIR_R)
    int t_ret, i;
    struct stat sb;
    struct dirent entry, *result = NULL;
    char entry_name[255];
    DIR *dir = opendir( path );

    if( dir == NULL)
        return( POLARSSL_ERR_X509_FILE_IO_ERROR );

    while( ( t_ret = readdir_r( dir, &entry, &result ) ) == 0 )
    {
        if( result == NULL )
            break;

        snprintf( entry_name, sizeof(entry_name), "%s/%s", path, entry.d_name );

        i = stat( entry_name, &sb );

        if( i == -1 )
        {
            closedir( dir );
            return( POLARSSL_ERR_X509_FILE_IO_ERROR );
        }

        if( !S_ISREG( sb.st_mode ) )
            continue;

        // Ignore parse errors
        //
        t_ret = x509_crt_parse_file( chain, entry_name );
        if( t_ret < 0 )
            ret++;
        else
            ret += t_ret;
    }
    closedir( dir );
#else /* POLARSSL_HAVE_READDIR_R */
    ((void) chain);
    ((void) path);
    ret = POLARSSL_ERR_X509_FEATURE_UNAVAILABLE;
#endif /* POLARSSL_HAVE_READDIR_R */
#endif /* _WIN32 */

    return( ret );
}
#endif /* POLARSSL_FS_IO */

#if defined(_MSC_VER) && !defined snprintf && !defined(EFIX64) && \
    !defined(EFI32)
#include <stdarg.h>

#if !defined vsnprintf
#define vsnprintf _vsnprintf
#endif // vsnprintf

/*
 * Windows _snprintf and _vsnprintf are not compatible to linux versions.
 * Result value is not size of buffer needed, but -1 if no fit is possible.
 *
 * This fuction tries to 'fix' this by at least suggesting enlarging the
 * size by 20.
 */
static int compat_snprintf(char *str, size_t size, const char *format, ...)
{
    va_list ap;
    int res = -1;

    va_start( ap, format );

    res = vsnprintf( str, size, format, ap );

    va_end( ap );

    // No quick fix possible
    if ( res < 0 )
        return( (int) size + 20 );

    return res;
}

#define snprintf compat_snprintf
#endif

#define POLARSSL_ERR_DEBUG_BUF_TOO_SMALL    -2

#define SAFE_SNPRINTF()                         \
{                                               \
    if( ret == -1 )                             \
        return( -1 );                           \
                                                \
    if ( (unsigned int) ret > n ) {             \
        p[n - 1] = '\0';                        \
        return POLARSSL_ERR_DEBUG_BUF_TOO_SMALL;\
    }                                           \
                                                \
    n -= (unsigned int) ret;                    \
    p += (unsigned int) ret;                    \
}

/*
 * Return an informational string about the certificate.
 */
#define BEFORE_COLON    14
#define BC              "14"
int x509_crt_info( char *buf, size_t size, const char *prefix,
                   const x509_crt *crt )
{
    int ret;
    size_t n;
    char *p;
    const char *desc = NULL;
    char key_size_str[BEFORE_COLON];

    p = buf;
    n = size;

    ret = snprintf( p, n, "%scert. version : %d\n",
                               prefix, crt->version );
    SAFE_SNPRINTF();
    ret = snprintf( p, n, "%sserial number : ",
                               prefix );
    SAFE_SNPRINTF();

    ret = x509_serial_gets( p, n, &crt->serial);
    SAFE_SNPRINTF();

    ret = snprintf( p, n, "\n%sissuer name   : ", prefix );
    SAFE_SNPRINTF();
    ret = x509_dn_gets( p, n, &crt->issuer  );
    SAFE_SNPRINTF();

    ret = snprintf( p, n, "\n%ssubject name  : ", prefix );
    SAFE_SNPRINTF();
    ret = x509_dn_gets( p, n, &crt->subject );
    SAFE_SNPRINTF();

    ret = snprintf( p, n, "\n%sissued  on    : " \
                   "%04d-%02d-%02d %02d:%02d:%02d", prefix,
                   crt->valid_from.year, crt->valid_from.mon,
                   crt->valid_from.day,  crt->valid_from.hour,
                   crt->valid_from.min,  crt->valid_from.sec );
    SAFE_SNPRINTF();

    ret = snprintf( p, n, "\n%sexpires on    : " \
                   "%04d-%02d-%02d %02d:%02d:%02d", prefix,
                   crt->valid_to.year, crt->valid_to.mon,
                   crt->valid_to.day,  crt->valid_to.hour,
                   crt->valid_to.min,  crt->valid_to.sec );
    SAFE_SNPRINTF();

    ret = snprintf( p, n, "\n%ssigned using  : ", prefix );
    SAFE_SNPRINTF();

    ret = oid_get_sig_alg_desc( &crt->sig_oid1, &desc );
    if( ret != 0 )
        ret = snprintf( p, n, "???"  );
    else
        ret = snprintf( p, n, "%s", desc );
    SAFE_SNPRINTF();

    if( ( ret = x509_key_size_helper( key_size_str, BEFORE_COLON,
                                      pk_get_name( &crt->pk ) ) ) != 0 )
    {
        return( ret );
    }

    ret = snprintf( p, n, "\n%s%-" BC "s: %d bits\n", prefix, key_size_str,
                          (int) pk_get_size( &crt->pk ) );
    SAFE_SNPRINTF();

    return( (int) ( size - n ) );
}

#if defined(POLARSSL_X509_CRL_PARSE_C)
/*
 * Return 1 if the certificate is revoked, or 0 otherwise.
 */
int x509_crt_revoked( const x509_crt *crt, const x509_crl *crl )
{
    const x509_crl_entry *cur = &crl->entry;

    while( cur != NULL && cur->serial.len != 0 )
    {
        if( crt->serial.len == cur->serial.len &&
            memcmp( crt->serial.p, cur->serial.p, crt->serial.len ) == 0 )
        {
            if( x509_time_expired( &cur->revocation_date ) )
                return( 1 );
        }

        cur = cur->next;
    }

    return( 0 );
}

/*
 * Check that the given certificate is valid according to the CRL.
 */
static int x509_crt_verifycrl( x509_crt *crt, x509_crt *ca,
                               x509_crl *crl_list)
{
    int flags = 0;
    unsigned char hash[POLARSSL_MD_MAX_SIZE];
    const md_info_t *md_info;

    if( ca == NULL )
        return( flags );

    /*
     * TODO: What happens if no CRL is present?
     * Suggestion: Revocation state should be unknown if no CRL is present.
     * For backwards compatibility this is not yet implemented.
     */

    while( crl_list != NULL )
    {
        if( crl_list->version == 0 ||
            crl_list->issuer_raw.len != ca->subject_raw.len ||
            memcmp( crl_list->issuer_raw.p, ca->subject_raw.p,
                    crl_list->issuer_raw.len ) != 0 )
        {
            crl_list = crl_list->next;
            continue;
        }

        /*
         * Check if CRL is correctly signed by the trusted CA
         */
        md_info = md_info_from_type( crl_list->sig_md );
        if( md_info == NULL )
        {
            /*
             * Cannot check 'unknown' hash
             */
            flags |= BADCRL_NOT_TRUSTED;
            break;
        }

        md( md_info, crl_list->tbs.p, crl_list->tbs.len, hash );

        if( pk_can_do( &ca->pk, crl_list->sig_pk ) == 0 ||
            pk_verify( &ca->pk, crl_list->sig_md, hash, md_info->size,
                       crl_list->sig.p, crl_list->sig.len ) != 0 )
        {
            flags |= BADCRL_NOT_TRUSTED;
            break;
        }

        /*
         * Check for validity of CRL (Do not drop out)
         */
        if( x509_time_expired( &crl_list->next_update ) )
            flags |= BADCRL_EXPIRED;

        /*
         * Check if certificate is revoked
         */
        if( x509_crt_revoked(crt, crl_list) )
        {
            flags |= BADCERT_REVOKED;
            break;
        }

        crl_list = crl_list->next;
    }
    return flags;
}
#endif /* POLARSSL_X509_CRL_PARSE_C */

// Equal == 0, inequal == 1
static int x509_name_cmp( const void *s1, const void *s2, size_t len )
{
    size_t i;
    unsigned char diff;
    const unsigned char *n1 = s1, *n2 = s2;

    for( i = 0; i < len; i++ )
    {
        diff = n1[i] ^ n2[i];

        if( ( n1[i] >= 'a' || n1[i] <= 'z' ) && ( diff == 0 || diff == 32 ) )
            continue;

        if( ( n1[i] >= 'A' || n1[i] <= 'Z' ) && ( diff == 0 || diff == 32 ) )
            continue;

        return( 1 );
    }

    return( 0 );
}

static int x509_wildcard_verify( const char *cn, x509_buf *name )
{
    size_t i;
    size_t cn_idx = 0;

    if( name->len < 3 || name->p[0] != '*' || name->p[1] != '.' )
        return( 0 );

    for( i = 0; i < strlen( cn ); ++i )
    {
        if( cn[i] == '.' )
        {
            cn_idx = i;
            break;
        }
    }

    if( cn_idx == 0 )
        return( 0 );

    if( strlen( cn ) - cn_idx == name->len - 1 &&
        x509_name_cmp( name->p + 1, cn + cn_idx, name->len - 1 ) == 0 )
    {
        return( 1 );
    }

    return( 0 );
}

static int x509_crt_verify_top(
                x509_crt *child, x509_crt *trust_ca,
                x509_crl *ca_crl, int path_cnt, int *flags,
                int (*f_vrfy)(void *, x509_crt *, int, int *),
                void *p_vrfy )
{
    int ret;
    int ca_flags = 0, check_path_cnt = path_cnt + 1;
    unsigned char hash[POLARSSL_MD_MAX_SIZE];
    const md_info_t *md_info;

    if( x509_time_expired( &child->valid_to ) )
        *flags |= BADCERT_EXPIRED;

    /*
     * Child is the top of the chain. Check against the trust_ca list.
     */
    *flags |= BADCERT_NOT_TRUSTED;

    md_info = md_info_from_type( child->sig_md );
    if( md_info == NULL )
    {
        /*
         * Cannot check 'unknown', no need to try any CA
         */
        trust_ca = NULL;
    }
    else
        md( md_info, child->tbs.p, child->tbs.len, hash );

    while( trust_ca != NULL )
    {
        if( trust_ca->version == 0 ||
            child->issuer_raw.len != trust_ca->subject_raw.len ||
            memcmp( child->issuer_raw.p, trust_ca->subject_raw.p,
                    child->issuer_raw.len ) != 0 )
        {
            trust_ca = trust_ca->next;
            continue;
        }

        /*
         * Reduce path_len to check against if top of the chain is
         * the same as the trusted CA
         */
        if( child->subject_raw.len == trust_ca->subject_raw.len &&
            memcmp( child->subject_raw.p, trust_ca->subject_raw.p,
                            child->issuer_raw.len ) == 0 )
        {
            check_path_cnt--;
        }

        if( trust_ca->max_pathlen > 0 &&
            trust_ca->max_pathlen < check_path_cnt )
        {
            trust_ca = trust_ca->next;
            continue;
        }

        if( pk_can_do( &trust_ca->pk, child->sig_pk ) == 0 ||
            pk_verify( &trust_ca->pk, child->sig_md, hash, md_info->size,
                       child->sig.p, child->sig.len ) != 0 )
        {
            trust_ca = trust_ca->next;
            continue;
        }

        /*
         * Top of chain is signed by a trusted CA
         */
        *flags &= ~BADCERT_NOT_TRUSTED;
        break;
    }

    /*
     * If top of chain is not the same as the trusted CA send a verify request
     * to the callback for any issues with validity and CRL presence for the
     * trusted CA certificate.
     */
    if( trust_ca != NULL &&
        ( child->subject_raw.len != trust_ca->subject_raw.len ||
          memcmp( child->subject_raw.p, trust_ca->subject_raw.p,
                            child->issuer_raw.len ) != 0 ) )
    {
#if defined(POLARSSL_X509_CRL_PARSE_C)
        /* Check trusted CA's CRL for the chain's top crt */
        *flags |= x509_crt_verifycrl( child, trust_ca, ca_crl );
#else
        ((void) ca_crl);
#endif

        if( x509_time_expired( &trust_ca->valid_to ) )
            ca_flags |= BADCERT_EXPIRED;

        if( NULL != f_vrfy )
        {
            if( ( ret = f_vrfy( p_vrfy, trust_ca, path_cnt + 1, &ca_flags ) ) != 0 )
                return( ret );
        }
    }

    /* Call callback on top cert */
    if( NULL != f_vrfy )
    {
        if( ( ret = f_vrfy(p_vrfy, child, path_cnt, flags ) ) != 0 )
            return( ret );
    }

    *flags |= ca_flags;

    return( 0 );
}

static int x509_crt_verify_child(
                x509_crt *child, x509_crt *parent, x509_crt *trust_ca,
                x509_crl *ca_crl, int path_cnt, int *flags,
                int (*f_vrfy)(void *, x509_crt *, int, int *),
                void *p_vrfy )
{
    int ret;
    int parent_flags = 0;
    unsigned char hash[POLARSSL_MD_MAX_SIZE];
    x509_crt *grandparent;
    const md_info_t *md_info;

    if( x509_time_expired( &child->valid_to ) )
        *flags |= BADCERT_EXPIRED;

    md_info = md_info_from_type( child->sig_md );
    if( md_info == NULL )
    {
        /*
         * Cannot check 'unknown' hash
         */
        *flags |= BADCERT_NOT_TRUSTED;
    }
    else
    {
        md( md_info, child->tbs.p, child->tbs.len, hash );

        if( pk_can_do( &parent->pk, child->sig_pk ) == 0 ||
            pk_verify( &parent->pk, child->sig_md, hash, md_info->size,
                       child->sig.p, child->sig.len ) != 0 )
        {
            *flags |= BADCERT_NOT_TRUSTED;
        }
    }

#if defined(POLARSSL_X509_CRL_PARSE_C)
    /* Check trusted CA's CRL for the given crt */
    *flags |= x509_crt_verifycrl(child, parent, ca_crl);
#endif

    grandparent = parent->next;

    while( grandparent != NULL )
    {
        if( grandparent->version == 0 ||
            grandparent->ca_istrue == 0 ||
            parent->issuer_raw.len != grandparent->subject_raw.len ||
            memcmp( parent->issuer_raw.p, grandparent->subject_raw.p,
                    parent->issuer_raw.len ) != 0 )
        {
            grandparent = grandparent->next;
            continue;
        }
        break;
    }

    if( grandparent != NULL )
    {
        /*
         * Part of the chain
         */
        ret = x509_crt_verify_child( parent, grandparent, trust_ca, ca_crl, path_cnt + 1, &parent_flags, f_vrfy, p_vrfy );
        if( ret != 0 )
            return( ret );
    }
    else
    {
        ret = x509_crt_verify_top( parent, trust_ca, ca_crl, path_cnt + 1, &parent_flags, f_vrfy, p_vrfy );
        if( ret != 0 )
            return( ret );
    }

    /* child is verified to be a child of the parent, call verify callback */
    if( NULL != f_vrfy )
        if( ( ret = f_vrfy( p_vrfy, child, path_cnt, flags ) ) != 0 )
            return( ret );

    *flags |= parent_flags;

    return( 0 );
}

/*
 * Verify the certificate validity
 */
int x509_crt_verify( x509_crt *crt,
                     x509_crt *trust_ca,
                     x509_crl *ca_crl,
                     const char *cn, int *flags,
                     int (*f_vrfy)(void *, x509_crt *, int, int *),
                     void *p_vrfy )
{
    size_t cn_len;
    int ret;
    int pathlen = 0;
    x509_crt *parent;
    x509_name *name;
    x509_sequence *cur = NULL;

    *flags = 0;

    if( cn != NULL )
    {
        name = &crt->subject;
        cn_len = strlen( cn );

        if( crt->ext_types & EXT_SUBJECT_ALT_NAME )
        {
            cur = &crt->subject_alt_names;

            while( cur != NULL )
            {
                if( cur->buf.len == cn_len &&
                    x509_name_cmp( cn, cur->buf.p, cn_len ) == 0 )
                    break;

                if( cur->buf.len > 2 &&
                    memcmp( cur->buf.p, "*.", 2 ) == 0 &&
                            x509_wildcard_verify( cn, &cur->buf ) )
                    break;

                cur = cur->next;
            }

            if( cur == NULL )
                *flags |= BADCERT_CN_MISMATCH;
        }
        else
        {
            while( name != NULL )
            {
                if( OID_CMP( OID_AT_CN, &name->oid ) )
                {
                    if( name->val.len == cn_len &&
                        x509_name_cmp( name->val.p, cn, cn_len ) == 0 )
                        break;

                    if( name->val.len > 2 &&
                        memcmp( name->val.p, "*.", 2 ) == 0 &&
                                x509_wildcard_verify( cn, &name->val ) )
                        break;
                }

                name = name->next;
            }

            if( name == NULL )
                *flags |= BADCERT_CN_MISMATCH;
        }
    }

    /*
     * Iterate upwards in the given cert chain, to find our crt parent.
     * Ignore any upper cert with CA != TRUE.
     */
    parent = crt->next;

    while( parent != NULL && parent->version != 0 )
    {
        if( parent->ca_istrue == 0 ||
            crt->issuer_raw.len != parent->subject_raw.len ||
            memcmp( crt->issuer_raw.p, parent->subject_raw.p,
                    crt->issuer_raw.len ) != 0 )
        {
            parent = parent->next;
            continue;
        }
        break;
    }

    if( parent != NULL )
    {
        /*
         * Part of the chain
         */
        ret = x509_crt_verify_child( crt, parent, trust_ca, ca_crl, pathlen, flags, f_vrfy, p_vrfy );
        if( ret != 0 )
            return( ret );
    }
    else
    {
        ret = x509_crt_verify_top( crt, trust_ca, ca_crl, pathlen, flags, f_vrfy, p_vrfy );
        if( ret != 0 )
            return( ret );
    }

    if( *flags != 0 )
        return( POLARSSL_ERR_X509_CERT_VERIFY_FAILED );

    return( 0 );
}

/*
 * Initialize a certificate chain
 */
void x509_crt_init( x509_crt *crt )
{
    memset( crt, 0, sizeof(x509_crt) );
}

/*
 * Unallocate all certificate data
 */
void x509_crt_free( x509_crt *crt )
{
    x509_crt *cert_cur = crt;
    x509_crt *cert_prv;
    x509_name *name_cur;
    x509_name *name_prv;
    x509_sequence *seq_cur;
    x509_sequence *seq_prv;

    if( crt == NULL )
        return;

    do
    {
        pk_free( &cert_cur->pk );

        name_cur = cert_cur->issuer.next;
        while( name_cur != NULL )
        {
            name_prv = name_cur;
            name_cur = name_cur->next;
            memset( name_prv, 0, sizeof( x509_name ) );
            polarssl_free( name_prv );
        }

        name_cur = cert_cur->subject.next;
        while( name_cur != NULL )
        {
            name_prv = name_cur;
            name_cur = name_cur->next;
            memset( name_prv, 0, sizeof( x509_name ) );
            polarssl_free( name_prv );
        }

        seq_cur = cert_cur->ext_key_usage.next;
        while( seq_cur != NULL )
        {
            seq_prv = seq_cur;
            seq_cur = seq_cur->next;
            memset( seq_prv, 0, sizeof( x509_sequence ) );
            polarssl_free( seq_prv );
        }

        seq_cur = cert_cur->subject_alt_names.next;
        while( seq_cur != NULL )
        {
            seq_prv = seq_cur;
            seq_cur = seq_cur->next;
            memset( seq_prv, 0, sizeof( x509_sequence ) );
            polarssl_free( seq_prv );
        }

        if( cert_cur->raw.p != NULL )
        {
            memset( cert_cur->raw.p, 0, cert_cur->raw.len );
            polarssl_free( cert_cur->raw.p );
        }

        cert_cur = cert_cur->next;
    }
    while( cert_cur != NULL );

    cert_cur = crt;
    do
    {
        cert_prv = cert_cur;
        cert_cur = cert_cur->next;

        memset( cert_prv, 0, sizeof( x509_crt ) );
        if( cert_prv != crt )
            polarssl_free( cert_prv );
    }
    while( cert_cur != NULL );
}

#endif
