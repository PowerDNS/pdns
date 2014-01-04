/*
 *  Elliptic curve DSA
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
 * References:
 *
 * SEC1 http://www.secg.org/index.php?action=secg,docs_secg
 */

#include "polarssl/config.h"

#if defined(POLARSSL_ECDSA_C)

#include "polarssl/ecdsa.h"
#include "polarssl/asn1write.h"

/*
 * Derive a suitable integer for group grp from a buffer of length len
 * SEC1 4.1.3 step 5 aka SEC1 4.1.4 step 3
 */
static int derive_mpi( const ecp_group *grp, mpi *x,
                       const unsigned char *buf, size_t blen )
{
    size_t n_size = (grp->nbits + 7) / 8;
    return( mpi_read_binary( x, buf, blen > n_size ? n_size : blen ) );
}

/*
 * Compute ECDSA signature of a hashed message (SEC1 4.1.3)
 * Obviously, compared to SEC1 4.1.3, we skip step 4 (hash message)
 */
int ecdsa_sign( ecp_group *grp, mpi *r, mpi *s,
                const mpi *d, const unsigned char *buf, size_t blen,
                int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    int ret, key_tries, sign_tries;
    ecp_point R;
    mpi k, e;

    ecp_point_init( &R );
    mpi_init( &k );
    mpi_init( &e );

    sign_tries = 0;
    do
    {
        /*
         * Steps 1-3: generate a suitable ephemeral keypair
         * and set r = xR mod n
         */
        key_tries = 0;
        do
        {
            MPI_CHK( ecp_gen_keypair( grp, &k, &R, f_rng, p_rng ) );
            MPI_CHK( mpi_mod_mpi( r, &R.X, &grp->N ) );

            if( key_tries++ > 10 )
            {
                ret = POLARSSL_ERR_ECP_RANDOM_FAILED;
                goto cleanup;
            }
        }
        while( mpi_cmp_int( r, 0 ) == 0 );

        /*
         * Step 5: derive MPI from hashed message
         */
        MPI_CHK( derive_mpi( grp, &e, buf, blen ) );

        /*
         * Step 6: compute s = (e + r * d) / k mod n
         */
        MPI_CHK( mpi_mul_mpi( s, r, d ) );
        MPI_CHK( mpi_add_mpi( &e, &e, s ) );
        MPI_CHK( mpi_inv_mod( s, &k, &grp->N ) );
        MPI_CHK( mpi_mul_mpi( s, s, &e ) );
        MPI_CHK( mpi_mod_mpi( s, s, &grp->N ) );

        if( sign_tries++ > 10 )
        {
            ret = POLARSSL_ERR_ECP_RANDOM_FAILED;
            goto cleanup;
        }
    }
    while( mpi_cmp_int( s, 0 ) == 0 );

cleanup:
    ecp_point_free( &R );
    mpi_free( &k );
    mpi_free( &e );

    return( ret );
}

/*
 * Verify ECDSA signature of hashed message (SEC1 4.1.4)
 * Obviously, compared to SEC1 4.1.3, we skip step 2 (hash message)
 */
int ecdsa_verify( ecp_group *grp,
                  const unsigned char *buf, size_t blen,
                  const ecp_point *Q, const mpi *r, const mpi *s)
{
    int ret;
    mpi e, s_inv, u1, u2;
    ecp_point R, P;

    ecp_point_init( &R ); ecp_point_init( &P );
    mpi_init( &e ); mpi_init( &s_inv ); mpi_init( &u1 ); mpi_init( &u2 );

    /*
     * Step 1: make sure r and s are in range 1..n-1
     */
    if( mpi_cmp_int( r, 1 ) < 0 || mpi_cmp_mpi( r, &grp->N ) >= 0 ||
        mpi_cmp_int( s, 1 ) < 0 || mpi_cmp_mpi( s, &grp->N ) >= 0 )
    {
        ret = POLARSSL_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

    /*
     * Additional precaution: make sure Q is valid
     */
    MPI_CHK( ecp_check_pubkey( grp, Q ) );

    /*
     * Step 3: derive MPI from hashed message
     */
    MPI_CHK( derive_mpi( grp, &e, buf, blen ) );

    /*
     * Step 4: u1 = e / s mod n, u2 = r / s mod n
     */
    MPI_CHK( mpi_inv_mod( &s_inv, s, &grp->N ) );

    MPI_CHK( mpi_mul_mpi( &u1, &e, &s_inv ) );
    MPI_CHK( mpi_mod_mpi( &u1, &u1, &grp->N ) );

    MPI_CHK( mpi_mul_mpi( &u2, r, &s_inv ) );
    MPI_CHK( mpi_mod_mpi( &u2, &u2, &grp->N ) );

    /*
     * Step 5: R = u1 G + u2 Q
     *
     * Since we're not using any secret data, no need to pass a RNG to
     * ecp_mul() for countermesures.
     */
    MPI_CHK( ecp_mul( grp, &R, &u1, &grp->G, NULL, NULL ) );
    MPI_CHK( ecp_mul( grp, &P, &u2, Q, NULL, NULL ) );
    MPI_CHK( ecp_add( grp, &R, &R, &P ) );

    if( ecp_is_zero( &R ) )
    {
        ret = POLARSSL_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

    /*
     * Step 6: convert xR to an integer (no-op)
     * Step 7: reduce xR mod n (gives v)
     */
    MPI_CHK( mpi_mod_mpi( &R.X, &R.X, &grp->N ) );

    /*
     * Step 8: check if v (that is, R.X) is equal to r
     */
    if( mpi_cmp_mpi( &R.X, r ) != 0 )
    {
        ret = POLARSSL_ERR_ECP_VERIFY_FAILED;
        goto cleanup;
    }

cleanup:
    ecp_point_free( &R ); ecp_point_free( &P );
    mpi_free( &e ); mpi_free( &s_inv ); mpi_free( &u1 ); mpi_free( &u2 );

    return( ret );
}

/*
 * RFC 4492 page 20:
 *
 *     Ecdsa-Sig-Value ::= SEQUENCE {
 *         r       INTEGER,
 *         s       INTEGER
 *     }
 *
 * Size is at most
 *    1 (tag) + 1 (len) + 1 (initial 0) + ECP_MAX_BYTES for each of r and s,
 *    twice that + 1 (tag) + 2 (len) for the sequence
 * (assuming ECP_MAX_BYTES is less than 126 for r and s,
 * and less than 124 (total len <= 255) for the sequence)
 */
#if POLARSSL_ECP_MAX_BYTES > 124
#error "POLARSSL_ECP_MAX_BYTES bigger than expected, please fix MAX_SIG_LEN"
#endif
#define MAX_SIG_LEN ( 3 + 2 * ( 2 + POLARSSL_ECP_MAX_BYTES ) )

/*
 * Compute and write signature
 */
int ecdsa_write_signature( ecdsa_context *ctx,
                           const unsigned char *hash, size_t hlen,
                           unsigned char *sig, size_t *slen,
                           int (*f_rng)(void *, unsigned char *, size_t),
                           void *p_rng )
{
    int ret;
    unsigned char buf[MAX_SIG_LEN];
    unsigned char *p = buf + sizeof( buf );
    size_t len = 0;

    if( ( ret = ecdsa_sign( &ctx->grp, &ctx->r, &ctx->s, &ctx->d,
                            hash, hlen, f_rng, p_rng ) ) != 0 )
    {
        return( ret );
    }

    ASN1_CHK_ADD( len, asn1_write_mpi( &p, buf, &ctx->s ) );
    ASN1_CHK_ADD( len, asn1_write_mpi( &p, buf, &ctx->r ) );

    ASN1_CHK_ADD( len, asn1_write_len( &p, buf, len ) );
    ASN1_CHK_ADD( len, asn1_write_tag( &p, buf,
                                       ASN1_CONSTRUCTED | ASN1_SEQUENCE ) );

    memcpy( sig, p, len );
    *slen = len;

    return( 0 );
}

/*
 * Read and check signature
 */
int ecdsa_read_signature( ecdsa_context *ctx,
                          const unsigned char *hash, size_t hlen,
                          const unsigned char *sig, size_t slen )
{
    int ret;
    unsigned char *p = (unsigned char *) sig;
    const unsigned char *end = sig + slen;
    size_t len;

    if( ( ret = asn1_get_tag( &p, end, &len,
                    ASN1_CONSTRUCTED | ASN1_SEQUENCE ) ) != 0 )
    {
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA + ret );
    }

    if( p + len != end )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA +
                POLARSSL_ERR_ASN1_LENGTH_MISMATCH );

    if( ( ret = asn1_get_mpi( &p, end, &ctx->r ) ) != 0 ||
        ( ret = asn1_get_mpi( &p, end, &ctx->s ) ) != 0 )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA + ret );

    if( p != end )
        return( POLARSSL_ERR_ECP_BAD_INPUT_DATA +
                POLARSSL_ERR_ASN1_LENGTH_MISMATCH );

    return( ecdsa_verify( &ctx->grp, hash, hlen, &ctx->Q, &ctx->r, &ctx->s ) );
}

/*
 * Generate key pair
 */
int ecdsa_genkey( ecdsa_context *ctx, ecp_group_id gid,
                  int (*f_rng)(void *, unsigned char *, size_t), void *p_rng )
{
    return( ecp_use_known_dp( &ctx->grp, gid ) ||
            ecp_gen_keypair( &ctx->grp, &ctx->d, &ctx->Q, f_rng, p_rng ) );
}

/*
 * Set context from an ecp_keypair
 */
int ecdsa_from_keypair( ecdsa_context *ctx, const ecp_keypair *key )
{
    int ret;

    if( ( ret = ecp_group_copy( &ctx->grp, &key->grp ) ) != 0 ||
        ( ret = mpi_copy( &ctx->d, &key->d ) ) != 0 ||
        ( ret = ecp_copy( &ctx->Q, &key->Q ) ) != 0 )
    {
        ecdsa_free( ctx );
    }

    return( ret );
}

/*
 * Initialize context
 */
void ecdsa_init( ecdsa_context *ctx )
{
    ecp_group_init( &ctx->grp );
    mpi_init( &ctx->d );
    ecp_point_init( &ctx->Q );
    mpi_init( &ctx->r );
    mpi_init( &ctx->s );
}

/*
 * Free context
 */
void ecdsa_free( ecdsa_context *ctx )
{
    ecp_group_free( &ctx->grp );
    mpi_free( &ctx->d );
    ecp_point_free( &ctx->Q );
    mpi_free( &ctx->r );
    mpi_free( &ctx->s );
}

#if defined(POLARSSL_SELF_TEST)

/*
 * Checkup routine
 */
int ecdsa_self_test( int verbose )
{
    return( verbose++ );
}

#endif

#endif /* defined(POLARSSL_ECDSA_C) */
