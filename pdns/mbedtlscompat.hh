#define MBEDTLS_VERSION_STRING POLARSSL_VERSION_STRING

#define MBEDTLS_MD_MAX_SIZE POLARSSL_MD_MAX_SIZE
#define MBEDTLS_MD_MD5 POLARSSL_MD_MD5 
#define MBEDTLS_MD_SHA1 POLARSSL_MD_SHA1
#define MBEDTLS_MD_SHA224 POLARSSL_MD_SHA224 
#define MBEDTLS_MD_SHA256 POLARSSL_MD_SHA256 
#define MBEDTLS_MD_SHA384 POLARSSL_MD_SHA384 
#define MBEDTLS_MD_SHA512 POLARSSL_MD_SHA512

#define MBEDTLS_RSA_PKCS_V15 RSA_PKCS_V15
#define MBEDTLS_RSA_PRIVATE RSA_PRIVATE
#define MBEDTLS_RSA_PUBLIC RSA_PUBLIC

#define MBEDTLS_ECP_DP_SECP256R1 POLARSSL_ECP_DP_SECP256R1
#define MBEDTLS_ECP_DP_SECP384R1 POLARSSL_ECP_DP_SECP384R1
#define MBEDTLS_ECP_MAX_PT_LEN POLARSSL_ECP_MAX_PT_LEN
#define MBEDTLS_ECP_PF_UNCOMPRESSED POLARSSL_ECP_PF_UNCOMPRESSED

// Types
#define mbedtls_aes_context aes_context

#define mbedtls_sha1_context sha1_context
#define mbedtls_sha256_context sha256_context
#define mbedtls_sha512_context sha512_context

#ifdef POLARSSL_MD_H
typedef md_info_t mbedtls_md_info_t;
typedef md_type_t mbedtls_md_type_t;
#endif

#define mbedtls_entropy_context entropy_context

#define mbedtls_ctr_drbg_context ctr_drbg_context

#define mbedtls_rsa_context rsa_context

#define mbedtls_mpi mpi

#define mbedtls_ecdsa_context ecdsa_context

#define mbedtls_ecp_group ecp_group
#define mbedtls_ecp_group_id ecp_group_id

// Functions macro
#define mbedtls_aes_crypt_ctr aes_crypt_ctr
#define mbedtls_aes_setkey_enc aes_setkey_enc

#define mbedtls_sha1 sha1 
#define mbedtls_sha1_starts sha1_starts
#define mbedtls_sha1_update sha1_update
#define mbedtls_sha1_finish sha1_finish 

#define mbedtls_sha256 sha256
#define mbedtls_sha256_starts sha256_starts
#define mbedtls_sha256_update sha256_update
#define mbedtls_sha256_finish sha256_finish 

#define mbedtls_sha512 sha512
#define mbedtls_sha512_starts sha512_starts
#define mbedtls_sha512_update sha512_update
#define mbedtls_sha512_finish sha512_finish 

#define mbedtls_md_hmac md_hmac
#define mbedtls_md_get_size md_get_size
#define mbedtls_md_info_from_type md_info_from_type

#define mbedtls_md5 md5

#define mbedtls_mpi_init mpi_init
#define mbedtls_mpi_size mpi_size
#define mbedtls_mpi_free mpi_free

#define mbedtls_entropy_init entropy_init
#define mbedtls_entropy_func entropy_func
#define mbedtls_entropy_free entropy_free

#define mbedtls_ctr_drbg_init
#define mbedtls_ctr_drbg_seed ctr_drbg_init
#define mbedtls_ctr_drbg_random ctr_drbg_random
#define mbedtls_ctr_drbg_free ctr_drbg_free

#define mbedtls_rsa_init rsa_init
#define mbedtls_rsa_gen_key rsa_gen_key
#define mbedtls_rsa_pkcs1_sign rsa_pkcs1_sign
#define mbedtls_rsa_pkcs1_verify rsa_pkcs1_verify

#define mbedtls_mpi_copy mpi_copy
#define mbedtls_mpi_cmp_mpi mpi_cmp_mpi
#define mbedtls_mpi_bitlen mpi_msb
#define mbedtls_mpi_write_binary mpi_write_binary
#define mbedtls_mpi_read_binary mpi_read_binary

#define mbedtls_ecdsa_free ecdsa_free
#define mbedtls_ecdsa_genkey ecdsa_genkey
#define mbedtls_ecdsa_init ecdsa_init
#define mbedtls_ecdsa_sign_det ecdsa_sign_det
#define mbedtls_ecdsa_verify ecdsa_verify

#define mbedtls_ecp_copy ecp_copy
#define mbedtls_ecp_group_init ecp_group_init
#define mbedtls_ecp_group_copy ecp_group_copy
#define mbedtls_ecp_group_load ecp_use_known_dp
#define mbedtls_ecp_group_free ecp_group_free
#define mbedtls_ecp_mul ecp_mul
#define mbedtls_ecp_point_init ecp_point_init
#define mbedtls_ecp_point_read_binary ecp_point_read_binary
#define mbedtls_ecp_point_write_binary ecp_point_write_binary

// Functions
#ifdef POLARSSL_BASE64_H
#ifndef COMPAT_BASE64
#define COMPAT_BASE64

inline int mbedtls_base64_decode( unsigned char *dst, size_t dlen, size_t *olen, const unsigned char *src, size_t slen ) {
  int ret = base64_decode( dst, &dlen, src, slen );
  *olen = dlen;
  return ret;
}

inline int mbedtls_base64_encode( unsigned char *dst, size_t dlen, size_t *olen, const unsigned char *src, size_t slen ) {
  int ret = base64_encode( dst, &dlen, src, slen );
  *olen = dlen;
  return ret;
}

#endif
#endif
