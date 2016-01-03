#ifndef _SHA_HH
#define _SHA_HH

#include <string>
#include <stdint.h>
#ifdef HAVE_MBEDTLS2
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#elif defined(HAVE_MBEDTLS)
#include <polarssl/sha1.h>
#include <polarssl/sha256.h>
#include <polarssl/sha512.h>
#include "mbedtlscompat.hh"
#elif defined(HAVE_OPENSSL)
#include <openssl/sha.h>
#else
#error "No SHA implementation found"
#endif

inline std::string pdns_sha1sum(const std::string& input)
{
  unsigned char result[20] = {0};
#ifdef HAVE_MBEDTLS
  mbedtls_sha1(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), result);
#elif defined(HAVE_OPENSSL)
  SHA1(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), result);
#else
#error "No sha1 implementation found"
#endif
  return std::string(result, result + sizeof result);
}

inline std::string pdns_sha256sum(const std::string& input)
{
  unsigned char result[32] = {0};
#ifdef HAVE_MBEDTLS
  mbedtls_sha256(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), result, 0);
#elif defined(HAVE_OPENSSL)
  SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), result);
#else
#error "No sha256 implementation found"
#endif
  return std::string(result, result + sizeof result);
}

inline std::string pdns_sha384sum(const std::string& input)
{
  unsigned char result[48] = {0};
#ifdef HAVE_MBEDTLS
  mbedtls_sha512(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), result, 1);
#elif defined(HAVE_OPENSSL)
  SHA384(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), result);
#else
#error "No sha384 implementation found"
#endif
  return std::string(result, result + sizeof result);
}

inline std::string pdns_sha512sum(const std::string& input)
{
  unsigned char result[64] = {0};
#ifdef HAVE_MBEDTLS
  mbedtls_sha512(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), result, 0);
#elif defined(HAVE_OPENSSL)
  SHA512(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), result);
#else
#error "No sha512 implementation found"
#endif
  return std::string(result, result + sizeof result);
}

#endif /* sha.hh */
