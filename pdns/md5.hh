#ifndef _MD5_H
#define _MD5_H

#include <string>
#include <stdint.h>
#ifdef HAVE_MBEDTLS2
#include <mbedtls/md5.h>
#elif defined(HAVE_MBEDTLS)
#include <polarssl/md5.h>
#include "mbedtlscompat.hh"
#elif HAVE_OPENSSL
#include <openssl/md5.h>
#endif

inline std::string pdns_md5sum(const std::string& input)
{
  unsigned char result[16] = {0};
#ifdef HAVE_MBEDTLS
  mbedtls_md5(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), result);
#elif defined(HAVE_OPENSSL)
  MD5(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), result);
#else
#error "No md5 implementation found"
#endif
  return std::string(result, result + sizeof result);
}

#endif /* md5.h */
