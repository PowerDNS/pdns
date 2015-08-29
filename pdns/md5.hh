#ifndef _MD5_H
#define _MD5_H

#include <string>
#include <stdint.h>
#ifdef HAVE_MBEDTLS2
#include <mbedtls/md5.h>
#else
#include <polarssl/md5.h>
#include "mbedtlscompat.hh"
#endif

inline std::string pdns_md5sum(const std::string& input)
{
  unsigned char result[16] = {0};
  mbedtls_md5(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), result);
  return std::string(result, result + sizeof result);
}

#endif /* md5.h */
