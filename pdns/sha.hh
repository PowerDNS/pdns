#ifndef _SHA_HH
#define _SHA_HH

#include <string>
#include <stdint.h>
#include <openssl/sha.h>

inline std::string pdns_sha1sum(const std::string& input)
{
  unsigned char result[20] = {0};
  SHA1(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), result);
  return std::string(result, result + sizeof result);
}

inline std::string pdns_sha256sum(const std::string& input)
{
  unsigned char result[32] = {0};
  SHA256(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), result);
  return std::string(result, result + sizeof result);
}

inline std::string pdns_sha384sum(const std::string& input)
{
  unsigned char result[48] = {0};
  SHA384(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), result);
  return std::string(result, result + sizeof result);
}

inline std::string pdns_sha512sum(const std::string& input)
{
  unsigned char result[64] = {0};
  SHA512(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), result);
  return std::string(result, result + sizeof result);
}

#endif /* sha.hh */
