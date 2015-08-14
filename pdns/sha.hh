#ifndef _SHA_HH
#define _SHA_HH

#include <string>
#include <stdint.h>
#ifdef HAVE_MBEDTLS2
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#else
#include <polarssl/sha1.h>
#include <polarssl/sha256.h>
#include <polarssl/sha512.h>
#include "mbedtlscompat.hh"
#endif

class SHA1Summer
{
public:
   SHA1Summer() { mbedtls_sha1_starts(&d_context); };
   void feed(const std::string &str) { feed(str.c_str(), str.length()); };
   void feed(const char *ptr, size_t len) { mbedtls_sha1_update(&d_context, reinterpret_cast<const unsigned char*>(ptr), len); };
   const std::string get() const { 
     mbedtls_sha1_context ctx2;
     unsigned char result[20] = {0};
     ctx2=d_context;
     mbedtls_sha1_finish(&ctx2, result);
     return std::string(result, result + sizeof result);
   };
private:
   SHA1Summer(const SHA1Summer&);
   SHA1Summer& operator=(const SHA1Summer&);
   mbedtls_sha1_context d_context;
};

class SHA256Summer
{
public:
   SHA256Summer() { mbedtls_sha256_starts(&d_context, 0); };
   void feed(const std::string &str) { feed(str.c_str(), str.length()); };
   void feed(const char *ptr, size_t len) { mbedtls_sha256_update(&d_context, reinterpret_cast<const unsigned char*>(ptr), len); };
   const std::string get() const {
     mbedtls_sha256_context ctx2;
     unsigned char result[32] = {0};
     ctx2=d_context;
     mbedtls_sha256_finish(&ctx2, result);
     return std::string(result, result + 32);
   };
private:
   SHA256Summer(const SHA1Summer&);
   SHA256Summer& operator=(const SHA1Summer&);
   mbedtls_sha256_context d_context;
};

class SHA384Summer
{
public:
   SHA384Summer() { mbedtls_sha512_starts(&d_context, 1); };
   void feed(const std::string &str) { feed(str.c_str(), str.length()); };
   void feed(const char *ptr, size_t len) { mbedtls_sha512_update(&d_context, reinterpret_cast<const unsigned char*>(ptr), len); };
   const std::string get() const {
     mbedtls_sha512_context ctx2;
     unsigned char result[64] = {0};
     ctx2 = d_context;
     mbedtls_sha512_finish(&ctx2, result);
     return std::string(result, result + 48);
   };
private:
   SHA384Summer(const SHA1Summer&);
   SHA384Summer& operator=(const SHA1Summer&);
   mbedtls_sha512_context d_context;
};

class SHA512Summer
{
public:
   SHA512Summer() { mbedtls_sha512_starts(&d_context, 0); };
   void feed(const std::string &str) { feed(str.c_str(), str.length()); };
   void feed(const char *ptr, size_t len) { mbedtls_sha512_update(&d_context, reinterpret_cast<const unsigned char*>(ptr), len); };
   const std::string get() const {
     mbedtls_sha512_context ctx2;
     unsigned char result[64] = {0};
     ctx2=d_context;
     mbedtls_sha512_finish(&ctx2, result);
     return std::string(result, result + sizeof result);
   };
private:
   SHA512Summer(const SHA1Summer&);
   SHA512Summer& operator=(const SHA1Summer&);
   mbedtls_sha512_context d_context;
};

#endif /* sha.hh */
