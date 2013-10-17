#ifndef _SHA_HH
#define _SHA_HH

#include <string>
#include <stdint.h>
#include <polarssl/version.h>
#if POLARSSL_VERSION_NUMBER >= 0x01030000
  #include <polarssl/sha1.h>
  #include <polarssl/sha256.h>
  #include <polarssl/sha512.h>
  typedef sha256_context sha2_context;
  typedef sha512_context sha4_context;
  #define sha2_finish sha256_finish
  #define sha2_hmac_finish sha256_hmac_finish
  #define sha2_hmac_starts sha256_hmac_starts
  #define sha2_hmac_update sha256_hmac_update
  #define sha2_starts sha256_starts
  #define sha2_update sha256_update
  #define sha4_finish sha512_finish
  #define sha4_hmac_finish sha512_hmac_finish
  #define sha4_hmac_starts sha512_hmac_starts
  #define sha4_hmac_update sha512_hmac_update
  #define sha4_starts sha512_starts
  #define sha4_update sha512_update
  #define POLARSSL_SHA2_C POLARSSL_SHA256_C
  #define POLARSSL_SHA4_C POLARSSL_SHA512_C
  #define SIG_RSA_SHA1    POLARSSL_MD_SHA1
  #define SIG_RSA_SHA224  POLARSSL_MD_SHA224
  #define SIG_RSA_SHA256  POLARSSL_MD_SHA256
  #define SIG_RSA_SHA384  POLARSSL_MD_SHA384
  #define SIG_RSA_SHA512  POLARSSL_MD_SHA512
#else
  #include <polarssl/sha1.h>
  #include <polarssl/sha2.h>
  #include <polarssl/sha4.h>
  typedef int md_type_t;
#endif

class SHA1Summer
{
public:
   SHA1Summer() { sha1_starts(&d_context); };
   void feed(const std::string &str) { feed(str.c_str(), str.length()); };
   void feed(const char *ptr, size_t len) { sha1_update(&d_context, reinterpret_cast<const unsigned char*>(ptr), len); };
   const std::string get() const { 
     sha1_context ctx2;
     unsigned char result[20] = {0};
     ctx2=d_context;
     sha1_finish(&ctx2, result);
     return std::string(result, result + sizeof result);
   };
private:
   SHA1Summer(const SHA1Summer&);
   SHA1Summer& operator=(const SHA1Summer&);
   sha1_context d_context;
};

class SHA224Summer
{
public:
   SHA224Summer() { sha2_starts(&d_context, 1); };
   void feed(const std::string &str) { feed(str.c_str(), str.length()); };
   void feed(const char *ptr, size_t len) { sha2_update(&d_context, reinterpret_cast<const unsigned char*>(ptr), len); };
   const std::string get() const { 
     sha2_context ctx2;
     unsigned char result[32] = {0};
     ctx2=d_context;
     sha2_finish(&ctx2, result);
     return std::string(result, result + 28);
   };
private:
   SHA224Summer(const SHA1Summer&);
   SHA224Summer& operator=(const SHA1Summer&);
   sha2_context d_context;
};

class SHA256Summer
{
public:
   SHA256Summer() { sha2_starts(&d_context, 0); };
   void feed(const std::string &str) { feed(str.c_str(), str.length()); };
   void feed(const char *ptr, size_t len) { sha2_update(&d_context, reinterpret_cast<const unsigned char*>(ptr), len); };
   const std::string get() const {
     sha2_context ctx2;
     unsigned char result[32] = {0};
     ctx2=d_context;
     sha2_finish(&ctx2, result);
     return std::string(result, result + 32);
   };
private:
   SHA256Summer(const SHA1Summer&);
   SHA256Summer& operator=(const SHA1Summer&);
   sha2_context d_context;
};

class SHA384Summer
{
public:
   SHA384Summer() { sha4_starts(&d_context, 1); };
   void feed(const std::string &str) { feed(str.c_str(), str.length()); };
   void feed(const char *ptr, size_t len) { sha4_update(&d_context, reinterpret_cast<const unsigned char*>(ptr), len); };
   const std::string get() const {
     sha4_context ctx2;
     unsigned char result[64] = {0};
     ctx2 = d_context;
     sha4_finish(&ctx2, result);
     return std::string(result, result + 48);
   };
private:
   SHA384Summer(const SHA1Summer&);
   SHA384Summer& operator=(const SHA1Summer&);
   sha4_context d_context;
};

class SHA512Summer
{
public:
   SHA512Summer() { sha4_starts(&d_context, 0); };
   void feed(const std::string &str) { feed(str.c_str(), str.length()); };
   void feed(const char *ptr, size_t len) { sha4_update(&d_context, reinterpret_cast<const unsigned char*>(ptr), len); };
   const std::string get() const {
     sha4_context ctx2;
     unsigned char result[64] = {0};
     ctx2=d_context;
     sha4_finish(&ctx2, result);
     return std::string(result, result + sizeof result);
   };
private:
   SHA512Summer(const SHA1Summer&);
   SHA512Summer& operator=(const SHA1Summer&);
   sha4_context d_context;
};

#endif /* sha.hh */
