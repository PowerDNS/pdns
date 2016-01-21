#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "base64.hh"
#include <boost/scoped_array.hpp>
#include <openssl/bio.h>
#include <openssl/evp.h>

int B64Decode(const std::string& src, std::string& dst)
{
  if (src.empty() ) {
    dst.clear();
    return 0;
  }
  size_t dlen = ( src.length() * 6 + 7 ) / 8 ;
  size_t olen = 0;
  boost::scoped_array<unsigned char> d( new unsigned char[dlen] );
  BIO *bio, *b64;
  bio = BIO_new(BIO_s_mem());
  BIO_write(bio, src.c_str(), src.length());
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
  olen = BIO_read(b64, d.get(), dlen);
  BIO_free_all(bio);
  if (olen > 0) {
    dst = std::string( (const char*) d.get(), olen );
    return 0;
  }
  return -1;
}

std::string Base64Encode (const std::string& src)
{
  if (!src.empty()) {
    size_t olen = 0;
    BIO *bio, *b64;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, src.c_str(), src.length());
    BIO_flush(bio);
    char* pp;
    std::string out;
    olen = BIO_get_mem_data(bio, &pp);
    if (olen > 0) {
      out = std::string(pp, olen);
    }
    BIO_free_all(bio);
    return out;
  }
  return "";
}

#if 0
#include <iostream>
int main() {
  std::string in = "PowerDNS Test String 1";
  std::string out = Base64Encode(in);
  std::cout << out << std::endl;
  if (out != "UG93ZXJETlMgVGVzdCBTdHJpbmcgMQ==") {
    std::cerr << "output did not match expected data" << std::endl;
  }
  std::string roundtrip;
  B64Decode(out, roundtrip);
  std::cout << roundtrip << std::endl;
  if (roundtrip != in) {
    std::cerr << "roundtripped data did not match input data" << std::endl;
  }
  return 0;
}
#endif
