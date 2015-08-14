#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "base64.hh"
#include <boost/scoped_array.hpp>
#ifdef HAVE_MBEDTLS2
#include <mbedtls/base64.h>
#else
#include <polarssl/base64.h>
#include "mbedtlscompat.hh"
#endif

int B64Decode(const std::string& src, std::string& dst)
{
  if (src.empty() ) {
    dst.clear();
    return 0;
  }
  size_t dlen = ( src.length() * 6 + 7 ) / 8 ;
  size_t olen = 0;
  boost::scoped_array<unsigned char> d( new unsigned char[dlen] );
  if ( mbedtls_base64_decode( d.get(), dlen, &olen, (const unsigned char*) src.c_str(), src.length() ) == 0 ) {
    dst = std::string( (const char*) d.get(), olen );
    return 0;
  }
  return -1;
}

std::string Base64Encode (const std::string& src)
{
  if (!src.empty()) {
    size_t dlen = ( ( ( src.length() + 2 ) / 3 ) * 4 ) + 1;
    size_t olen = 0;
    boost::scoped_array<unsigned char> dst( new unsigned char[dlen] );
    if( mbedtls_base64_encode( dst.get(), dlen, &olen, (const unsigned char*) src.c_str(), src.length() ) == 0 )
      return std::string( (const char*) dst.get(), olen );
  }
  return "";
}
