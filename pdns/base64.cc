#include "base64.hh"
#include <boost/scoped_ptr.hpp>
#include <polarssl/base64.h>

int B64Decode(const std::string& src, std::string& dst)
{
  if (src.empty() ) {
    dst.clear();
    return 0;
  }
  size_t dlen = ( src.length() * 6 + 7 ) / 8 ;
  boost::scoped_ptr<unsigned char> d( new unsigned char[dlen] );
  if ( base64_decode( d.get(), &dlen, (const unsigned char*) src.c_str(), src.length() ) == 0 ) {
    dst = std::string( (const char*) d.get(), dlen );
    return 0;
  }
  return -1;
}

std::string Base64Encode (const std::string& src)
{
  if (!src.empty()) {
    size_t dlen = ( ( ( src.length() + 2 ) / 3 ) * 4 ) + 1;
    boost::scoped_ptr<unsigned char> dst( new unsigned char[dlen] );
    if( base64_encode( dst.get(), &dlen, (const unsigned char*) src.c_str(), src.length() ) == 0 )
      return std::string( (const char*) dst.get(), dlen );
  }
  return "";
}
