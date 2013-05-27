#ifndef _MD5_H
#define _MD5_H

#include <string>
#include <stdint.h>
#ifdef HAVE_LIBPOLARSSLSSL
#include <polarssl/md5.h>
#else
#include "ext/polarssl-1.1.2/include/polarssl/md5.h"
#endif

class MD5Summer
{
public:
  MD5Summer() { md5_starts(&d_context); };
  void feed(const std::string &str) { feed(str.c_str(), str.length()); }
  void feed(const char* ptr, size_t len) { md5_update(&d_context, reinterpret_cast<const unsigned char*>(ptr), len); };
  const std::string get() const {  
    md5_context ctx2;
    unsigned char result[16] = {0};
    ctx2=d_context;
    md5_finish(&ctx2, result);
    return std::string(result, result + sizeof result);
  };
private:
  MD5Summer(const MD5Summer&);
  MD5Summer& operator=(const MD5Summer&);

  md5_context d_context;
};

inline std::string pdns_md5sum(const std::string& input)
{
  unsigned char result[16] = {0};
  md5(reinterpret_cast<const unsigned char*>(input.c_str()), input.length(), result);
  return std::string(result, result + sizeof result);
}

#endif /* md5.h */
