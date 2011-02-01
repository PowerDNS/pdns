#ifndef _MD5_H
#define _MD5_H

#include <string>
#include <stdint.h>
class MD5Summer
{
public:
  MD5Summer();
  void feed(const std::string &str);
  void feed(const char* ptr, size_t len);
  const std::string get() const;

  struct md5_context
  {
    uint32_t total[2];
    uint32_t state[4];
    uint8_t buffer[64];
  };

private:
  MD5Summer(const MD5Summer&);
  MD5Summer& operator=(const MD5Summer&);
  struct md5_context d_context;
};

inline std::string pdns_md5sum(const std::string& input)
{
  MD5Summer md5;
  md5.feed(input);
  return md5.get();
}

#endif /* md5.h */
