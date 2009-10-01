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


#endif /* md5.h */
