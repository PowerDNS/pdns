#include "dns.hh"
#include <stdexcept>

void questionExpand(const char* packet, uint16_t len, char* qname, int maxlen, uint16_t& type)
{
  type=0;
  const unsigned char* end=(const unsigned char*)packet+len;
  unsigned char* lbegin=(unsigned char*)packet+12;
  unsigned char* pos=lbegin;
  unsigned char labellen;

  // 3www4ds9a2nl0
  char *dst=qname;
  char* lend=dst + maxlen;
  
  if(!*pos)
    *dst++='.';

  while((labellen=*pos++) && pos < end) { // "scan and copy"
    if(dst >= lend)
      throw std::runtime_error("Label length exceeded destination length");
    for(;labellen;--labellen)
      *dst++ = *pos++;
    *dst++='.';
  }
  *dst=0;

  if(pos + labellen + 2 <= end)  // is this correct XXX FIXME?
    type=(*pos)*256 + *(pos+1);
}

string questionExpand(const char* packet, uint16_t len, uint16_t& type)
{
  char tmp[512];
  questionExpand(packet, len, tmp, sizeof(tmp), type);
  return tmp;
}
