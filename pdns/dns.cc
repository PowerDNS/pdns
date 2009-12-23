#include "dns.hh"
#include <stdexcept>

string questionExpand(const char* packet, uint16_t len, uint16_t& type)
{
  type=0;
  string ret;
  if(len < 12) 
    throw runtime_error("Error parsing question in incoming packet: packet too short");
    
  const unsigned char* end = (const unsigned char*)packet+len;
  const unsigned char* pos = (const unsigned char*)packet+12;
  unsigned char labellen;
  
  if(!*pos)
    ret.assign(1, '.');

  while((labellen=*pos++) && pos < end) { // "scan and copy"
    if(pos + labellen > end)
      throw runtime_error("Error parsing question in incoming packet: label extends beyond packet");
      
    ret.append((const char*)pos, labellen);
    ret.append(1, '.');
    pos += labellen;
  }

  if(pos + labellen + 2 <= end)  
    type=(*pos)*256 + *(pos+1);
  return ret;
}
