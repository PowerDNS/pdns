#include "dns.hh"
#include "misc.hh"
#include <stdexcept>
#include <iostream>
#include <boost/algorithm/string.hpp>

static void appendEscapedLabel(string& ret, const char* begin, unsigned char labellen)
{
  unsigned char n = 0;
  for(n = 0 ; n < labellen; ++n)
    if(begin[n] == '.' || begin[n] == '\\')
      break;
  
  if( n == labellen) {
    ret.append(begin, labellen);
    return;
  }
  string label(begin, labellen);
  boost::replace_all(label, "\\",  "\\\\");
  boost::replace_all(label, ".",  "\\.");
  ret.append(label);
}

class BoundsCheckingPointer
{
public:
  explicit BoundsCheckingPointer(const char* a, unsigned int length)
    : d_ptr(a), d_length(length) 
    {}
  
  explicit BoundsCheckingPointer(const std::string& str)
    : d_ptr(str.c_str()), d_length(str.size()) 
    {}
  
    
  const char operator[](unsigned int offset) const
  {
    if(offset < d_length)
      return d_ptr[offset];
    else throw runtime_error("out of bounds");
  }
private:  
  const char* d_ptr;
  const unsigned int d_length;
};

//! compares two dns packets, skipping the header, but including the question and the qtype
bool dnspacketLessThan(const std::string& a, const std::string& b)
{
  if(a.length() < 12 || b.length() < 12) 
    throw runtime_error("Error parsing question in incoming packet: packet too short");
    
  // we find: 3www4ds9a2nl0XXYY, where XX and YY are each 2 bytes describing class and type
  
  BoundsCheckingPointer aSafe(a), bSafe(b);
  int aPos=12, bPos=12;
  
  unsigned char aLabelLen, bLabelLen;

  do {  
    aLabelLen = aSafe[aPos++]; bLabelLen = bSafe[bPos++];
    // cerr<<"aLabelLen: "<<(int)aLabelLen<<", bLabelLen: "<< (int)bLabelLen<<endl;
    
    int result=0;
    unsigned int n;
    for(n = 0; n < aLabelLen && n < bLabelLen; ++n) 
      if((result = aSafe[aPos + n] - bSafe[bPos +n]))
        break;
    // cerr<<"Done loop, result="<<result<<", n = "<<n<<", aLabelLen="<<aLabelLen<<", bLabelLen="<<bLabelLen<<endl;
    if(result < 0)
      return true;
    if(result > 0)
      return false;
    if(n == aLabelLen && n != bLabelLen)
      return true; // a is shorter, shortest wins
    if(n != aLabelLen && n == bLabelLen)
      return false; // a is longer
    //~ cerr<<"did not return\n";
    aPos += aLabelLen; bPos += bLabelLen;
  } while(aLabelLen && bLabelLen);
  
  if(aLabelLen || bLabelLen) //
    throw runtime_error("Error in label comparison routing, should not happen");
        
  uint16_t aQtype = aSafe[aPos+2]*256 + aSafe[aPos + 3];
  uint16_t bQtype = bSafe[bPos+2]*256 + bSafe[bPos + 3];
  
  //~ cerr<<"qtypes: "<<aQtype<<", "<<bQtype<<endl;
  
  return aQtype < bQtype;
}


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
    
    appendEscapedLabel(ret, (const char*) pos, labellen);
    
    ret.append(1, '.');
    pos += labellen;
  }

  if(pos + labellen + 2 <= end)  
    type=(*pos)*256 + *(pos+1);
  // cerr << "returning: '"<<ret<<"'"<<endl;
  return ret;
}
