#include "dns.hh"
#include "misc.hh"
#include "arguments.hh"
#include <stdexcept>
#include <iostream>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>

static void appendEscapedLabel(string& ret, const char* begin, unsigned char labellen)
{
  unsigned char n = 0;
  for(n = 0 ; n < labellen; ++n)
    if(begin[n] == '.' || begin[n] == '\\' || begin[n] == ' ')
      break;
  
  if( n == labellen) {
    ret.append(begin, labellen);
    return;
  }
  string label(begin, labellen);
  boost::replace_all(label, "\\",  "\\\\");
  boost::replace_all(label, ".",  "\\.");
  boost::replace_all(label, " ",  "\\032");
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
    else throw runtime_error("out of bounds: "+boost::lexical_cast<string>(offset)+" >= " + boost::lexical_cast<string>(d_length));
  }
private:  
  const char* d_ptr;
  const unsigned int d_length;
};

//! compares two dns packets, skipping the header, but including the question and the qtype
bool dnspacketLessThan(const std::string& a, const std::string& b)
{
  if(a.length() <= 12 || b.length() <= 12) 
    return a.length() < b.length();
//    throw runtime_error("Error parsing question in dnspacket comparison: packet too short");
    
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
      
  uint16_t aQtype = aSafe[aPos]*256 + aSafe[aPos + 1];
  uint16_t bQtype = bSafe[bPos]*256 + bSafe[bPos + 1];
  
  uint16_t aQclass = aSafe[aPos+2]*256 + aSafe[aPos + 3];
  uint16_t bQclass = bSafe[bPos+2]*256 + bSafe[bPos + 3];
  
  return boost::tie(aQtype, aQclass) < boost::tie(bQtype, bQclass);
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

void fillSOAData(const string &content, SOAData &data)
{
  // content consists of fields separated by spaces:
  //  nameservername hostmaster serial-number [refresh [retry [expire [ minimum] ] ] ]

  // fill out data with some plausible defaults:
  // 10800 3600 604800 3600
  vector<string>parts;
  stringtok(parts,content);
  int pleft=parts.size();

  //  cout<<"'"<<content<<"'"<<endl;

  if(pleft)
    data.nameserver=parts[0];

  if(pleft>1) 
    data.hostmaster=attodot(parts[1]); // ahu@ds9a.nl -> ahu.ds9a.nl, piet.puk@ds9a.nl -> piet\.puk.ds9a.nl

  data.serial = pleft > 2 ? strtoul(parts[2].c_str(), NULL, 10) : 0;

  data.refresh = pleft > 3 ? atoi(parts[3].c_str())
        : ::arg().asNum("soa-refresh-default");

  data.retry = pleft > 4 ? atoi(parts[4].c_str())
        : ::arg().asNum("soa-retry-default");

  data.expire = pleft > 5 ? atoi(parts[5].c_str())
        : ::arg().asNum("soa-expire-default");

  data.default_ttl = pleft > 6 ?atoi(parts[6].c_str())
        : ::arg().asNum("soa-minimum-ttl");
}

string serializeSOAData(const SOAData &d)
{
  ostringstream o;
  //  nameservername hostmaster serial-number [refresh [retry [expire [ minimum] ] ] ]
  o<<d.nameserver<<" "<< d.hostmaster <<" "<< d.serial <<" "<< d.refresh << " "<< d.retry << " "<< d.expire << " "<< d.default_ttl;

  return o.str();
}
// the functions below update the 'arcount' and 'ancount', plus they serialize themselves to the stringbuffer

string& attodot(string &str)
{
   if(str.find_first_of("@")==string::npos)
      return str;

   for (unsigned int i = 0; i < str.length(); i++)
   {
      if (str[i] == '@') {
         str[i] = '.';
         break;
      } else if (str[i] == '.') {
         str.insert(i++, "\\");
      }
   }
   return str;
}

string strrcode(unsigned char rcode)
{
  static const char* rcodes[]={"No Error", "FormErr", "SERVFAIL", "NXDOMAIN", "NotImp", "Refused", "", "", "", "Not Auth"};
  if((rcode < sizeof(rcodes) / sizeof(*rcodes)) && *rcodes[rcode])
    return rcodes[rcode];
  return "Err#"+lexical_cast<string>((int)rcode);
}
