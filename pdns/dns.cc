#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "dns.hh"
#include "misc.hh"
#include <stdexcept>
#include <iostream>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/assign/list_of.hpp>
#include "dnsparser.hh"

std::vector<std::string> RCode::rcodes_s = boost::assign::list_of 
  ("No Error")
  ("Form Error")
  ("Server Failure")
  ("Non-Existent domain")
  ("Not Implemented")
  ("Query Refused")
  ("Name Exists when it should not")
  ("RR Set Exists when it should not")
  ("RR Set that should exist does not")
  ("Server Not Authoritative for zone / Not Authorized")
  ("Name not contained in zone")
  ("Err#11")
  ("Err#12")
  ("Err#13")
  ("Err#14")
  ("Err#15")
  ("Bad OPT Version / TSIG Signature Failure")
  ("Key not recognized")
  ("Signature out of time window")
  ("Bad TKEY Mode")
  ("Duplicate key name")
  ("Algorithm not supported")
  ("Bad Truncation")
;

std::string RCode::to_s(unsigned short rcode) {
  if (rcode > RCode::rcodes_s.size()-1 ) 
    return std::string("Err#")+boost::lexical_cast<std::string>(rcode);
  return RCode::rcodes_s[rcode];
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
  
    
  char operator[](unsigned int offset) const
  {
    if(offset < d_length)
      return d_ptr[offset];
    throw runtime_error("out of bounds: "+boost::lexical_cast<string>(offset)+" >= " + boost::lexical_cast<string>(d_length));
  }
private:  
  const char* d_ptr;
  const unsigned int d_length;
};


// goal is to hash based purely on the question name, and turn error into 'default'
uint32_t hashQuestion(const char* packet, uint16_t len, uint32_t init)
{
  if(len < 12) 
    return init;
  
  uint32_t ret=init;
  const unsigned char* end = (const unsigned char*)packet+len;
  const unsigned char* pos = (const unsigned char*)packet+12;

  unsigned char labellen;
  while((labellen=*pos++) && pos < end) { 
    if(pos + labellen + 1 > end) // include length field  in hash
      return 0;
    ret=burtleCI(pos, labellen+1, ret);
    pos += labellen;
  }
  return ret;
}


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

vector<DNSResourceRecord> convertRRS(const vector<DNSRecord>& in)
{
  vector<DNSResourceRecord> out;
  for(const auto& d : in) {
    DNSResourceRecord rr;
    rr.qname = d.d_name;
    rr.qtype = QType(d.d_type);
    rr.ttl = d.d_ttl;
    rr.content = d.d_content->getZoneRepresentation();
    rr.auth = false;
    rr.qclass = d.d_class;
    out.push_back(rr);
  }
  return out;
}
