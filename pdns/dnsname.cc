#include "dnsname.hh"
#include <boost/format.hpp>
#include <string>
#include "dnswriter.hh"
#include "misc.hh"

DNSName::DNSName(const char* p)
{
  auto vec = segmentDNSName(p);
  for(auto& e : vec)
    d_labels.push_back(e);
}

DNSName::DNSName(const char* pos, int len, uint16_t* qtype)
{
  unsigned char labellen;
  const char* end = pos + len;
  while((labellen=*pos++) && pos < end) { // "scan and copy"
    d_labels.push_back(string(pos, labellen));
    pos+=labellen;
  }
  if(qtype && pos + labellen + 2 <= end)  
    *qtype=(*(const unsigned char*)pos)*256 + *((const unsigned char*)pos+1);

}

std::string DNSName::toString() const
{
  if(d_labels.empty())  // I keep wondering if there is some deeper meaning to the need to do this
    return ".";
  std::string ret;
  for(const auto& s : d_labels) {
    ret+= escapeLabel(s) + ".";
  }
  return ret;
}

std::string DNSName::toDNSString() const
{
  std::string ret;
  for(const auto& s : d_labels) {
    ret.append(1, (char) s.length());
    ret.append(s);
  }
  ret.append(1, (char)0);
  return ret;
}


bool DNSName::isPartOf(const DNSName& parent) const
{
  auto us = d_labels.crbegin();
  auto p = parent.d_labels.crbegin();
  for(; us != d_labels.crend() && p != parent.d_labels.crend(); ++us, ++p) {
    if(!pdns_iequals(*p, *us))
      break;
  }
  return (p==parent.d_labels.crend());
}

void DNSName::appendRawLabel(const std::string& label)
{
  d_labels.push_back(label);
}

void DNSName::prependRawLabel(const std::string& label)
{
  d_labels.push_front(label);
}

deque<string> DNSName::getRawLabels() const
{
  return d_labels;
}

bool DNSName::chopOff() 
{
  if(d_labels.empty())
    return false;
  d_labels.pop_front();
  return true;
}

bool DNSName::operator==(const DNSName& rhs) const
{
  if(rhs.d_labels.size() != d_labels.size())
    return false;

  auto us = d_labels.crbegin();
  auto p = rhs.d_labels.crbegin();
  for(; us != d_labels.crend() && p != rhs.d_labels.crend(); ++us, ++p) {
    if(!pdns_iequals(*p, *us))
      return false;
  }
  return true;
}

string DNSName::escapeLabel(const std::string& label)
{
  string ret;
  for(uint8_t p : label) {
    if(p=='.') 
      ret+="\\.";
    else if(p=='\\')
      ret+="\\\\";
    else if(p > 0x21 && p < 0x7e)
      ret.append(1, (char)p);
    else {
      ret+="\\" + (boost::format("%03o") % (unsigned int)p).str();
    }
  }
  return ret;
}
