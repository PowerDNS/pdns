#include "dnsname.hh"
#include <boost/format.hpp>
#include <string>

#include "dnswriter.hh"
#include "misc.hh"

#include <boost/functional/hash.hpp>

/* raw storage
   in DNS label format, with trailing 0. W/o trailing 0, we are 'empty'
   www.powerdns.com = 3www8powerdns3com0
*/

std::ostream & operator<<(std::ostream &os, const DNSName& d)
{
  return os <<d.toString();
}


DNSName::DNSName(const char* p)
{
  if(p[0]==0 || (p[0]=='.' && p[1]==0)) {
    d_storage.assign(1, (char)0);
  } else {
    d_storage.reserve(strlen(p)+1);
    auto labels = segmentDNSName(p);
    for(const auto& e : labels)
      appendRawLabel(e);
  }
}

DNSName::DNSName(const char* pos, int len, int offset, bool uncompress, uint16_t* qtype, uint16_t* qclass, unsigned int* consumed)
{
  if (offset >= len)
    throw std::range_error("Trying to read past the end of the buffer");

  if(!uncompress) {
    if(const void * fnd=memchr(pos+offset, 0, len-offset)) {
      d_storage.reserve(2+(const char*)fnd-(pos+offset));
    }
  }

  packetParser(pos, len, offset, uncompress, qtype, qclass, consumed);
}

// this should be the __only__ dns name parser in PowerDNS.
void DNSName::packetParser(const char* qpos, int len, int offset, bool uncompress, uint16_t* qtype, uint16_t* qclass, unsigned int* consumed, int depth)
{
  const unsigned char* pos=(const unsigned char*)qpos;
  unsigned char labellen;
  const unsigned char *opos = pos;

  if (offset >= len)
    throw std::range_error("Trying to read past the end of the buffer");

  pos += offset;
  const unsigned char* end = pos + len;
  while((labellen=*pos++) && pos < end) { // "scan and copy"
    if(labellen & 0xc0) {
      if(!uncompress)
        throw std::range_error("Found compressed label, instructed not to follow");

      labellen &= (~0xc0);
      int newpos = (labellen << 8) + *(const unsigned char*)pos;

      if(newpos < offset) {
        if (++depth > 100)
          throw std::range_error("Abort label decompression after 100 redirects");
        packetParser((const char*)opos, len, newpos, true, 0, 0, 0, depth);
      } else
        throw std::range_error("Found a forward reference during label decompression");
      pos++;
      break;
    }
    if (pos + labellen < end) {
      appendRawLabel((const char*)pos, labellen);
    }
    else
      throw std::range_error("Found an invalid label length in qname");
    pos+=labellen;
  }
  if(d_storage.empty())
    d_storage.append(1, (char)0); // we just parsed the root
  if(consumed)
    *consumed = pos - opos - offset;
  if(qtype && pos + labellen + 2 <= end)
    *qtype=(*(const unsigned char*)pos)*256 + *((const unsigned char*)pos+1);

  pos+=2;
  if(qclass && pos + labellen + 2 <= end)
    *qclass=(*(const unsigned char*)pos)*256 + *((const unsigned char*)pos+1);

}

std::string DNSName::toString(const std::string& separator, const bool trailing) const
{
  if (empty()) {
    throw std::out_of_range("Attempt to print an unset dnsname");
  }

 if(isRoot())
    return trailing ? separator : "";

  std::string ret;
  for(const auto& s : getRawLabels()) {
    ret+= escapeLabel(s) + separator;
  }

  return ret.substr(0, ret.size()-!trailing);
}

std::string DNSName::toDNSString() const
{
  if (empty())
    throw std::out_of_range("Attempt to DNSString an unset dnsname");

  return std::string(d_storage.c_str(), d_storage.length());
}

std::string DNSName::toDNSStringLC() const
{
  return toLower(toDNSString()); // label lengths are always < 'A'
}

/**
 * Get the length of the DNSName on the wire
 *
 * @return the total wirelength of the DNSName
 */
size_t DNSName::wirelength() const {
  return d_storage.length();
}

// Are WE part of parent
bool DNSName::isPartOf(const DNSName& parent) const
{
  if(parent.empty() || empty())
    throw std::out_of_range("empty dnsnames aren't part of anything");

  if(parent.d_storage.size() > d_storage.size())
    return false;

  // this is slightly complicated since we can't start from the end, since we can't see where a label begins/ends then
  for(auto us=d_storage.cbegin(); us<d_storage.cend() && std::distance(us,d_storage.cend()) >= static_cast<unsigned int>(parent.d_storage.size()); us+=*us+1) {
    if (std::distance(us,d_storage.cend()) == static_cast<unsigned int>(parent.d_storage.size())) {
      auto p = parent.d_storage.cbegin();
      for(; us != d_storage.cend(); ++us, ++p) {
        if(dns2_tolower(*p) != dns2_tolower(*us))
          return false;
      }
      return true;
    }
  }
  return false;
}

DNSName DNSName::makeRelative(const DNSName& zone) const
{
  DNSName ret(*this);
  ret.makeUsRelative(zone);
  return ret.empty() ? zone : ret; // HACK FIXME400
}
void DNSName::makeUsRelative(const DNSName& zone) 
{
  if (isPartOf(zone)) {
    d_storage.erase(d_storage.size()-zone.d_storage.size());
    d_storage.append(1, (char)0); // put back the trailing 0
  } 
  else
    clear();
}

DNSName DNSName::labelReverse() const
{
  DNSName ret;

  if(isRoot())
    return *this; // we don't create the root automatically below

  if (!empty()) {
    vector<string> l=getRawLabels();
    while(!l.empty()) {
      ret.appendRawLabel(l.back());
      l.pop_back();
    }
  }
  return ret;
}

void DNSName::appendRawLabel(const std::string& label)
{
  appendRawLabel(label.c_str(), label.length());
}

void DNSName::appendRawLabel(const char* start, unsigned int length)
{
  if(length==0)
    throw std::range_error("no such thing as an empty label to append");
  if(length > 63)
    throw std::range_error("label too long to append");
  if(d_storage.size() + length > 254) // reserve two bytes, one for length and one for the root label
    throw std::range_error("name too long to append");

  if(d_storage.empty()) {
    d_storage.append(1, (char)length);
  }
  else {
    *d_storage.rbegin()=(char)length;
  }
  d_storage.append(start, length);
  d_storage.append(1, (char)0);
}

void DNSName::prependRawLabel(const std::string& label)
{
  if(label.empty())
    throw std::range_error("no such thing as an empty label to prepend");
  if(label.size() > 63)
    throw std::range_error("label too long to prepend");
  if(d_storage.size() + label.size() > 254) // reserve two bytes, one for length and one for the root label
    throw std::range_error("name too long to prepend");

  if(d_storage.empty())
    d_storage.append(1, (char)0);

  string_t prep(1, (char)label.size());
  prep.append(label.c_str(), label.size());
  d_storage = prep+d_storage;
}

bool DNSName::slowCanonCompare(const DNSName& rhs) const 
{
  auto ours=getRawLabels(), rhsLabels = rhs.getRawLabels();
  return std::lexicographical_compare(ours.rbegin(), ours.rend(), rhsLabels.rbegin(), rhsLabels.rend(), CIStringCompare());
}

vector<string> DNSName::getRawLabels() const
{
  vector<string> ret;
  ret.reserve(countLabels());
  // 3www4ds9a2nl0
  for(const char* p = d_storage.c_str(); p < d_storage.c_str() + d_storage.size() && *p; p+=*p+1)
    ret.push_back({p+1, (unsigned int)*p}); // XXX FIXME
  return ret;
}


bool DNSName::chopOff()
{
  if(d_storage.empty() || d_storage[0]==0)
    return false;
  d_storage.erase(0, (unsigned int)d_storage[0]+1);
  return true;
}

bool DNSName::isWildcard() const
{
  if(d_storage.size() < 2)
    return false;
  auto p = d_storage.begin();
  return (*p == 0x01 && *++p == '*');
}

unsigned int DNSName::countLabels() const
{
  unsigned int count=0;
  for(const char* p = d_storage.c_str(); p < d_storage.c_str() + d_storage.size() && *p; p+=*p+1)
    ++count;
  return count;
}

void DNSName::trimToLabels(unsigned int to)
{
  while(countLabels() > to && chopOff())
    ;
}

bool DNSName::operator==(const DNSName& rhs) const
{
  if(rhs.empty() != empty() || rhs.d_storage.size() != d_storage.size())
    return false;

  auto us = d_storage.crbegin();
  auto p = rhs.d_storage.crbegin();
  for(; us != d_storage.crend() && p != rhs.d_storage.crend(); ++us, ++p) {   // why does this go backward? 
    if(tolower(*p) != tolower(*us))
      return false;
  }
  return true;
}

size_t hash_value(DNSName const& d)
{
  return d.hash();
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
      ret+="\\" + (boost::format("%03d") % (unsigned int)p).str();
    }
  }
  return ret;
}
