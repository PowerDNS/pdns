#include "dnsname.hh"
#include <boost/format.hpp>
#include <string>

#include "dnswriter.hh"
#include "misc.hh"

#include <boost/functional/hash.hpp>

/* raw storage
   in DNS label format, without trailing 0. So the root is of length 0.

   www.powerdns.com = 3www8powerdns3com

   a primitive is nextLabel()
*/

/* FIXME400: @nlyan suggests that we should only have a string constructor, and make sure
 * char* does not implicitly map to it, to avoid issues with embedded NULLs */
DNSName::DNSName(const char* p)
{
  d_empty=false;
  auto labels = segmentDNSName(p);
  for(const auto& e : labels)
    appendRawLabel(e);
}

DNSName::DNSName(const char* pos, int len, int offset, bool uncompress, uint16_t* qtype, uint16_t* qclass, unsigned int* consumed)
{
  d_empty=false;
  d_recurse = 0;
  packetParser(pos, len, offset, uncompress, qtype, qclass, consumed);
}

// this should be the __only__ dns name parser in PowerDNS.
void DNSName::packetParser(const char* pos, int len, int offset, bool uncompress, uint16_t* qtype, uint16_t* qclass, unsigned int* consumed)
{
  unsigned char labellen;
  const char *opos = pos;
  pos += offset;
  const char* end = pos + len;
  while((labellen=*pos++) && pos < end) { // "scan and copy"
    if(labellen & 0xc0) {
      if(!uncompress)
        throw std::range_error("Found compressed label, instructed not to follow");

      labellen &= (~0xc0);
      int newpos = (labellen << 8) + *(const unsigned char*)pos;

      if(newpos < offset) {
        if (++d_recurse > 100)
          throw std::range_error("Abort label decompression after 100 redirects");
        packetParser(opos, len, newpos, true);
      } else
        throw std::range_error("Found a forward reference during label decompression");
      pos++;
      break;
    }
    if (pos + labellen < end) {
      appendRawLabel(string(pos, labellen));
    }
    else
      throw std::range_error("Found an invalid label length in qname");
    pos+=labellen;
  }
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
  if (d_empty)
    return "";
  if(d_storage.empty() && trailing)  // I keep wondering if there is some deeper meaning to the need to do this
    return separator;
  std::string ret;
  for(const auto& s : getRawLabels()) {
    ret+= escapeLabel(s) + separator;
  }
  return ret.substr(0, ret.size()-!trailing);
}

std::string DNSName::toDNSString() const
{
  if (d_empty)
    return "";
  string ret(d_storage.c_str(), d_storage.length());
  ret.append(1,(char)0);
  return toLower(ret); // toLower or not toLower, that is the question
  // return ret;
}

size_t DNSName::length() const {
  return this->toString().length();
}

// are WE part of parent
bool DNSName::isPartOf(const DNSName& parent) const
{
  if(parent.d_empty || d_empty)
    return false;
  if(parent.d_storage.empty())
    return true;
  if(parent.d_storage.size() > d_storage.size())
    return false;

  // this is slightly complicated since we can't start from the end, since we can't see where a label begins/ends then
  for(auto us=d_storage.cbegin(); us<d_storage.cend() && std::distance(us,d_storage.cend()) >= static_cast<unsigned int>(parent.d_storage.size()); us+=*us+1) {
    if (std::distance(us,d_storage.cend()) == static_cast<unsigned int>(parent.d_storage.size())) {
      auto p = parent.d_storage.cbegin();
      for(; us != d_storage.cend(); ++us, ++p) {
        if(tolower(*p) != tolower(*us))
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
  if (ret.isPartOf(zone)) {
    ret.d_storage.erase(ret.d_storage.size()-zone.d_storage.size());
  } else
    ret.clear();
  return ret;
}

DNSName DNSName::labelReverse() const
{
  DNSName ret;
  if (!d_empty) {
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
  if(label.empty())
    throw std::range_error("no such thing as an empty label to append");
  if(label.size() > 63)
    throw std::range_error("label too long to append");
  if(d_storage.size() + label.size() > 253) // reserve two bytes, one for length and one for the root label
    throw std::range_error("name too long to append");

  d_empty=false;
  d_storage.append(1, (char)label.size());
  d_storage.append(label.c_str(), label.length());
}

void DNSName::prependRawLabel(const std::string& label)
{
  if(label.empty())
    throw std::range_error("no such thing as an empty label to prepend");
  if(label.size() > 63)
    throw std::range_error("label too long to prepend");
  if(d_storage.size() + label.size() > 253) // reserve two bytes, one for length and one for the root label
    throw std::range_error("name too long to prepend");

  d_empty=false;
  string_t prep(1, (char)label.size());
  prep.append(label.c_str(), label.size());
  d_storage = prep+d_storage;
}

vector<string> DNSName::getRawLabels() const
{
  vector<string> ret;

  // 3www4ds9a2nl
  for(const char* p = d_storage.c_str(); p < d_storage.c_str() + d_storage.size(); p+=*p+1)
    ret.push_back({p+1, (unsigned int)*p}); // XXX FIXME
  return ret;
}

bool DNSName::canonCompare(const DNSName& rhs) const
{
  auto ours=getRawLabels(), rhsLabels = rhs.getRawLabels();
  return std::lexicographical_compare(ours.rbegin(), ours.rend(), rhsLabels.rbegin(), rhsLabels.rend(), CIStringCompare());
}

bool DNSName::chopOff()
{
  if(d_storage.empty())
    return false;
  d_storage = d_storage.substr((unsigned int)d_storage[0]+1);
  return true;
}

bool DNSName::isWildcard() const
{
  if(d_storage.empty())
    return false;
  auto p = d_storage.begin();
  return (*p == 0x01 && *++p == '*');
}

unsigned int DNSName::countLabels() const
{
  unsigned int count=0;
  for(const char* p = d_storage.c_str(); p < d_storage.c_str() + d_storage.size(); p+=*p+1)
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
  if(rhs.d_empty != d_empty || rhs.d_storage.size() != d_storage.size())
    return false;

  auto us = d_storage.crbegin();
  auto p = rhs.d_storage.crbegin();
  for(; us != d_storage.crend() && p != rhs.d_storage.crend(); ++us, ++p) {
    if(tolower(*p) != tolower(*us))
      return false;
  }
  return true;
}

size_t hash_value(DNSName const& d)
{
  boost::hash<string> hasher;
  return hasher(toLower(d.toString())); // FIXME400 HACK
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
