/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include "dnsname.hh"
#include <boost/format.hpp>
#include <string>
#include <cinttypes>

#include "dnswriter.hh"
#include "misc.hh"

#include <boost/functional/hash.hpp>

const DNSName g_rootdnsname("."), g_wildcarddnsname("*");

/* raw storage
   in DNS label format, with trailing 0. W/o trailing 0, we are 'empty'
   www.powerdns.com = 3www8powerdns3com0
*/

std::ostream & operator<<(std::ostream &os, const DNSName& d)
{
  return os <<d.toLogString();
}

DNSName::DNSName(const char* p)
{
  if(p[0]==0 || (p[0]=='.' && p[1]==0)) {
    d_storage.assign(1, (char)0);
  } else {
    if(!strchr(p, '\\')) {
      unsigned char lenpos=0;
      unsigned char labellen=0;
      size_t plen=strlen(p);
      const char* const pbegin=p, *pend=p+plen;
      d_storage.reserve(plen+1);
      for(auto iter = pbegin; iter != pend; ) {
        lenpos = d_storage.size();
        if(*iter=='.')
          throw std::runtime_error("Found . in wrong position in DNSName "+string(p));
        d_storage.append(1, (char)0);
        labellen=0;
        auto begiter=iter;
        for(; iter != pend && *iter!='.'; ++iter) {
          labellen++;
        }
        d_storage.append(begiter,iter);
        if(iter != pend)
          ++iter;
        if(labellen > 63)
          throw std::range_error("label too long to append");

        if(iter-pbegin > 254) // reserve two bytes, one for length and one for the root label
          throw std::range_error("name too long to append");

        d_storage[lenpos]=labellen;
      }
      d_storage.append(1, (char)0);
    }
    else {
      d_storage=segmentDNSNameRaw(p); 
      if(d_storage.size() > 255) {
        throw std::range_error("name too long");
      }
    }
  }
}


DNSName::DNSName(const char* pos, int len, int offset, bool uncompress, uint16_t* qtype, uint16_t* qclass, unsigned int* consumed, uint16_t minOffset)
{
  if (offset >= len)
    throw std::range_error("Trying to read past the end of the buffer ("+std::to_string(offset)+ " >= "+std::to_string(len)+")");

  if(!uncompress) {
    if(const void * fnd=memchr(pos+offset, 0, len-offset)) {
      d_storage.reserve(2+(const char*)fnd-(pos+offset));
    }
  }

  packetParser(pos, len, offset, uncompress, qtype, qclass, consumed, 0, minOffset);
}

// this should be the __only__ dns name parser in PowerDNS.
void DNSName::packetParser(const char* qpos, int len, int offset, bool uncompress, uint16_t* qtype, uint16_t* qclass, unsigned int* consumed, int depth, uint16_t minOffset)
{
  const unsigned char* pos=(const unsigned char*)qpos;
  unsigned char labellen;
  const unsigned char *opos = pos;

  if (offset >= len)
    throw std::range_error("Trying to read past the end of the buffer ("+std::to_string(offset)+ " >= "+std::to_string(len)+")");
  if (offset < (int) minOffset)
    throw std::range_error("Trying to read before the beginning of the buffer ("+std::to_string(offset)+ " < "+std::to_string(minOffset)+")");

  const unsigned char* end = pos + len;
  pos += offset;
  while((labellen=*pos++) && pos < end) { // "scan and copy"
    if(labellen >= 0xc0) {
      if(!uncompress)
        throw std::range_error("Found compressed label, instructed not to follow");

      labellen &= (~0xc0);
      int newpos = (labellen << 8) + *(const unsigned char*)pos;

      if(newpos < offset) {
        if(newpos < (int) minOffset)
          throw std::range_error("Invalid label position during decompression ("+std::to_string(newpos)+ " < "+std::to_string(minOffset)+")");
        if (++depth > 100)
          throw std::range_error("Abort label decompression after 100 redirects");
        packetParser((const char*)opos, len, newpos, true, 0, 0, 0, depth, minOffset);
      } else
        throw std::range_error("Found a forward reference during label decompression");
      pos++;
      break;
    } else if(labellen & 0xc0) {
      throw std::range_error("Found an invalid label length in qname (only one of the first two bits is set)");
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
  if(qtype) {
    if (pos + 2 > end) {
      throw std::range_error("Trying to read qtype past the end of the buffer ("+std::to_string((pos - opos) + 2)+ " > "+std::to_string(len)+")");
    }
    *qtype=(*(const unsigned char*)pos)*256 + *((const unsigned char*)pos+1);
  }
  pos+=2;
  if(qclass) {
    if (pos + 2 > end) {
      throw std::range_error("Trying to read qclass past the end of the buffer ("+std::to_string((pos - opos) + 2)+ " > "+std::to_string(len)+")");
    }
    *qclass=(*(const unsigned char*)pos)*256 + *((const unsigned char*)pos+1);
  }
}

std::string DNSName::toString(const std::string& separator, const bool trailing) const
{
  if (empty()) {
    throw std::out_of_range("Attempt to print an unset dnsname");
  }

  if(isRoot())
    return trailing ? separator : "";

  std::string ret;
  ret.reserve(d_storage.size());

  {
    // iterate over the raw labels
    const char* p = d_storage.c_str();
    const char* end = p + d_storage.size();

    while (p < end && *p) {
      appendEscapedLabel(ret, p + 1, static_cast<size_t>(*p));
      ret += separator;
      p += *p + 1;
    }
  }
  if (!trailing) {
    ret.resize(ret.size() - separator.size());
  }
  return ret;
}

std::string DNSName::toLogString() const
{
  if (empty()) {
    return "(empty)";
  }

  return toStringRootDot();
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
  for(auto us=d_storage.cbegin(); us<d_storage.cend(); us+=*us+1) {
    auto distance = std::distance(us,d_storage.cend());
    if (distance < 0 || static_cast<size_t>(distance) < parent.d_storage.size()) {
      break;
    }
    if (static_cast<size_t>(distance) == parent.d_storage.size()) {
      auto p = parent.d_storage.cbegin();
      for(; us != d_storage.cend(); ++us, ++p) {
        if(dns_tolower(*p) != dns_tolower(*us))
          return false;
      }
      return true;
    }
    if (*us < 0) {
      throw std::out_of_range("negative label length in dnsname");
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

DNSName DNSName::getCommonLabels(const DNSName& other) const
{
  DNSName result;

  const std::vector<std::string> ours = getRawLabels();
  const std::vector<std::string> others = other.getRawLabels();

  for (size_t pos = 0; ours.size() > pos && others.size() > pos; pos++) {
    const std::string& ourLabel = ours.at(ours.size() - pos - 1);
    const std::string& otherLabel = others.at(others.size() - pos - 1);

    if (!pdns_iequals(ourLabel, otherLabel)) {
      break;
    }

    result.prependRawLabel(ourLabel);
  }

  return result;
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
  if(d_storage.size() + length > 254) // reserve one byte for the label length
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
  if(d_storage.size() + label.size() > 254) // reserve one byte for the label length
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

vector<std::string> DNSName::getRawLabels() const
{
  vector<std::string> ret;
  ret.reserve(countLabels());
  // 3www4ds9a2nl0
  for(const unsigned char* p = (const unsigned char*) d_storage.c_str(); p < ((const unsigned char*) d_storage.c_str()) + d_storage.size() && *p; p+=*p+1) {
    ret.push_back({(const char*)p+1, (size_t)*p}); // XXX FIXME
  }
  return ret;
}

std::string DNSName::getRawLabel(unsigned int pos) const
{
  unsigned int currentPos = 0;
  for(const unsigned char* p = (const unsigned char*) d_storage.c_str(); p < ((const unsigned char*) d_storage.c_str()) + d_storage.size() && *p; p+=*p+1, currentPos++) {
    if (currentPos == pos) {
      return std::string((const char*)p+1, (size_t)*p);
    }
  }

  throw std::out_of_range("trying to get label at position "+std::to_string(pos)+" of a DNSName that only has "+std::to_string(currentPos)+" labels");
}

DNSName DNSName::getLastLabel() const
{
  DNSName ret(*this);
  ret.trimToLabels(1);
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

/*
 * Returns true if the DNSName is a valid RFC 1123 hostname, this function uses
 * a regex on the string, so it is probably best not used when speed is essential.
 */
bool DNSName::isHostname() const
{
  static Regex hostNameRegex = Regex("^(([A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)\\.)+$");
  return hostNameRegex.match(this->toString());
}

unsigned int DNSName::countLabels() const
{
  unsigned int count=0;
  const unsigned char* p = reinterpret_cast<const unsigned char*>(d_storage.c_str());
  const unsigned char* end = reinterpret_cast<const unsigned char*>(p + d_storage.size());

  while (p < end && *p) {
    ++count;
    p += *p + 1;
  }
  return count;
}

void DNSName::trimToLabels(unsigned int to)
{
  while(countLabels() > to && chopOff())
    ;
}


size_t hash_value(DNSName const& d)
{
  return d.hash();
}

void DNSName::appendEscapedLabel(std::string& appendTo, const char* orig, size_t len)
{
  size_t pos = 0;

  while (pos < len) {
    auto p = static_cast<uint8_t>(orig[pos]);
    if(p=='.')
      appendTo+="\\.";
    else if(p=='\\')
      appendTo+="\\\\";
    else if(p > 0x20 && p < 0x7f)
      appendTo.append(1, (char)p);
    else {
      char buf[] = "000";
      auto got = snprintf(buf, sizeof(buf), "%03" PRIu8, p);
      if (got < 0 || static_cast<size_t>(got) >= sizeof(buf)) {
        throw std::runtime_error("Error, snprintf returned " + std::to_string(got) + " while escaping label " + std::string(orig, len));
      }
      appendTo.append(1, '\\');
      appendTo += buf;
    }
    ++pos;
  }
}
