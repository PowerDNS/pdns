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

void DNSName::throwSafeRangeError(const std::string& msg, const char* buf, size_t length)
{
  std::string dots;
  if (length > s_maxDNSNameLength) {
    length = s_maxDNSNameLength;
    dots = "...";
  }
  std::string label;
  DNSName::appendEscapedLabel(label, buf, length);
  throw std::range_error(msg + label + dots);
}

DNSName::DNSName(const std::string_view sw)
{
  const char* p = sw.data();
  size_t length = sw.length();

  if(length == 0 || (length == 1 && p[0]=='.')) {
    d_storage.assign(1, '\0');
  } else {
    if(!std::memchr(p, '\\', length)) {
      unsigned char lenpos=0;
      unsigned char labellen=0;
      const char* const pbegin=p, *pend=p+length;

      d_storage.reserve(length+1);
      for(auto iter = pbegin; iter != pend; ) {
        lenpos = d_storage.size();
        if(*iter=='.')
          throwSafeRangeError("Found . in wrong position in DNSName: ", p, length);
        d_storage.append(1, '\0');
        labellen=0;
        auto begiter=iter;
        for(; iter != pend && *iter!='.'; ++iter) {
          labellen++;
        }
        d_storage.append(begiter,iter);
        if(iter != pend)
          ++iter;
        if(labellen > 63)
          throwSafeRangeError("label too long to append: ", p, length);

        if(iter-pbegin > static_cast<ptrdiff_t>(s_maxDNSNameLength - 1)) // reserve two bytes, one for length and one for the root label
          throwSafeRangeError("name too long to append: ", p, length);

        d_storage[lenpos]=labellen;
      }
      d_storage.append(1, '\0');
    }
    else {
      d_storage=segmentDNSNameRaw(p, length);
      if(d_storage.size() > s_maxDNSNameLength) {
        throwSafeRangeError("name too long: ", p, length);
      }
    }
  }
}

DNSName::DNSName(const char* pos, size_t len, size_t offset, bool uncompress, uint16_t* qtype, uint16_t* qclass, unsigned int* consumed, uint16_t minOffset)
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

static void checkLabelLength(uint8_t length)
{
  if (length == 0) {
    throw std::range_error("no such thing as an empty label to append");
  }
  if (length > 63) {
    throw std::range_error("label too long to append");
  }
}

// this parses a DNS name until a compression pointer is found
size_t DNSName::parsePacketUncompressed(const pdns::views::UnsignedCharView& view, size_t pos, bool uncompress)
{
  const size_t initialPos = pos;
  size_t totalLength = 0;
  unsigned char labellen = 0;

  do {
    labellen = view.at(pos);
    ++pos;

    if (labellen == 0) {
      --pos;
      break;
    }

    if (labellen >= 0xc0) {
      if (!uncompress) {
        throw std::range_error("Found compressed label, instructed not to follow");
      }
      --pos;
      break;
    }

    if ((labellen & 0xc0) != 0) {
      throw std::range_error("Found an invalid label length in qname (only one of the first two bits is set)");
    }
    checkLabelLength(labellen);
    // reserve one byte for the label length
    if (totalLength + labellen > s_maxDNSNameLength - 1) {
      throw std::range_error("name too long to append");
    }
    if (pos + labellen >= view.size()) {
      throw std::range_error("Found an invalid label length in qname");
    }
    pos += labellen;
    totalLength += 1 + labellen;
  }
  while (pos < view.size());

  if (totalLength != 0) {
    auto existingSize = d_storage.size();
    if (existingSize > 0) {
      // remove the last label count, we are about to override it */
      --existingSize;
    }
    d_storage.reserve(existingSize + totalLength + 1);
    d_storage.resize(existingSize + totalLength);
    memcpy(&d_storage.at(existingSize), &view.at(initialPos), totalLength);
    d_storage.append(1, static_cast<char>(0));
  }
  return pos;
}

// this should be the __only__ dns name parser in PowerDNS.
void DNSName::packetParser(const char* qpos, size_t len, size_t offset, bool uncompress, uint16_t* qtype, uint16_t* qclass, unsigned int* consumed, int depth, uint16_t minOffset)
{
  if (offset >= len) {
    throw std::range_error("Trying to read past the end of the buffer ("+std::to_string(offset)+ " >= "+std::to_string(len)+")");
  }

  if (offset < static_cast<size_t>(minOffset)) {
    throw std::range_error("Trying to read before the beginning of the buffer ("+std::to_string(offset)+ " < "+std::to_string(minOffset)+")");
  }
  unsigned char labellen{0};

  pdns::views::UnsignedCharView view(qpos, len);
  auto pos = parsePacketUncompressed(view, offset, uncompress);

  labellen = view.at(pos);
  pos++;
  if (labellen != 0 && pos < view.size()) {
    if (labellen < 0xc0) {
      abort();
    }

    if (!uncompress) {
      throw std::range_error("Found compressed label, instructed not to follow");
    }

    labellen &= (~0xc0);
    size_t newpos = (labellen << 8) + view.at(pos);

    if (newpos >= offset) {
      throw std::range_error("Found a forward reference during label decompression");
    }

    if (newpos < minOffset) {
      throw std::range_error("Invalid label position during decompression ("+std::to_string(newpos)+ " < "+std::to_string(minOffset)+")");
    }

    if (++depth > 100) {
      throw std::range_error("Abort label decompression after 100 redirects");
    }

    packetParser(qpos, len, newpos, true, nullptr, nullptr, nullptr, depth, minOffset);

    pos++;
  }

  if (d_storage.empty()) {
    d_storage.append(1, static_cast<char>(0)); // we just parsed the root
  }

  if (consumed != nullptr) {
    *consumed = pos - offset;
  }

  if (qtype != nullptr) {
    if (pos + 2 > view.size()) {
      throw std::range_error("Trying to read qtype past the end of the buffer ("+std::to_string(pos + 2)+ " > "+std::to_string(len)+")");
    }
    *qtype = view.at(pos)*256 + view.at(pos+1);
  }

  pos += 2;
  if (qclass != nullptr) {
    if (pos + 2 > view.size()) {
      throw std::range_error("Trying to read qclass past the end of the buffer ("+std::to_string(pos + 2)+ " > "+std::to_string(len)+")");
    }
    *qclass = view.at(pos)*256 + view.at(pos+1);
  }
}

std::string DNSName::toString(const std::string& separator, const bool trailing) const
{
  std::string ret;
  toString(ret, separator, trailing);
  return ret;
}

void DNSName::toString(std::string& output, const std::string& separator, const bool trailing) const
{
  if (empty()) {
    throw std::out_of_range("Attempt to print an unset DNSName");
  }

  if (isRoot()) {
    output += (trailing ? separator : "");
    return;
  }

  if (output.capacity() < (output.size() + d_storage.size())) {
    output.reserve(output.size() + d_storage.size());
  }

  {
    // iterate over the raw labels
    const char* p = d_storage.c_str();
    const char* end = p + d_storage.size();

    while (p < end && *p) {
      appendEscapedLabel(output, p + 1, static_cast<size_t>(*p));
      output += separator;
      p += *p + 1;
    }
  }

  if (!trailing) {
    output.resize(output.size() - separator.size());
  }
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
  if (empty()) {
    throw std::out_of_range("Attempt to DNSString an unset DNSName");
  }

  return std::string(d_storage.c_str(), d_storage.length());
}

std::string DNSName::toDNSStringLC() const
{
  auto result = toDNSString();
  toLowerInPlace(result); // label lengths are always < 'A'
  return result;
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
  if(parent.empty() || empty()) {
    throw std::out_of_range("empty DNSNames aren't part of anything");
  }

  if(parent.d_storage.size() > d_storage.size()) {
    return false;
  }

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
    if (static_cast<uint8_t>(*us) > 63) {
      throw std::out_of_range("illegal label length in DNSName");
    }
  }
  return false;
}

DNSName DNSName::makeRelative(const DNSName& zone) const
{
  DNSName ret(*this);
  ret.makeUsRelative(zone);
  return ret;
}

void DNSName::makeUsRelative(const DNSName& zone)
{
  if (isPartOf(zone)) {
    d_storage.erase(d_storage.size()-zone.d_storage.size());
    d_storage.append(1, static_cast<char>(0)); // put back the trailing 0
  }
  else {
    clear();
  }
}

DNSName DNSName::getCommonLabels(const DNSName& other) const
{
  if (empty() || other.empty()) {
    return DNSName();
  }

  DNSName result(g_rootdnsname);

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

  if (isRoot()) {
    return *this; // we don't create the root automatically below
  }

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
  checkLabelLength(length);

  // reserve one byte for the label length
  if (d_storage.size() + length > s_maxDNSNameLength - 1) {
    throw std::range_error("name too long to append");
  }

  if (d_storage.empty()) {
    d_storage.reserve(1 + length + 1);
    d_storage.append(1, static_cast<char>(length));
  }
  else {
    d_storage.reserve(d_storage.size() + length + 1);
    *d_storage.rbegin() = static_cast<char>(length);
  }
  d_storage.append(start, length);
  d_storage.append(1, static_cast<char>(0));
}

void DNSName::prependRawLabel(const std::string& label)
{
  checkLabelLength(label.size());

  // reserve one byte for the label length
  if (d_storage.size() + label.size() > s_maxDNSNameLength - 1) {
    throw std::range_error("name too long to prepend");
  }

  if (d_storage.empty()) {
    d_storage.reserve(1 + label.size() + 1);
    d_storage.append(1, static_cast<char>(0));
  }
  else {
    d_storage.reserve(d_storage.size() + 1 + label.size());
  }

  string_t prep(1, static_cast<char>(label.size()));
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
  if (d_storage.empty() || d_storage[0]==0) {
    return false;
  }
  d_storage.erase(0, (unsigned int)d_storage[0]+1);
  return true;
}

bool DNSName::isWildcard() const
{
  if (d_storage.size() < 2) {
    return false;
  }
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
  while(countLabels() > to && chopOff()) {
    ;
  }
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
    if (p=='.') {
      appendTo+="\\.";
    }
    else if (p=='\\') {
      appendTo+="\\\\";
    }
    else if (p > 0x20 && p < 0x7f) {
      appendTo.append(1, static_cast<char>(p));
    }
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

bool DNSName::has8bitBytes() const
{
  const auto& s = d_storage;
  string::size_type pos = 0;
  uint8_t length = s.at(pos);
  while (length > 0) {
    for (size_t idx = 0; idx < length; idx++) {
      ++pos;
      char c = s.at(pos);
      if (!((c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') ||
            c =='-' || c == '_' || c=='*' || c=='.' || c=='/' || c=='@' || c==' ' || c=='\\' || c==':')) {
        return true;
      }
    }
    ++pos;
    length = s.at(pos);
  }

  return false;
}

// clang-format off
const unsigned char dns_toupper_table[256] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
  0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
  0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
  0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
  0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
  0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
  0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
  0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
  0x60, 'A',  'B',  'C',  'D',  'E',  'F',  'G',
  'H',  'I',  'J',  'K',  'L',  'M',  'N',  'O',
  'P',  'Q',  'R',  'S',  'T',  'U',  'V',  'W',
  'X',  'Y',  'Z',  0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
  0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
  0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
  0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
  0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
  0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
  0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
  0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
  0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
  0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
  0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
  0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
  0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
  0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
  0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
  0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
  0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

const unsigned char dns_tolower_table[256] = {
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
  0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
  0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
  0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
  0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
  0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
  0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
  0x40, 'a',  'b',  'c',  'd',  'e',  'f',  'g',
  'h',  'i',  'j',  'k',  'l',  'm',  'n',  'o',
  'p',  'q',  'r',  's',  't',  'u',  'v',  'w',
  'x',  'y',  'z',  0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
  0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
  0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
  0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
  0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
  0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
  0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
  0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
  0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
  0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
  0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf,
  0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6, 0xb7,
  0xb8, 0xb9, 0xba, 0xbb, 0xbc, 0xbd, 0xbe, 0xbf,
  0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
  0xc8, 0xc9, 0xca, 0xcb, 0xcc, 0xcd, 0xce, 0xcf,
  0xd0, 0xd1, 0xd2, 0xd3, 0xd4, 0xd5, 0xd6, 0xd7,
  0xd8, 0xd9, 0xda, 0xdb, 0xdc, 0xdd, 0xde, 0xdf,
  0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7,
  0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef,
  0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
  0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
};

DNSName::RawLabelsVisitor::RawLabelsVisitor(const DNSName::string_t& storage): d_storage(storage)
{
  size_t position = 0;
  while (position < storage.size()) {
    auto labelLength = static_cast<uint8_t>(storage.at(position));
    if (labelLength == 0) {
      break;
    }
    d_labelPositions.at(d_position) = position;
    d_position++;
    position += labelLength + 1;
  }
}

DNSName::RawLabelsVisitor DNSName::getRawLabelsVisitor() const
{
  return DNSName::RawLabelsVisitor(getStorage());
}

std::string_view DNSName::RawLabelsVisitor::front() const
{
  if (d_position == 0) {
    throw std::out_of_range("trying to access the front of an empty DNSName::RawLabelsVisitor");
  }
  uint8_t length = d_storage.at(0);
  if (length == 0) {
    return std::string_view();
  }
  return std::string_view(&d_storage.at(1), length);
}

std::string_view DNSName::RawLabelsVisitor::back() const
{
  if (d_position == 0) {
    throw std::out_of_range("trying to access the back of an empty DNSName::RawLabelsVisitor");
  }
  size_t offset = d_labelPositions.at(d_position-1);
  uint8_t length = d_storage.at(offset);
  if (length == 0) {
    return std::string_view();
  }
  return std::string_view(&d_storage.at(offset + 1), length);
}

bool DNSName::RawLabelsVisitor::pop_back()
{
  if (d_position > 0) {
    d_position--;
    return true;
  }
  return false;
}

bool DNSName::RawLabelsVisitor::empty() const
{
  return d_position == 0;
}
