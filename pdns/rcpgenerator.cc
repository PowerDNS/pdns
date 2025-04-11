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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "rcpgenerator.hh"
#include "dnsparser.hh"
#include "misc.hh"
#include "utility.hh"
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/format.hpp>

#include <iostream>
#include "base32.hh"
#include "base64.hh"
#include "namespaces.hh"

RecordTextReader::RecordTextReader(string str, ZoneName zone) :
  d_string(std::move(str)), d_zone(std::move(zone))
{
   /* remove whitespace */
   if(!d_string.empty() && ( dns_isspace(*d_string.begin()) || dns_isspace(*d_string.rbegin()) ))
     boost::trim_if(d_string, dns_isspace);
   d_end = d_string.size();
}

void RecordTextReader::xfr48BitInt(uint64_t &val)
{
  xfr64BitInt(val);
  if (val > 281474976710655LL)
    throw RecordTextException("Overflow reading 48 bit integer from record content"); // fixme improve
}

void RecordTextReader::xfrNodeOrLocatorID(NodeOrLocatorID& val) {
  skipSpaces();
  size_t len;
  for(len=0;
      d_pos+len < d_string.length() && (isxdigit(d_string.at(d_pos+len)) || d_string.at(d_pos+len) == ':');
      len++) ;   // find length of ID

  // Parse as v6, and then strip the final 64 zero bytes
  struct in6_addr tmpbuf;
  string to_parse = d_string.substr(d_pos, len) + ":0:0:0:0";

  if (inet_pton(AF_INET6, to_parse.c_str(), &tmpbuf) != 1) {
    throw RecordTextException("while parsing colon-delimited 64-bit field: '" + d_string.substr(d_pos, len) + "' is invalid");
  }

  std::memcpy(&val.content, tmpbuf.s6_addr, sizeof(val.content));
  d_pos += len;
}

void RecordTextReader::xfr64BitInt(uint64_t &val)
{
  skipSpaces();

  if(!isdigit(d_string.at(d_pos)))
    throw RecordTextException("expected digits at position "+std::to_string(d_pos)+" in '"+d_string+"'");

  size_t pos;
  val=std::stoull(d_string.substr(d_pos), &pos);

  d_pos += pos;
}


void RecordTextReader::xfr32BitInt(uint32_t &val)
{
  skipSpaces();

  if(!isdigit(d_string.at(d_pos)))
    throw RecordTextException("expected digits at position "+std::to_string(d_pos)+" in '"+d_string+"'");

  size_t pos;
  val = pdns::checked_stoi<uint32_t>(d_string.c_str() + d_pos, &pos);

  d_pos += pos;
}

void RecordTextReader::xfrTime(uint32_t &val)
{
  struct tm tm;
  memset(&tm, 0, sizeof(tm));

  uint64_t itmp;
  xfr64BitInt(itmp);

  if (itmp <= (uint32_t)~0) {
    // formatted as seconds since epoch, not as YYYYMMDDHHmmSS:
    val = (uint32_t) itmp;
    return;
  }

  ostringstream tmp;

  tmp<<itmp;

  if (sscanf(tmp.str().c_str(), "%04d%02d%02d" "%02d%02d%02d",
             &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
             &tm.tm_hour, &tm.tm_min, &tm.tm_sec) != 6) {
    throw RecordTextException("unable to parse '"+std::to_string(itmp)+"' into a valid time at position "+std::to_string(d_pos)+" in '"+d_string+"'");
  }

  tm.tm_year-=1900;
  tm.tm_mon-=1;
  // coverity[store_truncates_time_t]
  val=(uint32_t)Utility::timegm(&tm);
}

void RecordTextReader::xfrIP(uint32_t &val)
{
  skipSpaces();

  if(!isdigit(d_string.at(d_pos)))
    throw RecordTextException("while parsing IP address, expected digits at position "+std::to_string(d_pos)+" in '"+d_string+"'");

  uint32_t octet=0;
  val=0;
  char count=0;
  bool last_was_digit = false;

  for(;;) {
    if(d_string.at(d_pos)=='.') {
      if (!last_was_digit)
        throw RecordTextException(string("unable to parse IP address, dot without previous digit"));
      last_was_digit = false;
      val<<=8;
      val+=octet;
      octet=0;
      count++;
      if(count > 3)
        throw RecordTextException(string("unable to parse IP address, too many dots"));
    }
    else if(isdigit(d_string.at(d_pos))) {
      last_was_digit = true;
      octet*=10;
      octet+=d_string.at(d_pos) - '0';
      if(octet > 255)
        throw RecordTextException("unable to parse IP address");
    }
    else if(dns_isspace(d_string.at(d_pos)) || d_string.at(d_pos) == ',')
      break;
    else {
      throw RecordTextException(string("unable to parse IP address, strange character: ")+d_string.at(d_pos));
    }
    d_pos++;
    if(d_pos == d_string.length())
      break;
  }
  if (count != 3)
    throw RecordTextException(string("unable to parse IP address, not enough dots"));
  if (!last_was_digit)
    throw RecordTextException(string("unable to parse IP address, trailing dot"));
  val<<=8;
  val+=octet;
  val=ntohl(val);
}


void RecordTextReader::xfrIP6(std::string &val)
{
  struct in6_addr tmpbuf;

  skipSpaces();

  size_t len;
  // lookup end of value - think of ::ffff encoding too, has dots in it!
  for(len=0;
      d_pos+len < d_string.length() && (isxdigit(d_string.at(d_pos+len)) || d_string.at(d_pos+len) == ':' || d_string.at(d_pos+len)=='.');
    len++);

  if(!len)
    throw RecordTextException("while parsing IPv6 address, expected xdigits at position "+std::to_string(d_pos)+" in '"+d_string+"'");

  // end of value is here, try parse as IPv6
  string address=d_string.substr(d_pos, len);

  if (inet_pton(AF_INET6, address.c_str(), &tmpbuf) != 1) {
    throw RecordTextException("while parsing IPv6 address: '" + address + "' is invalid");
  }

  val = std::string((char*)tmpbuf.s6_addr, 16);

  d_pos += len;
}

void RecordTextReader::xfrCAWithoutPort(uint8_t version, ComboAddress &val)
{
  if (version == 4) {
    uint32_t ip;
    xfrIP(ip);
    val = makeComboAddressFromRaw(4, string((const char*) &ip, 4));
  }
  else if (version == 6) {
    string ip;
    xfrIP6(ip);
    val = makeComboAddressFromRaw(6, ip);
  }
  else throw RecordTextException("invalid address family");
}

void RecordTextReader::xfrCAPort(ComboAddress &val)
{
  uint16_t port;
  xfr16BitInt(port);
  val.sin4.sin_port = port;
}

bool RecordTextReader::eof()
{
  return d_pos==d_end;
}

void RecordTextReader::xfr16BitInt(uint16_t &val)
{
  uint32_t tmp;
  xfr32BitInt(tmp);
  val=tmp;
  if(val!=tmp)
    throw RecordTextException("Overflow reading 16 bit integer from record content"); // fixme improve
}

void RecordTextReader::xfr8BitInt(uint8_t &val)
{
  uint32_t tmp;
  xfr32BitInt(tmp);
  val=tmp;
  if(val!=tmp)
    throw RecordTextException("Overflow reading 8 bit integer from record content"); // fixme improve
}

// this code should leave all the escapes around
void RecordTextReader::xfrName(DNSName& val, bool, bool)
{
  skipSpaces();
  DNSName sval;

  string::size_type begin_pos = d_pos;
  while (d_pos < d_end) {
    if (d_string[d_pos]!='\r' && dns_isspace(d_string[d_pos])) {
      break;
    }

    d_pos++;
  }

  {
    std::string_view view(d_string);
    sval = DNSName(view.substr(begin_pos, d_pos - begin_pos));
  }

  if (sval.empty()) {
    sval = d_zone;
  }
  else if (!d_zone.empty()) {
    sval += d_zone;
  }
  val = std::move(sval);
}

static bool isbase64(char c, bool acceptspace)
{
  if(dns_isspace(c))
    return acceptspace;
  if(c >= '0' && c <= '9')
    return true;
  if(c >= 'a' && c <= 'z')
    return true;
  if(c >= 'A' && c <= 'Z')
    return true;
  if(c=='+' || c=='/' || c=='=')
    return true;
  return false;
}

void RecordTextReader::xfrBlobNoSpaces(string& val, int len) {
  skipSpaces();
  int pos=(int)d_pos;
  const char* strptr=d_string.c_str();
  while(d_pos < d_end && isbase64(strptr[d_pos], false))
    d_pos++;

  string tmp;
  tmp.assign(d_string.c_str()+pos, d_string.c_str() + d_pos);
  boost::erase_all(tmp," ");
  val.clear();
  B64Decode(tmp, val);

  if (len>-1 && val.size() != static_cast<size_t>(len))
    throw RecordTextException("Record length "+std::to_string(val.size()) + " does not match expected length '"+std::to_string(len));
}

void RecordTextReader::xfrBlob(string& val, int)
{
  skipSpaces();
  int pos=(int)d_pos;
  const char* strptr=d_string.c_str();
  while(d_pos < d_end && isbase64(strptr[d_pos], true))
    d_pos++;

  string tmp;
  tmp.assign(d_string.c_str()+pos, d_string.c_str() + d_pos);
  boost::erase_all(tmp," ");
  val.clear();
  B64Decode(tmp, val);
}

void RecordTextReader::xfrRFC1035CharString(string &val) {
  auto ctr = parseRFC1035CharString(d_string.substr(d_pos, d_end - d_pos), val);
  d_pos += ctr;
}

void RecordTextReader::xfrSVCBValueList(vector<string> &val) {
  auto ctr = parseSVCBValueList(d_string.substr(d_pos, d_end - d_pos), val);
  d_pos += ctr;
}

void RecordTextReader::xfrSvcParamKeyVals(set<SvcParam>& val) // NOLINT(readability-function-cognitive-complexity)
{
  while (d_pos != d_end) {
    skipSpaces();
    if (d_pos == d_end)
      return;

    // Find the SvcParamKey
    size_t pos = d_pos;
    while (d_pos != d_end) {
      if (d_string.at(d_pos) == '=' || d_string.at(d_pos) == ' ') {
        break;
      }
      d_pos++;
    }

    // We've reached a space or equals-sign or the end of the string (d_pos is at this char)
    string k = d_string.substr(pos, d_pos - pos);
    SvcParam::SvcParamKey key;
    bool generic;
    try {
      key = SvcParam::keyFromString(k, generic);
    } catch (const std::invalid_argument &e) {
      throw RecordTextException(e.what());
    }

    if (key != SvcParam::no_default_alpn) {
      if (d_pos == d_end || d_string.at(d_pos) != '=') {
        throw RecordTextException("expected '=' after " + k);
      }
      d_pos++; // Now on the first character after '='
      if (d_pos == d_end || d_string.at(d_pos) == ' ') {
        throw RecordTextException("expected value after " + k + "=");
      }
    }

    switch (key) {
    case SvcParam::no_default_alpn:
      if (d_pos != d_end && d_string.at(d_pos) == '=') {
        throw RecordTextException(k + " key can not have values");
      }
      val.insert(SvcParam(key));
      break;
    case SvcParam::ipv4hint: /* fall-through */
    case SvcParam::ipv6hint: {
      vector<ComboAddress> hints;
      bool doAuto{false};
      if (generic) {
        string value;
        xfrRFC1035CharString(value);
        size_t len = key == SvcParam::ipv4hint ? 4 : 16;
        if (value.size() % len != 0) {
          throw RecordTextException(k + " in generic format has wrong number of bytes");
        }
        for (size_t i=0; i<value.size(); i += len) {
          auto hint = makeComboAddressFromRaw(static_cast<uint8_t>(key), &value.at(i), len);
          hints.push_back(hint);
        }
      } else {
        vector<string> value;
        xfrSVCBValueList(value);
        for (auto const &v: value) {
          if (v == "auto") {
            doAuto = true;
            hints.clear();
            break;
          }
          hints.push_back(ComboAddress(v));
        }
      }
      try {
        auto p = SvcParam(key, std::move(hints));
        p.setAutoHint(doAuto);
        val.insert(std::move(p));
      }
      catch (const std::invalid_argument& e) {
        throw RecordTextException(e.what());
      }
      break;
    }
    case SvcParam::alpn: {
      vector<string> value;
      if (generic) {
        string v;
        xfrRFC1035CharString(v);
        size_t spos{0}, len;
        while (spos < v.length()) {
          len = v.at(spos);
          spos += 1;
          if (len > v.length() - spos) {
            throw RecordTextException("Length of ALPN value goes over total length of alpn SVC Param");
          }
          value.push_back(v.substr(spos, len));
          spos += len;
        }
      } else {
        xfrSVCBValueList(value);
      }
      val.insert(SvcParam(key, std::move(value)));
      break;
    }
    case SvcParam::mandatory: {
      if (generic) {
        string v;
        xfrRFC1035CharString(v);
        if (v.length() % 2 != 0) {
          throw RecordTextException("Wrong number of bytes in SVC Param " + k);
        }
        std::set<SvcParam::SvcParamKey> keys;
        for (size_t i=0; i < v.length(); i += 2) {
          uint16_t mand = (v.at(i) << 8);
          mand += v.at(i+1);
          keys.insert(SvcParam::SvcParamKey(mand));
        }
        val.insert(SvcParam(key, std::move(keys)));
        break;
      }
      vector<string> parts;
      xfrSVCBValueList(parts);
      set<string> values(parts.begin(), parts.end());
      val.insert(SvcParam(key, std::move(values)));
      break;
    }
    case SvcParam::port: {
      uint16_t port;
      if (generic) {
        string v;
        xfrRFC1035CharString(v);
        if (v.length() != 2) {
          throw RecordTextException("port in generic format has the wrong length, expected 2, got " + std::to_string(v.length()));
        }
        port = (v.at(0) << 8);
        port += v.at(1);
      } else {
        string portstring;
        xfrRFC1035CharString(portstring);
        try {
          pdns::checked_stoi_into(port, portstring);
        } catch (const std::exception &e) {
          throw RecordTextException(e.what());
        }
      }
      val.insert(SvcParam(key, port));
      break;
    }
    case SvcParam::ech: {
      string value;
      if (generic) {
        xfrRFC1035CharString(value);
      } else {
        bool haveQuote = d_string.at(d_pos) == '"';
        if (haveQuote) {
          d_pos++;
        }
        xfrBlobNoSpaces(value);
        if (haveQuote) {
          if (d_string.at(d_pos) != '"') {
            throw RecordTextException("ech value starts, but does not end with a '\"' symbol");
          }
          d_pos++;
        }
      }
      val.insert(SvcParam(key, value));
      break;
    }
    default: {
      string value;
      xfrRFC1035CharString(value);
      val.insert(SvcParam(key, value));
      break;
    }
    }
  }
}

static inline uint8_t hextodec(uint8_t val)
{
  if(val >= '0' && val<='9')
    return val-'0';
  else if(val >= 'A' && val<='F')
    return 10+(val-'A');
  else if(val >= 'a' && val<='f')
    return 10+(val-'a');
  else
    throw RecordTextException("Unknown hexadecimal character '"+std::to_string(val)+"'");
}


static void HEXDecode(const char* begin, const char* end, string& out)
{
  if(end - begin == 1 && *begin=='-') {
    out.clear();
    return;
  }
  out.clear();
  out.reserve((end-begin)/2);
  uint8_t mode=0, val=0;
  for(; begin != end; ++begin) {
    if(!isalnum(*begin))
      continue;
    if(mode==0) {
      val = 16*hextodec(*begin);
      mode=1;
    } else {
      val += hextodec(*begin);
      out.append(1, (char) val);
      mode = 0;
      val = 0;
    }
  }
  if(mode)
    throw RecordTextException("Hexadecimal blob with odd number of characters");
}

void RecordTextReader::xfrHexBlob(string& val, bool keepReading)
{
  skipSpaces();
  int pos=(int)d_pos;
  while(d_pos < d_end && (keepReading || !dns_isspace(d_string[d_pos])))
    d_pos++;

  HEXDecode(d_string.c_str()+pos, d_string.c_str() + d_pos, val);
}

void RecordTextReader::xfrBase32HexBlob(string& val)
{
  skipSpaces();
  int pos=(int)d_pos;
  while(d_pos < d_end && !dns_isspace(d_string[d_pos]))
    d_pos++;

  val=fromBase32Hex(string(d_string.c_str()+pos, d_pos-pos));
}


void RecordTextWriter::xfrBase32HexBlob(const string& val)
{
  if(!d_string.empty())
    d_string.append(1,' ');

  d_string.append(toUpper(toBase32Hex(val)));
}


void RecordTextReader::xfrText(string& val, bool multi, bool /* lenField */)
{
  val.clear();
  val.reserve(d_end - d_pos);

  while(d_pos != d_end) {
    if(!val.empty())
      val.append(1, ' ');

    skipSpaces();
    if(d_string[d_pos]!='"') { // special case 'plenus' - without quotes
      string::size_type pos = d_pos;
      while(pos != d_end && isalnum(d_string[pos]))
        pos++;
      if(pos == d_end) {
        val.append(1, '"');
        val.append(d_string.c_str() + d_pos, d_end - d_pos);
        val.append(1, '"');
        d_pos = d_end;
        break;
      }
      throw RecordTextException("Data field in DNS should start with quote (\") at position "+std::to_string(d_pos)+" of '"+d_string+"'");
    }
    val.append(1, '"');
    while(++d_pos < d_end && d_string[d_pos]!='"') {
      if(d_string[d_pos]=='\\' && d_pos+1!=d_end) {
        val.append(1, d_string[d_pos++]);
      }
      val.append(1, d_string[d_pos]);
    }
    val.append(1,'"');
    if(d_pos == d_end)
      throw RecordTextException("Data field in DNS should end on a quote (\") in '"+d_string+"'");
    d_pos++;
    if(!multi)
      break;
  }
}

void RecordTextReader::xfrUnquotedText(string& val, bool /* lenField */)
{
  val.clear();
  val.reserve(d_end - d_pos);

  if(!val.empty())
    val.append(1, ' ');

  skipSpaces();
  val.append(1, d_string[d_pos]);
  while(++d_pos < d_end && d_string[d_pos] != ' '){
    val.append(1, d_string[d_pos]);
  }
}

void RecordTextReader::xfrType(uint16_t& val)
{
  skipSpaces();
  int pos=(int)d_pos;
  while(d_pos < d_end && !dns_isspace(d_string[d_pos]))
    d_pos++;

  string tmp;
  tmp.assign(d_string.c_str()+pos, d_string.c_str() + d_pos);

  val=DNSRecordContent::TypeToNumber(tmp);
}


void RecordTextReader::skipSpaces()
{
  const char* strptr = d_string.c_str();
  while(d_pos < d_end && dns_isspace(strptr[d_pos]))
    d_pos++;
  if(d_pos == d_end)
    throw RecordTextException("missing field at the end of record content '"+d_string+"'");
}


RecordTextWriter::RecordTextWriter(string& str, bool noDot) : d_string(str)
{
  d_string.clear();
  d_nodot=noDot;
}

void RecordTextWriter::xfrNodeOrLocatorID(const NodeOrLocatorID& val)
{
  if(!d_string.empty()) {
    d_string.append(1,' ');
  }

  size_t ctr = 0;
  char tmp[5];
  for (auto const &c : val.content) {
    snprintf(tmp, sizeof(tmp), "%02X", c);
    d_string+=tmp;
    ctr++;
    if (ctr % 2 == 0 && ctr != 8) {
      d_string+=':';
    }
  }
}

void RecordTextWriter::xfr48BitInt(const uint64_t& val)
{
  if(!d_string.empty())
    d_string.append(1,' ');
  d_string+=std::to_string(val);
}


void RecordTextWriter::xfr32BitInt(const uint32_t& val)
{
  if(!d_string.empty())
    d_string.append(1,' ');
  d_string+=std::to_string(val);
}

void RecordTextWriter::xfrType(const uint16_t& val)
{
  if(!d_string.empty())
    d_string.append(1,' ');
  d_string+=DNSRecordContent::NumberToType(val);
}

// this function is on the fast path for the pdns_recursor
void RecordTextWriter::xfrIP(const uint32_t& val)
{
  if(!d_string.empty())
    d_string.append(1,' ');

  char tmp[17];
  uint32_t ip=val;
  uint8_t vals[4];

  memcpy(&vals[0], &ip, sizeof(ip));

  char *pos=tmp;

  for(int n=0; n < 4; ++n) {
    if(vals[n]<10) {
      *(pos++)=vals[n]+'0';
    } else if(vals[n] < 100) {
      *(pos++)=(vals[n]/10) +'0';
      *(pos++)=(vals[n]%10) +'0';
    } else {
      *(pos++)=(vals[n]/100) +'0';
      vals[n]%=100;
      *(pos++)=(vals[n]/10) +'0';
      *(pos++)=(vals[n]%10) +'0';
    }
    if(n!=3)
      *(pos++)='.';
  }
  *pos=0;
  d_string.append(tmp, pos);
}

void RecordTextWriter::xfrIP6(const std::string& val)
{
  char tmpbuf[16];
  char addrbuf[40];

  if(!d_string.empty())
   d_string.append(1,' ');

  val.copy(tmpbuf,16);

  if (inet_ntop(AF_INET6, tmpbuf, addrbuf, sizeof addrbuf) == nullptr)
    throw RecordTextException("Unable to convert to ipv6 address");

  d_string += std::string(addrbuf);
}

void RecordTextWriter::xfrCAWithoutPort(uint8_t /* version */, ComboAddress &val)
{
  string ip = val.toString();

  if(!d_string.empty())
    d_string.append(1,' ');

  d_string += ip;
}

void RecordTextWriter::xfrCAPort(ComboAddress &val)
{
  xfr16BitInt(val.sin4.sin_port);
}

void RecordTextWriter::xfrTime(const uint32_t& val)
{
  if(!d_string.empty())
    d_string.append(1,' ');

  struct tm tm;
  time_t time=val; // Y2038 bug!
  gmtime_r(&time, &tm);

  static const boost::format fmt("%04d%02d%02d" "%02d%02d%02d");
  d_string += boost::str(boost::format(fmt) % (tm.tm_year+1900) % (tm.tm_mon+1) % tm.tm_mday % tm.tm_hour % tm.tm_min % tm.tm_sec);
}


void RecordTextWriter::xfr16BitInt(const uint16_t& val)
{
  xfr32BitInt(val);
}

void RecordTextWriter::xfr8BitInt(const uint8_t& val)
{
  xfr32BitInt(val);
}

// should not mess with the escapes
void RecordTextWriter::xfrName(const DNSName& val, bool /* unused */, bool /* noDot */)
{
  if(!d_string.empty())
    d_string.append(1,' ');

  if(d_nodot) {
    d_string+=val.toStringRootDot();
  }
  else
  {
    d_string+=val.toString();
  }
}

void RecordTextWriter::xfrBlobNoSpaces(const string& val, int size)
{
  xfrBlob(val, size);
}

void RecordTextWriter::xfrBlob(const string& val, int)
{
  if(!d_string.empty())
    d_string.append(1,' ');

  d_string+=Base64Encode(val);
}

void RecordTextWriter::xfrHexBlob(const string& val, bool)
{
  if(!d_string.empty())
    d_string.append(1,' ');

  if(val.empty()) {
    d_string.append(1,'-');
    return;
  }

  string::size_type limit=val.size();
  char tmp[5];
  for(string::size_type n = 0; n < limit; ++n) {
    snprintf(tmp, sizeof(tmp), "%02x", (unsigned char)val[n]);
    d_string+=tmp;
  }
}

// FIXME copied from dnsparser.cc, see #6010 and #3503 if you want a proper solution
static string txtEscape(const string &name)
{
  string ret;
  char ebuf[5];

  for(char i : name) {
    if((unsigned char) i >= 127 || (unsigned char) i < 32) {
      snprintf(ebuf, sizeof(ebuf), "\\%03u", (unsigned char)i);
      ret += ebuf;
    }
    else if(i=='"' || i=='\\'){
      ret += '\\';
      ret += i;
    }
    else
      ret += i;
  }
  return ret;
}

void RecordTextWriter::xfrSVCBValueList(const vector<string> &val) {
  bool shouldQuote{false};
  vector<string> escaped;
  escaped.reserve(val.size());
  for (auto const &v : val) {
    if (v.find_first_of(' ') != string::npos) {
      shouldQuote = true;
    }
    string tmp = txtEscape(v);
    string unescaped;
    unescaped.reserve(tmp.size() + 4);
    for (auto const &ch : tmp) {
      if (ch == '\\') {
        unescaped += R"F(\\)F";
        continue;
      }
      if (ch == ',') {
        unescaped += R"F(\\,)F";
        continue;
      }
      unescaped += ch;
    }
    escaped.push_back(std::move(unescaped));
  }
  if (shouldQuote) {
    d_string.append(1, '"');
  }
  d_string.append(boost::join(escaped, ","));
  if (shouldQuote) {
    d_string.append(1, '"');
  }
}

void RecordTextWriter::xfrSvcParamKeyVals(const set<SvcParam>& val) {
  for (auto const &param : val) {
    if (!d_string.empty())
      d_string.append(1, ' ');

    d_string.append(SvcParam::keyToString(param.getKey()));
    if (param.getKey() != SvcParam::no_default_alpn) {
      d_string.append(1, '=');
    }

    switch (param.getKey())
    {
    case SvcParam::no_default_alpn:
      break;
    case SvcParam::ipv4hint: /* fall-through */
    case SvcParam::ipv6hint:
      // TODO use xfrCA and put commas in between?
      if (param.getAutoHint()) {
        d_string.append("auto");
        break;
      }
      d_string.append(ComboAddress::caContainerToString(param.getIPHints(), false));
      break;
    case SvcParam::alpn:
      xfrSVCBValueList(param.getALPN());
      break;
    case SvcParam::mandatory:
    {
      bool doComma = false;
      for (auto const &k: param.getMandatory()) {
        if (doComma)
          d_string.append(1, ',');
        d_string.append(SvcParam::keyToString(k));
        doComma = true;
      }
      break;
    }
    case SvcParam::port: {
      auto str = d_string;
      d_string.clear();
      xfr16BitInt(param.getPort());
      d_string = str + d_string;
      break;
    }
    case SvcParam::ech: {
      auto str = d_string;
      d_string.clear();
      xfrBlobNoSpaces(param.getECH());
      d_string = str + '"' + d_string + '"';
      break;
    }
    default:
      auto str = d_string;
      d_string.clear();
      xfrText(param.getValue(), false, false);
      d_string = str + '"' + txtEscape(d_string) + '"';
      break;
    }
  }
}

void RecordTextWriter::xfrText(const string& val, bool /* multi */, bool /* lenField */)
{
  if(!d_string.empty())
    d_string.append(1,' ');

  d_string.append(val);
}

void RecordTextWriter::xfrUnquotedText(const string& val, bool /* lenField */)
{
  if(!d_string.empty())
    d_string.append(1,' ');
  d_string.append(val);
}

#ifdef TESTING

int main(int argc, char**argv)
try
{
  RecordTextReader rtr(argv[1], argv[2]);

  unsigned int order, pref;
  string flags, services, regexp, replacement;
  string mx;

  rtr.xfrInt(order);
  rtr.xfrInt(pref);
  rtr.xfrText(flags);
  rtr.xfrText(services);
  rtr.xfrText(regexp);
  rtr.xfrName(replacement);

  cout<<"order: "<<order<<", pref: "<<pref<<"\n";
  cout<<"flags: \""<<flags<<"\", services: \""<<services<<"\", regexp: \""<<regexp<<"\", replacement: "<<replacement<<"\n";

  string out;
  RecordTextWriter rtw(out);

  rtw.xfrInt(order);
  rtw.xfrInt(pref);
  rtw.xfrText(flags);
  rtw.xfrText(services);
  rtw.xfrText(regexp);
  rtw.xfrName(replacement);

  cout<<"Regenerated: '"<<out<<"'\n";

}
catch(std::exception& e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}

#endif
