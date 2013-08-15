/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2005 - 2011 PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#include "rcpgenerator.hh"
#include "dnsparser.hh"
#include "misc.hh"
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>
#include <iostream>
#include "base32.hh"
#include "base64.hh"
#include "namespaces.hh"

RecordTextReader::RecordTextReader(const string& str, const string& zone) : d_string(str), d_zone(zone), d_pos(0), d_end(str.size())
{
}

void RecordTextReader::xfr48BitInt(uint64_t &val)
{
  xfr64BitInt(val);
}

void RecordTextReader::xfr64BitInt(uint64_t &val)
{
  skipSpaces();

  if(!isdigit(d_string.at(d_pos)))
    throw RecordTextException("expected digits at position "+lexical_cast<string>(d_pos)+" in '"+d_string+"'");

  char *endptr;
  unsigned long ret=strtoull(d_string.c_str() + d_pos, &endptr, 10);
  val=ret;
  
  d_pos = endptr - d_string.c_str();
}


void RecordTextReader::xfr32BitInt(uint32_t &val)
{
  skipSpaces();

  if(!isdigit(d_string.at(d_pos)))
    throw RecordTextException("expected digits at position "+lexical_cast<string>(d_pos)+" in '"+d_string+"'");

  char *endptr;
  unsigned long ret=strtoul(d_string.c_str() + d_pos, &endptr, 10);
  val=ret;
  
  d_pos = endptr - d_string.c_str();
}

void RecordTextReader::xfrTime(uint32_t &val)
{
  struct tm tm;
  memset(&tm, 0, sizeof(tm));
  
  string tmp;
  xfrLabel(tmp); // ends on number, so this works 

  sscanf(tmp.c_str(), "%04d%02d%02d" "%02d%02d%02d", 
         &tm.tm_year, &tm.tm_mon, &tm.tm_mday, 
         &tm.tm_hour, &tm.tm_min, &tm.tm_sec);

  tm.tm_year-=1900;
  tm.tm_mon-=1;
  val=(uint32_t)Utility::timegm(&tm); 
}

void RecordTextReader::xfrIP(uint32_t &val)
{
  skipSpaces();

  if(!isdigit(d_string.at(d_pos)))
    throw RecordTextException("while parsing IP address, expected digits at position "+lexical_cast<string>(d_pos)+" in '"+d_string+"'");

  uint32_t octet=0;
  val=0;
  char count=0;
  
  for(;;) {
    if(d_string.at(d_pos)=='.') {
      val<<=8;
      val+=octet;
      octet=0;
      count++;
      if(count > 3)
        break;
    }
    else if(isdigit(d_string.at(d_pos))) {
      octet*=10;
      octet+=d_string.at(d_pos) - '0';
      if(octet > 255)
        throw RecordTextException("unable to parse IP address");
    }
    else if(dns_isspace(d_string.at(d_pos))) 
      break;
    else {
      throw RecordTextException(string("unable to parse IP address, strange character: ")+d_string.at(d_pos));
    }
    d_pos++;
    if(d_pos == d_string.length())
      break;
  }
  if(count<=3) {
    val<<=8;
    val+=octet;
  }
  val=ntohl(val);
}


void RecordTextReader::xfrIP6(std::string &val)
{
  struct in6_addr tmpbuf;

  skipSpaces();
  
  size_t len;
  // lookup end of value
  for(len=0; 
    d_pos+len < d_string.length() && (isxdigit(d_string.at(d_pos+len)) || d_string.at(d_pos+len) == ':');
    len++);

  if(!len)
    throw RecordTextException("while parsing IPv6 address, expected xdigits at position "+lexical_cast<string>(d_pos)+" in '"+d_string+"'");

  // end of value is here, try parse as IPv6
  string address=d_string.substr(d_pos, len);
  
  if (inet_pton(AF_INET6, address.c_str(), &tmpbuf) != 1) {
    throw RecordTextException("while parsing IPv6 address: '" + address + "' is invalid");
  }

  val = std::string((char*)tmpbuf.s6_addr, 16);

  d_pos += len;
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
void RecordTextReader::xfrLabel(string& val, bool) 
{
  skipSpaces();
  val.clear();
  val.reserve(d_end - d_pos);

  const char* strptr=d_string.c_str();
  string::size_type begin_pos = d_pos;
  while(d_pos < d_end) {
    if(strptr[d_pos]!='\r' && dns_isspace(strptr[d_pos]))
      break;
      
    d_pos++;
  }
  val.append(strptr+begin_pos, strptr+d_pos);      

  if(val.empty())
    val=d_zone;
  else if(!d_zone.empty()) {
    char last=val[val.size()-1];
   
    if(last =='.')
      val.resize(val.size()-1);
    else if(last != '.' && !isdigit(last)) // don't add zone to IP address
      val+="."+d_zone;
  }
}

static bool isbase64(char c)
{
  if(dns_isspace(c))
    return true;
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

void RecordTextReader::xfrBlob(string& val, int)
{
  skipSpaces();
  int pos=(int)d_pos;
  const char* strptr=d_string.c_str();
  while(d_pos < d_end && isbase64(strptr[d_pos]))
    d_pos++;
  
  string tmp;
  tmp.assign(d_string.c_str()+pos, d_string.c_str() + d_pos);
  boost::erase_all(tmp," ");
  val.clear();
  B64Decode(tmp, val);
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
    throw RecordTextException("Unknown hexadecimal character '"+lexical_cast<string>(val)+"'");
}


void HEXDecode(const char* begin, const char* end, string& out)
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
    out.append(1, (char) val);

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


void RecordTextReader::xfrText(string& val, bool multi)
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
      throw RecordTextException("Data field in DNS should start with quote (\") at position "+lexical_cast<string>(d_pos)+" of '"+d_string+"'");
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


RecordTextWriter::RecordTextWriter(string& str) : d_string(str)
{
  d_string.clear();
}

void RecordTextWriter::xfr48BitInt(const uint64_t& val)
{
  if(!d_string.empty())
    d_string.append(1,' ');
  d_string+=lexical_cast<string>(val);
}


void RecordTextWriter::xfr32BitInt(const uint32_t& val)
{
  if(!d_string.empty())
    d_string.append(1,' ');
  d_string+=lexical_cast<string>(val);
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

  if (inet_ntop(AF_INET6, tmpbuf, addrbuf, sizeof addrbuf) == NULL)
    throw RecordTextException("Unable to convert to ipv6 address");
  
  d_string += std::string(addrbuf);
}

void RecordTextWriter::xfrTime(const uint32_t& val)
{
  if(!d_string.empty())
    d_string.append(1,' ');
  
  struct tm tm;
  time_t time=val; // Y2038 bug!
#ifndef WIN32
  gmtime_r(&time, &tm);
#else
  struct tm* tmptr;
  tmptr=gmtime(&time);
  if(!tmptr)
    throw RecordTextException("Unable to convert timestamp into pretty printable time");
  tm=*tmptr;
#endif
  
  char tmp[16];
  snprintf(tmp,sizeof(tmp)-1, "%04d%02d%02d" "%02d%02d%02d", 
           tm.tm_year+1900, tm.tm_mon+1, tm.tm_mday, 
           tm.tm_hour, tm.tm_min, tm.tm_sec);
  
  d_string += tmp;
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
void RecordTextWriter::xfrLabel(const string& val, bool)
{
  if(!d_string.empty())
    d_string.append(1,' ');
  
  d_string+=val;
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
    snprintf(tmp, sizeof(tmp)-1, "%02x", (unsigned char)val[n]);
    d_string+=tmp;
  }
}

void RecordTextWriter::xfrText(const string& val, bool multi)
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
  rtr.xfrLabel(replacement);

  cout<<"order: "<<order<<", pref: "<<pref<<"\n";
  cout<<"flags: \""<<flags<<"\", services: \""<<services<<"\", regexp: \""<<regexp<<"\", replacement: "<<replacement<<"\n";

  string out;
  RecordTextWriter rtw(out);

  rtw.xfrInt(order);
  rtw.xfrInt(pref);
  rtw.xfrText(flags);
  rtw.xfrText(services);
  rtw.xfrText(regexp);
  rtw.xfrLabel(replacement);

  cout<<"Regenerated: '"<<out<<"'\n";
  
}
catch(std::exception& e)
{
  cerr<<"Fatal: "<<e.what()<<endl;
}

#endif
