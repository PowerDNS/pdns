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

#include <boost/format.hpp>

#include "utility.hh"
#include "dnsrecords.hh"
#include "iputils.hh"

void DNSResourceRecord::setContent(const string &cont) {
  content = cont;
  switch(qtype.getCode()) {
    case QType::SRV:
    case QType::MX:
      if (content.size() >= 2 && *(content.rbegin()+1) == ' ')
        return;
      [[fallthrough]];
#if !defined(RECURSOR)
    case QType::ALIAS:
#endif
    case QType::CNAME:
    case QType::DNAME:
    case QType::NS:
    case QType::PTR:
      if (content.size() >= 2 && *(content.rbegin()) == '.')
        boost::erase_tail(content, 1);
  }
}

string DNSResourceRecord::getZoneRepresentation(bool noDot) const {
  ostringstream ret;
  vector<string> parts;
  string last;

  switch(qtype.getCode()) {
    case QType::SRV:
    case QType::MX:
      stringtok(parts, content);
      if (parts.empty())
        return "";
      last = *parts.rbegin();
      ret << content;
      if (last == ".")
        break;
      if (*(last.rbegin()) != '.' && !noDot)
        ret << ".";
      break;
#if !defined(RECURSOR)
    case QType::ALIAS:
#endif
    case QType::CNAME:
    case QType::DNAME:
    case QType::NS:
    case QType::PTR:
      ret<<content;
      if (*(content.rbegin()) != '.' && !noDot)
        ret<<".";
      break;
    default:
      ret<<content;
    break;
  }
  return ret.str();
}

bool DNSResourceRecord::operator==(const DNSResourceRecord& rhs) const
{
  string lcontent=toLower(content);
  string rcontent=toLower(rhs.content);

  return
    std::tie(qname, qtype, lcontent, ttl) ==
    std::tie(rhs.qname, rhs.qtype, rcontent, rhs.ttl);
}

boilerplate_conv(A, conv.xfrIP(d_ip));

ARecordContent::ARecordContent(uint32_t ip)
{
  d_ip = ip;
}

ARecordContent::ARecordContent(const ComboAddress& ca)
{
  d_ip = ca.sin4.sin_addr.s_addr;
}

AAAARecordContent::AAAARecordContent(const ComboAddress& ca)
{
  d_ip6.assign((const char*)ca.sin6.sin6_addr.s6_addr, 16);
}



ComboAddress ARecordContent::getCA(int port) const
{
  ComboAddress ret;
  ret.sin4.sin_family=AF_INET;
  ret.sin4.sin_port=htons(port);
  memcpy(&ret.sin4.sin_addr.s_addr, &d_ip, sizeof(ret.sin4.sin_addr.s_addr));
  return ret;
}

ComboAddress AAAARecordContent::getCA(int port) const
{
  ComboAddress ret;
  ret.reset();

  ret.sin4.sin_family=AF_INET6;
  ret.sin6.sin6_port = htons(port);
  memcpy(&ret.sin6.sin6_addr.s6_addr, d_ip6.c_str(), sizeof(ret.sin6.sin6_addr.s6_addr));
  return ret;
}


void ARecordContent::doRecordCheck(const DNSRecord& dr)
{
  if(dr.d_clen!=4)
    throw MOADNSException("Wrong size for A record ("+std::to_string(dr.d_clen)+")");
}

boilerplate_conv(AAAA, conv.xfrIP6(d_ip6); );

boilerplate_conv(NS, conv.xfrName(d_content, true));
boilerplate_conv(PTR, conv.xfrName(d_content, true));
boilerplate_conv(CNAME, conv.xfrName(d_content, true));
#if !defined(RECURSOR)
boilerplate_conv(ALIAS, conv.xfrName(d_content, false));
#endif
boilerplate_conv(DNAME, conv.xfrName(d_content));
boilerplate_conv(MB, conv.xfrName(d_madname, true));
boilerplate_conv(MG, conv.xfrName(d_mgmname, true));
boilerplate_conv(MR, conv.xfrName(d_alias, true));
boilerplate_conv(MINFO, conv.xfrName(d_rmailbx, true); conv.xfrName(d_emailbx, true));
boilerplate_conv(TXT, conv.xfrText(d_text, true));
#ifdef HAVE_LUA_RECORDS
boilerplate_conv(LUA, conv.xfrType(d_type); conv.xfrText(d_code, true));
#endif
boilerplate_conv(ENT, );
boilerplate_conv(SPF, conv.xfrText(d_text, true));
boilerplate_conv(HINFO, conv.xfrText(d_cpu);   conv.xfrText(d_host));

boilerplate_conv(RP,
                 conv.xfrName(d_mbox);
                 conv.xfrName(d_info)
                 );


boilerplate_conv(OPT,
                   conv.xfrBlob(d_data)
                 );

#ifdef HAVE_LUA_RECORDS

bool g_luaRecordInsertWhitespace;

string LUARecordContent::getCode() const
{
  // in d_code, series of "part1" "part2"
  vector<string> parts;
  stringtok(parts, d_code, "\"");
  string ret;
  if (g_luaRecordInsertWhitespace) { // default before 5.0
    for(const auto& part : parts) {
      ret += part;
      ret.append(1, ' ');
    }
  }
  else { // default since 5.0
    for(const auto& part : parts) {
      if (part != " ") {
        ret += part;
      }
    }
  }
  return ret;
}
#endif

void OPTRecordContent::getData(vector<pair<uint16_t, string> >& options) const
{
  string::size_type pos=0;
  uint16_t code, len;
  while(d_data.size() >= 4 + pos) {
    code = 256 * (unsigned char)d_data.at(pos) + (unsigned char)d_data.at(pos+1);
    len = 256 * (unsigned char)d_data.at(pos+2) + (unsigned char)d_data.at(pos+3);
    pos+=4;

    if(pos + len > d_data.size())
      break;

    string field(d_data.c_str() + pos, len);
    pos+=len;
    options.emplace_back(code, std::move(field));
  }
}

boilerplate_conv(TSIG,
                 conv.xfrName(d_algoName);
                 conv.xfr48BitInt(d_time);
                 conv.xfr16BitInt(d_fudge);
                 uint16_t size=d_mac.size();
                 conv.xfr16BitInt(size);
                 if (size>0) conv.xfrBlobNoSpaces(d_mac, size);
                 conv.xfr16BitInt(d_origID);
                 conv.xfr16BitInt(d_eRcode);
                 size=d_otherData.size();
                 conv.xfr16BitInt(size);
                 if (size>0) conv.xfrBlobNoSpaces(d_otherData, size);
                 );

MXRecordContent::MXRecordContent(uint16_t preference, DNSName  mxname):  d_preference(preference), d_mxname(std::move(mxname))
{
}

boilerplate_conv(MX,
                 conv.xfr16BitInt(d_preference);
                 conv.xfrName(d_mxname, true);
                 )

boilerplate_conv(KX,
                 conv.xfr16BitInt(d_preference);
                 conv.xfrName(d_exchanger, false);
                 )

boilerplate_conv(IPSECKEY,
   conv.xfr8BitInt(d_preference);
   conv.xfr8BitInt(d_gatewaytype);
   conv.xfr8BitInt(d_algorithm);

   // now we need to determine values
   switch(d_gatewaytype) {
   case 0: // NO KEY
     break;
   case 1: // IPv4 GW
     conv.xfrIP(d_ip4);
     break;
   case 2: // IPv6 GW
     conv.xfrIP6(d_ip6);
     break;
   case 3: // DNS label
     conv.xfrName(d_gateway, false);
     break;
   default:
     throw MOADNSException("Parsing record content: invalid gateway type");
   };

   switch(d_algorithm) {
   case 0:
     break;
   case 1:
   case 2:
     conv.xfrBlob(d_publickey);
     break;
   default:
     throw MOADNSException("Parsing record content: invalid algorithm type");
   }
)

boilerplate_conv(DHCID,
                 conv.xfrBlob(d_content);
                 )


boilerplate_conv(AFSDB,
                 conv.xfr16BitInt(d_subtype);
                 conv.xfrName(d_hostname);
                 )


boilerplate_conv(NAPTR,
                 conv.xfr16BitInt(d_order);    conv.xfr16BitInt(d_preference);
                 conv.xfrText(d_flags);        conv.xfrText(d_services);         conv.xfrText(d_regexp);
                 conv.xfrName(d_replacement);
                 )


SRVRecordContent::SRVRecordContent(uint16_t preference, uint16_t weight, uint16_t port, DNSName  target)
: d_weight(weight), d_port(port), d_target(std::move(target)), d_preference(preference)
{}

boilerplate_conv(SRV,
                 conv.xfr16BitInt(d_preference);   conv.xfr16BitInt(d_weight);   conv.xfr16BitInt(d_port);
                 conv.xfrName(d_target);
                 )

SOARecordContent::SOARecordContent(DNSName  mname, DNSName  rname, const struct soatimes& st)
: d_mname(std::move(mname)), d_rname(std::move(rname)), d_st(st)
{
}

boilerplate_conv(SOA,
                 conv.xfrName(d_mname, true);
                 conv.xfrName(d_rname, true);
                 conv.xfr32BitInt(d_st.serial);
                 conv.xfr32BitInt(d_st.refresh);
                 conv.xfr32BitInt(d_st.retry);
                 conv.xfr32BitInt(d_st.expire);
                 conv.xfr32BitInt(d_st.minimum);
                 );
#undef KEY
boilerplate_conv(KEY,
                 conv.xfr16BitInt(d_flags);
                 conv.xfr8BitInt(d_protocol);
                 conv.xfr8BitInt(d_algorithm);
                 conv.xfrBlob(d_certificate);
                 );

boilerplate_conv(ZONEMD,
                 conv.xfr32BitInt(d_serial);
                 conv.xfr8BitInt(d_scheme);
                 conv.xfr8BitInt(d_hashalgo);
                 conv.xfrHexBlob(d_digest, true); // keep reading across spaces
                 );

boilerplate_conv(CERT,
                 conv.xfr16BitInt(d_type);
                 if (d_type == 0) throw MOADNSException("CERT type 0 is reserved");

                 conv.xfr16BitInt(d_tag);
                 conv.xfr8BitInt(d_algorithm);
                 conv.xfrBlob(d_certificate);
                 )

boilerplate_conv(TLSA,
                 conv.xfr8BitInt(d_certusage);
                 conv.xfr8BitInt(d_selector);
                 conv.xfr8BitInt(d_matchtype);
                 conv.xfrHexBlob(d_cert, true);
                 )

boilerplate_conv(OPENPGPKEY,
                 conv.xfrBlob(d_keyring);
                 )

boilerplate_conv(SVCB,
                 conv.xfr16BitInt(d_priority);
                 conv.xfrName(d_target, false);
                 if (d_priority != 0) {
                   conv.xfrSvcParamKeyVals(d_params);
                 }
                 )

boilerplate_conv(HTTPS,
                 conv.xfr16BitInt(d_priority);
                 conv.xfrName(d_target, false);
                 if (d_priority != 0) {
                   conv.xfrSvcParamKeyVals(d_params);
                 }
                 )

boilerplate_conv(HHIT,
                 conv.xfrBlob(d_data);
                 )

boilerplate_conv(BRID,
                 conv.xfrBlob(d_data);
                 )

boilerplate_conv(SMIMEA,
                 conv.xfr8BitInt(d_certusage);
                 conv.xfr8BitInt(d_selector);
                 conv.xfr8BitInt(d_matchtype);
                 conv.xfrHexBlob(d_cert, true);
                 )

DSRecordContent::DSRecordContent() = default;
boilerplate_conv(DS,
                 conv.xfr16BitInt(d_tag);
                 conv.xfr8BitInt(d_algorithm);
                 conv.xfr8BitInt(d_digesttype);
                 conv.xfrHexBlob(d_digest, true); // keep reading across spaces
                 )

CDSRecordContent::CDSRecordContent() = default;
boilerplate_conv(CDS,
                 conv.xfr16BitInt(d_tag);
                 conv.xfr8BitInt(d_algorithm);
                 conv.xfr8BitInt(d_digesttype);
                 conv.xfrHexBlob(d_digest, true); // keep reading across spaces
                 )

DLVRecordContent::DLVRecordContent() = default;
boilerplate_conv(DLV,
                 conv.xfr16BitInt(d_tag);
                 conv.xfr8BitInt(d_algorithm);
                 conv.xfr8BitInt(d_digesttype);
                 conv.xfrHexBlob(d_digest, true); // keep reading across spaces
                 )


boilerplate_conv(SSHFP,
                 conv.xfr8BitInt(d_algorithm);
                 conv.xfr8BitInt(d_fptype);
                 conv.xfrHexBlob(d_fingerprint, true);
                 )

boilerplate_conv(RRSIG,
                 conv.xfrType(d_type);
                   conv.xfr8BitInt(d_algorithm);
                   conv.xfr8BitInt(d_labels);
                   conv.xfr32BitInt(d_originalttl);
                   conv.xfrTime(d_sigexpire);
                   conv.xfrTime(d_siginception);
                 conv.xfr16BitInt(d_tag);
                 conv.xfrName(d_signer);
                 conv.xfrBlob(d_signature);
                 )

RRSIGRecordContent::RRSIGRecordContent() = default;

boilerplate_conv(DNSKEY,
                 conv.xfr16BitInt(d_flags);
                 conv.xfr8BitInt(d_protocol);
                 conv.xfr8BitInt(d_algorithm);
                 conv.xfrBlob(d_key);
                 )
DNSKEYRecordContent::DNSKEYRecordContent() = default;

boilerplate_conv(CDNSKEY,
                 conv.xfr16BitInt(d_flags);
                 conv.xfr8BitInt(d_protocol);
                 conv.xfr8BitInt(d_algorithm);
                 conv.xfrBlob(d_key);
                 )
CDNSKEYRecordContent::CDNSKEYRecordContent() = default;

boilerplate_conv(RKEY,
                 conv.xfr16BitInt(d_flags);
                 conv.xfr8BitInt(d_protocol);
                 conv.xfr8BitInt(d_algorithm);
                 conv.xfrBlob(d_key);
                 )
RKEYRecordContent::RKEYRecordContent() = default;

boilerplate_conv(NID,
                 conv.xfr16BitInt(d_preference);
                 conv.xfrNodeOrLocatorID(d_node_id);)

boilerplate_conv(L32,
                 conv.xfr16BitInt(d_preference);
                 conv.xfrIP(d_locator);)

boilerplate_conv(L64,
                 conv.xfr16BitInt(d_preference);
                 conv.xfrNodeOrLocatorID(d_locator);)

boilerplate_conv(LP,
                 conv.xfr16BitInt(d_preference);
                 conv.xfrName(d_fqdn, false);)

/* EUI48 start */
void EUI48RecordContent::report(const ReportIsOnlyCallableByReportAllTypes& /* unused */)
{
  regist(1, QType::EUI48, &make, &make, "EUI48");
}
std::shared_ptr<DNSRecordContent> EUI48RecordContent::make(const DNSRecord &dr, PacketReader& pr)
{
    if(dr.d_clen!=6)
      throw MOADNSException("Wrong size for EUI48 record");

    auto ret=std::make_shared<EUI48RecordContent>();
    pr.copyRecord((uint8_t*) &ret->d_eui48, 6);
    return ret;
}
std::shared_ptr<DNSRecordContent> EUI48RecordContent::make(const string& zone)
{
    // try to parse
    auto ret=std::make_shared<EUI48RecordContent>();
    // format is 6 hex bytes and dashes
    if (sscanf(zone.c_str(), "%2hhx-%2hhx-%2hhx-%2hhx-%2hhx-%2hhx",
           ret->d_eui48, ret->d_eui48+1, ret->d_eui48+2,
           ret->d_eui48+3, ret->d_eui48+4, ret->d_eui48+5) != 6) {
       throw MOADNSException("Asked to encode '"+zone+"' as an EUI48 address, but does not parse");
    }
    return ret;
}
void EUI48RecordContent::toPacket(DNSPacketWriter& pw) const
{
    string blob(d_eui48, d_eui48+6);
    pw.xfrBlob(blob);
}

string EUI48RecordContent::getZoneRepresentation(bool /* noDot */) const
{
    char tmp[18];
    snprintf(tmp,sizeof(tmp),"%02x-%02x-%02x-%02x-%02x-%02x",
           d_eui48[0], d_eui48[1], d_eui48[2],
           d_eui48[3], d_eui48[4], d_eui48[5]);
    return tmp;
}

/* EUI48 end */

/* EUI64 start */

void EUI64RecordContent::report(const ReportIsOnlyCallableByReportAllTypes& /* unused */)
{
  regist(1, QType::EUI64, &make, &make, "EUI64");
}
std::shared_ptr<DNSRecordContent> EUI64RecordContent::make(const DNSRecord &dr, PacketReader& pr)
{
    if(dr.d_clen!=8)
      throw MOADNSException("Wrong size for EUI64 record");

    auto ret=std::make_shared<EUI64RecordContent>();
    pr.copyRecord((uint8_t*) &ret->d_eui64, 8);
    return ret;
}
std::shared_ptr<DNSRecordContent> EUI64RecordContent::make(const string& zone)
{
    // try to parse
    auto ret=std::make_shared<EUI64RecordContent>();
    // format is 8 hex bytes and dashes
    if (sscanf(zone.c_str(), "%2hhx-%2hhx-%2hhx-%2hhx-%2hhx-%2hhx-%2hhx-%2hhx",
           ret->d_eui64, ret->d_eui64+1, ret->d_eui64+2,
           ret->d_eui64+3, ret->d_eui64+4, ret->d_eui64+5,
           ret->d_eui64+6, ret->d_eui64+7) != 8) {
       throw MOADNSException("Asked to encode '"+zone+"' as an EUI64 address, but does not parse");
    }
    return ret;
}
void EUI64RecordContent::toPacket(DNSPacketWriter& pw) const
{
    string blob(d_eui64, d_eui64+8);
    pw.xfrBlob(blob);
}

string EUI64RecordContent::getZoneRepresentation(bool /* noDot */) const
{
    char tmp[24];
    snprintf(tmp,sizeof(tmp),"%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x",
           d_eui64[0], d_eui64[1], d_eui64[2],
           d_eui64[3], d_eui64[4], d_eui64[5],
           d_eui64[6], d_eui64[7]);
    return tmp;
}

/* EUI64 end */

/* APL start */
/* https://tools.ietf.org/html/rfc3123 */
void APLRecordContent::report(const ReportIsOnlyCallableByReportAllTypes& /* unused */)
{
  regist(1, QType::APL, &make, &make, "APL");
}

// Parse incoming packets (e.g. nsupdate)
std::shared_ptr<DNSRecordContent> APLRecordContent::make(const DNSRecord &dr, PacketReader& pr) {
  uint8_t temp;
  APLRDataElement ard;
  size_t processed = 0;

  auto ret=std::make_shared<APLRecordContent>();

  while (processed<dr.d_clen) {
    pr.xfr16BitInt(ard.d_family);
    pr.xfr8BitInt(ard.d_prefix);
    pr.xfr8BitInt(temp);
    ard.d_n = (temp & 128) >> 7;
    ard.d_afdlength = temp & 127;

    if (ard.d_family == APL_FAMILY_IPV4) {
      if (ard.d_afdlength > 4) {
        throw MOADNSException("Invalid IP length for IPv4 APL");
      }
      memset(ard.d_ip.d_ip4, 0, sizeof(ard.d_ip.d_ip4));
      for (u_int i=0; i < ard.d_afdlength; i++)
        pr.xfr8BitInt(ard.d_ip.d_ip4[i]);
    } else if (ard.d_family == APL_FAMILY_IPV6) {
      if (ard.d_afdlength > 16) {
        throw MOADNSException("Invalid IP length for IPv6 APL");
      }
      memset(ard.d_ip.d_ip6, 0, sizeof(ard.d_ip.d_ip6));
      for (u_int i=0; i < ard.d_afdlength; i++)
        pr.xfr8BitInt(ard.d_ip.d_ip6[i]);
    } else
    throw MOADNSException("Unknown family for APL record");

    processed += 4 + ard.d_afdlength;

    ret->aplrdata.push_back(ard);
  }

  return ret;
}

// Parse a single APL <apitem>
APLRDataElement APLRecordContent::parseAPLElement(const string& element) {
  string record;
  Netmask nm;
  unsigned int bytes;
  bool done_trimming;
  APLRDataElement ard;

  // Parse the optional leading ! (negate)
  if (element.at(0) == '!') {
    ard.d_n = true;
    record = element.substr(1, element.length()-1);
  } else {
    ard.d_n = false;
    record = element;
  }

  if (record.find('/') == string::npos) { // Required by RFC section 5
    throw MOADNSException("Asked to decode '"+element+"' as an APL record, but missing subnet mask");
  }


  if (record.find("1:", 0) == 0) { // IPv4
    uint32_t v4ip;

    ard.d_family = APL_FAMILY_IPV4;

    // Ensure that a mask is provided

    // Read IPv4 string into a Netmask object
    nm = Netmask(record.substr(2, record.length() - 2));
    ard.d_prefix = nm.getBits();

    if (nm.getNetwork().isIPv4() == 0)
      throw MOADNSException("Asked to decode '"+element+"' as an APL v4 record");

    // Section 4.1 of RFC 3123 (don't send trailing "0" bytes)
    // Copy data; using array of bytes since we might end up truncating them in the packet
    v4ip = ntohl(nm.getNetwork().sin4.sin_addr.s_addr);
    memset(ard.d_ip.d_ip4, 0, sizeof(ard.d_ip.d_ip4));
    bytes  = 4; // Start by assuming we'll send 4 bytes
    done_trimming = false;
    for (int i=0; i<4; i++) {
      ard.d_ip.d_ip4[3-i] = (v4ip & 255);
      // Remove trailing "0" bytes from packet and update length
      if ((v4ip & 255) == 0 and !done_trimming) {
        bytes--;
      } else {
        done_trimming = true;
      }
      v4ip = v4ip >> 8;
    }
    ard.d_afdlength = bytes;

  } else if (record.find("2:", 0) == 0) { // IPv6
    ard.d_family = APL_FAMILY_IPV6;

    // Parse IPv6 string into a Netmask object
    nm = Netmask(record.substr(2, record.length() - 2));
    ard.d_prefix = nm.getBits();

    if (nm.getNetwork().isIPv6() == 0)
      throw MOADNSException("Asked to decode '"+element+"' as an APL v6 record");

    // Section 4.2 of RFC 3123 (don't send trailing "0" bytes)
    // Remove trailing "0" bytes from packet and reduce length
    memset(ard.d_ip.d_ip6, 0, sizeof(ard.d_ip.d_ip6));
    bytes = 16; // Start by assuming we'll send 16 bytes
    done_trimming = false;
    for (int i=0; i<16; i++) {
      ard.d_ip.d_ip6[15-i] = nm.getNetwork().sin6.sin6_addr.s6_addr[15-i];
      if (nm.getNetwork().sin6.sin6_addr.s6_addr[15-i] == 0 and !done_trimming) {
        // trailing 0 byte, update length
        bytes--;
      } else {
        done_trimming = true;
      }
    }
    ard.d_afdlength = bytes;

  } else {
      throw MOADNSException("Asked to encode '"+element+"' as an IPv6 APL record but got unknown Address Family");
  }
  return ard;

}

// Parse backend record (0, 1 or more <apitem>)
std::shared_ptr<DNSRecordContent> APLRecordContent::make(const string& zone) {
  APLRDataElement ard;
  vector<string> elements;

  auto ret=std::make_shared<APLRecordContent>();

  boost::split(elements, zone, boost::is_any_of(" "));
  for (auto & element : elements) {
    if (!element.empty()) {
      ard = ret->parseAPLElement(element);
      ret->aplrdata.push_back(ard);
    }
  }
  return ret;
}


// DNSRecord to Packet conversion
void APLRecordContent::toPacket(DNSPacketWriter& pw) const {
  for (auto & ard : aplrdata) {
    pw.xfr16BitInt(ard.d_family);
    pw.xfr8BitInt(ard.d_prefix);
    pw.xfr8BitInt((ard.d_n << 7) + ard.d_afdlength);
    if (ard.d_family == APL_FAMILY_IPV4) {
      for (int i=0; i<ard.d_afdlength; i++) {
        pw.xfr8BitInt(ard.d_ip.d_ip4[i]);
      }
    } else if (ard.d_family == APL_FAMILY_IPV6) {
      for (int i=0; i<ard.d_afdlength; i++) {
        pw.xfr8BitInt(ard.d_ip.d_ip6[i]);
      }
    }
  }
}

// Decode record into string
string APLRecordContent::getZoneRepresentation(bool /* noDot */) const {
  string s_n, s_family, output;
  ComboAddress ca;
  Netmask nm;

  output = "";

  for (std::vector<APLRDataElement>::const_iterator ard = aplrdata.begin() ; ard != aplrdata.end(); ++ard) {

    // Negation flag
    if (ard->d_n) {
      s_n = "!";
    } else {
      s_n = "";
    }

    if (ard->d_family == APL_FAMILY_IPV4) { // IPv4
      s_family = std::to_string(APL_FAMILY_IPV4);
      ca = ComboAddress();
      memcpy(&ca.sin4.sin_addr.s_addr, ard->d_ip.d_ip4, sizeof(ca.sin4.sin_addr.s_addr));
    } else if (ard->d_family == APL_FAMILY_IPV6) { // IPv6
      s_family = std::to_string(APL_FAMILY_IPV6);
      ca = ComboAddress();
      ca.sin4.sin_family = AF_INET6;
      memset(&ca.sin6.sin6_addr.s6_addr, 0, sizeof(ca.sin6.sin6_addr.s6_addr));
      memcpy(&ca.sin6.sin6_addr.s6_addr, ard->d_ip.d_ip6, ard->d_afdlength);
    } else {
      throw MOADNSException("Asked to decode APL record but got unknown Address Family");
    }

    nm = Netmask(ca, ard->d_prefix);

    output += s_n + s_family + ":" + nm.toString();
    if (std::next(ard) != aplrdata.end())
      output += " ";
  }
  return output;
}

/* APL end */

/* SVCB start */
bool SVCBBaseRecordContent::autoHint(const SvcParam::SvcParamKey &key) const {
  auto p = getParamIt(key);
  if (p == d_params.end()) {
    return false;
  }
  return p->getAutoHint();
}

void SVCBBaseRecordContent::setHints(const SvcParam::SvcParamKey &key, const std::vector<ComboAddress> &addresses) {
  auto p = getParamIt(key);
  if (p == d_params.end()) {
    return;
  }

  std::vector<ComboAddress> h;
  h.reserve(h.size() + addresses.size());
  h.insert(h.end(), addresses.begin(), addresses.end());

  try {
    auto newParam = SvcParam(key, std::move(h));
    d_params.erase(p);
    d_params.insert(std::move(newParam));
  } catch (...) {
    // XXX maybe we should SERVFAIL instead?
    return;
  }
}

void SVCBBaseRecordContent::removeParam(const SvcParam::SvcParamKey &key) {
  auto p = getParamIt(key);
  if (p == d_params.end()) {
    return;
  }
  d_params.erase(p);
}

bool SVCBBaseRecordContent::hasParams() const {
  return !d_params.empty();
}

bool SVCBBaseRecordContent::hasParam(const SvcParam::SvcParamKey &key) const {
  return getParamIt(key) != d_params.end();
}

SvcParam SVCBBaseRecordContent::getParam(const SvcParam::SvcParamKey &key) const {
  auto p = getParamIt(key);
  if (p == d_params.end()) {
    throw std::out_of_range("No param with key " + SvcParam::keyToString(key));
  }
  return *p;
}

set<SvcParam>::const_iterator SVCBBaseRecordContent::getParamIt(const SvcParam::SvcParamKey &key) const {
  return std::find(d_params.begin(), d_params.end(), key);
}

std::shared_ptr<SVCBBaseRecordContent> SVCBRecordContent::clone() const
{
  return std::shared_ptr<SVCBBaseRecordContent>(std::make_shared<SVCBRecordContent>(*this));
}

std::shared_ptr<SVCBBaseRecordContent> HTTPSRecordContent::clone() const
{
  return std::shared_ptr<SVCBBaseRecordContent>(std::make_shared<HTTPSRecordContent>(*this));
}

/* SVCB end */

std::shared_ptr<DRIPBaseRecordContent> HHITRecordContent::clone() const
{
  return {std::make_shared<HHITRecordContent>(*this)};
}

std::shared_ptr<DRIPBaseRecordContent> BRIDRecordContent::clone() const
{
  return {std::make_shared<BRIDRecordContent>(*this)};
}

boilerplate_conv(TKEY,
                 conv.xfrName(d_algo);
                 conv.xfr32BitInt(d_inception);
                 conv.xfr32BitInt(d_expiration);
                 conv.xfr16BitInt(d_mode);
                 conv.xfr16BitInt(d_error);
                 conv.xfr16BitInt(d_keysize);
                 if (d_keysize>0) conv.xfrBlobNoSpaces(d_key, d_keysize);
                 conv.xfr16BitInt(d_othersize);
                 if (d_othersize>0) conv.xfrBlobNoSpaces(d_other, d_othersize);
                 )
TKEYRecordContent::TKEYRecordContent() { d_othersize = 0; } // fix CID#1288932

boilerplate_conv(URI,
                 conv.xfr16BitInt(d_priority);
                 conv.xfr16BitInt(d_weight);
                 conv.xfrText(d_target, true, false);
                 )

boilerplate_conv(CAA,
                 conv.xfr8BitInt(d_flags);
                 conv.xfrUnquotedText(d_tag, true);
                 conv.xfrText(d_value, true, false); /* no lenField */
                )

static uint16_t makeTag(const std::string& data)
{
  const unsigned char* key=(const unsigned char*)data.c_str();
  unsigned int keysize=data.length();

  unsigned long ac;     /* assumed to be 32 bits or larger */
  unsigned int i;                /* loop index */

  for ( ac = 0, i = 0; i < keysize; ++i )
    ac += (i & 1) ? key[i] : key[i] << 8;
  ac += (ac >> 16) & 0xFFFF;
  return ac & 0xFFFF;
}

uint16_t DNSKEYRecordContent::getTag() const
{
  return makeTag(this->serialize(DNSName()));
}


/*
 * Fills `eo` by parsing the EDNS(0) OPT RR (RFC 6891)
 */
bool getEDNSOpts(const MOADNSParser& mdp, EDNSOpts* eo)
{
  eo->d_extFlags=0;
  if(mdp.d_header.arcount && !mdp.d_answers.empty()) {
    for(const MOADNSParser::answers_t::value_type& val :  mdp.d_answers) {
      if(val.d_place == DNSResourceRecord::ADDITIONAL && val.d_type == QType::OPT) {
        eo->d_packetsize=val.d_class;

        EDNS0Record stuff;
        uint32_t ttl=ntohl(val.d_ttl);
        static_assert(sizeof(EDNS0Record) == sizeof(uint32_t), "sizeof(EDNS0Record) must match sizeof(uint32_t)");
        memcpy(&stuff, &ttl, sizeof(stuff));

        eo->d_extRCode=stuff.extRCode;
        eo->d_version=stuff.version;
        eo->d_extFlags = ntohs(stuff.extFlags);
        auto orc = getRR<OPTRecordContent>(val);
        if(orc == nullptr)
          return false;
        orc->getData(eo->d_options);
        return true;
      }
    }
  }
  return false;
}

static void reportBasicTypes(const ReportIsOnlyCallableByReportAllTypes& guard)
{
  ARecordContent::report(guard);
  AAAARecordContent::report(guard);
  NSRecordContent::report(guard);
  CNAMERecordContent::report(guard);
  MXRecordContent::report(guard);
  SOARecordContent::report(guard);
  SRVRecordContent::report(guard);
  PTRRecordContent::report(guard);
  DNSRecordContent::regist(QClass::CHAOS, QType::TXT, &TXTRecordContent::make, &TXTRecordContent::make, "TXT");
  TXTRecordContent::report(guard);
#ifdef HAVE_LUA_RECORDS
  LUARecordContent::report(guard);
#endif
  DNSRecordContent::regist(QClass::IN, QType::ANY, nullptr, nullptr, "ANY");
  DNSRecordContent::regist(QClass::IN, QType::AXFR, nullptr, nullptr, "AXFR");
  DNSRecordContent::regist(QClass::IN, QType::IXFR, nullptr, nullptr, "IXFR");
}

static void reportOtherTypes(const ReportIsOnlyCallableByReportAllTypes& guard)
{
   MBRecordContent::report(guard);
   MGRecordContent::report(guard);
   MRRecordContent::report(guard);
   AFSDBRecordContent::report(guard);
   DNAMERecordContent::report(guard);
#if !defined(RECURSOR)
   ALIASRecordContent::report(guard);
#endif
   SPFRecordContent::report(guard);
   NAPTRRecordContent::report(guard);
   KXRecordContent::report(guard);
   LOCRecordContent::report(guard);
   ENTRecordContent::report(guard);
   HINFORecordContent::report(guard);
   RPRecordContent::report(guard);
   KEYRecordContent::report(guard);
   DNSKEYRecordContent::report(guard);
   DHCIDRecordContent::report(guard);
   CDNSKEYRecordContent::report(guard);
   RKEYRecordContent::report(guard);
   RRSIGRecordContent::report(guard);
   DSRecordContent::report(guard);
   CDSRecordContent::report(guard);
   SSHFPRecordContent::report(guard);
   CERTRecordContent::report(guard);
   NSECRecordContent::report(guard);
   NSEC3RecordContent::report(guard);
   NSEC3PARAMRecordContent::report(guard);
   TLSARecordContent::report(guard);
   SMIMEARecordContent::report(guard);
   OPENPGPKEYRecordContent::report(guard);
   SVCBRecordContent::report(guard);
   HTTPSRecordContent::report(guard);
   HHITRecordContent::report(guard);
   BRIDRecordContent::report(guard);
   DLVRecordContent::report(guard);
   DNSRecordContent::regist(QClass::ANY, QType::TSIG, &TSIGRecordContent::make, &TSIGRecordContent::make, "TSIG");
   DNSRecordContent::regist(QClass::ANY, QType::TKEY, &TKEYRecordContent::make, &TKEYRecordContent::make, "TKEY");
   //TSIGRecordContent::report(guard);
   OPTRecordContent::report(guard);
   EUI48RecordContent::report(guard);
   EUI64RecordContent::report(guard);
   MINFORecordContent::report(guard);
   URIRecordContent::report(guard);
   CAARecordContent::report(guard);
   APLRecordContent::report(guard);
   IPSECKEYRecordContent::report(guard);
   CSYNCRecordContent::report(guard);
   NIDRecordContent::report(guard);
   L32RecordContent::report(guard);
   L64RecordContent::report(guard);
   LPRecordContent::report(guard);
   ZONEMDRecordContent::report(guard);
}

struct ReportIsOnlyCallableByReportAllTypes
{
};

void reportAllTypes()
{
  ReportIsOnlyCallableByReportAllTypes guard;
  reportBasicTypes(guard);
  reportOtherTypes(guard);
  DNSRecordContent::lock();
}

ComboAddress getAddr(const DNSRecord& dr, uint16_t defport)
{
  if (auto a = getRR<ARecordContent>(dr)) {
    return a->getCA(defport);
  }
  else if (auto aaaa = getRR<AAAARecordContent>(dr)) {
    return aaaa->getCA(defport);
  }
  throw std::invalid_argument("not an A or AAAA record");
}

/**
 * Check if the DNSNames that should be hostnames, are hostnames
 */
void checkHostnameCorrectness(const DNSResourceRecord& rr)
{
  if (rr.qtype.getCode() == QType::NS || rr.qtype.getCode() == QType::MX || rr.qtype.getCode() == QType::SRV) {
    DNSName toCheck;
    if (rr.qtype.getCode() == QType::SRV) {
      vector<string> parts;
      stringtok(parts, rr.getZoneRepresentation());
      if (parts.size() == 4) toCheck = DNSName(parts[3]);
    } else if (rr.qtype.getCode() == QType::MX) {
      vector<string> parts;
      stringtok(parts, rr.getZoneRepresentation());
      if (parts.size() == 2) toCheck = DNSName(parts[1]);
    } else {
      toCheck = DNSName(rr.content);
    }

    if (toCheck.empty()) {
      throw std::runtime_error("unable to extract hostname from content");
    }
    else if ((rr.qtype.getCode() == QType::MX || rr.qtype.getCode() == QType::SRV) && toCheck == g_rootdnsname) {
      // allow null MX/SRV
    } else if(!toCheck.isHostname()) {
      throw std::runtime_error(boost::str(boost::format("non-hostname content %s") % toCheck.toString()));
    }
  }
}

vector<pair<uint16_t, string>>::const_iterator EDNSOpts::getFirstOption(uint16_t optionCode) const
{
  for (auto iter = d_options.cbegin(); iter != d_options.cend(); ++iter) {
    if (iter->first == optionCode) {
      return iter;
    }
  }
  return d_options.cend();
}

#if 0
static struct Reporter
{
  Reporter()
  {
    reportAllTypes();
  }
} reporter __attribute__((init_priority(65535)));
#endif
