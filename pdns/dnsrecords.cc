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
      /* Falls through. */
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
      if (!parts.size())
        return "";
      last = *parts.rbegin();
      ret << content;
      if (last == ".")
        break;
      if (*(last.rbegin()) != '.' && !noDot)
        ret << ".";
      break;
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

bool DNSResourceRecord::operator==(const DNSResourceRecord& rhs)
{
  string lcontent=toLower(content);
  string rcontent=toLower(rhs.content);

  return
    tie(qname, qtype, lcontent, ttl) ==
    tie(rhs.qname, rhs.qtype, rcontent, rhs.ttl);
}

boilerplate_conv(A, QType::A, conv.xfrIP(d_ip));

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

boilerplate_conv(AAAA, QType::AAAA, conv.xfrIP6(d_ip6); );

boilerplate_conv(NS, QType::NS, conv.xfrName(d_content, true));
boilerplate_conv(PTR, QType::PTR, conv.xfrName(d_content, true));
boilerplate_conv(CNAME, QType::CNAME, conv.xfrName(d_content, true));
boilerplate_conv(ALIAS, QType::ALIAS, conv.xfrName(d_content, false));
boilerplate_conv(DNAME, QType::DNAME, conv.xfrName(d_content));
boilerplate_conv(MB, QType::MB, conv.xfrName(d_madname, true));
boilerplate_conv(MG, QType::MG, conv.xfrName(d_mgmname, true));
boilerplate_conv(MR, QType::MR, conv.xfrName(d_alias, true));
boilerplate_conv(MINFO, QType::MINFO, conv.xfrName(d_rmailbx, true); conv.xfrName(d_emailbx, true));
boilerplate_conv(TXT, QType::TXT, conv.xfrText(d_text, true));
#ifdef HAVE_LUA_RECORDS
boilerplate_conv(LUA, QType::LUA, conv.xfrType(d_type); conv.xfrText(d_code, true));
#endif
boilerplate_conv(ENT, 0, );
boilerplate_conv(SPF, 99, conv.xfrText(d_text, true));
boilerplate_conv(HINFO, QType::HINFO,  conv.xfrText(d_cpu);   conv.xfrText(d_host));

boilerplate_conv(RP, QType::RP,
                 conv.xfrName(d_mbox);   
                 conv.xfrName(d_info)
                 );


boilerplate_conv(OPT, QType::OPT, 
                   conv.xfrBlob(d_data)
                 );

#ifdef HAVE_LUA_RECORDS
string LUARecordContent::getCode() const
{
  // in d_code, series of "part1" "part2"
  vector<string> parts;
  stringtok(parts, d_code, "\"");
  string ret;
  for(const auto& p : parts) {
    ret += p;
    ret.append(1, ' ');
  }
  return ret;
}
#endif

void OPTRecordContent::getData(vector<pair<uint16_t, string> >& options)
{
  string::size_type pos=0;
  uint16_t code, len;
  while(d_data.size() >= 4 + pos) {
    code = 256 * (unsigned char)d_data[pos] + (unsigned char)d_data[pos+1];
    len = 256 * (unsigned char)d_data[pos+2] + (unsigned char)d_data[pos+3];
    pos+=4;

    if(pos + len > d_data.size())
      break;

    string field(d_data.c_str() + pos, len);
    pos+=len;
    options.push_back(make_pair(code, field));
  }
}

boilerplate_conv(TSIG, QType::TSIG,
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

MXRecordContent::MXRecordContent(uint16_t preference, const DNSName& mxname):  d_preference(preference), d_mxname(mxname)
{
}

boilerplate_conv(MX, QType::MX, 
                 conv.xfr16BitInt(d_preference);
                 conv.xfrName(d_mxname, true);
                 )

boilerplate_conv(KX, QType::KX, 
                 conv.xfr16BitInt(d_preference);
                 conv.xfrName(d_exchanger, false);
                 )

boilerplate_conv(IPSECKEY, QType::IPSECKEY,
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

boilerplate_conv(DHCID, 49, 
                 conv.xfrBlob(d_content);
                 )


boilerplate_conv(AFSDB, QType::AFSDB, 
                 conv.xfr16BitInt(d_subtype);
                 conv.xfrName(d_hostname);
                 )


boilerplate_conv(NAPTR, QType::NAPTR,
                 conv.xfr16BitInt(d_order);    conv.xfr16BitInt(d_preference);
                 conv.xfrText(d_flags);        conv.xfrText(d_services);         conv.xfrText(d_regexp);
                 conv.xfrName(d_replacement);
                 )


SRVRecordContent::SRVRecordContent(uint16_t preference, uint16_t weight, uint16_t port, const DNSName& target) 
: d_weight(weight), d_port(port), d_target(target), d_preference(preference)
{}

boilerplate_conv(SRV, QType::SRV, 
                 conv.xfr16BitInt(d_preference);   conv.xfr16BitInt(d_weight);   conv.xfr16BitInt(d_port);
                 conv.xfrName(d_target); 
                 )

SOARecordContent::SOARecordContent(const DNSName& mname, const DNSName& rname, const struct soatimes& st) 
: d_mname(mname), d_rname(rname), d_st(st)
{
}

boilerplate_conv(SOA, QType::SOA,
                 conv.xfrName(d_mname, true);
                 conv.xfrName(d_rname, true);
                 conv.xfr32BitInt(d_st.serial);
                 conv.xfr32BitInt(d_st.refresh);
                 conv.xfr32BitInt(d_st.retry);
                 conv.xfr32BitInt(d_st.expire);
                 conv.xfr32BitInt(d_st.minimum);
                 );
#undef KEY
boilerplate_conv(KEY, QType::KEY, 
                 conv.xfr16BitInt(d_flags); 
                 conv.xfr8BitInt(d_protocol); 
                 conv.xfr8BitInt(d_algorithm); 
                 conv.xfrBlob(d_certificate);
                 );

boilerplate_conv(CERT, 37, 
                 conv.xfr16BitInt(d_type); 
                 if (d_type == 0) throw MOADNSException("CERT type 0 is reserved");

                 conv.xfr16BitInt(d_tag); 
                 conv.xfr8BitInt(d_algorithm); 
                 conv.xfrBlob(d_certificate);
                 )

boilerplate_conv(TLSA, 52, 
                 conv.xfr8BitInt(d_certusage); 
                 conv.xfr8BitInt(d_selector); 
                 conv.xfr8BitInt(d_matchtype); 
                 conv.xfrHexBlob(d_cert, true);
                 )                 
                 
boilerplate_conv(OPENPGPKEY, 61,
                 conv.xfrBlob(d_keyring);
                 )

boilerplate_conv(SMIMEA, 53,
                 conv.xfr8BitInt(d_certusage);
                 conv.xfr8BitInt(d_selector);
                 conv.xfr8BitInt(d_matchtype);
                 conv.xfrHexBlob(d_cert, true);
                 )

DSRecordContent::DSRecordContent() {}
boilerplate_conv(DS, 43, 
                 conv.xfr16BitInt(d_tag); 
                 conv.xfr8BitInt(d_algorithm); 
                 conv.xfr8BitInt(d_digesttype); 
                 conv.xfrHexBlob(d_digest, true); // keep reading across spaces
                 )

CDSRecordContent::CDSRecordContent() {}
boilerplate_conv(CDS, 59, 
                 conv.xfr16BitInt(d_tag); 
                 conv.xfr8BitInt(d_algorithm); 
                 conv.xfr8BitInt(d_digesttype); 
                 conv.xfrHexBlob(d_digest, true); // keep reading across spaces
                 )

DLVRecordContent::DLVRecordContent() {}
boilerplate_conv(DLV,32769 , 
                 conv.xfr16BitInt(d_tag); 
                 conv.xfr8BitInt(d_algorithm); 
                 conv.xfr8BitInt(d_digesttype); 
                 conv.xfrHexBlob(d_digest, true); // keep reading across spaces
                 )


boilerplate_conv(SSHFP, 44, 
                 conv.xfr8BitInt(d_algorithm); 
                 conv.xfr8BitInt(d_fptype); 
                 conv.xfrHexBlob(d_fingerprint, true);
                 )

boilerplate_conv(RRSIG, 46, 
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
                 
RRSIGRecordContent::RRSIGRecordContent() {}

boilerplate_conv(DNSKEY, 48, 
                 conv.xfr16BitInt(d_flags); 
                 conv.xfr8BitInt(d_protocol); 
                 conv.xfr8BitInt(d_algorithm); 
                 conv.xfrBlob(d_key);
                 )
DNSKEYRecordContent::DNSKEYRecordContent() {}

boilerplate_conv(CDNSKEY, 60, 
                 conv.xfr16BitInt(d_flags); 
                 conv.xfr8BitInt(d_protocol); 
                 conv.xfr8BitInt(d_algorithm); 
                 conv.xfrBlob(d_key);
                 )
CDNSKEYRecordContent::CDNSKEYRecordContent() {}

boilerplate_conv(RKEY, 57, 
                 conv.xfr16BitInt(d_flags); 
                 conv.xfr8BitInt(d_protocol); 
                 conv.xfr8BitInt(d_algorithm); 
                 conv.xfrBlob(d_key);
                 )
RKEYRecordContent::RKEYRecordContent() {}

/* EUI48 start */
void EUI48RecordContent::report(void) 
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
void EUI48RecordContent::toPacket(DNSPacketWriter& pw)
{
    string blob(d_eui48, d_eui48+6);
    pw.xfrBlob(blob); 
}
string EUI48RecordContent::getZoneRepresentation(bool noDot) const
{
    char tmp[18]; 
    snprintf(tmp,sizeof(tmp),"%02x-%02x-%02x-%02x-%02x-%02x",
           d_eui48[0], d_eui48[1], d_eui48[2], 
           d_eui48[3], d_eui48[4], d_eui48[5]);
    return tmp;
}

/* EUI48 end */

/* EUI64 start */

void EUI64RecordContent::report(void)
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
void EUI64RecordContent::toPacket(DNSPacketWriter& pw)
{
    string blob(d_eui64, d_eui64+8);
    pw.xfrBlob(blob);
}
string EUI64RecordContent::getZoneRepresentation(bool noDot) const
{
    char tmp[24]; 
    snprintf(tmp,sizeof(tmp),"%02x-%02x-%02x-%02x-%02x-%02x-%02x-%02x",
           d_eui64[0], d_eui64[1], d_eui64[2],
           d_eui64[3], d_eui64[4], d_eui64[5],
           d_eui64[6], d_eui64[7]);
    return tmp;
}

/* EUI64 end */

boilerplate_conv(TKEY, QType::TKEY,
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

boilerplate_conv(URI, QType::URI,
                 conv.xfr16BitInt(d_priority);
                 conv.xfr16BitInt(d_weight);
                 conv.xfrText(d_target, true, false);
                 )

boilerplate_conv(CAA, QType::CAA,
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
  DNSKEYRecordContent tmp(*this);
  return makeTag(tmp.serialize(DNSName()));  // this can't be const for some reason
}

uint16_t DNSKEYRecordContent::getTag() 
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
      if(val.first.d_place == DNSResourceRecord::ADDITIONAL && val.first.d_type == QType::OPT) {
        eo->d_packetsize=val.first.d_class;

        EDNS0Record stuff;
        uint32_t ttl=ntohl(val.first.d_ttl);
        static_assert(sizeof(EDNS0Record) == sizeof(uint32_t), "sizeof(EDNS0Record) must match sizeof(uint32_t)");
        memcpy(&stuff, &ttl, sizeof(stuff));

        eo->d_extRCode=stuff.extRCode;
        eo->d_version=stuff.version;
        eo->d_extFlags = ntohs(stuff.extFlags);
        auto orc = getRR<OPTRecordContent>(val.first);
        if(orc == nullptr)
          return false;
        orc->getData(eo->d_options);
        return true;
      }
    }
  }
  return false;
}

DNSRecord makeOpt(const uint16_t udpsize, const uint16_t extRCode, const uint16_t extFlags)
{
  EDNS0Record stuff;
  stuff.extRCode=0;
  stuff.version=0;
  stuff.extFlags=htons(extFlags);
  DNSRecord dr;
  static_assert(sizeof(EDNS0Record) == sizeof(dr.d_ttl), "sizeof(EDNS0Record) must match sizeof(DNSRecord.d_ttl)");
  memcpy(&dr.d_ttl, &stuff, sizeof(stuff));
  dr.d_ttl=ntohl(dr.d_ttl);
  dr.d_name=g_rootdnsname;
  dr.d_type = QType::OPT;
  dr.d_class=udpsize;
  dr.d_place=DNSResourceRecord::ADDITIONAL;
  dr.d_content = std::make_shared<OPTRecordContent>();
  // if we ever do options, I think we stuff them into OPTRecordContent::data
  return dr;
}

void reportBasicTypes()
{
  ARecordContent::report();
  AAAARecordContent::report();
  NSRecordContent::report();
  CNAMERecordContent::report();
  MXRecordContent::report();
  SOARecordContent::report();
  SRVRecordContent::report();
  PTRRecordContent::report();
  DNSRecordContent::regist(QClass::CHAOS, QType::TXT, &TXTRecordContent::make, &TXTRecordContent::make, "TXT");
  TXTRecordContent::report();
#ifdef HAVE_LUA_RECORDS
  LUARecordContent::report();
#endif
  DNSRecordContent::regist(QClass::IN, QType::ANY, 0, 0, "ANY");
  DNSRecordContent::regist(QClass::IN, QType::AXFR, 0, 0, "AXFR");
  DNSRecordContent::regist(QClass::IN, QType::IXFR, 0, 0, "IXFR");
}

void reportOtherTypes()
{
   MBRecordContent::report();
   MGRecordContent::report();
   MRRecordContent::report();
   AFSDBRecordContent::report();
   DNAMERecordContent::report();
   ALIASRecordContent::report();
   SPFRecordContent::report();
   NAPTRRecordContent::report();
   KXRecordContent::report();
   LOCRecordContent::report();
   ENTRecordContent::report();
   HINFORecordContent::report();
   RPRecordContent::report();
   KEYRecordContent::report();
   DNSKEYRecordContent::report();
   DHCIDRecordContent::report();
   CDNSKEYRecordContent::report();
   RKEYRecordContent::report();
   RRSIGRecordContent::report();
   DSRecordContent::report();
   CDSRecordContent::report();
   SSHFPRecordContent::report();
   CERTRecordContent::report();
   NSECRecordContent::report();
   NSEC3RecordContent::report();
   NSEC3PARAMRecordContent::report();
   TLSARecordContent::report();
   SMIMEARecordContent::report();
   OPENPGPKEYRecordContent::report();
   DLVRecordContent::report();
   DNSRecordContent::regist(QClass::ANY, QType::TSIG, &TSIGRecordContent::make, &TSIGRecordContent::make, "TSIG");
   DNSRecordContent::regist(QClass::ANY, QType::TKEY, &TKEYRecordContent::make, &TKEYRecordContent::make, "TKEY");
   //TSIGRecordContent::report();
   OPTRecordContent::report();
   EUI48RecordContent::report();
   EUI64RecordContent::report();
   MINFORecordContent::report();
   URIRecordContent::report();
   CAARecordContent::report();
}

void reportAllTypes()
{
  reportBasicTypes();
  reportOtherTypes();
}

ComboAddress getAddr(const DNSRecord& dr, uint16_t defport)
{
  if(auto addr=getRR<ARecordContent>(dr)) {
    return addr->getCA(defport);
  }
  else
    return getRR<AAAARecordContent>(dr)->getCA(defport);
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

#if 0
static struct Reporter
{
  Reporter()
  {
    reportAllTypes();
  }
} reporter __attribute__((init_priority(65535)));
#endif
