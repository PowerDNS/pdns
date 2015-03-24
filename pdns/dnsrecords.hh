/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2005 - 2010  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation

    Additionally, the license of this program contains a special
    exception which allows to distribute the program in binary form when
    it is linked against OpenSSL.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef PDNS_DNSRECORDS_HH
#define PDNS_DNSRECORDS_HH

#include "dnsparser.hh"
#include "dnswriter.hh"
#include "rcpgenerator.hh"
#include <boost/lexical_cast.hpp>
#include <set>
#include <bitset>

#include "namespaces.hh"
#include "namespaces.hh"

#define includeboilerplate(RNAME)   RNAME##RecordContent(const DNSRecord& dr, PacketReader& pr); \
  RNAME##RecordContent(const string& zoneData);                                                  \
  static void report(void);                                                                      \
  static void unreport(void);                                                                    \
  static DNSRecordContent* make(const DNSRecord &dr, PacketReader& pr);                          \
  static DNSRecordContent* make(const string& zonedata);                                         \
  string getZoneRepresentation() const;                                                          \
  void toPacket(DNSPacketWriter& pw);                                                            \
  template<class Convertor> void xfrPacket(Convertor& conv);                             

class NAPTRRecordContent : public DNSRecordContent
{
public:
  NAPTRRecordContent(uint16_t order, uint16_t preference, string flags, string services, string regexp, string replacement);

  includeboilerplate(NAPTR);
  template<class Convertor> void xfrRecordContent(Convertor& conv);
private:
  uint16_t d_order, d_preference;
  string d_flags, d_services, d_regexp, d_replacement;
};


class ARecordContent : public DNSRecordContent
{
public:
  explicit ARecordContent(uint32_t ip);
  includeboilerplate(A);
  void doRecordCheck(const DNSRecord& dr);
  uint32_t getIP() const;

private:
  uint32_t d_ip;
};

class AAAARecordContent : public DNSRecordContent
{
public:
  AAAARecordContent(std::string &val);
  includeboilerplate(AAAA);
private:
  std::string d_ip6;
};

class MXRecordContent : public DNSRecordContent
{
public:
  MXRecordContent(uint16_t preference, const string& mxname);

  includeboilerplate(MX)

  uint16_t d_preference;
  string d_mxname;
};

class KXRecordContent : public DNSRecordContent
{
public:
  KXRecordContent(uint16_t preference, const string& exchanger);

  includeboilerplate(KX)

private:
  uint16_t d_preference;
  string d_exchanger;
};

class IPSECKEYRecordContent : public DNSRecordContent
{
public:
  IPSECKEYRecordContent(uint16_t preference, uint8_t gatewaytype, uint8_t algo, const std::string& gateway, const std::string &publickey);

  includeboilerplate(IPSECKEY)

private:
  uint8_t d_preference, d_gatewaytype, d_algorithm;
  string d_gateway, d_publickey;
  uint32_t d_ip4;
  string d_ip6;
};

class DHCIDRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(DHCID)

private:
  string d_content;
};


class SRVRecordContent : public DNSRecordContent
{
public:
  SRVRecordContent(uint16_t preference, uint16_t weight, uint16_t port, const string& target);

  includeboilerplate(SRV)

  uint16_t d_preference, d_weight, d_port;
  string d_target;
};

class TSIGRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(TSIG)
  TSIGRecordContent() : DNSRecordContent(QType::TSIG) {}

  string d_algoName;
  uint64_t d_time; // 48 bits
  uint16_t d_fudge;
  //  uint16_t d_macSize;
  string d_mac;
  uint16_t d_origID;
  uint16_t d_eRcode;
  // uint16_t d_otherLen
  string d_otherData;
};


class TXTRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(TXT)

private:
  string d_text;
};

class SPFRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(SPF)

private:
  string d_text;
};


class NSRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(NS)

private:
  string d_content;
};

class PTRRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(PTR)

private:
  string d_content;
};

class CNAMERecordContent : public DNSRecordContent
{
public:
  includeboilerplate(CNAME)

private:
  string d_content;
};

class ALIASRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(ALIAS)

private:
  string d_content;
};


class DNAMERecordContent : public DNSRecordContent
{
public:
  includeboilerplate(DNAME)

private:
  string d_content;
};


class MRRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(MR)

private:
  string d_alias;
};

class MINFORecordContent : public DNSRecordContent
{
public:
  includeboilerplate(MINFO)

private:
  string d_rmailbx;
  string d_emailbx;
};

class OPTRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(OPT)
  void getData(vector<pair<uint16_t, string> > &opts);
private:
  string d_data;
};


class HINFORecordContent : public DNSRecordContent
{
public:
  includeboilerplate(HINFO)

private:
  string d_cpu, d_host;
};

class RPRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(RP)

private:
  string d_mbox, d_info;
};


class DNSKEYRecordContent : public DNSRecordContent
{
public:
  DNSKEYRecordContent();
  includeboilerplate(DNSKEY)
  uint16_t getTag();

  uint16_t d_flags;
  uint8_t d_protocol;
  uint8_t d_algorithm;
  string d_key;
};

class DSRecordContent : public DNSRecordContent
{
public:
  DSRecordContent();
  includeboilerplate(DS)

  uint16_t d_tag;
  uint8_t d_algorithm, d_digesttype;
  string d_digest;
};

class DLVRecordContent : public DNSRecordContent
{
public:
  DLVRecordContent();
  includeboilerplate(DLV)

  uint16_t d_tag;
  uint8_t d_algorithm, d_digesttype;
  string d_digest;
};


class SSHFPRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(SSHFP)

private:
  uint8_t d_algorithm, d_fptype;
  string d_fingerprint;
};

class KEYRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(KEY)

private:
  uint16_t d_flags;
  uint8_t d_protocol, d_algorithm;
  string d_certificate;
};

class AFSDBRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(AFSDB)

private:
  uint16_t d_subtype;
  string d_hostname;
};


class CERTRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(CERT)

private:
  uint16_t d_type, d_tag;
  uint8_t d_algorithm;
  string d_certificate;
};

class TLSARecordContent : public DNSRecordContent
{
public:
  includeboilerplate(TLSA)

private:
  uint8_t d_certusage, d_selector, d_matchtype;
  string d_cert;
};


class RRSIGRecordContent : public DNSRecordContent
{
public:
  RRSIGRecordContent(); 
  includeboilerplate(RRSIG)

  uint16_t d_type;
  uint8_t d_algorithm, d_labels;
  uint32_t d_originalttl, d_sigexpire, d_siginception;
  uint16_t d_tag;
  string d_signer, d_signature;
};



//namespace {
  struct soatimes 
  {
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;
    uint32_t minimum;
  };
//}

class RKEYRecordContent : public DNSRecordContent
{
public:
  RKEYRecordContent();
  includeboilerplate(RKEY)
  uint16_t d_flags;
  uint8_t d_protocol, d_algorithm;
  string d_key;
};

class SOARecordContent : public DNSRecordContent
{
public:
  includeboilerplate(SOA)
  SOARecordContent(const string& mname, const string& rname, const struct soatimes& st);

  string d_mname;
  string d_rname;
  struct soatimes d_st;
};

class NSECRecordContent : public DNSRecordContent
{
public:
  static void report(void);
  NSECRecordContent() : DNSRecordContent(47)
  {}
  NSECRecordContent(const string& content, const string& zone="");

  static DNSRecordContent* make(const DNSRecord &dr, PacketReader& pr);
  static DNSRecordContent* make(const string& content);
  string getZoneRepresentation() const;
  void toPacket(DNSPacketWriter& pw);
  string d_next;
  std::set<uint16_t> d_set;
private:
};

class NSEC3RecordContent : public DNSRecordContent
{
public:
  static void report(void);
  NSEC3RecordContent() : DNSRecordContent(50)
  {}
  NSEC3RecordContent(const string& content, const string& zone="");

  static DNSRecordContent* make(const DNSRecord &dr, PacketReader& pr);
  static DNSRecordContent* make(const string& content);
  string getZoneRepresentation() const;
  void toPacket(DNSPacketWriter& pw);

  uint8_t d_algorithm, d_flags;
  uint16_t d_iterations;
  uint8_t d_saltlength;
  string d_salt;
  uint8_t d_nexthashlength;
  string d_nexthash;
  std::set<uint16_t> d_set;

private:
};


class NSEC3PARAMRecordContent : public DNSRecordContent
{
public:
  static void report(void);
  NSEC3PARAMRecordContent() : DNSRecordContent(51)
  {}
  NSEC3PARAMRecordContent(const string& content, const string& zone="");

  static DNSRecordContent* make(const DNSRecord &dr, PacketReader& pr);
  static DNSRecordContent* make(const string& content);
  string getZoneRepresentation() const;
  void toPacket(DNSPacketWriter& pw);


  uint8_t d_algorithm, d_flags;
  uint16_t d_iterations;
  uint8_t d_saltlength;
  string d_salt;
};


class LOCRecordContent : public DNSRecordContent
{
public:
  static void report(void);
  LOCRecordContent() : DNSRecordContent(QType::LOC)
  {}
  LOCRecordContent(const string& content, const string& zone="");

  static DNSRecordContent* make(const DNSRecord &dr, PacketReader& pr);
  static DNSRecordContent* make(const string& content);
  string getZoneRepresentation() const;
  void toPacket(DNSPacketWriter& pw);

  uint8_t d_version, d_size, d_horizpre, d_vertpre;
  uint32_t d_latitude, d_longitude, d_altitude;
  
private:
};


class WKSRecordContent : public DNSRecordContent
{
public:
  static void report(void);
  WKSRecordContent() : DNSRecordContent(QType::WKS)
  {}
  WKSRecordContent(const string& content, const string& zone="");

  static DNSRecordContent* make(const DNSRecord &dr, PacketReader& pr);
  static DNSRecordContent* make(const string& content);
  string getZoneRepresentation() const;
  void toPacket(DNSPacketWriter& pw);

  uint32_t d_ip;
  std::bitset<65535> d_services;
private:
};

class EUI48RecordContent : public DNSRecordContent 
{
public:
  EUI48RecordContent() : DNSRecordContent(QType::EUI48) {};
  static void report(void);
  static DNSRecordContent* make(const DNSRecord &dr, PacketReader& pr);
  static DNSRecordContent* make(const string& zone);
  void toPacket(DNSPacketWriter& pw);
  string getZoneRepresentation() const;
private:
 // storage for the bytes
 uint8_t d_eui48[6]; 
};

class EUI64RecordContent : public DNSRecordContent
{
public:
  EUI64RecordContent() : DNSRecordContent(QType::EUI64) {};
  static void report(void);
  static DNSRecordContent* make(const DNSRecord &dr, PacketReader& pr);
  static DNSRecordContent* make(const string& zone);
  void toPacket(DNSPacketWriter& pw);
  string getZoneRepresentation() const;
private:
 // storage for the bytes
 uint8_t d_eui64[8];
};

class TKEYRecordContent : public DNSRecordContent
{
public:
  TKEYRecordContent();
  includeboilerplate(TKEY)

  // storage for the bytes
  string d_algo;
  uint32_t d_inception;
  uint32_t d_expiration;
  uint16_t d_mode;
  uint16_t d_error;
  uint16_t d_keysize;
  string d_key;
  uint16_t d_othersize;
  string d_other;
private:
};

#define boilerplate(RNAME, RTYPE)                                                                         \
RNAME##RecordContent::DNSRecordContent* RNAME##RecordContent::make(const DNSRecord& dr, PacketReader& pr) \
{                                                                                                  \
  return new RNAME##RecordContent(dr, pr);                                                         \
}                                                                                                  \
                                                                                                   \
RNAME##RecordContent::RNAME##RecordContent(const DNSRecord& dr, PacketReader& pr) : DNSRecordContent(RTYPE) \
{                                                                                                  \
  doRecordCheck(dr);                                                                               \
  xfrPacket(pr);                                                                                   \
}                                                                                                  \
                                                                                                   \
RNAME##RecordContent::DNSRecordContent* RNAME##RecordContent::make(const string& zonedata)         \
{                                                                                                  \
  return new RNAME##RecordContent(zonedata);                                                       \
}                                                                                                  \
                                                                                                   \
void RNAME##RecordContent::toPacket(DNSPacketWriter& pw)                                           \
{                                                                                                  \
  this->xfrPacket(pw);                                                                             \
}                                                                                                  \
                                                                                                   \
void RNAME##RecordContent::report(void)                                                            \
{                                                                                                  \
  regist(1, RTYPE, &RNAME##RecordContent::make, &RNAME##RecordContent::make, #RNAME);              \
  regist(254, RTYPE, &RNAME##RecordContent::make, &RNAME##RecordContent::make, #RNAME);            \
}                                                                                                  \
void RNAME##RecordContent::unreport(void)                                                          \
{                                                                                                  \
  unregist(1, RTYPE);                                                                              \
  unregist(254, RTYPE);                                                                            \
}                                                                                                  \
                                                                                                   \
RNAME##RecordContent::RNAME##RecordContent(const string& zoneData) : DNSRecordContent(RTYPE)       \
{                                                                                                  \
  try {                                                                                            \
    RecordTextReader rtr(zoneData);                                                                \
    xfrPacket(rtr);                                                                                \
  }                                                                                                \
  catch(RecordTextException& rtr) {                                                                \
    throw MOADNSException("Parsing record content: "+string(rtr.what()));                          \
  }        											   \
}                                                                                                  \
                                                                                                   \
string RNAME##RecordContent::getZoneRepresentation() const                                         \
{                                                                                                  \
  string ret;                                                                                      \
  RecordTextWriter rtw(ret);                                                                       \
  const_cast<RNAME##RecordContent*>(this)->xfrPacket(rtw);                                         \
  return ret;                                                                                      \
}                                                                                                  
                                                                                           

#define boilerplate_conv(RNAME, TYPE, CONV)                       \
boilerplate(RNAME, TYPE)                                          \
template<class Convertor>                                         \
void RNAME##RecordContent::xfrPacket(Convertor& conv)             \
{                                                                 \
  CONV;                                                           \
  if (conv.eof() == false) throw MOADNSException("All data was not consumed"); \
}                                                                 \

struct EDNSOpts
{
  uint16_t d_packetsize;
  uint8_t d_extRCode, d_version;
  uint16_t d_Z;
  vector<pair<uint16_t, string> > d_options;
  enum zFlags { DNSSECOK=32768 };
};
//! Convenience function that fills out EDNS0 options, and returns true if there are any

class MOADNSParser;
bool getEDNSOpts(const MOADNSParser& mdp, EDNSOpts* eo);

void reportBasicTypes();
void reportOtherTypes();
void reportAllTypes();

#endif 
