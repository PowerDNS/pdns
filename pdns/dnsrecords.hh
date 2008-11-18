/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2005 - 2007  PowerDNS.COM BV

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

#ifndef PDNS_DNSRECORDS_HH
#define PDNS_DNSRECORDS_HH

#include "dnsparser.hh"
#include "dnswriter.hh"
#include "rcpgenerator.hh"
#include <boost/lexical_cast.hpp>
#include <set>

using namespace std;
using namespace boost;

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

class MXRecordContent : public DNSRecordContent
{
public:
  MXRecordContent(uint16_t preference, const string& mxname);

  includeboilerplate(MX)

private:
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

private:
  uint16_t d_preference, d_weight, d_port;
  string d_target;
};

class TSIGRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(TSIG)

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

class MRRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(MR)

private:
  string d_alias;
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
  includeboilerplate(DNSKEY)

private:
  uint16_t d_flags;
  uint8_t d_protocol;
  uint8_t d_algorithm;
  string d_key;
};

class DSRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(DS)

private:
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

class RRSIGRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(RRSIG)

private:
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


class SOARecordContent : public DNSRecordContent
{
public:
  includeboilerplate(SOA)
  SOARecordContent(const string& mname, const string& rname, const struct soatimes& st);

private:
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

class LOCRecordContent : public DNSRecordContent
{
public:
  static void report(void);
  LOCRecordContent() : DNSRecordContent(ns_t_loc)
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

class URLRecordContent : public DNSRecordContent // Fake, 'fancy record' with type 256
{
public:
  includeboilerplate(URL)
private:
  string d_url;
};

class MBOXFWRecordContent : public DNSRecordContent // Fake, 'fancy record' with type 256
{
public:
  includeboilerplate(MBOXFW)
private:
  string d_mboxfw;
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
}                                                                                                  \
void RNAME##RecordContent::unreport(void)                                                          \
{                                                                                                  \
  unregist(1, RTYPE);                                                                              \
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
  }												   \
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
}                                                                 \

struct EDNSOpts
{
  uint16_t d_packetsize;
  uint8_t d_extRCode, d_version;
  uint16_t d_Z;
  vector<pair<uint16_t, string> > d_options;
};
//! Convenience function that fills out EDNS0 options, and returns true if there are any

class MOADNSParser;
bool getEDNSOpts(const MOADNSParser& mdp, EDNSOpts* eo);

void reportBasicTypes();
void reportOtherTypes();
void reportAllTypes();
void reportFancyTypes();

#endif 
