/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2005  PowerDNS.COM BV

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as 
    published by the Free Software Foundation

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
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

class SRVRecordContent : public DNSRecordContent
{
public:
  SRVRecordContent(uint16_t preference, uint16_t weight, uint16_t port, const string& target);

  includeboilerplate(SRV)

private:
  uint16_t d_preference, d_weight, d_port;
  string d_target;
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


class OPTRecordContent : public DNSRecordContent
{
public:
  includeboilerplate(OPT)

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



namespace {
  struct soatimes 
  {
    uint32_t serial;
    uint32_t refresh;
    uint32_t retry;
    uint32_t expire;
    uint32_t minimum;
  };
}


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

  NSECRecordContent()
  {}

  NSECRecordContent(const string& content, const string& zone="");

  static DNSRecordContent* make(const DNSRecord &dr, PacketReader& pr);

  string getZoneRepresentation() const;
  void toPacket(DNSPacketWriter& pw);
  string d_next;
  std::set<uint16_t> d_set;
private:

};



#define boilerplate(RNAME, RTYPE)                                                                         \
RNAME##RecordContent::DNSRecordContent* RNAME##RecordContent::make(const DNSRecord& dr, PacketReader& pr) \
{                                                                                                  \
  return new RNAME##RecordContent(dr, pr);                                                         \
}                                                                                                  \
                                                                                                   \
RNAME##RecordContent::RNAME##RecordContent(const DNSRecord& dr, PacketReader& pr)                  \
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
  regist(1, RTYPE, &RNAME##RecordContent::make, #RNAME);                                           \
}                                                                                                  \
                                                                                                   \
RNAME##RecordContent::RNAME##RecordContent(const string& zoneData)                                 \
{                                                                                                  \
  RecordTextReader rtr(zoneData);                                                                  \
  xfrPacket(rtr);                                                                                  \
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

#endif 
