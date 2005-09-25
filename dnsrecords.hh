#ifndef PDNS_DNSRECORDS_HH
#define PDNS_DNSRECORDS_HH

#include "dnsparser.hh"
#include "dnswriter.hh"
#include <boost/lexical_cast.hpp>
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

#endif 
