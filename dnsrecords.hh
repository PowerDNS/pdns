#ifndef PDNS_DNSRECORDS_HH
#define PDNS_DNSRECORDS_HH

#include "dnsparser.hh"
#include "dnswriter.hh"
#include <boost/lexical_cast.hpp>
using namespace std;
using namespace boost;


class NAPTRRecordContent : public DNSRecordContent
{
public:
  NAPTRRecordContent(uint16_t order, uint16_t preference, string flags, string services, string regexp, string replacement);
  NAPTRRecordContent(const DNSRecord& dr, PacketReader& pr);
  NAPTRRecordContent(const string& zoneData);

  static void report(void);
  static DNSRecordContent* make(const DNSRecord &dr, PacketReader& pr);
  string getZoneRepresentation() const;

  void toPacket(DNSPacketWriter& pw);

  template<class Convertor> void xfrPacket(Convertor& conv);

private:
  uint16_t d_order, d_preference;
  string d_flags, d_services, d_regexp, d_replacement;
};

class ARecordContent : public DNSRecordContent
{
public:
  ARecordContent(const DNSRecord& dr, PacketReader& pr);
  ARecordContent(const string& zone);

  static void report(void);

  static DNSRecordContent* make(const DNSRecord& dr, PacketReader& pr);

  template<class Convertor> void xfrPacket(Convertor& conv);
  uint32_t getIP() const;
  
  void toPacket(DNSPacketWriter& pw);
  string getZoneRepresentation() const;

private:
  uint32_t d_ip;
};


#endif 
