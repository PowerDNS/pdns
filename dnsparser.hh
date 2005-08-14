#ifndef DNSPARSER_HH
#define DNSPARSER_HH

#include <map>
#include <sstream>
#include <stdexcept>
#include <pcap.h>
#include <iostream>
#include <vector>
#include <errno.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include "misc.hh"
#include <boost/shared_ptr.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>
namespace {
  typedef HEADER dnsheader;
}

using namespace std;
using namespace boost;
typedef runtime_error MOADNSException;

struct dnsrecordheader
{
  u_int16_t d_type;
  u_int16_t d_class;
  u_int32_t d_ttl;
  u_int16_t d_clen;
} __attribute__((packed));


class MOADNSParser;

class PacketReader
{
public:
  PacketReader(const vector<u_int8_t>& content) 
    : d_pos(0), d_content(content)
  {}

  u_int32_t get32BitInt();
  u_int16_t get16BitInt();
  static u_int16_t get16BitInt(const vector<unsigned char>&content, u_int16_t& pos);
  static void getLabelFromContent(const vector<u_int8_t>& content, u_int16_t& frompos, string& ret, int recurs);
  u_int8_t get8BitInt();
  void getDnsrecordheader(struct dnsrecordheader &ah);
  void copyRecord(vector<unsigned char>& dest, u_int16_t len);
  void copyRecord(unsigned char* dest, u_int16_t len);
  string getLabel(unsigned int recurs=0);

  u_int16_t d_pos;
private:
  const vector<u_int8_t>& d_content;

};

class DNSRecord;

class DNSRecordContent
{
public:
  static DNSRecordContent* mastermake(const DNSRecord &dr, PacketReader& pr);
  virtual std::string getZoneRepresentation() const = 0;
  virtual ~DNSRecordContent() {}

  std::string label;
  struct dnsrecordheader header;

  typedef DNSRecordContent* makerfunc_t(const struct DNSRecord& dr, PacketReader& pr);  
  static void regist(uint16_t cl, uint16_t ty, makerfunc_t* f, const char* name)
  {
    typemap[make_pair(cl,ty)]=f;
    namemap[make_pair(cl,ty)]=name;
  }

  static uint16_t TypeToNumber(const string& name)
  {
    for(namemap_t::const_iterator i=namemap.begin(); i!=namemap.end();++i)
      if(i->second==name)
	return i->first.second;

    throw runtime_error("Unknown DNS type '"+name+"'");

  }

  static const string NumberToType(uint16_t num)
  {
    if(!namemap.count(make_pair(1,num)))
      return "#" + lexical_cast<string>(num);
      //      throw runtime_error("Unknown DNS type with numerical id "+lexical_cast<string>(num));
    return namemap[make_pair(1,num)];
  }


protected:

  typedef std::map<std::pair<u_int16_t, u_int16_t>, makerfunc_t* > typemap_t;
  static typemap_t typemap;
  typedef std::map<std::pair<u_int16_t, u_int16_t>, string > namemap_t;
  static namemap_t namemap;
};

struct DNSRecord
{
  std::string d_label;
  u_int16_t d_type;
  u_int16_t d_class;
  u_int32_t d_ttl;
  u_int16_t d_clen;
  enum {Answer, Nameserver, Additional} d_place;
  boost::shared_ptr<DNSRecordContent> d_content;

  bool operator<(const DNSRecord& rhs) const
  {
    string lzrp, rzrp;
    if(d_content)
      lzrp=toLower(d_content->getZoneRepresentation());
    if(rhs.d_content)
      rzrp=toLower(rhs.d_content->getZoneRepresentation());
    
    string llabel=toLower(d_label);
    string rlabel=toLower(rhs.d_label);

    return 
      tie(llabel,     d_type,     d_class, lzrp) <
      tie(rlabel, rhs.d_type, rhs.d_class, rzrp);
  }

  bool operator==(const DNSRecord& rhs) const
  {
    string lzrp, rzrp;
    if(d_content)
      lzrp=toLower(d_content->getZoneRepresentation());
    if(rhs.d_content)
      rzrp=toLower(rhs.d_content->getZoneRepresentation());
    
    string llabel=toLower(d_label);
    string rlabel=toLower(rhs.d_label);
    
    return 
      tie(llabel,     d_type,     d_class, lzrp) ==
      tie(rlabel, rhs.d_type, rhs.d_class, rzrp);
  }
};


class MOADNSParser
{
public:
  MOADNSParser(const string& buffer) 
  {
    init(buffer.c_str(), buffer.size());
  }

  MOADNSParser(const char *packet, unsigned int len)
  {
    init(packet, len);
  }
  dnsheader d_header;
  string d_qname;
  u_int16_t d_qclass, d_qtype;
  uint8_t d_rcode;

  typedef vector<pair<DNSRecord, uint16_t > > answers_t;
  answers_t d_answers;

  shared_ptr<PacketReader> getPacketReader(uint16_t offset)
  {
    shared_ptr<PacketReader> pr(new PacketReader(d_content));
    pr->d_pos=offset;
    return pr;
  }
private:
  void getDnsrecordheader(struct dnsrecordheader &ah);
  void init(const char *packet, unsigned int len);
  vector<uint8_t> d_content;
};




#endif
