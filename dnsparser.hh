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

/** DNS records have three representations:
    1) in the packet
    2) parsed in a class, ready for use
    3) in the zone

    We should implement bidirectional transitions between 1&2 and 2&3.
    Currently we have: 1 -> 2
                       2 -> 3

    We can add:        2 -> 1  easily by reversing the packetwriter
    And we might be able to reverse 2 -> 3 as well
*/
    

namespace {
  typedef HEADER dnsheader;
}

using namespace std;
using namespace boost;
typedef runtime_error MOADNSException;

struct dnsrecordheader
{
  uint16_t d_type;
  uint16_t d_class;
  uint32_t d_ttl;
  uint16_t d_clen;
} __attribute__((packed));


class MOADNSParser;

class PacketReader
{
public:
  PacketReader(const vector<uint8_t>& content) 
    : d_pos(0), d_content(content)
  {}

  uint32_t get32BitInt();
  uint16_t get16BitInt();
  uint8_t get8BitInt();

  void xfr32BitInt(uint32_t& val)
  {
    val=get32BitInt();
  }

  void xfrIP(uint32_t& val)
  {
    xfr32BitInt(val);
  }

  void xfr16BitInt(uint16_t& val)
  {
    val=get16BitInt();
  }

  void xfr8BitInt(uint8_t& val)
  {
    val=get8BitInt();
  }


  void xfrLabel(string &label)
  {
    label=getLabel();
  }

  void xfrText(string &text)
  {
    text=getText();
  }

  void xfrBlob(string& blob);

  static uint16_t get16BitInt(const vector<unsigned char>&content, uint16_t& pos);
  static void getLabelFromContent(const vector<uint8_t>& content, uint16_t& frompos, string& ret, int recurs);

  void getDnsrecordheader(struct dnsrecordheader &ah);
  void copyRecord(vector<unsigned char>& dest, uint16_t len);
  void copyRecord(unsigned char* dest, uint16_t len);

  string getLabel(unsigned int recurs=0);
  string getText();

  uint16_t d_pos;

private:
  uint16_t d_startrecordpos; // needed for getBlob later on
  uint16_t d_recordlen;      // dito
  const vector<uint8_t>& d_content;
};

class DNSRecord;

class DNSRecordContent
{
public:
  static DNSRecordContent* mastermake(const DNSRecord &dr, PacketReader& pr);

  virtual std::string getZoneRepresentation() const = 0;
  virtual ~DNSRecordContent() {}

  void doRecordCheck(const struct DNSRecord&){}

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
      if(!strcasecmp(i->second.c_str(), name.c_str()))
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

  typedef std::map<std::pair<uint16_t, uint16_t>, makerfunc_t* > typemap_t;
  static typemap_t typemap;
  typedef std::map<std::pair<uint16_t, uint16_t>, string > namemap_t;
  static namemap_t namemap;
};

struct DNSRecord
{
  std::string d_label;
  uint16_t d_type;
  uint16_t d_class;
  uint32_t d_ttl;
  uint16_t d_clen;
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
  uint16_t d_qclass, d_qtype;
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
