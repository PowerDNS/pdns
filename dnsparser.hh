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
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

#ifndef DNSPARSER_HH
#define DNSPARSER_HH

#include <map>
#include <sstream>
#include <stdexcept>
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
#include "dnswriter.hh"

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
    

//namespace {
  typedef HEADER dnsheader;
//}

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

  void xfrTime(uint32_t& val)
  {
    xfr32BitInt(val);
  }


  void xfr16BitInt(uint16_t& val)
  {
    val=get16BitInt();
  }

  void xfrType(uint16_t& val)
  {
    xfr16BitInt(val);
  }


  void xfr8BitInt(uint8_t& val)
  {
    val=get8BitInt();
  }


  void xfrLabel(string &label, bool compress=false)
  {
    label=getLabel();
  }

  void xfrText(string &text)
  {
    text=getText();
  }

  void xfrBlob(string& blob);
  void xfrHexBlob(string& blob);

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

struct DNSRecord;

class DNSRecordContent
{
public:
  static DNSRecordContent* mastermake(const DNSRecord &dr, PacketReader& pr);
  static DNSRecordContent* mastermake(uint16_t qtype, uint16_t qclass, const string& zone);

  virtual std::string getZoneRepresentation() const = 0;
  virtual ~DNSRecordContent() {}
  virtual void toPacket(DNSPacketWriter& pw)=0;
  virtual string serialize(const string& qname)
  {
    vector<uint8_t> packet;
    DNSPacketWriter pw(packet, "", 1);
    
    pw.startRecord(qname, d_qtype);
    this->toPacket(pw);
    pw.commit();
    
    string record;
    pw.getRecords(record);
    return record;
  }

  static shared_ptr<DNSRecordContent> unserialize(const string& qname, uint16_t qtype, const string& serialized);

  void doRecordCheck(const struct DNSRecord&){}

  std::string label;
  struct dnsrecordheader header;

  typedef DNSRecordContent* makerfunc_t(const struct DNSRecord& dr, PacketReader& pr);  
  typedef DNSRecordContent* zmakerfunc_t(const string& str);  

  static void regist(uint16_t cl, uint16_t ty, makerfunc_t* f, zmakerfunc_t* z, const char* name)
  {
    if(f)
      getTypemap()[make_pair(cl,ty)]=f;
    if(z)
      getZmakermap()[make_pair(cl,ty)]=z;

    getNamemap()[make_pair(cl,ty)]=name;
  }

  static uint16_t TypeToNumber(const string& name)
  {
    for(namemap_t::const_iterator i=getNamemap().begin(); i!=getNamemap().end();++i)
      if(!strcasecmp(i->second.c_str(), name.c_str()))
	return i->first.second;

    throw runtime_error("Unknown DNS type '"+name+"'");
  }

  static const string NumberToType(uint16_t num)
  {
    if(!getNamemap().count(make_pair(1,num)))
      return "#" + lexical_cast<string>(num);
      //      throw runtime_error("Unknown DNS type with numerical id "+lexical_cast<string>(num));
    return getNamemap()[make_pair(1,num)];
  }

  explicit DNSRecordContent(uint16_t type) : d_qtype(type)
  {}
  const uint16_t d_qtype;

protected:
  typedef std::map<std::pair<uint16_t, uint16_t>, makerfunc_t* > typemap_t;
  typedef std::map<std::pair<uint16_t, uint16_t>, zmakerfunc_t* > zmakermap_t;
  typedef std::map<std::pair<uint16_t, uint16_t>, string > namemap_t;

  static typemap_t& getTypemap();
  static namemap_t& getNamemap();
  static zmakermap_t& getZmakermap();
};

struct DNSRecord
{
  std::string d_label;
  uint16_t d_type;
  uint16_t d_class;
  uint32_t d_ttl;
  uint16_t d_clen;
  enum {Answer=1, Nameserver, Additional} d_place;
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

//! This class can be used to parse incoming packets, and is copyable
class MOADNSParser
{
public:
  //! Parse from a string
  MOADNSParser(const string& buffer) 
  {
    init(buffer.c_str(), buffer.size());
  }

  //! Parse from a pointer and length
  MOADNSParser(const char *packet, unsigned int len)
  {
    init(packet, len);
  }

  dnsheader d_header;
  string d_qname;
  uint16_t d_qclass, d_qtype;
  uint8_t d_rcode;

  typedef vector<pair<DNSRecord, uint16_t > > answers_t;
  
  //! All answers contained in this packet
  answers_t d_answers;

  shared_ptr<PacketReader> getPacketReader(uint16_t offset)
  {
    shared_ptr<PacketReader> pr(new PacketReader(d_content));
    pr->d_pos=offset;
    return pr;
  }

  struct EDNSOpts
  {
    uint16_t d_packetsize;
    uint8_t d_extRCode, d_version;
    uint16_t d_Z;
  };

  //! Convenience function that fills out EDNS0 options, and returns true if there are any
  bool getEDNSOpts(EDNSOpts* eo);

private:
  void getDnsrecordheader(struct dnsrecordheader &ah);
  void init(const char *packet, unsigned int len);
  vector<uint8_t> d_content;
};



#endif
