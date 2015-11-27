/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2005 - 2011 PowerDNS.COM BV

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

#ifndef DNSPARSER_HH
#define DNSPARSER_HH

#include <map>
#include <sstream>
#include <stdexcept>
#include <iostream>
#include <vector>
#include <errno.h>
// #include <netinet/in.h>
#include "misc.hh"

#include <boost/lexical_cast.hpp>
#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include "dns.hh"
#include "dnswriter.hh"
#include "dnsname.hh"
#include "pdnsexception.hh"

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
    
#include "namespaces.hh"
#include "namespaces.hh"

class MOADNSException : public runtime_error
{
public:
  MOADNSException(const string& str) : runtime_error(str)
  {}
};


class MOADNSParser;

class PacketReader
{
public:
  PacketReader(const vector<uint8_t>& content) 
    : d_pos(0), d_startrecordpos(0), d_content(content)
  {
    d_recordlen = content.size();
    not_used = 0;
  }

  uint32_t get32BitInt();
  uint16_t get16BitInt();
  uint8_t get8BitInt();
  
  void xfr48BitInt(uint64_t& val);

  void xfr32BitInt(uint32_t& val)
  {
    val=get32BitInt();
  }

  void xfrIP(uint32_t& val)
  {
    xfr32BitInt(val);
    val=htonl(val);
  }

  void xfrIP6(std::string &val) {
    xfrBlob(val, 16);
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


  void xfrName(DNSName &name, bool compress=false, bool noDot=false)
  {
    name=getName();
  }

  void xfrText(string &text, bool multi=false)
  {
    text=getText(multi);
  }

  void xfrBlob(string& blob);
  void xfrBlobNoSpaces(string& blob, int len);
  void xfrBlob(string& blob, int length);
  void xfrHexBlob(string& blob, bool keepReading=false);

  static uint16_t get16BitInt(const vector<unsigned char>&content, uint16_t& pos);

  void getDnsrecordheader(struct dnsrecordheader &ah);
  void copyRecord(vector<unsigned char>& dest, uint16_t len);
  void copyRecord(unsigned char* dest, uint16_t len);

  DNSName getName();
  string getText(bool multi);

  uint16_t d_pos;

  bool eof() { return true; };

private:
  uint16_t d_startrecordpos; // needed for getBlob later on
  uint16_t d_recordlen;      // ditto
  uint16_t not_used; // Alighns the whole class on 8-byte boundries
  const vector<uint8_t>& d_content;
};

struct DNSRecord;

class DNSRecordContent
{
public:
  static DNSRecordContent* mastermake(const DNSRecord &dr, PacketReader& pr);
  static DNSRecordContent* mastermake(const DNSRecord &dr, PacketReader& pr, uint16_t opcode);
  static DNSRecordContent* mastermake(uint16_t qtype, uint16_t qclass, const string& zone);
  static std::unique_ptr<DNSRecordContent> makeunique(uint16_t qtype, uint16_t qclass, const string& content);

  virtual std::string getZoneRepresentation(bool noDot=false) const = 0;
  virtual ~DNSRecordContent() {}
  virtual void toPacket(DNSPacketWriter& pw)=0;
  virtual string serialize(const DNSName& qname, bool canonic=false, bool lowerCase=false) // it would rock if this were const, but it is too hard
  {
    vector<uint8_t> packet;
    DNSName empty;
    DNSPacketWriter pw(packet, empty, 1);
    if(canonic)
      pw.setCanonic(true);

    if(lowerCase)
      pw.setLowercase(true);

    pw.startRecord(qname, this->getType());
    this->toPacket(pw);
    pw.commit();
    
    string record;
    pw.getRecords(record);
    return record;
  }

  static shared_ptr<DNSRecordContent> unserialize(const DNSName& qname, uint16_t qtype, const string& serialized);

  void doRecordCheck(const struct DNSRecord&){}

  typedef DNSRecordContent* makerfunc_t(const struct DNSRecord& dr, PacketReader& pr);  
  typedef DNSRecordContent* zmakerfunc_t(const string& str);  

  static void regist(uint16_t cl, uint16_t ty, makerfunc_t* f, zmakerfunc_t* z, const char* name)
  {
    if(f)
      getTypemap()[make_pair(cl,ty)]=f;
    if(z)
      getZmakermap()[make_pair(cl,ty)]=z;

    getT2Namemap().insert(make_pair(make_pair(cl,ty), name));
    getN2Typemap().insert(make_pair(name, make_pair(cl,ty)));
  }

  static void unregist(uint16_t cl, uint16_t ty) 
  {
    pair<uint16_t, uint16_t> key=make_pair(cl, ty);
    getTypemap().erase(key);
    getZmakermap().erase(key);
  }

  static uint16_t TypeToNumber(const string& name)
  {
    n2typemap_t::const_iterator iter = getN2Typemap().find(toUpper(name));
    if(iter != getN2Typemap().end())
      return iter->second.second;
    
    if(boost::starts_with(name, "TYPE"))
        return atoi(name.c_str()+4);
    
    throw runtime_error("Unknown DNS type '"+name+"'");
  }

  static const string NumberToType(uint16_t num, uint16_t classnum=1)
  {
    t2namemap_t::const_iterator iter = getT2Namemap().find(make_pair(classnum, num));
    if(iter == getT2Namemap().end()) 
      return "TYPE" + lexical_cast<string>(num);
      //      throw runtime_error("Unknown DNS type with numerical id "+lexical_cast<string>(num));
    return iter->second;
  }

  virtual uint16_t getType() const = 0;

protected:
  typedef std::map<std::pair<uint16_t, uint16_t>, makerfunc_t* > typemap_t;
  typedef std::map<std::pair<uint16_t, uint16_t>, zmakerfunc_t* > zmakermap_t;
  typedef std::map<std::pair<uint16_t, uint16_t>, string > t2namemap_t;
  typedef std::map<string, std::pair<uint16_t, uint16_t> > n2typemap_t;
  static typemap_t& getTypemap();
  static t2namemap_t& getT2Namemap();
  static n2typemap_t& getN2Typemap();
  static zmakermap_t& getZmakermap();
};

struct DNSRecord
{
  DNSRecord() {
    d_type = 0;
    d_class = QClass::IN;
    d_ttl = 0;
    d_clen = 0;
    d_place = DNSResourceRecord::ANSWER;
  }
  explicit DNSRecord(const DNSResourceRecord& rr);
  DNSName d_name;
  std::shared_ptr<DNSRecordContent> d_content;
  uint16_t d_type;
  uint16_t d_class;
  uint32_t d_ttl;
  uint16_t d_clen;
  DNSResourceRecord::Place d_place;

  bool operator<(const DNSRecord& rhs) const
  {
    if(tie(d_name, d_type, d_class) < tie(rhs.d_name, rhs.d_type, rhs.d_class))
      return true;
    
    if(tie(d_name, d_type, d_class) != tie(rhs.d_name, rhs.d_type, rhs.d_class))
      return false;
    
    string lzrp, rzrp;
    if(d_content)
      lzrp=toLower(d_content->getZoneRepresentation());
    if(rhs.d_content)
      rzrp=toLower(rhs.d_content->getZoneRepresentation());
    
    return lzrp < rzrp;
  }

  bool operator==(const DNSRecord& rhs) const
  {
    string lzrp, rzrp;
    if(d_content)
      lzrp=toLower(d_content->getZoneRepresentation());
    if(rhs.d_content)
      rzrp=toLower(rhs.d_content->getZoneRepresentation());
    
    string llabel=toLower(d_name.toString()); 
    string rlabel=toLower(rhs.d_name.toString()); 
    
    return 
      tie(llabel,     d_type,     d_class, lzrp) ==
      tie(rlabel, rhs.d_type, rhs.d_class, rzrp);
  }
};

//! This class can be used to parse incoming packets, and is copyable
class MOADNSParser : public boost::noncopyable
{
public:
  //! Parse from a string
  MOADNSParser(const string& buffer)  : d_tsigPos(0)
  {
    init(buffer.c_str(), (unsigned int)buffer.size());
  }

  //! Parse from a pointer and length
  MOADNSParser(const char *packet, unsigned int len) : d_tsigPos(0)
  {
    init(packet, len);
  }

  DNSName d_qname;
  uint16_t d_qclass, d_qtype;
  //uint8_t d_rcode;
  dnsheader d_header;

  typedef vector<pair<DNSRecord, uint16_t > > answers_t;
  
  //! All answers contained in this packet
  answers_t d_answers;

  shared_ptr<PacketReader> getPacketReader(uint16_t offset)
  {
    shared_ptr<PacketReader> pr(new PacketReader(d_content));
    pr->d_pos=offset;
    return pr;
  }

  uint16_t getTSIGPos()
  {
    return d_tsigPos;
  }
private:
  void getDnsrecordheader(struct dnsrecordheader &ah);
  void init(const char *packet, unsigned int len);
  vector<uint8_t> d_content;
  uint16_t d_tsigPos;
};

string simpleCompress(const string& label, const string& root="");
void simpleExpandTo(const string& label, unsigned int frompos, string& ret);
void ageDNSPacket(std::string& packet, uint32_t seconds);

template<typename T>
std::shared_ptr<T> getRR(const DNSRecord& dr)
{
  return std::dynamic_pointer_cast<T>(dr.d_content);
}

#endif
