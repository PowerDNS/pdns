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

#include <boost/tuple/tuple.hpp>
#include <boost/tuple/tuple_comparison.hpp>
#include "dns.hh"
#include "dnswriter.hh"
#include "dnsname.hh"
#include "pdnsexception.hh"
#include "iputils.hh"

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
  PacketReader(const std::string& content, uint16_t initialPos=sizeof(dnsheader))
    : d_pos(initialPos), d_startrecordpos(initialPos), d_content(content)
  {
    if(content.size() > std::numeric_limits<uint16_t>::max())
      throw std::out_of_range("packet too large");

    d_recordlen = (uint16_t) content.size();
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

  void xfrCAWithoutPort(uint8_t version, ComboAddress &val) {
    string blob;
    if (version == 4) xfrBlob(blob, 4);
    else if (version == 6) xfrBlob(blob, 16);
    else throw runtime_error("invalid IP protocol");
    val = makeComboAddressFromRaw(version, blob);
  }

  void xfrCAPort(ComboAddress &val) {
    uint16_t port;
    xfr16BitInt(port);
    val.sin4.sin_port = port;
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

  void xfrText(string &text, bool multi=false, bool lenField=true)
  {
    text=getText(multi, lenField);
  }

  void xfrUnquotedText(string &text, bool lenField){
    text=getUnquotedText(lenField);
  }

  void xfrBlob(string& blob);
  void xfrBlobNoSpaces(string& blob, int len);
  void xfrBlob(string& blob, int length);
  void xfrHexBlob(string& blob, bool keepReading=false);

  void getDnsrecordheader(struct dnsrecordheader &ah);
  void copyRecord(vector<unsigned char>& dest, uint16_t len);
  void copyRecord(unsigned char* dest, uint16_t len);

  DNSName getName();
  string getText(bool multi, bool lenField);
  string getUnquotedText(bool lenField);


  bool eof() { return true; };
  const string getRemaining() const {
    return "";
  };

  uint16_t getPosition() const
  {
    return d_pos;
  }

  void skip(uint16_t n)
  {
    d_pos += n;
  }

private:
  uint16_t d_pos;
  uint16_t d_startrecordpos; // needed for getBlob later on
  uint16_t d_recordlen;      // ditto
  uint16_t not_used; // Aligns the whole class on 8-byte boundries
  const std::string& d_content;
};

struct DNSRecord;

class DNSRecordContent
{
public:
  static std::shared_ptr<DNSRecordContent> mastermake(const DNSRecord &dr, PacketReader& pr);
  static std::shared_ptr<DNSRecordContent> mastermake(const DNSRecord &dr, PacketReader& pr, uint16_t opcode);
  static std::shared_ptr<DNSRecordContent> mastermake(uint16_t qtype, uint16_t qclass, const string& zone);
  static std::unique_ptr<DNSRecordContent> makeunique(uint16_t qtype, uint16_t qclass, const string& content);

  virtual std::string getZoneRepresentation(bool noDot=false) const = 0;
  virtual ~DNSRecordContent() {}
  virtual void toPacket(DNSPacketWriter& pw)=0;
  virtual string serialize(const DNSName& qname, bool canonic=false, bool lowerCase=false) // it would rock if this were const, but it is too hard
  {
    vector<uint8_t> packet;
    DNSPacketWriter pw(packet, g_rootdnsname, 1);
    if(canonic)
      pw.setCanonic(true);

    if(lowerCase)
      pw.setLowercase(true);

    pw.startRecord(qname, this->getType());
    this->toPacket(pw);
    
    string record;
    pw.getRecordPayload(record); // needs to be called before commit()
    return record;
  }

  virtual bool operator==(const DNSRecordContent& rhs) const
  {
    return typeid(*this)==typeid(rhs) && this->getZoneRepresentation() == rhs.getZoneRepresentation();
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
    
    if(boost::starts_with(name, "TYPE") || boost::starts_with(name, "type"))
      return (uint16_t) pdns_stou(name.substr(4));
    
    throw runtime_error("Unknown DNS type '"+name+"'");
  }

  static const string NumberToType(uint16_t num, uint16_t classnum=1)
  {
    t2namemap_t::const_iterator iter = getT2Namemap().find(make_pair(classnum, num));
    if(iter == getT2Namemap().end()) 
      return "TYPE" + std::to_string(num);
      //      throw runtime_error("Unknown DNS type with numerical id "+std::to_string(num));
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
  DNSRecord() : d_type(0), d_class(QClass::IN), d_ttl(0), d_clen(0), d_place(DNSResourceRecord::ANSWER)
  {}
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
    if(tie(d_name, d_type, d_class, d_ttl) < tie(rhs.d_name, rhs.d_type, rhs.d_class, rhs.d_ttl))
      return true;
    
    if(tie(d_name, d_type, d_class, d_ttl) != tie(rhs.d_name, rhs.d_type, rhs.d_class, rhs.d_ttl))
      return false;
    
    string lzrp, rzrp;
    if(d_content)
      lzrp=toLower(d_content->getZoneRepresentation());
    if(rhs.d_content)
      rzrp=toLower(rhs.d_content->getZoneRepresentation());
    
    return lzrp < rzrp;
  }

  // this orders in canonical order and keeps the SOA record on top
  static bool prettyCompare(const DNSRecord& a, const DNSRecord& b) 
  {
    auto aType = (a.d_type == QType::SOA) ? 0 : a.d_type; 
    auto bType = (b.d_type == QType::SOA) ? 0 : b.d_type; 

    if(a.d_name.canonCompare(b.d_name))
      return true;
    if(b.d_name.canonCompare(a.d_name))
      return false;

    if(tie(aType, a.d_class, a.d_ttl) < tie(bType, b.d_class, b.d_ttl))
      return true;
    
    if(tie(aType, a.d_class, a.d_ttl) != tie(bType, b.d_class, b.d_ttl))
      return false;
    
    string lzrp, rzrp;
    if(a.d_content)
      lzrp=toLower(a.d_content->getZoneRepresentation());
    if(b.d_content)
      rzrp=toLower(b.d_content->getZoneRepresentation());
    
    return lzrp < rzrp;
  }


  bool operator==(const DNSRecord& rhs) const
  {
    if(d_type != rhs.d_type || d_class != rhs.d_class || d_name != rhs.d_name)
      return false;
    
    return *d_content == *rhs.d_content;
  }
};

struct DNSZoneRecord
{
  int domain_id{-1};
  uint8_t scopeMask{0};
  int signttl{0};
  DNSName wildcardname;
  bool auth{true};
  DNSRecord dr;
};


//! This class can be used to parse incoming packets, and is copyable
class MOADNSParser : public boost::noncopyable
{
public:
  //! Parse from a string
  MOADNSParser(bool query, const string& buffer): d_tsigPos(0)
  {
    init(query, buffer);
  }

  //! Parse from a pointer and length
  MOADNSParser(bool query, const char *packet, unsigned int len) : d_tsigPos(0)
  {
    init(query, std::string(packet, len));
  }

  DNSName d_qname;
  uint16_t d_qclass, d_qtype;
  //uint8_t d_rcode;
  dnsheader d_header;

  typedef vector<pair<DNSRecord, uint16_t > > answers_t;
  
  //! All answers contained in this packet (everything *but* the question section)
  answers_t d_answers;

  uint16_t getTSIGPos() const
  {
    return d_tsigPos;
  }
private:
  void init(bool query, const std::string& packet);
  uint16_t d_tsigPos;
};

string simpleCompress(const string& label, const string& root="");
void ageDNSPacket(char* packet, size_t length, uint32_t seconds);
void ageDNSPacket(std::string& packet, uint32_t seconds);
void editDNSPacketTTL(char* packet, size_t length, std::function<uint32_t(uint8_t, uint16_t, uint16_t, uint32_t)> visitor);
uint32_t getDNSPacketMinTTL(const char* packet, size_t length, bool* seenAuthSOA=nullptr);
uint32_t getDNSPacketLength(const char* packet, size_t length);
uint16_t getRecordsOfTypeCount(const char* packet, size_t length, uint8_t section, uint16_t type);
bool getEDNSUDPPayloadSizeAndZ(const char* packet, size_t length, uint16_t* payloadSize, uint16_t* z);

template<typename T>
std::shared_ptr<T> getRR(const DNSRecord& dr)
{
  return std::dynamic_pointer_cast<T>(dr.d_content);
}

#endif
