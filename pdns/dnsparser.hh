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
#pragma once
#include <atomic>
#include <map>
#include <sstream>
#include <stdexcept>
#include <iostream>
#include <unordered_set>
#include <utility>
#include <vector>
#include <cerrno>
// #include <netinet/in.h>
#include "misc.hh"

#include "dns.hh"
#include "dnswriter.hh"
#include "dnsname.hh"
#include "noinitvector.hh"
#include "pdnsexception.hh"
#include "iputils.hh"
#include "svc-records.hh"

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
  PacketReader(const std::string_view& content, uint16_t initialPos=sizeof(dnsheader), bool internalRepresentation = false)
    : d_pos(initialPos), d_startrecordpos(initialPos), d_content(content), d_internal(internalRepresentation)
  {
    if(content.size() > std::numeric_limits<uint16_t>::max())
      throw std::out_of_range("packet too large");

    d_recordlen = (uint16_t) content.size();
    not_used = 0;
  }

  uint32_t get32BitInt();
  uint16_t get16BitInt();
  uint8_t get8BitInt();

  void xfrNodeOrLocatorID(NodeOrLocatorID& val);
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

  void xfrName(DNSName& name, bool /* compress */ = false)
  {
    name = getName();
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
  void xfrSvcParamKeyVals(set<SvcParam> &kvs);

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
  uint16_t not_used; // Aligns the whole class on 8-byte boundaries
  const std::string_view d_content;
  bool d_internal;
};

struct DNSRecord;

class DNSRecordContent
{
public:
  static std::shared_ptr<DNSRecordContent> make(const DNSRecord& dr, PacketReader& pr);
  static std::shared_ptr<DNSRecordContent> make(const DNSRecord& dr, PacketReader& pr, uint16_t opcode);
  static std::shared_ptr<DNSRecordContent> make(uint16_t qtype, uint16_t qclass, const string& zone);
  static string upgradeContent(const DNSName& qname, const QType& qtype, const string& content);

  virtual std::string getZoneRepresentation(bool noDot=false) const = 0;
  virtual ~DNSRecordContent() = default;
  virtual void toPacket(DNSPacketWriter& pw) const = 0;
  // returns the wire format of the content or the full record, possibly including compressed pointers pointing to the owner name (unless canonic or lowerCase are set)
  [[nodiscard]] string serialize(const DNSName& qname, bool canonic = false, bool lowerCase = false, bool full = false) const
  {
    vector<uint8_t> packet;
    DNSPacketWriter packetWriter(packet, g_rootdnsname, QType::A);

    if (canonic) {
      packetWriter.setCanonic(true);
    }
    if (lowerCase) {
      packetWriter.setLowercase(true);
    }

    packetWriter.startRecord(qname, getType());
    toPacket(packetWriter);

    string record;
    if (full) {
      packetWriter.getWireFormatContent(record); // needs to be called before commit()
    } else {
      packetWriter.getRecordPayload(record); // needs to be called before commit()
    }
    return record;
  }

  virtual bool operator==(const DNSRecordContent& rhs) const
  {
    return typeid(*this)==typeid(rhs) && this->getZoneRepresentation() == rhs.getZoneRepresentation();
  }

  // parse the content in wire format, possibly including compressed pointers pointing to the owner name.
  // internalRepresentation is set when the data comes from an internal source,
  // such as the LMDB backend.
  static shared_ptr<DNSRecordContent> deserialize(const DNSName& qname, uint16_t qtype, const string& serialized, uint16_t qclass=QClass::IN, bool internalRepresentation = false);

  void doRecordCheck(const struct DNSRecord&){}

  typedef std::shared_ptr<DNSRecordContent> makerfunc_t(const struct DNSRecord& dr, PacketReader& pr);
  typedef std::shared_ptr<DNSRecordContent> zmakerfunc_t(const string& str);

  static void regist(uint16_t cl, uint16_t ty, makerfunc_t* f, zmakerfunc_t* z, const char* name)
  {
    assert(!d_locked.load()); // NOLINT: it's the API
    if(f)
      getTypemap()[pair(cl,ty)]=f;
    if(z)
      getZmakermap()[pair(cl,ty)]=z;

    getT2Namemap().emplace(pair(cl, ty), name);
    getN2Typemap().emplace(name, pair(cl, ty));
  }

  static bool isUnknownType(const string& name)
  {
    return boost::starts_with(name, "TYPE") || boost::starts_with(name, "type");
  }

  static uint16_t TypeToNumber(const string& name)
  {
    n2typemap_t::const_iterator iter = getN2Typemap().find(toUpper(name));
    if(iter != getN2Typemap().end())
      return iter->second.second;

    if (isUnknownType(name)) {
      return pdns::checked_stoi<uint16_t>(name.substr(4));
    }

    throw runtime_error("Unknown DNS type '"+name+"'");
  }

  static const string NumberToType(uint16_t num, uint16_t classnum = QClass::IN)
  {
    auto iter = getT2Namemap().find(pair(classnum, num));
    if(iter == getT2Namemap().end())
      return "TYPE" + std::to_string(num);
      //      throw runtime_error("Unknown DNS type with numerical id "+std::to_string(num));
    return iter->second;
  }

  /**
   * \brief Return whether we have implemented a content representation for this type
   */
  static bool isRegisteredType(uint16_t rtype, uint16_t rclass = QClass::IN);

  virtual uint16_t getType() const = 0;

  static void lock()
  {
    d_locked.store(true);
  }

  [[nodiscard]] virtual size_t sizeEstimate() const = 0;

protected:
  typedef std::map<std::pair<uint16_t, uint16_t>, makerfunc_t* > typemap_t;
  typedef std::map<std::pair<uint16_t, uint16_t>, zmakerfunc_t* > zmakermap_t;
  typedef std::map<std::pair<uint16_t, uint16_t>, string > t2namemap_t;
  typedef std::map<string, std::pair<uint16_t, uint16_t> > n2typemap_t;
  static typemap_t& getTypemap();
  static t2namemap_t& getT2Namemap();
  static n2typemap_t& getN2Typemap();
  static zmakermap_t& getZmakermap();
  static std::atomic<bool> d_locked;
};

struct DNSRecord
{
  DNSRecord() :
    d_class(QClass::IN)
  {}
  explicit DNSRecord(const DNSResourceRecord& rr);
  DNSRecord(const std::string& name,
            std::shared_ptr<DNSRecordContent> content,
            const uint16_t type,
            const uint16_t qclass = QClass::IN,
            const uint32_t ttl = 86400,
            const uint16_t clen = 0,
            const DNSResourceRecord::Place place = DNSResourceRecord::ANSWER) :
    d_name(DNSName(name)),
    d_content(std::move(content)),
    d_type(type),
    d_class(qclass),
    d_ttl(ttl),
    d_clen(clen),
    d_place(place) {}

  DNSName d_name;
private:
  std::shared_ptr<const DNSRecordContent> d_content;
public:
  uint16_t d_type{};
  uint16_t d_class{};
  uint32_t d_ttl{};
  uint16_t d_clen{};
  DNSResourceRecord::Place d_place{DNSResourceRecord::ANSWER};

  [[nodiscard]] std::string print(const std::string& indent = "") const
  {
    std::stringstream s;
    s << indent << "Content = " << d_content->getZoneRepresentation() << std::endl;
    s << indent << "Type = " << d_type << std::endl;
    s << indent << "Class = " << d_class << std::endl;
    s << indent << "TTL = " << d_ttl << std::endl;
    s << indent << "clen = " << d_clen << std::endl;
    s << indent << "Place = " << std::to_string(d_place) << std::endl;
    return s.str();
  }

  [[nodiscard]] std::string toString() const
  {
    std::string ret(d_name.toLogString());
    ret += '|';
    ret += QType(d_type).toString();
    ret += '|';
    ret += getContent()->getZoneRepresentation();
    return ret;
  }

  void setContent(const std::shared_ptr<const DNSRecordContent>& content)
  {
    d_content = content;
  }

  void setContent(std::shared_ptr<const DNSRecordContent>&& content)
  {
    d_content = std::move(content);
  }

  [[nodiscard]] const std::shared_ptr<const DNSRecordContent>& getContent() const
  {
    return d_content;
  }

  bool operator<(const DNSRecord& rhs) const
  {
    if(std::tie(d_name, d_type, d_class, d_ttl) < std::tie(rhs.d_name, rhs.d_type, rhs.d_class, rhs.d_ttl))
      return true;

    if(std::tie(d_name, d_type, d_class, d_ttl) != std::tie(rhs.d_name, rhs.d_type, rhs.d_class, rhs.d_ttl))
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

    if(std::tie(aType, a.d_class, a.d_ttl) < std::tie(bType, b.d_class, b.d_ttl))
      return true;

    if(std::tie(aType, a.d_class, a.d_ttl) != std::tie(bType, b.d_class, b.d_ttl))
      return false;

    string lzrp, rzrp;
    if(a.d_content)
      lzrp = a.d_content->getZoneRepresentation();
    if(b.d_content)
      rzrp = b.d_content->getZoneRepresentation();

    switch (a.d_type) {
    case QType::TXT:
    case QType::SPF:
#if !defined(RECURSOR)
    case QType::LUA:
#endif
      return lzrp < rzrp;
    default:
      return toLower(lzrp) < toLower(rzrp);
    }
  }

  bool operator==(const DNSRecord& rhs) const
  {
    if (d_type != rhs.d_type || d_class != rhs.d_class || d_name != rhs.d_name) {
      return false;
    }

    return *d_content == *rhs.d_content;
  }

  [[nodiscard]] size_t sizeEstimate() const
  {
    return sizeof(*this) + d_name.sizeEstimate() + (d_content ? d_content->sizeEstimate() : 0U);
  }
};

struct DNSZoneRecord
{
  domainid_t domain_id{UnknownDomainID};
  uint8_t scopeMask{0};
  int signttl{0};
  DNSName wildcardname;
  bool auth{true};
  bool disabled{false};
  DNSRecord dr;

  bool operator<(const DNSZoneRecord& other) const {
    return dr.d_ttl < other.dr.d_ttl;
  }
};

class UnknownRecordContent : public DNSRecordContent
{
public:
  UnknownRecordContent(const DNSRecord& dr, PacketReader& pr)
    : d_dr(dr)
  {
    pr.copyRecord(d_record, dr.d_clen);
  }

  UnknownRecordContent(const string& zone);

  string getZoneRepresentation(bool noDot) const override;
  void toPacket(DNSPacketWriter& pw) const override;
  uint16_t getType() const override
  {
    return d_dr.d_type;
  }

  const vector<uint8_t>& getRawContent() const
  {
    return d_record;
  }

  [[nodiscard]] size_t sizeEstimate() const override
  {
    return sizeof(*this) + d_dr.sizeEstimate() + d_record.size();
  }

private:
  DNSRecord d_dr;
  vector<uint8_t> d_record;
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
    init(query, std::string_view(packet, len));
  }

  DNSName d_qname;
  uint16_t d_qclass, d_qtype;
  dnsheader d_header;

  using answers_t = vector<DNSRecord>;

  //! All answers contained in this packet (everything *but* the question section)
  answers_t d_answers;

  uint16_t getTSIGPos() const
  {
    return d_tsigPos;
  }

  bool hasEDNS() const;

private:
  void init(bool query, const std::string_view& packet);
  uint16_t d_tsigPos;
};

string simpleCompress(const string& label, const string& root="");
void ageDNSPacket(char* packet, size_t length, uint32_t seconds, const dnsheader_aligned&);
void ageDNSPacket(std::string& packet, uint32_t seconds, const dnsheader_aligned&);
void editDNSPacketTTL(char* packet, size_t length, const std::function<uint32_t(uint8_t, uint16_t, uint16_t, uint32_t)>& visitor);
void clearDNSPacketRecordTypes(vector<uint8_t>& packet, const std::unordered_set<QType>& qtypes);
void clearDNSPacketRecordTypes(PacketBuffer& packet, const std::unordered_set<QType>& qtypes);
void clearDNSPacketRecordTypes(char* packet, size_t& length, const std::unordered_set<QType>& qtypes);
uint32_t getDNSPacketMinTTL(const char* packet, size_t length, bool* seenAuthSOA=nullptr);
uint32_t getDNSPacketLength(const char* packet, size_t length);
uint16_t getRecordsOfTypeCount(const char* packet, size_t length, uint8_t section, uint16_t type);
bool getEDNSUDPPayloadSizeAndZ(const char* packet, size_t length, uint16_t* payloadSize, uint16_t* z);
/* call the visitor for every records in the answer, authority and additional sections, passing the section, class, type, ttl, rdatalength and rdata
   to the visitor. Stops whenever the visitor returns false or at the end of the packet */
bool visitDNSPacket(const std::string_view& packet, const std::function<bool(uint8_t, uint16_t, uint16_t, uint32_t, uint16_t, const char*)>& visitor);

template<typename T>
std::shared_ptr<const T> getRR(const DNSRecord& dr)
{
  return std::dynamic_pointer_cast<const T>(dr.getContent());
}

/** Simple DNSPacketMangler. Ritual is: get a pointer into the packet and moveOffset() to beyond your needs
 *  If you survive that, feel free to read from the pointer */
class DNSPacketMangler
{
public:
  explicit DNSPacketMangler(std::string& packet)
    : d_packet(packet.data()), d_length(packet.length()), d_notyouroffset(12), d_offset(d_notyouroffset)
  {}
  DNSPacketMangler(char* packet, size_t length)
    : d_packet(packet), d_length(length), d_notyouroffset(12), d_offset(d_notyouroffset)
  {}

  /*! Advances past a wire-format domain name
   * The name is not checked for adherence to length restrictions.
   * Compression pointers are not followed.
   */
  void skipDomainName()
  {
    uint8_t len;
    while((len=get8BitInt())) {
      if(len >= 0xc0) { // extended label
        get8BitInt();
        return;
      }
      skipBytes(len);
    }
  }

  void skipBytes(uint16_t bytes)
  {
    moveOffset(bytes);
  }
  void rewindBytes(uint16_t by)
  {
    rewindOffset(by);
  }
  uint32_t get32BitInt()
  {
    const char* p = d_packet + d_offset;
    moveOffset(4);
    uint32_t ret;
    memcpy(&ret, p, sizeof(ret));
    return ntohl(ret);
  }
  uint16_t get16BitInt()
  {
    const char* p = d_packet + d_offset;
    moveOffset(2);
    uint16_t ret;
    memcpy(&ret, p, sizeof(ret));
    return ntohs(ret);
  }

  uint8_t get8BitInt()
  {
    const char* p = d_packet + d_offset;
    moveOffset(1);
    return *p;
  }

  void skipRData()
  {
    auto toskip = get16BitInt();
    moveOffset(toskip);
  }

  void decreaseAndSkip32BitInt(uint32_t decrease)
  {
    const char *p = d_packet + d_offset;
    moveOffset(4);

    uint32_t tmp;
    memcpy(&tmp, p, sizeof(tmp));
    tmp = ntohl(tmp);
    if (tmp > decrease) {
      tmp -= decrease;
    } else {
      tmp = 0;
    }
    tmp = htonl(tmp);
    memcpy(d_packet + d_offset-4, (const char*)&tmp, sizeof(tmp));
  }

  void setAndSkip32BitInt(uint32_t value)
  {
    moveOffset(4);

    value = htonl(value);
    memcpy(d_packet + d_offset-4, (const char*)&value, sizeof(value));
  }

  uint32_t getOffset() const
  {
    return d_offset;
  }

private:
  void moveOffset(uint16_t by)
  {
    d_notyouroffset += by;
    if(d_notyouroffset > d_length)
      throw std::out_of_range("dns packet out of range: "+std::to_string(d_notyouroffset) +" > "
      + std::to_string(d_length) );
  }

  void rewindOffset(uint16_t by)
  {
    if(d_notyouroffset < by)
      throw std::out_of_range("Rewinding dns packet out of range: "+std::to_string(d_notyouroffset) +" < "
                              + std::to_string(by));
    d_notyouroffset -= by;
    if(d_notyouroffset < 12)
      throw std::out_of_range("Rewinding dns packet out of range: "+std::to_string(d_notyouroffset) +" < "
                              + std::to_string(12));
  }

  char* d_packet;
  size_t d_length;

  uint32_t d_notyouroffset;  // only 'moveOffset' can touch this
  const uint32_t&  d_offset; // look.. but don't touch
};

string txtEscape(const string &name);
