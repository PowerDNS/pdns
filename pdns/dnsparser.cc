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
#include "dnsparser.hh"
#include "dnswriter.hh"
#include <boost/algorithm/string.hpp>
#include <boost/format.hpp>

#include "namespaces.hh"

class UnknownRecordContent : public DNSRecordContent
{
public:
  UnknownRecordContent(const DNSRecord& dr, PacketReader& pr) 
    : d_dr(dr)
  {
    pr.copyRecord(d_record, dr.d_clen);
  }

  UnknownRecordContent(const string& zone) 
  {
    // parse the input
    vector<string> parts;
    stringtok(parts, zone);
    if(parts.size()!=3 && !(parts.size()==2 && equals(parts[1],"0")) )
      throw MOADNSException("Unknown record was stored incorrectly, need 3 fields, got "+std::to_string(parts.size())+": "+zone );
    const string& relevant=(parts.size() > 2) ? parts[2] : "";
    unsigned int total=pdns_stou(parts[1]);
    if(relevant.size() % 2 || relevant.size() / 2 != total)
      throw MOADNSException((boost::format("invalid unknown record length: size not equal to length field (%d != 2 * %d)") % relevant.size() % total).str());
    string out;
    out.reserve(total+1);
    for(unsigned int n=0; n < total; ++n) {
      int c;
      sscanf(relevant.c_str()+2*n, "%02x", &c);
      out.append(1, (char)c);
    }

    d_record.insert(d_record.end(), out.begin(), out.end());
  }

  string getZoneRepresentation(bool noDot) const override
  {
    ostringstream str;
    str<<"\\# "<<(unsigned int)d_record.size()<<" ";
    char hex[4];
    for(size_t n=0; n<d_record.size(); ++n) {
      snprintf(hex, sizeof(hex), "%02x", d_record.at(n));
      str << hex;
    }
    return str.str();
  }

  void toPacket(DNSPacketWriter& pw) override
  {
    pw.xfrBlob(string(d_record.begin(),d_record.end()));
  }

  uint16_t getType() const override
  {
    return d_dr.d_type;
  }
private:
  DNSRecord d_dr;
  vector<uint8_t> d_record;
};

shared_ptr<DNSRecordContent> DNSRecordContent::unserialize(const DNSName& qname, uint16_t qtype, const string& serialized)
{
  dnsheader dnsheader;
  memset(&dnsheader, 0, sizeof(dnsheader));
  dnsheader.qdcount=htons(1);
  dnsheader.ancount=htons(1);

  vector<uint8_t> packet; // build pseudo packet

  /* will look like: dnsheader, 5 bytes, encoded qname, dns record header, serialized data */

  string encoded=qname.toDNSString();

  packet.resize(sizeof(dnsheader) + 5 + encoded.size() + sizeof(struct dnsrecordheader) + serialized.size());

  uint16_t pos=0;

  memcpy(&packet[0], &dnsheader, sizeof(dnsheader)); pos+=sizeof(dnsheader);

  char tmp[6]="\x0" "\x0\x1" "\x0\x1"; // root question for ns_t_a
  memcpy(&packet[pos], &tmp, 5); pos+=5;

  memcpy(&packet[pos], encoded.c_str(), encoded.size()); pos+=(uint16_t)encoded.size();

  struct dnsrecordheader drh;
  drh.d_type=htons(qtype);
  drh.d_class=htons(QClass::IN);
  drh.d_ttl=0;
  drh.d_clen=htons(serialized.size());

  memcpy(&packet[pos], &drh, sizeof(drh)); pos+=sizeof(drh);
  if (serialized.size() > 0) {
    memcpy(&packet[pos], serialized.c_str(), serialized.size());
    pos += (uint16_t) serialized.size();
  }

  MOADNSParser mdp(false, (char*)&*packet.begin(), (unsigned int)packet.size());
  shared_ptr<DNSRecordContent> ret= mdp.d_answers.begin()->first.d_content;
  return ret;
}

std::shared_ptr<DNSRecordContent> DNSRecordContent::mastermake(const DNSRecord &dr,
                                               PacketReader& pr)
{
  uint16_t searchclass = (dr.d_type == QType::OPT) ? 1 : dr.d_class; // class is invalid for OPT

  typemap_t::const_iterator i=getTypemap().find(make_pair(searchclass, dr.d_type));
  if(i==getTypemap().end() || !i->second) {
    return std::make_shared<UnknownRecordContent>(dr, pr);
  }

  return i->second(dr, pr);
}

std::shared_ptr<DNSRecordContent> DNSRecordContent::mastermake(uint16_t qtype, uint16_t qclass,
                                               const string& content)
{
  zmakermap_t::const_iterator i=getZmakermap().find(make_pair(qclass, qtype));
  if(i==getZmakermap().end()) {
    return std::make_shared<UnknownRecordContent>(content);
  }

  return i->second(content);
}

std::shared_ptr<DNSRecordContent> DNSRecordContent::mastermake(const DNSRecord &dr, PacketReader& pr, uint16_t oc) {
  // For opcode UPDATE and where the DNSRecord is an answer record, we don't care about content, because this is
  // not used within the prerequisite section of RFC2136, so - we can simply use unknownrecordcontent.
  // For section 3.2.3, we do need content so we need to get it properly. But only for the correct QClasses.
  if (oc == Opcode::Update && dr.d_place == DNSResourceRecord::ANSWER && dr.d_class != 1)
    return std::make_shared<UnknownRecordContent>(dr, pr);

  uint16_t searchclass = (dr.d_type == QType::OPT) ? 1 : dr.d_class; // class is invalid for OPT

  typemap_t::const_iterator i=getTypemap().find(make_pair(searchclass, dr.d_type));
  if(i==getTypemap().end() || !i->second) {
    return std::make_shared<UnknownRecordContent>(dr, pr);
  }

  return i->second(dr, pr);
}


DNSRecordContent::typemap_t& DNSRecordContent::getTypemap()
{
  static DNSRecordContent::typemap_t typemap;
  return typemap;
}

DNSRecordContent::n2typemap_t& DNSRecordContent::getN2Typemap()
{
  static DNSRecordContent::n2typemap_t n2typemap;
  return n2typemap;
}

DNSRecordContent::t2namemap_t& DNSRecordContent::getT2Namemap()
{
  static DNSRecordContent::t2namemap_t t2namemap;
  return t2namemap;
}

DNSRecordContent::zmakermap_t& DNSRecordContent::getZmakermap()
{
  static DNSRecordContent::zmakermap_t zmakermap;
  return zmakermap;
}

DNSRecord::DNSRecord(const DNSResourceRecord& rr): d_name(rr.qname)
{
  d_type = rr.qtype.getCode();
  d_ttl = rr.ttl;
  d_class = rr.qclass;
  d_place = DNSResourceRecord::ANSWER;
  d_clen = 0;
  d_content = DNSRecordContent::mastermake(d_type, rr.qclass, rr.content);
}

// If you call this and you are not parsing a packet coming from a socket, you are doing it wrong.
DNSResourceRecord DNSResourceRecord::fromWire(const DNSRecord& d) {
  DNSResourceRecord rr;
  rr.qname = d.d_name;
  rr.qtype = QType(d.d_type);
  rr.ttl = d.d_ttl;
  rr.content = d.d_content->getZoneRepresentation(true);
  rr.auth = false;
  rr.qclass = d.d_class;
  return rr;
}

void MOADNSParser::init(bool query, const std::string& packet)
{
  if (packet.size() < sizeof(dnsheader))
    throw MOADNSException("Packet shorter than minimal header");
  
  memcpy(&d_header, packet.data(), sizeof(dnsheader));

  if(d_header.opcode != Opcode::Query && d_header.opcode != Opcode::Notify && d_header.opcode != Opcode::Update)
    throw MOADNSException("Can't parse non-query packet with opcode="+ std::to_string(d_header.opcode));

  d_header.qdcount=ntohs(d_header.qdcount);
  d_header.ancount=ntohs(d_header.ancount);
  d_header.nscount=ntohs(d_header.nscount);
  d_header.arcount=ntohs(d_header.arcount);

  if (query && (d_header.qdcount > 1))
    throw MOADNSException("Query with QD > 1 ("+std::to_string(d_header.qdcount)+")");
  
  unsigned int n=0;

  PacketReader pr(packet);
  bool validPacket=false;
  try {
    d_qtype = d_qclass = 0; // sometimes replies come in with no question, don't present garbage then

    for(n=0;n < d_header.qdcount; ++n) {
      d_qname=pr.getName();
      d_qtype=pr.get16BitInt();
      d_qclass=pr.get16BitInt();
    }

    struct dnsrecordheader ah;
    vector<unsigned char> record;
    bool seenTSIG = false;
    validPacket=true;
    d_answers.reserve((unsigned int)(d_header.ancount + d_header.nscount + d_header.arcount));
    for(n=0;n < (unsigned int)(d_header.ancount + d_header.nscount + d_header.arcount); ++n) {
      DNSRecord dr;
      
      if(n < d_header.ancount)
        dr.d_place=DNSResourceRecord::ANSWER;
      else if(n < d_header.ancount + d_header.nscount)
        dr.d_place=DNSResourceRecord::AUTHORITY;
      else 
        dr.d_place=DNSResourceRecord::ADDITIONAL;

      unsigned int recordStartPos=pr.getPosition();

      DNSName name=pr.getName();

      pr.getDnsrecordheader(ah);
      dr.d_ttl=ah.d_ttl;
      dr.d_type=ah.d_type;
      dr.d_class=ah.d_class;

      dr.d_name=name;
      dr.d_clen=ah.d_clen;

      if (query &&
          !(d_qtype == QType::IXFR && dr.d_place == DNSResourceRecord::AUTHORITY && dr.d_type == QType::SOA) && // IXFR queries have a SOA in their AUTHORITY section
          (dr.d_place == DNSResourceRecord::ANSWER || dr.d_place == DNSResourceRecord::AUTHORITY || (dr.d_type != QType::OPT && dr.d_type != QType::TSIG && dr.d_type != QType::SIG && dr.d_type != QType::TKEY) || ((dr.d_type == QType::TSIG || dr.d_type == QType::SIG || dr.d_type == QType::TKEY) && dr.d_class != QClass::ANY))) {
//        cerr<<"discarding RR, query is "<<query<<", place is "<<dr.d_place<<", type is "<<dr.d_type<<", class is "<<dr.d_class<<endl;
        dr.d_content=std::make_shared<UnknownRecordContent>(dr, pr);
      }
      else {
//        cerr<<"parsing RR, query is "<<query<<", place is "<<dr.d_place<<", type is "<<dr.d_type<<", class is "<<dr.d_class<<endl;
        dr.d_content=DNSRecordContent::mastermake(dr, pr, d_header.opcode);
      }

      /* XXX: XPF records should be allowed after TSIG as soon as the actual XPF option code has been assigned:
         if (dr.d_place == DNSResourceRecord::ADDITIONAL && seenTSIG && dr.d_type != QType::XPF)
      */
      if (dr.d_place == DNSResourceRecord::ADDITIONAL && seenTSIG) {
        /* only XPF records are allowed after a TSIG */
        throw MOADNSException("Packet ("+d_qname.toString()+"|#"+std::to_string(d_qtype)+") has an unexpected record ("+std::to_string(dr.d_type)+") after a TSIG one.");
      }

      if(dr.d_type == QType::TSIG && dr.d_class == QClass::ANY) {
        if(seenTSIG || dr.d_place != DNSResourceRecord::ADDITIONAL) {
          throw MOADNSException("Packet ("+d_qname.toLogString()+"|#"+std::to_string(d_qtype)+") has a TSIG record in an invalid position.");
        }
        seenTSIG = true;
        d_tsigPos = recordStartPos;
      }

      d_answers.push_back(make_pair(std::move(dr), pr.getPosition() - sizeof(dnsheader)));
    }

#if 0
    if(pr.getPosition()!=packet.size()) {
      throw MOADNSException("Packet ("+d_qname+"|#"+std::to_string(d_qtype)+") has trailing garbage ("+ std::to_string(pr.getPosition()) + " < " +
                            std::to_string(packet.size()) + ")");
    }
#endif
  }
  catch(const std::out_of_range &re) {
    if(validPacket && d_header.tc) { // don't sweat it over truncated packets, but do adjust an, ns and arcount
      if(n < d_header.ancount) {
        d_header.ancount=n; d_header.nscount = d_header.arcount = 0;
      }
      else if(n < d_header.ancount + d_header.nscount) {
        d_header.nscount = n - d_header.ancount; d_header.arcount=0;
      }
      else {
        d_header.arcount = n - d_header.ancount - d_header.nscount;
      }
    }
    else {
      throw MOADNSException("Error parsing packet of "+std::to_string(packet.size())+" bytes (rd="+
                            std::to_string(d_header.rd)+
                            "), out of bounds: "+string(re.what()));
    }
  }
}


void PacketReader::getDnsrecordheader(struct dnsrecordheader &ah)
{
  unsigned int n;
  unsigned char *p=reinterpret_cast<unsigned char*>(&ah);
  
  for(n=0; n < sizeof(dnsrecordheader); ++n) 
    p[n]=d_content.at(d_pos++);
  
  ah.d_type=ntohs(ah.d_type);
  ah.d_class=ntohs(ah.d_class);
  ah.d_clen=ntohs(ah.d_clen);
  ah.d_ttl=ntohl(ah.d_ttl);

  d_startrecordpos=d_pos; // needed for getBlob later on
  d_recordlen=ah.d_clen;
}


void PacketReader::copyRecord(vector<unsigned char>& dest, uint16_t len)
{
  dest.resize(len);
  if(!len)
    return;

  for(uint16_t n=0;n<len;++n) {
    dest.at(n)=d_content.at(d_pos++);
  }
}

void PacketReader::copyRecord(unsigned char* dest, uint16_t len)
{
  if(d_pos + len > d_content.size())
    throw std::out_of_range("Attempt to copy outside of packet");

  memcpy(dest, &d_content.at(d_pos), len);
  d_pos+=len;
}

void PacketReader::xfr48BitInt(uint64_t& ret)
{
  ret=0;
  ret+=static_cast<uint8_t>(d_content.at(d_pos++));
  ret<<=8;
  ret+=static_cast<uint8_t>(d_content.at(d_pos++));
  ret<<=8;
  ret+=static_cast<uint8_t>(d_content.at(d_pos++));
  ret<<=8;
  ret+=static_cast<uint8_t>(d_content.at(d_pos++));
  ret<<=8;
  ret+=static_cast<uint8_t>(d_content.at(d_pos++));
  ret<<=8;
  ret+=static_cast<uint8_t>(d_content.at(d_pos++));
}

uint32_t PacketReader::get32BitInt()
{
  uint32_t ret=0;
  ret+=static_cast<uint8_t>(d_content.at(d_pos++));
  ret<<=8;
  ret+=static_cast<uint8_t>(d_content.at(d_pos++));
  ret<<=8;
  ret+=static_cast<uint8_t>(d_content.at(d_pos++));
  ret<<=8;
  ret+=static_cast<uint8_t>(d_content.at(d_pos++));
  
  return ret;
}


uint16_t PacketReader::get16BitInt()
{
  uint16_t ret=0;
  ret+=static_cast<uint8_t>(d_content.at(d_pos++));
  ret<<=8;
  ret+=static_cast<uint8_t>(d_content.at(d_pos++));
  
  return ret;
}

uint8_t PacketReader::get8BitInt()
{
  return d_content.at(d_pos++);
}

DNSName PacketReader::getName()
{
  unsigned int consumed;
  try {
    DNSName dn((const char*) d_content.data(), d_content.size(), d_pos, true /* uncompress */, 0 /* qtype */, 0 /* qclass */, &consumed, sizeof(dnsheader));
    
    d_pos+=consumed;
    return dn;
  }
  catch(const std::range_error& re) {
    throw std::out_of_range(string("dnsname issue: ")+re.what());
  }
  catch(...) {
    throw std::out_of_range("dnsname issue");
  }
  throw PDNSException("PacketReader::getName(): name is empty");
}

static string txtEscape(const string &name)
{
  string ret;
  char ebuf[5];

  for(string::const_iterator i=name.begin();i!=name.end();++i) {
    if((unsigned char) *i >= 127 || (unsigned char) *i < 32) {
      snprintf(ebuf, sizeof(ebuf), "\\%03u", (unsigned char)*i);
      ret += ebuf;
    }
    else if(*i=='"' || *i=='\\'){
      ret += '\\';
      ret += *i;
    }
    else
      ret += *i;
  }
  return ret;
}

// exceptions thrown here do not result in logging in the main pdns auth server - just so you know!
string PacketReader::getText(bool multi, bool lenField)
{
  string ret;
  ret.reserve(40);
  while(d_pos < d_startrecordpos + d_recordlen ) {
    if(!ret.empty()) {
      ret.append(1,' ');
    }
    uint16_t labellen;
    if(lenField)
      labellen=static_cast<uint8_t>(d_content.at(d_pos++));
    else
      labellen=d_recordlen - (d_pos - d_startrecordpos);
    
    ret.append(1,'"');
    if(labellen) { // no need to do anything for an empty string
      string val(&d_content.at(d_pos), &d_content.at(d_pos+labellen-1)+1);
      ret.append(txtEscape(val)); // the end is one beyond the packet
    }
    ret.append(1,'"');
    d_pos+=labellen;
    if(!multi)
      break;
  }

  return ret;
}

string PacketReader::getUnquotedText(bool lenField)
{
  uint16_t stop_at;
  if(lenField)
    stop_at = static_cast<uint8_t>(d_content.at(d_pos)) + d_pos + 1;
  else
    stop_at = d_recordlen;

  /* think unsigned overflow */
  if (stop_at < d_pos) {
    throw std::out_of_range("getUnquotedText out of record range");
  }

  if(stop_at == d_pos)
    return "";

  d_pos++;
  string ret(&d_content.at(d_pos), &d_content.at(stop_at));
  d_pos = stop_at;
  return ret;
}

void PacketReader::xfrBlob(string& blob)
try
{
  if(d_recordlen && !(d_pos == (d_startrecordpos + d_recordlen))) {
    if (d_pos > (d_startrecordpos + d_recordlen)) {
      throw std::out_of_range("xfrBlob out of record range");
    }
    blob.assign(&d_content.at(d_pos), &d_content.at(d_startrecordpos + d_recordlen - 1 ) + 1);
  }
  else {
    blob.clear();
  }

  d_pos = d_startrecordpos + d_recordlen;
}
catch(...)
{
  throw std::out_of_range("xfrBlob out of range");
}

void PacketReader::xfrBlobNoSpaces(string& blob, int length) {
  xfrBlob(blob, length);
}

void PacketReader::xfrBlob(string& blob, int length)
{
  if(length) {
    if (length < 0) {
      throw std::out_of_range("xfrBlob out of range (negative length)");
    }

    blob.assign(&d_content.at(d_pos), &d_content.at(d_pos + length - 1 ) + 1 );

    d_pos += length;
  }
  else {
    blob.clear();
  }
}


void PacketReader::xfrHexBlob(string& blob, bool keepReading)
{
  xfrBlob(blob);
}

//FIXME400 remove this method completely
string simpleCompress(const string& elabel, const string& root)
{
  string label=elabel;
  // FIXME400: this relies on the semi-canonical escaped output from getName
  if(strchr(label.c_str(), '\\')) {
    boost::replace_all(label, "\\.", ".");
    boost::replace_all(label, "\\032", " ");
    boost::replace_all(label, "\\\\", "\\");   
  }
  typedef vector<pair<unsigned int, unsigned int> > parts_t;
  parts_t parts;
  vstringtok(parts, label, ".");
  string ret;
  ret.reserve(label.size()+4);
  for(parts_t::const_iterator i=parts.begin(); i!=parts.end(); ++i) {
    if(!root.empty() && !strncasecmp(root.c_str(), label.c_str() + i->first, 1 + label.length() - i->first)) { // also match trailing 0, hence '1 +'
      const unsigned char rootptr[2]={0xc0,0x11};
      ret.append((const char *) rootptr, 2);
      return ret;
    }
    ret.append(1, (char)(i->second - i->first));
    ret.append(label.c_str() + i->first, i->second - i->first);
  }
  ret.append(1, (char)0);
  return ret;
}


/** Simple DNSPacketMangler. Ritual is: get a pointer into the packet and moveOffset() to beyond your needs
 *  If you survive that, feel free to read from the pointer */
class DNSPacketMangler
{
public:
  explicit DNSPacketMangler(std::string& packet)
    : d_packet((char*) packet.c_str()), d_length(packet.length()), d_notyouroffset(12), d_offset(d_notyouroffset)
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
    memcpy(&ret, (void*)p, sizeof(ret));
    return ntohl(ret);
  }
  uint16_t get16BitInt()
  {
    const char* p = d_packet + d_offset;
    moveOffset(2);
    uint16_t ret;
    memcpy(&ret, (void*)p, sizeof(ret));
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
    int toskip = get16BitInt();
    moveOffset(toskip);
  }

  void decreaseAndSkip32BitInt(uint32_t decrease)
  {
    const char *p = d_packet + d_offset;
    moveOffset(4);

    uint32_t tmp;
    memcpy(&tmp, (void*) p, sizeof(tmp));
    tmp = ntohl(tmp);
    tmp-=decrease;
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

// method of operation: silently fail if it doesn't work - we're only trying to be nice, don't fall over on it
void editDNSPacketTTL(char* packet, size_t length, std::function<uint32_t(uint8_t, uint16_t, uint16_t, uint32_t)> visitor)
{
  if(length < sizeof(dnsheader))
    return;
  try
  {
    dnsheader dh;
    memcpy((void*)&dh, (const dnsheader*)packet, sizeof(dh));
    uint64_t numrecords = ntohs(dh.ancount) + ntohs(dh.nscount) + ntohs(dh.arcount);
    DNSPacketMangler dpm(packet, length);

    uint64_t n;
    for(n=0; n < ntohs(dh.qdcount) ; ++n) {
      dpm.skipDomainName();
      /* type and class */
      dpm.skipBytes(4);
    }

    for(n=0; n < numrecords; ++n) {
      dpm.skipDomainName();

      uint8_t section = n < ntohs(dh.ancount) ? 1 : (n < (ntohs(dh.ancount) + ntohs(dh.nscount)) ? 2 : 3);
      uint16_t dnstype = dpm.get16BitInt();
      uint16_t dnsclass = dpm.get16BitInt();

      if(dnstype == QType::OPT) // not getting near that one with a stick
        break;

      uint32_t dnsttl = dpm.get32BitInt();
      uint32_t newttl = visitor(section, dnsclass, dnstype, dnsttl);
      if (newttl) {
        dpm.rewindBytes(sizeof(newttl));
        dpm.setAndSkip32BitInt(newttl);
      }
      dpm.skipRData();
    }
  }
  catch(...)
  {
    return;
  }
}

// method of operation: silently fail if it doesn't work - we're only trying to be nice, don't fall over on it
void ageDNSPacket(char* packet, size_t length, uint32_t seconds)
{
  if(length < sizeof(dnsheader))
    return;
  try 
  {
    const dnsheader* dh = reinterpret_cast<const dnsheader*>(packet);
    const uint64_t dqcount = ntohs(dh->qdcount);
    const uint64_t numrecords = ntohs(dh->ancount) + ntohs(dh->nscount) + ntohs(dh->arcount);
    DNSPacketMangler dpm(packet, length);

    uint64_t n;
    for(n=0; n < dqcount; ++n) {
      dpm.skipDomainName();
      /* type and class */
      dpm.skipBytes(4);
    }
   // cerr<<"Skipped "<<n<<" questions, now parsing "<<numrecords<<" records"<<endl;
    for(n=0; n < numrecords; ++n) {
      dpm.skipDomainName();
      
      uint16_t dnstype = dpm.get16BitInt();
      /* class */
      dpm.skipBytes(2);
      
      if(dnstype == QType::OPT) // not aging that one with a stick
        break;
      
      dpm.decreaseAndSkip32BitInt(seconds);
      dpm.skipRData();
    }
  }
  catch(...)
  {
    return;
  }
}

void ageDNSPacket(std::string& packet, uint32_t seconds)
{
  ageDNSPacket((char*)packet.c_str(), packet.length(), seconds);
}

uint32_t getDNSPacketMinTTL(const char* packet, size_t length, bool* seenAuthSOA)
{
  uint32_t result = std::numeric_limits<uint32_t>::max();
  if(length < sizeof(dnsheader)) {
    return result;
  }
  try
  {
    const dnsheader* dh = (const dnsheader*) packet;
    DNSPacketMangler dpm(const_cast<char*>(packet), length);

    const uint16_t qdcount = ntohs(dh->qdcount);
    for(size_t n = 0; n < qdcount; ++n) {
      dpm.skipDomainName();
      /* type and class */
      dpm.skipBytes(4);
    }
    const size_t numrecords = ntohs(dh->ancount) + ntohs(dh->nscount) + ntohs(dh->arcount);
    for(size_t n = 0; n < numrecords; ++n) {
      dpm.skipDomainName();
      const uint16_t dnstype = dpm.get16BitInt();
      /* class */
      const uint16_t dnsclass = dpm.get16BitInt();

      if(dnstype == QType::OPT) {
        break;
      }

      /* report it if we see a SOA record in the AUTHORITY section */
      if(dnstype == QType::SOA && dnsclass == QClass::IN && seenAuthSOA != nullptr && n >= ntohs(dh->ancount) && n < (ntohs(dh->ancount) + ntohs(dh->nscount))) {
        *seenAuthSOA = true;
      }

      const uint32_t ttl = dpm.get32BitInt();
      if (result > ttl) {
        result = ttl;
      }

      dpm.skipRData();
    }
  }
  catch(...)
  {
  }
  return result;
}

uint32_t getDNSPacketLength(const char* packet, size_t length)
{
  uint32_t result = length;
  if(length < sizeof(dnsheader)) {
    return result;
  }
  try
  {
    const dnsheader* dh = reinterpret_cast<const dnsheader*>(packet);
    DNSPacketMangler dpm(const_cast<char*>(packet), length);

    const uint16_t qdcount = ntohs(dh->qdcount);
    for(size_t n = 0; n < qdcount; ++n) {
      dpm.skipDomainName();
      /* type and class */
      dpm.skipBytes(4);
    }
    const size_t numrecords = ntohs(dh->ancount) + ntohs(dh->nscount) + ntohs(dh->arcount);
    for(size_t n = 0; n < numrecords; ++n) {
      dpm.skipDomainName();
      /* type (2), class (2) and ttl (4) */
      dpm.skipBytes(8);
      dpm.skipRData();
    }
    result = dpm.getOffset();
  }
  catch(...)
  {
  }
  return result;
}

uint16_t getRecordsOfTypeCount(const char* packet, size_t length, uint8_t section, uint16_t type)
{
  uint16_t result = 0;
  if(length < sizeof(dnsheader)) {
    return result;
  }
  try
  {
    const dnsheader* dh = (const dnsheader*) packet;
    DNSPacketMangler dpm(const_cast<char*>(packet), length);

    const uint16_t qdcount = ntohs(dh->qdcount);
    for(size_t n = 0; n < qdcount; ++n) {
      dpm.skipDomainName();
      if (section == 0) {
        uint16_t dnstype = dpm.get16BitInt();
        if (dnstype == type) {
          result++;
        }
        /* class */
        dpm.skipBytes(2);
      } else {
        /* type and class */
        dpm.skipBytes(4);
      }
    }
    const uint16_t ancount = ntohs(dh->ancount);
    for(size_t n = 0; n < ancount; ++n) {
      dpm.skipDomainName();
      if (section == 1) {
        uint16_t dnstype = dpm.get16BitInt();
        if (dnstype == type) {
          result++;
        }
        /* class */
        dpm.skipBytes(2);
      } else {
        /* type and class */
        dpm.skipBytes(4);
      }
      /* ttl */
      dpm.skipBytes(4);
      dpm.skipRData();
    }
    const uint16_t nscount = ntohs(dh->nscount);
    for(size_t n = 0; n < nscount; ++n) {
      dpm.skipDomainName();
      if (section == 2) {
        uint16_t dnstype = dpm.get16BitInt();
        if (dnstype == type) {
          result++;
        }
        /* class */
        dpm.skipBytes(2);
      } else {
        /* type and class */
        dpm.skipBytes(4);
      }
      /* ttl */
      dpm.skipBytes(4);
      dpm.skipRData();
    }
    const uint16_t arcount = ntohs(dh->arcount);
    for(size_t n = 0; n < arcount; ++n) {
      dpm.skipDomainName();
      if (section == 3) {
        uint16_t dnstype = dpm.get16BitInt();
        if (dnstype == type) {
          result++;
        }
        /* class */
        dpm.skipBytes(2);
      } else {
        /* type and class */
        dpm.skipBytes(4);
      }
      /* ttl */
      dpm.skipBytes(4);
      dpm.skipRData();
    }
  }
  catch(...)
  {
  }
  return result;
}

bool getEDNSUDPPayloadSizeAndZ(const char* packet, size_t length, uint16_t* payloadSize, uint16_t* z)
{
  if (length < sizeof(dnsheader)) {
    return false;
  }

  *payloadSize = 0;
  *z = 0;

  try
  {
    const dnsheader* dh = (const dnsheader*) packet;
    DNSPacketMangler dpm(const_cast<char*>(packet), length);

    const uint16_t qdcount = ntohs(dh->qdcount);
    for(size_t n = 0; n < qdcount; ++n) {
      dpm.skipDomainName();
      /* type and class */
      dpm.skipBytes(4);
    }
    const size_t numrecords = ntohs(dh->ancount) + ntohs(dh->nscount) + ntohs(dh->arcount);
    for(size_t n = 0; n < numrecords; ++n) {
      dpm.skipDomainName();
      const uint16_t dnstype = dpm.get16BitInt();
      const uint16_t dnsclass = dpm.get16BitInt();

      if(dnstype == QType::OPT) {
        /* skip extended rcode and version */
        dpm.skipBytes(2);
        *z = dpm.get16BitInt();
        *payloadSize = dnsclass;
        return true;
      }

      /* TTL */
      dpm.skipBytes(4);
      dpm.skipRData();
    }
  }
  catch(...)
  {
  }

  return false;
}
