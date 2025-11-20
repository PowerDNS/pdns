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

#include "dns_random.hh"
#include "namespaces.hh"
#include "noinitvector.hh"

std::atomic<bool> DNSRecordContent::d_locked{false};

UnknownRecordContent::UnknownRecordContent(const string& zone)
{
  // parse the input
  vector<string> parts;
  stringtok(parts, zone);
  // we need exactly 3 parts, except if the length field is set to 0 then we only need 2
  if (parts.size() != 3 && !(parts.size() == 2 && boost::equals(parts.at(1), "0"))) {
    throw MOADNSException("Unknown record was stored incorrectly, need 3 fields, got " + std::to_string(parts.size()) + ": " + zone);
  }

  if (parts.at(0) != "\\#") {
    throw MOADNSException("Unknown record was stored incorrectly, first part should be '\\#', got '" + parts.at(0) + "'");
  }

  const string& relevant = (parts.size() > 2) ? parts.at(2) : "";
  auto total = pdns::checked_stoi<unsigned int>(parts.at(1));
  if (relevant.size() % 2 || (relevant.size() / 2) != total) {
    throw MOADNSException((boost::format("invalid unknown record length: size not equal to length field (%d != 2 * %d)") % relevant.size() % total).str());
  }

  string out;
  out.reserve(total + 1);

  for (unsigned int n = 0; n < total; ++n) {
    int c;
    if (sscanf(&relevant.at(2*n), "%02x", &c) != 1) {
      throw MOADNSException("unable to read data at position " + std::to_string(2 * n) + " from unknown record of size " + std::to_string(relevant.size()));
    }
    out.append(1, (char)c);
  }

  d_record.insert(d_record.end(), out.begin(), out.end());
}

string UnknownRecordContent::getZoneRepresentation(bool /* noDot */) const
{
  ostringstream str;
  str<<"\\# "<<(unsigned int)d_record.size()<<" ";
  char hex[4];
  for (unsigned char n : d_record) {
    snprintf(hex, sizeof(hex), "%02x", n);
    str << hex;
  }
  return str.str();
}

void UnknownRecordContent::toPacket(DNSPacketWriter& pw) const
{
  pw.xfrBlob(string(d_record.begin(),d_record.end()));
}

shared_ptr<DNSRecordContent> DNSRecordContent::deserialize(const DNSName& qname, uint16_t qtype, const string& serialized, uint16_t qclass, bool internalRepresentation)
{
  dnsheader dnsheader;
  memset(&dnsheader, 0, sizeof(dnsheader));
  dnsheader.qdcount=htons(1);
  dnsheader.ancount=htons(1);

  PacketBuffer packet; // build pseudo packet
  /* will look like: dnsheader, 5 bytes, encoded qname, dns record header, serialized data */
  const auto& encoded = qname.getStorage();
  packet.resize(sizeof(dnsheader) + 5 + encoded.size() + sizeof(struct dnsrecordheader) + serialized.size());

  uint16_t pos=0;
  memcpy(&packet[0], &dnsheader, sizeof(dnsheader)); pos+=sizeof(dnsheader);

  constexpr std::array<uint8_t, 5> tmp= {'\x0', '\x0', '\x1', '\x0', '\x1' }; // root question for ns_t_a
  memcpy(&packet[pos], tmp.data(), tmp.size()); pos += tmp.size();

  memcpy(&packet[pos], encoded.c_str(), encoded.size()); pos+=(uint16_t)encoded.size();

  struct dnsrecordheader drh;
  drh.d_type=htons(qtype);
  drh.d_class=htons(qclass);
  drh.d_ttl=0;
  drh.d_clen=htons(serialized.size());

  memcpy(&packet[pos], &drh, sizeof(drh)); pos+=sizeof(drh);
  if (!serialized.empty()) {
    memcpy(&packet[pos], serialized.c_str(), serialized.size());
    pos += (uint16_t) serialized.size();
    (void) pos;
  }

  DNSRecord dr;
  dr.d_class = qclass;
  dr.d_type = qtype;
  dr.d_name = qname;
  dr.d_clen = serialized.size();
  // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast): packet.data() is uint8_t *
  PacketReader reader(std::string_view(reinterpret_cast<const char*>(packet.data()), packet.size()), packet.size() - serialized.size() - sizeof(dnsrecordheader), internalRepresentation);
  /* needed to get the record boundaries right */
  reader.getDnsrecordheader(drh);
  auto content = DNSRecordContent::make(dr, reader, Opcode::Query);
  return content;
}

std::shared_ptr<DNSRecordContent> DNSRecordContent::make(const DNSRecord& dr,
                                                         PacketReader& pr)
{
  uint16_t searchclass = (dr.d_type == QType::OPT) ? 1 : dr.d_class; // class is invalid for OPT

  auto i = getTypemap().find(pair(searchclass, dr.d_type));
  if(i==getTypemap().end() || !i->second) {
    return std::make_shared<UnknownRecordContent>(dr, pr);
  }

  return i->second(dr, pr);
}

std::shared_ptr<DNSRecordContent> DNSRecordContent::make(uint16_t qtype, uint16_t qclass,
                                                         const string& content)
{
  auto i = getZmakermap().find(pair(qclass, qtype));
  if(i==getZmakermap().end()) {
    return std::make_shared<UnknownRecordContent>(content);
  }

  return i->second(content);
}

std::shared_ptr<DNSRecordContent> DNSRecordContent::make(const DNSRecord& dr, PacketReader& pr, uint16_t oc)
{
  // For opcode UPDATE and where the DNSRecord is an answer record, we don't care about content, because this is
  // not used within the prerequisite section of RFC2136, so - we can simply use unknownrecordcontent.
  // For section 3.2.3, we do need content so we need to get it properly. But only for the correct QClasses.
  if (oc == Opcode::Update && dr.d_place == DNSResourceRecord::ANSWER && dr.d_class != 1)
    return std::make_shared<UnknownRecordContent>(dr, pr);

  uint16_t searchclass = (dr.d_type == QType::OPT) ? 1 : dr.d_class; // class is invalid for OPT

  auto i = getTypemap().find(pair(searchclass, dr.d_type));
  if(i==getTypemap().end() || !i->second) {
    return std::make_shared<UnknownRecordContent>(dr, pr);
  }

  return i->second(dr, pr);
}

string DNSRecordContent::upgradeContent(const DNSName& qname, const QType& qtype, const string& content) {
  // seamless upgrade for previously unsupported but now implemented types.
  UnknownRecordContent unknown_content(content);
  shared_ptr<DNSRecordContent> rc = DNSRecordContent::deserialize(qname, qtype.getCode(), unknown_content.serialize(qname));
  return rc->getZoneRepresentation();
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

bool DNSRecordContent::isRegisteredType(uint16_t rtype, uint16_t rclass)
{
  return getTypemap().count(pair(rclass, rtype)) != 0;
}

DNSRecord::DNSRecord(const DNSResourceRecord& rr): d_name(rr.qname)
{
  d_type = rr.qtype.getCode();
  d_ttl = rr.ttl;
  d_class = rr.qclass;
  d_place = DNSResourceRecord::ANSWER;
  d_clen = 0;
  d_content = DNSRecordContent::make(d_type, rr.qclass, rr.content);
}

// If you call this and you are not parsing a packet coming from a socket, you are doing it wrong.
DNSResourceRecord DNSResourceRecord::fromWire(const DNSRecord& wire)
{
  DNSResourceRecord resourceRecord;
  resourceRecord.qname = wire.d_name;
  resourceRecord.qtype = QType(wire.d_type);
  resourceRecord.ttl = wire.d_ttl;
  resourceRecord.content = wire.getContent()->getZoneRepresentation(true);
  resourceRecord.auth = false;
  resourceRecord.qclass = wire.d_class;
  return resourceRecord;
}

void MOADNSParser::init(bool query, const std::string_view& packet)
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

      dr.d_name = std::move(name);
      dr.d_clen = ah.d_clen;

      if (query &&
          !(d_qtype == QType::IXFR && dr.d_place == DNSResourceRecord::AUTHORITY && dr.d_type == QType::SOA) && // IXFR queries have a SOA in their AUTHORITY section
          (dr.d_place == DNSResourceRecord::ANSWER || dr.d_place == DNSResourceRecord::AUTHORITY || (dr.d_type != QType::OPT && dr.d_type != QType::TSIG && dr.d_type != QType::SIG && dr.d_type != QType::TKEY) || ((dr.d_type == QType::TSIG || dr.d_type == QType::SIG || dr.d_type == QType::TKEY) && dr.d_class != QClass::ANY))) {
//        cerr<<"discarding RR, query is "<<query<<", place is "<<dr.d_place<<", type is "<<dr.d_type<<", class is "<<dr.d_class<<endl;
        dr.setContent(std::make_shared<UnknownRecordContent>(dr, pr));
      }
      else {
//        cerr<<"parsing RR, query is "<<query<<", place is "<<dr.d_place<<", type is "<<dr.d_type<<", class is "<<dr.d_class<<endl;
        dr.setContent(DNSRecordContent::make(dr, pr, d_header.opcode));
      }

      if (dr.d_place == DNSResourceRecord::ADDITIONAL && seenTSIG) {
        throw MOADNSException("Packet ("+d_qname.toString()+"|#"+std::to_string(d_qtype)+") has an unexpected record ("+std::to_string(dr.d_type)+") after a TSIG one.");
      }

      if(dr.d_type == QType::TSIG && dr.d_class == QClass::ANY) {
        if(seenTSIG || dr.d_place != DNSResourceRecord::ADDITIONAL) {
          throw MOADNSException("Packet ("+d_qname.toLogString()+"|#"+std::to_string(d_qtype)+") has a TSIG record in an invalid position.");
        }
        seenTSIG = true;
        d_tsigPos = recordStartPos;
      }

      d_answers.emplace_back(std::move(dr));
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

bool MOADNSParser::hasEDNS() const
{
  if (d_header.arcount == 0 || d_answers.empty()) {
    return false;
  }

  for (const auto& record : d_answers) {
    if (record.d_place == DNSResourceRecord::ADDITIONAL && record.d_type == QType::OPT) {
      return true;
    }
  }

  return false;
}

void PacketReader::getDnsrecordheader(struct dnsrecordheader &ah)
{
  unsigned char *p = reinterpret_cast<unsigned char*>(&ah);

  for(unsigned int n = 0; n < sizeof(dnsrecordheader); ++n) {
    p[n] = d_content.at(d_pos++);
  }

  ah.d_type = ntohs(ah.d_type);
  ah.d_class = ntohs(ah.d_class);
  ah.d_clen = ntohs(ah.d_clen);
  ah.d_ttl = ntohl(ah.d_ttl);

  d_startrecordpos = d_pos; // needed for getBlob later on
  d_recordlen = ah.d_clen;
}


void PacketReader::copyRecord(vector<unsigned char>& dest, uint16_t len)
{
  if (len == 0) {
    return;
  }
  if ((d_pos + len) > d_content.size()) {
    throw std::out_of_range("Attempt to copy outside of packet");
  }

  dest.resize(len);

  for (uint16_t n = 0; n < len; ++n) {
    dest.at(n) = d_content.at(d_pos++);
  }
}

void PacketReader::copyRecord(unsigned char* dest, uint16_t len)
{
  if (d_pos + len > d_content.size()) {
    throw std::out_of_range("Attempt to copy outside of packet");
  }

  memcpy(dest, &d_content.at(d_pos), len);
  d_pos += len;
}

void PacketReader::xfrNodeOrLocatorID(NodeOrLocatorID& ret)
{
  if (d_pos + sizeof(ret) > d_content.size()) {
    throw std::out_of_range("Attempt to read 64 bit value outside of packet");
  }
  memcpy(&ret.content, &d_content.at(d_pos), sizeof(ret.content));
  d_pos += sizeof(ret);
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
    DNSName dn((const char*) d_content.data(), d_content.size(), d_pos, true /* uncompress */, nullptr /* qtype */, nullptr /* qclass */, &consumed, sizeof(dnsheader));

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

// FIXME see #6010 and #3503 if you want a proper solution
string txtEscape(const string &name)
{
  string ret;
  std::array<char, 5> ebuf{};

  for (char letter : name) {
    const unsigned uch = static_cast<unsigned char>(letter);
    if (uch >= 127 || uch < 32) {
      snprintf(ebuf.data(), ebuf.size(), "\\%03u", uch);
      ret += ebuf.data();
    }
    else if (letter == '"' || letter == '\\'){
      ret += '\\';
      ret += letter;
    }
    else {
      ret += letter;
    }
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

  if (ret.empty() && !lenField) {
    // all lenField == false cases (CAA and URI at the time of this writing) want that emptiness to be explicit
    return "\"\"";
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
  string ret(d_content.substr(d_pos, stop_at-d_pos));
  d_pos = stop_at;
  return ret;
}

void PacketReader::xfrBlob(string& blob)
{
  try {
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

void PacketReader::xfrSvcParamKeyVals(set<SvcParam> &kvs) {
  while (d_pos < (d_startrecordpos + d_recordlen)) {
    if (d_pos + 2 > (d_startrecordpos + d_recordlen)) {
      throw std::out_of_range("incomplete key");
    }
    uint16_t keyInt;
    xfr16BitInt(keyInt);
    auto key = static_cast<SvcParam::SvcParamKey>(keyInt);
    uint16_t len;
    xfr16BitInt(len);

    if (d_pos + len > (d_startrecordpos + d_recordlen)) {
      throw std::out_of_range("record is shorter than SVCB lengthfield implies");
    }

    switch (key)
    {
    case SvcParam::mandatory: {
      if (len % 2 != 0) {
        throw std::out_of_range("mandatory SvcParam has invalid length");
      }
      if (len == 0) {
        throw std::out_of_range("empty 'mandatory' values");
      }
      std::set<SvcParam::SvcParamKey> paramKeys;
      size_t stop = d_pos + len;
      while (d_pos < stop) {
        uint16_t keyval;
        xfr16BitInt(keyval);
        paramKeys.insert(static_cast<SvcParam::SvcParamKey>(keyval));
      }
      kvs.insert(SvcParam(key, std::move(paramKeys)));
      break;
    }
    case SvcParam::alpn: {
      size_t stop = d_pos + len;
      std::vector<string> alpns;
      while (d_pos < stop) {
        string alpn;
        uint8_t alpnLen = 0;
        xfr8BitInt(alpnLen);
        if (alpnLen == 0) {
          throw std::out_of_range("alpn length of 0");
        }
        xfrBlob(alpn, alpnLen);
        alpns.push_back(std::move(alpn));
      }
      kvs.insert(SvcParam(key, std::move(alpns)));
      break;
    }
    case SvcParam::ohttp:
    case SvcParam::no_default_alpn: {
      if (len != 0) {
        throw std::out_of_range("invalid length for " + SvcParam::keyToString(key));
      }
      kvs.insert(SvcParam(key));
      break;
    }
    case SvcParam::port: {
      if (len != 2) {
        throw std::out_of_range("invalid length for port");
      }
      uint16_t port;
      xfr16BitInt(port);
      kvs.insert(SvcParam(key, port));
      break;
    }
    case SvcParam::ipv4hint:
    case SvcParam::ipv6hint: {
      size_t addrLen = (key == SvcParam::ipv4hint ? 4 : 16);
      if (len % addrLen != 0) {
        throw std::out_of_range("invalid length for " + SvcParam::keyToString(key));
      }
      vector<ComboAddress> addresses;
      auto stop = d_pos + len;
      while (d_pos < stop)
      {
        ComboAddress addr;
        xfrCAWithoutPort(key, addr);
        addresses.push_back(addr);
      }
      // If there were no addresses, and the input comes from internal
      // representation, we can reasonably assume this is the serialization
      // of "auto".
      bool doAuto{d_internal && len == 0};
      auto param = SvcParam(key, std::move(addresses));
      param.setAutoHint(doAuto);
      kvs.insert(std::move(param));
      break;
    }
    case SvcParam::ech: {
      std::string blob;
      blob.reserve(len);
      xfrBlobNoSpaces(blob, len);
      kvs.insert(SvcParam(key, blob));
      break;
    }
    case SvcParam::tls_supported_groups: {
      if (len % 2 != 0) {
        throw std::out_of_range("invalid length for " + SvcParam::keyToString(key));
      }
      vector<uint16_t> groups;
      groups.reserve(len / 2);
      auto stop = d_pos + len;
      while (d_pos < stop)
      {
        uint16_t group = 0;
        xfr16BitInt(group);
        groups.push_back(group);
      }
      auto param = SvcParam(key, std::move(groups));
      kvs.insert(std::move(param));
      break;
    }
    default: {
      std::string blob;
      blob.reserve(len);
      xfrBlob(blob, len);
      kvs.insert(SvcParam(key, blob));
      break;
    }
    }
  }
}


void PacketReader::xfrHexBlob(string& blob, bool /* keepReading */)
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
  for(const auto & part : parts) {
    if(!root.empty() && !strncasecmp(root.c_str(), label.c_str() + part.first, 1 + label.length() - part.first)) { // also match trailing 0, hence '1 +'
      const unsigned char rootptr[2]={0xc0,0x11};
      ret.append((const char *) rootptr, 2);
      return ret;
    }
    ret.append(1, (char)(part.second - part.first));
    ret.append(label.c_str() + part.first, part.second - part.first);
  }
  ret.append(1, (char)0);
  return ret;
}

// method of operation: silently fail if it doesn't work - we're only trying to be nice, don't fall over on it
void editDNSPacketTTL(char* packet, size_t length, const std::function<uint32_t(uint8_t, uint16_t, uint16_t, uint32_t)>& visitor)
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

static bool checkIfPacketContainsRecords(const PacketBuffer& packet, const std::unordered_set<QType>& qtypes)
{
  auto length = packet.size();
  if (length < sizeof(dnsheader)) {
    return false;
  }

  try {
    const dnsheader_aligned dh(packet.data());
    DNSPacketMangler dpm(const_cast<char*>(reinterpret_cast<const char*>(packet.data())), length);

    const uint16_t qdcount = ntohs(dh->qdcount);
    for (size_t n = 0; n < qdcount; ++n) {
      dpm.skipDomainName();
      /* type and class */
      dpm.skipBytes(4);
    }
    const size_t recordsCount = static_cast<size_t>(ntohs(dh->ancount)) + ntohs(dh->nscount) + ntohs(dh->arcount);
    for (size_t n = 0; n < recordsCount; ++n) {
      dpm.skipDomainName();
      uint16_t dnstype = dpm.get16BitInt();
      uint16_t dnsclass = dpm.get16BitInt();
      if (dnsclass == QClass::IN && qtypes.count(dnstype) > 0) {
        return true;
      }
      /* ttl */
      dpm.skipBytes(4);
      dpm.skipRData();
    }
  }
  catch (...) {
  }

  return false;
}

static int rewritePacketWithoutRecordTypes(const PacketBuffer& initialPacket, PacketBuffer& newContent, const std::unordered_set<QType>& qtypes)
{
  static const std::unordered_set<QType>& safeTypes{QType::A, QType::AAAA, QType::DHCID, QType::TXT, QType::OPT, QType::HINFO, QType::DNSKEY, QType::CDNSKEY, QType::DS, QType::CDS, QType::DLV, QType::SSHFP, QType::KEY, QType::CERT, QType::TLSA, QType::SMIMEA, QType::OPENPGPKEY, QType::SVCB, QType::HTTPS, QType::NSEC3, QType::CSYNC, QType::NSEC3PARAM, QType::LOC, QType::NID, QType::L32, QType::L64, QType::EUI48, QType::EUI64, QType::URI, QType::CAA};

  if (initialPacket.size() < sizeof(dnsheader)) {
    return EINVAL;
  }
  try {
    const dnsheader_aligned dh(initialPacket.data());

    if (ntohs(dh->qdcount) == 0)
      return ENOENT;
    auto packetView = std::string_view(reinterpret_cast<const char*>(initialPacket.data()), initialPacket.size());

    PacketReader pr(packetView);

    size_t idx = 0;
    DNSName rrname;
    uint16_t qdcount = ntohs(dh->qdcount);
    uint16_t ancount = ntohs(dh->ancount);
    uint16_t nscount = ntohs(dh->nscount);
    uint16_t arcount = ntohs(dh->arcount);
    uint16_t rrtype;
    uint16_t rrclass;
    string blob;
    struct dnsrecordheader ah;

    rrname = pr.getName();
    rrtype = pr.get16BitInt();
    rrclass = pr.get16BitInt();

    GenericDNSPacketWriter<PacketBuffer> pw(newContent, rrname, rrtype, rrclass, dh->opcode);
    pw.getHeader()->id=dh->id;
    pw.getHeader()->qr=dh->qr;
    pw.getHeader()->aa=dh->aa;
    pw.getHeader()->tc=dh->tc;
    pw.getHeader()->rd=dh->rd;
    pw.getHeader()->ra=dh->ra;
    pw.getHeader()->ad=dh->ad;
    pw.getHeader()->cd=dh->cd;
    pw.getHeader()->rcode=dh->rcode;

    /* consume remaining qd if any */
    if (qdcount > 1) {
      for(idx = 1; idx < qdcount; idx++) {
        rrname = pr.getName();
        rrtype = pr.get16BitInt();
        rrclass = pr.get16BitInt();
        (void) rrtype;
        (void) rrclass;
      }
    }

    /* copy AN */
    for (idx = 0; idx < ancount; idx++) {
      rrname = pr.getName();
      pr.getDnsrecordheader(ah);
      pr.xfrBlob(blob);

      if (qtypes.find(ah.d_type) == qtypes.end()) {
        // if this is not a safe type
        if (safeTypes.find(ah.d_type) == safeTypes.end()) {
          // "unsafe" types might contain compressed data, so cancel rewrite
          newContent.clear();
          return EIO;
        }
        pw.startRecord(rrname, ah.d_type, ah.d_ttl, ah.d_class, DNSResourceRecord::ANSWER, true);
        pw.xfrBlob(blob);
      }
    }

    /* copy NS */
    for (idx = 0; idx < nscount; idx++) {
      rrname = pr.getName();
      pr.getDnsrecordheader(ah);
      pr.xfrBlob(blob);

      if (qtypes.find(ah.d_type) == qtypes.end()) {
        if (safeTypes.find(ah.d_type) == safeTypes.end()) {
          // "unsafe" types might contain compressed data, so cancel rewrite
          newContent.clear();
          return EIO;
        }
        pw.startRecord(rrname, ah.d_type, ah.d_ttl, ah.d_class, DNSResourceRecord::AUTHORITY, true);
        pw.xfrBlob(blob);
      }
    }
    /* copy AR */
    for (idx = 0; idx < arcount; idx++) {
      rrname = pr.getName();
      pr.getDnsrecordheader(ah);
      pr.xfrBlob(blob);

      if (qtypes.find(ah.d_type) == qtypes.end()) {
        if (safeTypes.find(ah.d_type) == safeTypes.end()) {
          // "unsafe" types might contain compressed data, so cancel rewrite
          newContent.clear();
          return EIO;
        }
        pw.startRecord(rrname, ah.d_type, ah.d_ttl, ah.d_class, DNSResourceRecord::ADDITIONAL, true);
        pw.xfrBlob(blob);
      }
    }
    pw.commit();

  }
  catch (...)
  {
    newContent.clear();
    return EIO;
  }
  return 0;
}

void clearDNSPacketRecordTypes(vector<uint8_t>& packet, const std::unordered_set<QType>& qtypes)
{
  return clearDNSPacketRecordTypes(reinterpret_cast<PacketBuffer&>(packet), qtypes);
}

void clearDNSPacketRecordTypes(PacketBuffer& packet, const std::unordered_set<QType>& qtypes)
{
  if (!checkIfPacketContainsRecords(packet, qtypes)) {
    return;
  }

  PacketBuffer newContent;

  auto result = rewritePacketWithoutRecordTypes(packet, newContent, qtypes);
  if (!result) {
    packet = std::move(newContent);
  }
}

// method of operation: silently fail if it doesn't work - we're only trying to be nice, don't fall over on it
void ageDNSPacket(char* packet, size_t length, uint32_t seconds, const dnsheader_aligned& aligned_dh)
{
  if (length < sizeof(dnsheader)) {
    return;
  }
  try {
    const dnsheader* dhp = aligned_dh.get();
    const uint64_t dqcount = ntohs(dhp->qdcount);
    const uint64_t numrecords = ntohs(dhp->ancount) + ntohs(dhp->nscount) + ntohs(dhp->arcount);
    DNSPacketMangler dpm(packet, length);

    for (uint64_t rec = 0; rec < dqcount; ++rec) {
      dpm.skipDomainName();
      /* type and class */
      dpm.skipBytes(4);
    }

    for(uint64_t rec = 0; rec < numrecords; ++rec) {
      dpm.skipDomainName();

      uint16_t dnstype = dpm.get16BitInt();
      /* class */
      dpm.skipBytes(2);

      if (dnstype != QType::OPT) { // not aging that one with a stick
        dpm.decreaseAndSkip32BitInt(seconds);
      } else {
        dpm.skipBytes(4);
      }
      dpm.skipRData();
    }
  }
  catch(...) {
  }
}

void ageDNSPacket(std::string& packet, uint32_t seconds, const dnsheader_aligned& aligned_dh)
{
  ageDNSPacket(packet.data(), packet.length(), seconds, aligned_dh);
}

void shuffleDNSPacket(char* packet, size_t length, const dnsheader_aligned& aligned_dh)
{
  if (length < sizeof(dnsheader)) {
    return;
  }
  try {
    const dnsheader* dhp = aligned_dh.get();
    const uint16_t ancount = ntohs(dhp->ancount);
    if (ancount == 1) {
      // quick exit, nothing to shuffle
      return;
    }

    DNSPacketMangler dpm(packet, length);

    const uint16_t qdcount = ntohs(dhp->qdcount);

    for(size_t iter = 0; iter < qdcount; ++iter) {
      dpm.skipDomainName();
      /* type and class */
      dpm.skipBytes(4);
    }

    // for now shuffle only first rrset, only As and AAAAs
    uint16_t rrset_type = 0;
    DNSName rrset_dnsname{};
    std::vector<std::pair<uint32_t, uint32_t>> rrdata_indexes;
    rrdata_indexes.reserve(ancount);

    for(size_t iter = 0; iter < ancount; ++iter) {
      auto domain_start = dpm.getOffset();
      dpm.skipDomainName();
      const uint16_t dnstype = dpm.get16BitInt();
      if (dnstype == QType::A || dnstype == QType::AAAA) {
        if (rrdata_indexes.empty()) {
          rrset_type = dnstype;
          rrset_dnsname = DNSName(packet, length, domain_start, true);
        } else {
          if (dnstype != rrset_type) {
            break;
          }
          if (DNSName(packet, length, domain_start, true) != rrset_dnsname) {
            break;
          }
        }
        /* class */
        dpm.skipBytes(2);

        /* ttl */
        dpm.skipBytes(4);
        rrdata_indexes.push_back(dpm.skipRDataAndReturnOffsets());
      } else {
        if (!rrdata_indexes.empty()) {
          break;
        }
        /* class */
        dpm.skipBytes(2);

        /* ttl */
        dpm.skipBytes(4);
        dpm.skipRData();
      }
    }

    if (rrdata_indexes.size() >= 2) {
      using uid = std::uniform_int_distribution<std::vector<std::pair<uint32_t, uint32_t>>::size_type>;
      uid dist;

      pdns::dns_random_engine randomEngine;
      for (auto swapped = rrdata_indexes.size() - 1; swapped > 0; --swapped) {
        auto swapped_with = dist(randomEngine, uid::param_type(0, swapped));
        if (swapped != swapped_with) {
          dpm.swapInPlace(rrdata_indexes.at(swapped), rrdata_indexes.at(swapped_with));
        }
      }
    }
  }
  catch(...) {
  }
}

uint32_t getDNSPacketMinTTL(const char* packet, size_t length, bool* seenAuthSOA)
{
  uint32_t result = std::numeric_limits<uint32_t>::max();
  if(length < sizeof(dnsheader)) {
    return result;
  }
  try
  {
    const dnsheader_aligned dh(packet);
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
      result = std::min(result, ttl);

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
    const dnsheader_aligned dh(packet);
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
    const dnsheader_aligned dh(packet);
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
    const dnsheader_aligned dh(packet);
    if (dh->arcount == 0) {
      // The OPT pseudo-RR, if present, has to be in the additional section (https://datatracker.ietf.org/doc/html/rfc6891#section-6.1.1)
      return false;
    }

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
      const auto dnstype = dpm.get16BitInt();

      if (dnstype == QType::OPT) {
        const auto dnsclass = dpm.get16BitInt();
        /* skip extended rcode and version */
        dpm.skipBytes(2);
        *z = dpm.get16BitInt();
        *payloadSize = dnsclass;
        return true;
      }
      /* skip class */
      dpm.skipBytes(2);
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

bool visitDNSPacket(const std::string_view& packet, const std::function<bool(uint8_t, uint16_t, uint16_t, uint32_t, uint16_t, const char*)>& visitor)
{
  if (packet.size() < sizeof(dnsheader)) {
    return false;
  }

  try
  {
    const dnsheader_aligned dh(packet.data());
    uint64_t numrecords = ntohs(dh->ancount) + ntohs(dh->nscount) + ntohs(dh->arcount);
    PacketReader reader(packet);

    uint64_t n;
    for (n = 0; n < ntohs(dh->qdcount) ; ++n) {
      (void) reader.getName();
      /* type and class */
      reader.skip(4);
    }

    for (n = 0; n < numrecords; ++n) {
      (void) reader.getName();

      uint8_t section = n < ntohs(dh->ancount) ? 1 : (n < (ntohs(dh->ancount) + ntohs(dh->nscount)) ? 2 : 3);
      uint16_t dnstype = reader.get16BitInt();
      uint16_t dnsclass = reader.get16BitInt();

      if (dnstype == QType::OPT) {
        // not getting near that one with a stick
        break;
      }

      uint32_t dnsttl = reader.get32BitInt();
      uint16_t contentLength = reader.get16BitInt();
      uint16_t pos = reader.getPosition();

      bool done = visitor(section, dnsclass, dnstype, dnsttl, contentLength, &packet.at(pos));
      if (done) {
        return true;
      }

      reader.skip(contentLength);
    }
  }
  catch (...) {
    return false;
  }

  return true;
}
