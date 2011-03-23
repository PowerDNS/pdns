/*
    PowerDNS Versatile Database Driven Nameserver
    Copyright (C) 2005 - 2011  PowerDNS.COM BV

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

#include "dnsparser.hh"
#include "dnswriter.hh"
#include <boost/lexical_cast.hpp>
#include <boost/algorithm/string.hpp>

#include "namespaces.hh"

class UnknownRecordContent : public DNSRecordContent
{
public:
  UnknownRecordContent(const DNSRecord& dr, PacketReader& pr) 
    : DNSRecordContent(dr.d_type), d_dr(dr)
  {
    pr.copyRecord(d_record, dr.d_clen);
  }

  UnknownRecordContent(const string& zone) : DNSRecordContent(0)
  {
    d_record.insert(d_record.end(), zone.begin(), zone.end());
  }
  
  string getZoneRepresentation() const
  {
    ostringstream str;
    str<<"\\# "<<(unsigned int)d_record.size()<<" ";
    char hex[4];
    for(size_t n=0; n<d_record.size(); ++n) {
      snprintf(hex,sizeof(hex)-1, "%02x", d_record.at(n));
      str << hex;
    }
    return str.str();
  }
  
  void toPacket(DNSPacketWriter& pw)
  {
    string tmp((char*)&*d_record.begin(), d_record.size());
    vector<string> parts;
    stringtok(parts, tmp);
    if(parts.size()!=3 && !(parts.size()==2 && equals(parts[1],"0")) )
      throw MOADNSException("Unknown record was stored incorrectly, need 3 fields, got "+lexical_cast<string>(parts.size())+": "+tmp );
    const string& relevant=(parts.size() > 2) ? parts[2] : "";
    unsigned int total=atoi(parts[1].c_str());
    if(relevant.size()!=2*total)
      throw runtime_error("invalid unknown record");
    string out;
    out.reserve(total+1);
    for(unsigned int n=0; n < total; ++n) {
      int c;
      sscanf(relevant.c_str()+2*n, "%02x", &c);
      out.append(1, (char)c);
    }
    pw.xfrBlob(out);
  }
private:
  DNSRecord d_dr;
  vector<uint8_t> d_record;
};

static const string EncodeDNSLabel(const string& input)
{  
  if(input.length() == 1 && input[0]=='.') // otherwise we encode .. (long story)
    return string (1, 0);
    
  labelparts_t parts;
  bool unescapedSomething = labeltokUnescape(parts, input);
  string ret;

  if(!unescapedSomething) {
    for(labelparts_t::const_iterator i=parts.begin(); i!=parts.end(); ++i) {
      ret.append(1, i->second - i->first);
      ret.append(input.c_str() + i->first, i->second - i->first);
    }

  } else {
    for(labelparts_t::const_iterator i=parts.begin(); i!=parts.end(); ++i) {
      string part(input.c_str() + i->first, i->second - i->first);
      boost::replace_all(part, "\\\\", "\\");
      boost::replace_all(part, "\\.", ".");
    
      ret.append(1, part.length());
      ret.append(part);
    }  
  }    
  ret.append(1, 0);
  return ret;
}


shared_ptr<DNSRecordContent> DNSRecordContent::unserialize(const string& qname, uint16_t qtype, const string& serialized)
{
  dnsheader dnsheader;
  memset(&dnsheader, 0, sizeof(dnsheader));
  dnsheader.qdcount=htons(1);
  dnsheader.ancount=htons(1);

  vector<uint8_t> packet; // build pseudo packet

  /* will look like: dnsheader, 5 bytes, encoded qname, dns record header, serialized data */

  string encoded=EncodeDNSLabel(qname);

  packet.resize(sizeof(dnsheader) + 5 + encoded.size() + sizeof(struct dnsrecordheader) + serialized.size());

  uint16_t pos=0;

  memcpy(&packet[0], &dnsheader, sizeof(dnsheader)); pos+=sizeof(dnsheader);

  char tmp[6]="\x0" "\x0\x1" "\x0\x1"; // root question for ns_t_a
  memcpy(&packet[pos], &tmp, 5); pos+=5;

  memcpy(&packet[pos], encoded.c_str(), encoded.size()); pos+=(uint16_t)encoded.size();

  struct dnsrecordheader drh;
  drh.d_type=htons(qtype);
  drh.d_class=htons(1);
  drh.d_ttl=0;
  drh.d_clen=htons(serialized.size());

  memcpy(&packet[pos], &drh, sizeof(drh)); pos+=sizeof(drh);
  memcpy(&packet[pos], serialized.c_str(), serialized.size()); pos+=(uint16_t)serialized.size();

  MOADNSParser mdp((char*)&*packet.begin(), (unsigned int)packet.size());
  shared_ptr<DNSRecordContent> ret= mdp.d_answers.begin()->first.d_content;
  ret->header.d_type=ret->d_qtype;
  ret->label=mdp.d_answers.begin()->first.d_label;
  ret->header.d_ttl=mdp.d_answers.begin()->first.d_ttl;
  return ret;
}

DNSRecordContent* DNSRecordContent::mastermake(const DNSRecord &dr, 
        				       PacketReader& pr)
{
  uint16_t searchclass = (dr.d_type == QType::OPT) ? 1 : dr.d_class; // class is invalid for OPT

  typemap_t::const_iterator i=getTypemap().find(make_pair(searchclass, dr.d_type));
  if(i==getTypemap().end() || !i->second) {
    return new UnknownRecordContent(dr, pr);
  }

  return i->second(dr, pr);
}

DNSRecordContent* DNSRecordContent::mastermake(uint16_t qtype, uint16_t qclass,
        				       const string& content)
{
  zmakermap_t::const_iterator i=getZmakermap().find(make_pair(qclass, qtype));
  if(i==getZmakermap().end()) {
    return new UnknownRecordContent(content);
  }

  return i->second(content);
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

void MOADNSParser::init(const char *packet, unsigned int len)
{
  if(len < sizeof(dnsheader))
    throw MOADNSException("Packet shorter than minimal header");
  
  memcpy(&d_header, packet, sizeof(dnsheader));

  if(d_header.opcode!=0 && d_header.opcode != 4) // notification
    throw MOADNSException("Can't parse non-query packet with opcode="+ lexical_cast<string>(d_header.opcode));

  d_header.qdcount=ntohs(d_header.qdcount);
  d_header.ancount=ntohs(d_header.ancount);
  d_header.nscount=ntohs(d_header.nscount);
  d_header.arcount=ntohs(d_header.arcount);
  
  uint16_t contentlen=len-sizeof(dnsheader);

  d_content.resize(contentlen);
  copy(packet+sizeof(dnsheader), packet+len, d_content.begin());
  
  unsigned int n=0;

  PacketReader pr(d_content);
  bool validPacket=false;
  try {
    d_qtype = d_qclass = 0; // sometimes replies come in with no question, don't present garbage then

    for(n=0;n < d_header.qdcount; ++n) {
      d_qname=pr.getLabel();
      d_qtype=pr.get16BitInt();
      d_qclass=pr.get16BitInt();
    }

    struct dnsrecordheader ah;
    vector<unsigned char> record;
    validPacket=true;
    for(n=0;n < (unsigned int)(d_header.ancount + d_header.nscount + d_header.arcount); ++n) {
      DNSRecord dr;
      
      if(n < d_header.ancount)
        dr.d_place=DNSRecord::Answer;
      else if(n < d_header.ancount + d_header.nscount)
        dr.d_place=DNSRecord::Nameserver;
      else 
        dr.d_place=DNSRecord::Additional;
      
      unsigned int recordStartPos=pr.d_pos;

      string label=pr.getLabel();
      
      pr.getDnsrecordheader(ah);
      dr.d_ttl=ah.d_ttl;
      dr.d_type=ah.d_type;
      dr.d_class=ah.d_class;
      
      dr.d_label=label;
      dr.d_clen=ah.d_clen;

      dr.d_content=boost::shared_ptr<DNSRecordContent>(DNSRecordContent::mastermake(dr, pr));
      d_answers.push_back(make_pair(dr, pr.d_pos));

      if(dr.d_type == QType::TSIG && dr.d_class == 0xff) 
        d_tsigPos = recordStartPos + sizeof(struct dnsheader);
    }

#if 0    
    if(pr.d_pos!=contentlen) {
      throw MOADNSException("Packet ("+d_qname+"|#"+lexical_cast<string>(d_qtype)+") has trailing garbage ("+ lexical_cast<string>(pr.d_pos) + " < " + 
        		    lexical_cast<string>(contentlen) + ")");
    }
#endif 
  }
  catch(std::out_of_range &re) {
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
      throw MOADNSException("Error parsing packet of "+lexical_cast<string>(len)+" bytes (rd="+
        		    lexical_cast<string>(d_header.rd)+
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
  ret+=d_content.at(d_pos++);
  ret<<=8;
  ret+=d_content.at(d_pos++);
  ret<<=8;
  ret+=d_content.at(d_pos++);
  ret<<=8;
  ret+=d_content.at(d_pos++);
  ret<<=8;
  ret+=d_content.at(d_pos++);
  ret<<=8;
  ret+=d_content.at(d_pos++);
}

uint32_t PacketReader::get32BitInt()
{
  uint32_t ret=0;
  ret+=d_content.at(d_pos++);
  ret<<=8;
  ret+=d_content.at(d_pos++);
  ret<<=8;
  ret+=d_content.at(d_pos++);
  ret<<=8;
  ret+=d_content.at(d_pos++);
  
  return ret;
}


uint16_t PacketReader::get16BitInt()
{
  return get16BitInt(d_content, d_pos);
}

uint16_t PacketReader::get16BitInt(const vector<unsigned char>&content, uint16_t& pos)
{
  uint16_t ret=0;
  ret+=content.at(pos++);
  ret<<=8;
  ret+=content.at(pos++);
  
  return ret;
}

uint8_t PacketReader::get8BitInt()
{
  return d_content.at(d_pos++);
}


string PacketReader::getLabel(unsigned int recurs)
{
  string ret;
  ret.reserve(40);
  getLabelFromContent(d_content, d_pos, ret, recurs++);
  return ret;
}

static string txtEscape(const string &name)
{
  string ret;

  for(string::const_iterator i=name.begin();i!=name.end();++i)
    if(*i=='"' || *i=='\\'){
      ret += '\\';
      ret += *i;
    }
    else
      ret += *i;
  return ret;
}

// exceptions thrown here do not result in logging in the main pdns auth server - just so you know!
string PacketReader::getText(bool multi)
{
  string ret;
  ret.reserve(40);
  while(d_pos < d_startrecordpos + d_recordlen ) {
    if(!ret.empty()) {
      ret.append(1,' ');
    }
    unsigned char labellen=d_content.at(d_pos++);
    
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


void PacketReader::getLabelFromContent(const vector<uint8_t>& content, uint16_t& frompos, string& ret, int recurs) 
{
  if(recurs > 10)
    throw MOADNSException("Loop");

  for(;;) {
    unsigned char labellen=content.at(frompos++);

    if(!labellen) {
      if(ret.empty())
              ret.append(1,'.');
      break;
    }
    if((labellen & 0xc0) == 0xc0) {
      uint16_t offset=256*(labellen & ~0xc0) + (unsigned int)content.at(frompos++) - sizeof(dnsheader);
      //        cout<<"This is an offset, need to go to: "<<offset<<endl;
      return getLabelFromContent(content, offset, ret, ++recurs);
    }
    else {
      // XXX FIXME THIS MIGHT BE VERY SLOW!
      ret.reserve(ret.size() + labellen + 2);
      for(string::size_type n = 0 ; n < labellen; ++n, frompos++) {
        if(content.at(frompos)=='.' || content.at(frompos)=='\\') {
          ret.append(1, '\\');
          ret.append(1, content[frompos]);
        }
        else if(content.at(frompos)==' ') {
          ret+="\\032";
        }
        else 
          ret.append(1, content[frompos]);
      }
      ret.append(1,'.');
    }
  }
}

void PacketReader::xfrBlob(string& blob)
{
  if(d_recordlen)
    blob.assign(&d_content.at(d_pos), &d_content.at(d_startrecordpos + d_recordlen - 1 ) + 1);
  else
    blob.clear();

  d_pos = d_startrecordpos + d_recordlen;
}

void PacketReader::xfrBlob(string& blob, int length)
{
  if(length) {
    blob.assign(&d_content.at(d_pos), &d_content.at(d_pos + length - 1 ) + 1 );
    
    d_pos += length;
  }
  else 
    blob.clear();
}


void PacketReader::xfrHexBlob(string& blob, bool keepReading)
{
  xfrBlob(blob);
}

string simpleCompress(const string& label, const string& root)
{
  typedef vector<pair<unsigned int, unsigned int> > parts_t;
  parts_t parts;
  vstringtok(parts, label, ".");
  string ret;
  ret.reserve(label.size()+4);
  for(parts_t::const_iterator i=parts.begin(); i!=parts.end(); ++i) {
    if(!root.empty() && !strncasecmp(root.c_str(), label.c_str() + i->first, 1 + label.length() - i->first)) { // also match trailing 0, hence '1 +'
      const char rootptr[2]={0xc0,0x11};
      ret.append(rootptr, 2);
      return ret;
    }
    ret.append(1, (char)(i->second - i->first));
    ret.append(label.c_str() + i->first, i->second - i->first);
  }
  ret.append(1, (char)0);
  return ret;
}


void simpleExpandTo(const string& label, unsigned int frompos, string& ret)
{
  unsigned int labellen=0;
  while((labellen=label.at(frompos++))) {
    ret.append(label.c_str()+frompos, labellen);
    ret.append(1,'.');
    frompos+=labellen;
  }
}

/** Simple DNSPacketMangler. Ritual is: get a pointer into the packet and moveOffset() to beyond your needs
 *  If you survive that, feel free to read from the pointer */
class DNSPacketMangler
{
public:
  explicit DNSPacketMangler(std::string& packet)
    : d_packet(packet), d_notyouroffset(12), d_offset(d_notyouroffset)
  {}
  
  void skipLabel()
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
  uint16_t get16BitInt()
  {
    const char* p = d_packet.c_str() + d_offset;
    moveOffset(2);
    uint16_t ret;
    memcpy(&ret, (void*)p, 2);
    return ntohs(ret);
  }
  
  uint8_t get8BitInt()
  {
    const char* p = d_packet.c_str() + d_offset;
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
    const char *p = (const char*)d_packet.c_str() + d_offset;
    moveOffset(4);
    
    uint32_t tmp;
    memcpy(&tmp, (void*) p, sizeof(tmp));
    tmp = ntohl(tmp);
    tmp-=decrease;
    tmp = htonl(tmp);
    d_packet.replace(d_offset-4, sizeof(tmp), (const char*)&tmp, sizeof(tmp));
  }
private:
  void moveOffset(uint16_t by)
  {
    d_notyouroffset += by;
    if(d_notyouroffset > d_packet.length())
      throw std::out_of_range("dns packet out of range: "+lexical_cast<string>(d_notyouroffset) +" > " 
      + lexical_cast<string>(d_packet.length()) );
  }
  std::string& d_packet;
  
  uint32_t d_notyouroffset;  // only 'moveOffset' can touch this
  const uint32_t&  d_offset; // look.. but don't touch
  
};

// method of operation: silently fail if it doesn't work - we're only trying to be nice, don't fall over on it
void ageDNSPacket(std::string& packet, uint32_t seconds)
{
  if(packet.length() < sizeof(dnsheader))
    return;
  try 
  {
    dnsheader dh;
    memcpy((void*)&dh, (const dnsheader*)packet.c_str(), sizeof(dh));
    int numrecords = ntohs(dh.ancount) + ntohs(dh.nscount) + ntohs(dh.arcount);
    DNSPacketMangler dpm(packet);
    
    int n;
    for(n=0; n < ntohs(dh.qdcount) ; ++n) {
      dpm.skipLabel();
      dpm.skipBytes(4); // qtype, qclass
    }
   // cerr<<"Skipped "<<n<<" questions, now parsing "<<numrecords<<" records"<<endl;
    for(n=0; n < numrecords; ++n) {
      dpm.skipLabel();
      
      uint16_t dnstype = dpm.get16BitInt();
      /* uint16_t dnsclass = */ dpm.get16BitInt();
      
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
