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

#include "dnsparser.hh"
#include "dnswriter.hh"
#include <boost/lexical_cast.hpp>

using namespace boost;

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
  
    str<<"\\# "<<d_record.size()<<" ";
    char hex[4];
    for(size_t n=0; n<d_record.size(); ++n) {
      snprintf(hex,sizeof(hex)-1, "%02x", d_record.at(n));
      str << hex;
    }
    return str.str();
  }
  
  void toPacket(DNSPacketWriter& pw)
  {
    string tmp((char*)&*d_record.begin(), (char*)&*d_record.end());
    vector<string> parts;
    stringtok(parts, tmp);
    const string& relevant=parts[2];
    unsigned int total=atoi(parts[1].c_str());
    if(relevant.size()!=2*total)
      throw runtime_error("invalid unknown record");
    string out;
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
  typedef vector<string> parts_t;  
  parts_t parts;  
  stringtok(parts,input,".");   	  	 
  string ret;  
  for(parts_t::const_iterator i=parts.begin(); i!=parts.end(); ++i) {  
    ret.append(1,(char)i->length());  
    ret.append(*i);  
  }  
  ret.append(1,(char)0);  
  return ret;  
}  

shared_ptr<DNSRecordContent> DNSRecordContent::unserialize(const string& qname, uint16_t qtype, const string& serialized)
{
  dnsheader dnsheader;
  memset(&dnsheader, 0, sizeof(dnsheader));
  dnsheader.qdcount=htons(1);
  dnsheader.ancount=htons(1);

  vector<uint8_t> packet; // build pseudo packet
  const uint8_t* ptr=(const uint8_t*)&dnsheader;
  packet.insert(packet.end(), ptr, ptr + sizeof(dnsheader));    
  char tmp[6]="\x0" "\x0\x1" "\x0\x1"; // root question for ns_t_a
  packet.insert(packet.end(), tmp, tmp+5);

  string encoded=EncodeDNSLabel(qname);
  packet.insert(packet.end(), encoded.c_str(), encoded.c_str() + encoded.size()); // append the label

  struct dnsrecordheader drh;
  drh.d_type=htons(qtype);
  drh.d_class=htons(1);
  drh.d_ttl=0;
  drh.d_clen=htons(serialized.size());

  ptr=(const uint8_t*)&drh;
  packet.insert(packet.end(), ptr, ptr + sizeof(drh));

  packet.insert(packet.end(), serialized.c_str(), serialized.c_str() + serialized.size()); // this is our actual data
  
  MOADNSParser mdp((char*)&*packet.begin(), packet.size());
  shared_ptr<DNSRecordContent> ret= mdp.d_answers.begin()->first.d_content;
  ret->header.d_type=ret->d_qtype;
  ret->label=mdp.d_answers.begin()->first.d_label;
  ret->header.d_ttl=mdp.d_answers.begin()->first.d_ttl;
  return ret;
}

DNSRecordContent* DNSRecordContent::mastermake(const DNSRecord &dr, 
					       PacketReader& pr)
{
  typemap_t::const_iterator i=typemap.find(make_pair(dr.d_class, dr.d_type));
  if(i==typemap.end() || !i->second) {
    return new UnknownRecordContent(dr, pr);
  }

  return i->second(dr, pr);
}

DNSRecordContent* DNSRecordContent::mastermake(uint16_t qtype, uint16_t qclass,
					       const string& content)
{
  zmakermap_t::const_iterator i=zmakermap.find(make_pair(qclass, qtype));
  if(i==zmakermap.end()) {
    return new UnknownRecordContent(content);
  }

  return i->second(content);
}


DNSRecordContent::typemap_t DNSRecordContent::typemap __attribute__((init_priority(1000)));
DNSRecordContent::namemap_t DNSRecordContent::namemap __attribute__((init_priority(1000)));
DNSRecordContent::zmakermap_t DNSRecordContent::zmakermap __attribute__((init_priority(1000)));

void MOADNSParser::init(const char *packet, unsigned int len)
{
  if(len < sizeof(dnsheader))
    throw MOADNSException("Packet shorter than minimal header");
  
  memcpy(&d_header, packet, sizeof(dnsheader));

  d_header.qdcount=ntohs(d_header.qdcount);
  d_header.ancount=ntohs(d_header.ancount);
  d_header.nscount=ntohs(d_header.nscount);
  d_header.arcount=ntohs(d_header.arcount);
  
  uint16_t contentlen=len-sizeof(dnsheader);

  d_content.resize(contentlen);
  copy(packet+sizeof(dnsheader), packet+len, d_content.begin());
  
  unsigned int n;

  PacketReader pr(d_content);

  for(n=0;n < d_header.qdcount; ++n) {
    d_qname=pr.getLabel();
    d_qtype=pr.get16BitInt();
    d_qclass=pr.get16BitInt();
  }

  try {
    struct dnsrecordheader ah;
    vector<unsigned char> record;
    
    for(n=0;n < d_header.ancount + d_header.nscount + d_header.arcount; ++n) {
      
      DNSRecord dr;
      
      if(n < d_header.ancount)
	dr.d_place=DNSRecord::Answer;
      else if(n < d_header.ancount + d_header.nscount)
	dr.d_place=DNSRecord::Nameserver;
      else 
	dr.d_place=DNSRecord::Additional;
      
      string label=pr.getLabel();
      
      pr.getDnsrecordheader(ah);
      dr.d_ttl=ah.d_ttl;
      dr.d_type=ah.d_type;
      dr.d_class=ah.d_class;
      
      dr.d_label=label;
      dr.d_clen=ah.d_clen;
      
      dr.d_content=boost::shared_ptr<DNSRecordContent>(DNSRecordContent::mastermake(dr, pr));
      d_answers.push_back(make_pair(dr, pr.d_pos));
    }
    
    if(pr.d_pos!=contentlen) {
      throw MOADNSException("Packet has trailing garbage");
    }
  }
  catch(out_of_range &re) {
    throw MOADNSException("Packet parsing error, out of bounds: "+string(re.what()));
  }
  
}

bool MOADNSParser::getEDNSOpts(EDNSOpts* eo)
{
  if(d_header.arcount) {
    eo->d_packetsize=d_answers.back().first.d_class;
    struct Stuff {
      uint8_t extRCode, version;
      uint16_t Z;
    } __attribute__((packed));
    
    Stuff stuff;
    uint32_t ttl=ntohl(d_answers.back().first.d_ttl);
    memcpy(&stuff, &ttl, sizeof(stuff));

    eo->d_extRCode=stuff.extRCode;
    eo->d_version=stuff.version;
    eo->d_Z=stuff.Z;

    return true;
  }
  else
    return false;
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
    throw MOADNSException("Attempt to copy outside of packet");

  memcpy(dest, &d_content.at(d_pos), len);
  d_pos+=len;
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

u_int8_t PacketReader::get8BitInt()
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

string PacketReader::getText()
{
  string ret;
  ret.reserve(40);

  unsigned char labellen=d_content.at(d_pos++);
  ret.append(&d_content.at(d_pos), &d_content.at(d_pos+labellen-1)+1); // the end is one beyond the packet
  d_pos+=labellen;
  return ret;
}

void PacketReader::getLabelFromContent(const vector<u_int8_t>& content, uint16_t& frompos, string& ret, int recurs) 
{
  if(recurs > 10)
    throw MOADNSException("Loop");

  for(;;) {
    unsigned char labellen=content.at(frompos++);

    // cout<<"Labellen: "<<(int)labellen<<endl;
    if(!labellen) {
      //      if(ret.empty())
      //	ret.append(1,'.');
      break;
    }
    if((labellen & 0xc0) == 0xc0) {
      uint16_t offset=256*(labellen & ~0xc0) + (unsigned int)content.at(frompos++) - sizeof(dnsheader);
      //	cout<<"This is an offset, need to go to: "<<offset<<endl;
      return getLabelFromContent(content, offset, ret, ++recurs);
    }
    else {
      if(!ret.empty())
	ret.append(1,'.');
      ret.append(&content.at(frompos), &content.at(frompos+labellen));
      frompos+=labellen;
    }
  }
}

void PacketReader::xfrBlob(string& blob)
{
  blob.assign(&d_content.at(d_pos), &d_content.at(d_startrecordpos + d_recordlen - 1 ) + 1);

  d_pos = d_startrecordpos + d_recordlen;
}
