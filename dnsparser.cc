#include "dnsparser.hh"
#include <boost/lexical_cast.hpp>

using namespace boost;

class UnknownRecordContent : public DNSRecordContent
{
public:
  UnknownRecordContent(const struct dnsrecordheader& ah, PacketReader& pr) 
    : d_ah(ah)
  {
    pr.copyRecord(d_record, ah.d_clen);
  }

  string getType() const
  {
    return "#"+lexical_cast<string>(d_ah.d_type);
  }



  string getZoneRepresentation() const
  {
    ostringstream str;
    if(d_ah.d_class==1)
      str<<"IN";
    else
      str<<"CLASS"<<d_ah.d_class;

    str<<"\t";

    str<<"TYPE"<<d_ah.d_type<<"\t";

    str<<"\\# "<<d_record.size()<<" ";
    char hex[4];
    for(size_t n=0; n<d_record.size(); ++n) {
      snprintf(hex,sizeof(hex)-1, "%02x", d_record.at(n));
      str << hex;
    }
    str<<"\n";
    return str.str();
  }
  

private:
  struct dnsrecordheader d_ah;
  vector<u_int8_t> d_record;
};



DNSRecordContent* DNSRecordContent::mastermake(const struct dnsrecordheader& ah, 
					       PacketReader& pr)
{
  typemap_t::const_iterator i=typemap.find(make_pair(ah.d_class, ah.d_type));
  if(i==typemap.end()) {
    return new UnknownRecordContent(ah, pr);
  }
  return i->second(ah, pr);
}


DNSRecordContent::typemap_t DNSRecordContent::typemap __attribute__((init_priority(1000)));

void MOADNSParser::init(const char *packet, unsigned int len)
{
  if(len < sizeof(dnsheader))
    throw MOADNSException("Packet shorter than minimal header");
  
  memcpy(&d_header, packet, sizeof(dnsheader));

  d_header.qdcount=ntohs(d_header.qdcount);
  d_header.ancount=ntohs(d_header.ancount);
  d_header.nscount=ntohs(d_header.nscount);
  d_header.arcount=ntohs(d_header.arcount);
  
  u_int16_t contentlen=len-sizeof(dnsheader);

  d_content.resize(contentlen);
  copy(packet+sizeof(dnsheader), packet+len, d_content.begin());
  
  unsigned int n;

  PacketReader pr(d_content);

  for(n=0;n < d_header.qdcount; ++n) {
    d_qname=pr.getLabel();
    d_qtype=pr.get16BitInt();
    d_qclass=pr.get16BitInt();
    //    cout<<"Question is for '"<<d_qname<<"', type "<<d_qtype<<endl;
  }
  
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
    dr.d_ah=ah; 
    d_answers.push_back(make_pair(dr, pr.d_pos));

    dr.d_content=boost::shared_ptr<DNSRecordContent>(DNSRecordContent::mastermake(ah, pr));
    if(dr.d_content) {
      //      cout<<dr.d_label<<"\t"<<dr.d_content->getZoneRepresentation();
    }

  }
  
  if(pr.d_pos!=contentlen) {
    //    cout<<pr.d_pos<<" != " <<contentlen<<endl;
    throw MOADNSException("Packet has trailing garbage");
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
}


void PacketReader::copyRecord(vector<unsigned char>& dest, u_int16_t len)
{
  dest.resize(len);
  for(u_int16_t n=0;n<len;++n) {
    dest.at(n)=d_content.at(d_pos++);
  }
}

void PacketReader::copyRecord(unsigned char* dest, u_int16_t len)
{
  if(d_pos + len > d_content.size())
    throw MOADNSException("Attempt to copy outside of packet");

  memcpy(dest, &d_content[d_pos], len);
  d_pos+=len;
}


u_int32_t PacketReader::get32BitInt()
{
  u_int32_t ret=0;
  ret+=d_content.at(d_pos++);
  ret<<=8;
  ret+=d_content.at(d_pos++);
  ret<<=8;
  ret+=d_content.at(d_pos++);
  ret<<=8;
  ret+=d_content.at(d_pos++);
  
  return ret;
}


u_int16_t PacketReader::get16BitInt()
{
  return get16BitInt(d_content, d_pos);
}

u_int16_t PacketReader::get16BitInt(const vector<unsigned char>&content, u_int16_t& pos)
{
  u_int16_t ret=0;
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
  return getLabelFromContent(d_content, d_pos, recurs++);
}


string PacketReader::getLabelFromContent(const vector<u_int8_t>& content, u_int16_t& frompos, int recurs) 
{
  if(recurs > 10)
    throw MOADNSException("Loop");
  
  string ret;
  for(;;) {
    unsigned char labellen=content.at(frompos++);
    
    // cout<<"Labellen: "<<(int)labellen<<endl;
    if(!labellen) {
      if(ret.empty())
	ret+=".";
      break;
    }
    if((labellen & 0xc0) == 0xc0) {
      u_int16_t offset=(labellen & ~0xc0) + content.at(frompos++) - sizeof(dnsheader);
      //	cout<<"This is an offset, need to go to: "<<offset<<endl;
      return ret+getLabelFromContent(content, offset, ++recurs);
    }
    else {
      for(int n=0;n<labellen;++n) {
	ret+=content.at(frompos++);
      }
      ret+=".";
    }
  }
  
  return ret;
}
