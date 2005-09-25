#include "dnswriter.hh"
#include "misc.hh"
#include "dnsparser.hh"

static const string EncodeDNSLabel(const string& input)
{
  typedef vector<string> parts_t;
  parts_t parts;
  stringtok(parts,input,".");

  string ret;
  for(parts_t::const_iterator i=parts.begin(); i!=parts.end(); ++i) {
    ret.append(1, (char)i->length());
    ret.append(*i);
  }
  ret.append(1,(char)0);
  return ret;
}

DNSPacketWriter::DNSPacketWriter(vector<uint8_t>& content, const string& qname, uint16_t  qtype, uint16_t qclass)
  : d_pos(0), d_content(content), d_qname(qname), d_qtype(qtype), d_qclass(qclass)
{
  d_content.clear();
  dnsheader dnsheader;
  
  memset(&dnsheader, 0, sizeof(dnsheader));
  dnsheader.id=random();
  dnsheader.qdcount=htons(1);
  
  const uint8_t* ptr=(const uint8_t*)&dnsheader;
  d_content.insert(d_content.end(), ptr, ptr + sizeof(dnsheader));    
  
  string label=EncodeDNSLabel(d_qname);
  ptr=(const uint8_t*) label.c_str();
  d_content.insert(d_content.end(), ptr, ptr + label.length());    
  
  qtype=htons(qtype);
  ptr=(const uint8_t*)&qtype;
  d_content.insert(d_content.end(), ptr, ptr+2);
  
  qclass=htons(qclass);
  ptr=(const uint8_t*)&qclass;
  d_content.insert(d_content.end(), ptr, ptr+2);
}

void DNSPacketWriter::startRecord(const string& name, uint16_t qtype, uint16_t qclass)
{
  if(!d_record.empty()) 
    commit();
  d_recordqname=name;
  d_recordqtype=qtype;
  d_recordqclass=qclass;

  dnsheader* dh=(dnsheader*) &*d_content.begin();
  dh->ancount = htons(ntohs(dh->ancount) + 1);
}

void DNSPacketWriter::xfr32BitInt(uint32_t val)
{
  uint8_t* ptr=reinterpret_cast<uint8_t*>(&val);
  d_record.insert(d_record.end(), ptr, ptr+4);
}

void DNSPacketWriter::xfr16BitInt(uint16_t val)
{
  uint8_t* ptr=reinterpret_cast<uint8_t*>(&val);
  d_record.insert(d_record.end(), ptr, ptr+2);
}

void DNSPacketWriter::xfr8BitInt(uint8_t val)
{
  d_record.push_back(val);
}

void DNSPacketWriter::xfrText(const string& text)
{
  d_record.push_back(text.length());
  const uint8_t* ptr=(uint8_t*)(text.c_str());
  d_record.insert(d_record.end(), ptr, ptr+text.size());
}

void DNSPacketWriter::xfrLabel(const string& label)
{
  string encoded=EncodeDNSLabel(label);
  const uint8_t* ptr=reinterpret_cast<const uint8_t*>(encoded.c_str());

  d_record.insert(d_record.end(), ptr, ptr+encoded.size());
}


void DNSPacketWriter::commit()
{
  string label=EncodeDNSLabel(d_qname); // write out qname

  const uint8_t* ptr=(const uint8_t*) label.c_str();
  d_content.insert(d_content.end(), ptr, ptr + label.length());

  // write out dnsrecordheader
  struct dnsrecordheader drh;
  drh.d_type=htons(d_recordqtype);
  drh.d_class=htons(d_recordqclass);
  drh.d_ttl=htonl(3600);
  drh.d_clen=htons(d_record.size());

  ptr=(const uint8_t*)&drh;
  d_content.insert(d_content.end(), ptr, ptr+sizeof(drh));

  // write out d_record
  d_content.insert(d_content.end(), d_record.begin(), d_record.end());

  d_record.clear();   // clear d_record
}






