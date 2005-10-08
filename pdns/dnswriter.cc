#include "dnswriter.hh"
#include "misc.hh"
#include "dnsparser.hh"

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
  
  xfrLabel(qname, false);
  d_content.insert(d_content.end(), d_record.begin(), d_record.end());
  d_record.clear();

  qtype=htons(qtype);
  ptr=(const uint8_t*)&qtype;
  d_content.insert(d_content.end(), ptr, ptr+2);
  
  qclass=htons(qclass);
  ptr=(const uint8_t*)&qclass;
  d_content.insert(d_content.end(), ptr, ptr+2);
}

void DNSPacketWriter::setRD(bool rd)
{
  dnsheader* dh=reinterpret_cast<dnsheader*>( &*d_content.begin());
  dh->rd=rd;
}

void DNSPacketWriter::startRecord(const string& name, uint16_t qtype, uint32_t ttl, uint16_t qclass, Place place)
{
  if(!d_record.empty()) 
    commit();

  d_recordqname=name;
  d_recordqtype=qtype;
  d_recordqclass=qclass;
  d_recordttl=ttl;

  d_stuff = 0; 

  xfrLabel(d_recordqname, true);
  d_content.insert(d_content.end(), d_record.begin(), d_record.end());
  d_record.clear();

  d_stuff = sizeof(dnsrecordheader); // this is needed to get compressed label offsets right, the dnsrecordheader will be interspersed

  dnsheader* dh=reinterpret_cast<dnsheader*>( &*d_content.begin());
  switch(place) {
  case ANSWER:
    dh->ancount = htons(ntohs(dh->ancount) + 1);
    break;
  case AUTHORITY:
    dh->nscount = htons(ntohs(dh->nscount) + 1);
    break;
  case ADDITIONAL:
    dh->arcount = htons(ntohs(dh->arcount) + 1);
    break;
  }
}

void DNSPacketWriter::addOpt(int udpsize, int extRCode, int Z)
{
  uint32_t ttl=0;
  struct Stuff {
    uint8_t extRCode, version;
    uint16_t Z;
  } __attribute__((packed));

  Stuff stuff;

  stuff.extRCode=extRCode;
  stuff.version=0;
  stuff.Z=htons(Z);
  
  memcpy(&ttl, &stuff, sizeof(stuff));
  cout<<sizeof(stuff)<<endl;
  ttl=ntohl(ttl); // will be reversed later on
  
  startRecord("", ns_t_opt, ttl, udpsize, ADDITIONAL);
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


void DNSPacketWriter::xfrLabel(const string& label, bool compress)
{
  typedef vector<string> parts_t;
  parts_t parts;
  stringtok(parts, label, ".");
  
  string enc;
  unsigned int pos=d_content.size() + d_record.size() + d_stuff; // d_stuff is amount of stuff that is yet to be written out - the dnsrecordheader for example
  string chopped(label);
  
  for(parts_t::const_iterator i=parts.begin(); i!=parts.end(); ++i) {
    map<string, uint16_t>::iterator li;
    if(compress && (li=d_labelmap.find(chopped))!=d_labelmap.end()) {   // see if we've written out this domain before
      uint16_t offset=li->second;
      offset|=0xc000;
      enc.append(1, (char)(offset >> 8));
      enc.append(1, (char)(offset & 0xff));
      goto out;                                 // skip trailing 0 in case of compression
    }
    else if(compress || d_labelmap.count(chopped)) { // if 'compress' is true, li will be equal to d_labelmap.end()
      d_labelmap[chopped]=pos;                       //  if untrue, we need to count 
    }
    enc.append(1, (char)i->length());
    enc.append(*i);
    pos+=i->length()+1;
    chopOff(chopped);                   // www.powerdns.com -> powerdns.com -> com 
  }
  enc.append(1,(char)0);

 out:;

  const uint8_t* ptr=reinterpret_cast<const uint8_t*>(enc.c_str());
  d_record.insert(d_record.end(), ptr, ptr+enc.size());
}

void DNSPacketWriter::xfrBlob(const string& blob)
{
  const uint8_t* ptr=reinterpret_cast<const uint8_t*>(blob.c_str());

  d_record.insert(d_record.end(), ptr, ptr+blob.size());
}


void DNSPacketWriter::commit()
{
  // build dnsrecordheader
  struct dnsrecordheader drh;
  drh.d_type=htons(d_recordqtype);
  drh.d_class=htons(d_recordqclass);
  drh.d_ttl=htonl(d_recordttl);
  drh.d_clen=htons(d_record.size());

  // and write out the header
  const uint8_t* ptr=(const uint8_t*)&drh;
  d_content.insert(d_content.end(), ptr, ptr+sizeof(drh));

  // write out d_record
  d_content.insert(d_content.end(), d_record.begin(), d_record.end());

  d_record.clear();   // clear d_record, ready for next record
}






