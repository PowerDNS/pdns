#include "dnswriter.hh"
#include "misc.hh"
#include "dnsparser.hh"

DNSPacketWriter::DNSPacketWriter(vector<uint8_t>& content, const string& qname, uint16_t  qtype, uint16_t qclass)
  : d_pos(0), d_content(content), d_qname(qname), d_qtype(qtype), d_qclass(qclass)
{
  d_content.clear();
  dnsheader dnsheader;
  
  memset(&dnsheader, 0, sizeof(dnsheader));
  dnsheader.id=0;
  dnsheader.qdcount=htons(1);
  
  const uint8_t* ptr=(const uint8_t*)&dnsheader;
  uint32_t len=d_content.size();
  d_content.resize(len + sizeof(dnsheader));
  uint8_t* dptr=(&*d_content.begin()) + len;
  
  memcpy(dptr, ptr, sizeof(dnsheader));
  d_stuff=0;
  xfrLabel(qname, false);
  
  len=d_content.size();
  d_content.resize(len + d_record.size() + 4);

  ptr=&*d_record.begin();
  dptr=(&*d_content.begin()) + len;
  
  memcpy(dptr, ptr, d_record.size());

  len+=d_record.size();
  d_record.clear();

  qtype=htons(qtype);
  qclass=htons(qclass);

  vector<uint8_t>::iterator i=d_content.begin()+len; // this works around a gcc 3.4 bug
  memcpy(&*i, &qtype, 2);
  i+=2;
  memcpy(&*i, &qclass, 2);

  d_stuff=0xffff;
}

DNSPacketWriter::dnsheader* DNSPacketWriter::getHeader()
{
  return (dnsheader*)&*d_content.begin();
}


void DNSPacketWriter::startRecord(const string& name, uint16_t qtype, uint32_t ttl, uint16_t qclass, Place place)
{
  if(!d_record.empty()) 
    commit();

  d_recordqname=name;
  d_recordqtype=qtype;
  d_recordqclass=qclass;
  d_recordttl=ttl;
  d_recordplace=place;

  d_stuff = 0; 
  d_rollbackmarker=d_content.size();

  xfrLabel(d_recordqname, true);
  d_content.insert(d_content.end(), d_record.begin(), d_record.end());
  d_record.clear();

  d_stuff = sizeof(dnsrecordheader); // this is needed to get compressed label offsets right, the dnsrecordheader will be interspersed
  d_sor=d_content.size() + d_stuff; // start of real record 
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

  ttl=ntohl(ttl); // will be reversed later on
  
  startRecord("", ns_t_opt, ttl, udpsize, ADDITIONAL);
}

void DNSPacketWriter::xfr32BitInt(uint32_t val)
{
  int rval=htonl(val);
  uint8_t* ptr=reinterpret_cast<uint8_t*>(&rval);
  d_record.insert(d_record.end(), ptr, ptr+4);
}

void DNSPacketWriter::xfr16BitInt(uint16_t val)
{
  int rval=htons(val);
  uint8_t* ptr=reinterpret_cast<uint8_t*>(&rval);
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

// this is the absolute hottest function in the pdns recursor
void DNSPacketWriter::xfrLabel(const string& label, bool compress)
{
  typedef vector<pair<unsigned int, unsigned int> > parts_t;
  parts_t parts;
  vstringtok(parts, label, "."); // XXX FIXME this should deal with escaped .
  
  // d_stuff is amount of stuff that is yet to be written out - the dnsrecordheader for example
  unsigned int pos=d_content.size() + d_record.size() + d_stuff; 
  string chopped(label);

  for(parts_t::const_iterator i=parts.begin(); i!=parts.end(); ++i) {
    //    cerr<<"chopped: '"<<chopped<<"'\n";
    map<string, uint16_t>::iterator li=d_labelmap.end();
    // see if we've written out this domain before
    if(compress && (li=d_labelmap.find(chopped))!=d_labelmap.end()) {   
      uint16_t offset=li->second;
      offset|=0xc000;
      d_record.push_back((char)(offset >> 8));
      d_record.push_back((char)(offset & 0xff));
      goto out;                                 // skip trailing 0 in case of compression
    }

    if(li==d_labelmap.end() && pos< 16384)
      d_labelmap[chopped]=pos;                       //  if untrue, we need to count - also, don't store offsets > 16384, won't work
    
    d_record.push_back((char)(i->second - i->first));
    unsigned int len=d_record.size();
    d_record.resize(len + i->second - i->first);
    memcpy(((&*d_record.begin()) + len), label.c_str() + i-> first, i->second - i->first);
    //    cerr<<"Added: '"<<string(label.c_str() + i->first, i->second - i->first) <<"'\n";
    pos+=(i->second - i->first)+1;
    chopOff(chopped);                   // www.powerdns.com. -> powerdns.com. -> com. -> .
  }
  d_record.push_back(0);

 out:;
}

void DNSPacketWriter::xfrBlob(const string& blob)
{
  const uint8_t* ptr=reinterpret_cast<const uint8_t*>(blob.c_str());

  d_record.insert(d_record.end(), ptr, ptr+blob.size());
}

void DNSPacketWriter::xfrHexBlob(const string& blob)
{
  xfrBlob(blob);
}


void DNSPacketWriter::getRecords(string& records)
{
  records.assign(d_content.begin() + d_sor, d_content.end());
}

uint16_t DNSPacketWriter::size()
{
  return d_content.size() + d_stuff + d_record.size();
}

void DNSPacketWriter::rollback()
{
  d_content.resize(d_rollbackmarker);
  d_record.clear();
  d_stuff=0;
}

void DNSPacketWriter::commit()
{
  if(d_stuff==0xffff && (d_content.size()!=d_sor || !d_record.empty()))
    throw MOADNSException("DNSPacketWriter::commit() called without startRecord ever having been called, but a record was added");
  // build dnsrecordheader
  struct dnsrecordheader drh;
  drh.d_type=htons(d_recordqtype);
  drh.d_class=htons(d_recordqclass);
  drh.d_ttl=htonl(d_recordttl);
  drh.d_clen=htons(d_record.size());
  
  // and write out the header
  const uint8_t* ptr=(const uint8_t*)&drh;
  d_content.insert(d_content.end(), ptr, ptr+sizeof(drh));

  d_stuff=0;

  // write out d_record
  d_content.insert(d_content.end(), d_record.begin(), d_record.end());

  dnsheader* dh=reinterpret_cast<dnsheader*>( &*d_content.begin());
  switch(d_recordplace) {
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

  d_record.clear();   // clear d_record, ready for next record
}






