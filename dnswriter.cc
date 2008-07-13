#include "dnswriter.hh"
#include "misc.hh"
#include "dnsparser.hh"
#include <boost/tokenizer.hpp>
#include <boost/algorithm/string.hpp>

DNSPacketWriter::DNSPacketWriter(vector<uint8_t>& content, const string& qname, uint16_t  qtype, uint16_t qclass, uint8_t opcode)
  : d_pos(0), d_content(content), d_qname(qname), d_qtype(qtype), d_qclass(qclass)
{
  d_content.clear();
  dnsheader dnsheader;
  
  memset(&dnsheader, 0, sizeof(dnsheader));
  dnsheader.id=0;
  dnsheader.qdcount=htons(1);
  dnsheader.opcode=opcode;
  
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
  d_labelmap.reserve(16);
}

dnsheader* DNSPacketWriter::getHeader()
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

  if(iequals(d_qname,d_recordqname)) {  // don't do the whole label compression thing if we *know* we can get away with "see question"
    static char marker[2]={0xc0, 0x0c};
    d_content.insert(d_content.end(), &marker[0], &marker[2]);
  }
  else {
    xfrLabel(d_recordqname, true);
    d_content.insert(d_content.end(), d_record.begin(), d_record.end());
    d_record.clear();
  }
      
  d_stuff = sizeof(dnsrecordheader); // this is needed to get compressed label offsets right, the dnsrecordheader will be interspersed
  d_sor=d_content.size() + d_stuff; // start of real record 
}

void DNSPacketWriter::addOpt(int udpsize, int extRCode, int Z, const vector<pair<uint16_t,string> >& options)
{
  uint32_t ttl=0;

  EDNS0Record stuff;

  stuff.extRCode=extRCode;
  stuff.version=0;
  stuff.Z=htons(Z);

  memcpy(&ttl, &stuff, sizeof(stuff));

  ttl=ntohl(ttl); // will be reversed later on
  
  startRecord("", ns_t_opt, ttl, udpsize, ADDITIONAL);
  for(optvect_t::const_iterator iter = options.begin(); iter != options.end(); ++iter) {
    xfr16BitInt(iter->first);
    xfr16BitInt(iter->second.length());
    xfrBlob(iter->second);
  } 
}

void DNSPacketWriter::xfr48BitInt(uint64_t val)
{
  unsigned char bytes[6];
  bytes[5] = val % 0xff; val /= 0xff;  // untested code! XXX FIXME
  bytes[4] = val % 0xff; val /= 0xff;
  bytes[3] = val % 0xff; val /= 0xff;
  bytes[2] = val % 0xff; val /= 0xff;
  bytes[1] = val % 0xff; val /= 0xff;
  bytes[0] = val % 0xff; val /= 0xff;

  d_record.insert(d_record.end(), bytes, bytes + 6);
}


void DNSPacketWriter::xfr32BitInt(uint32_t val)
{
  int rval=htonl(val);
  uint8_t* ptr=reinterpret_cast<uint8_t*>(&rval);
  d_record.insert(d_record.end(), ptr, ptr+4);
}

void DNSPacketWriter::xfr16BitInt(uint16_t val)
{
  uint16_t rval=htons(val);
  uint8_t* ptr=reinterpret_cast<uint8_t*>(&rval);
  d_record.insert(d_record.end(), ptr, ptr+2);
}

void DNSPacketWriter::xfr8BitInt(uint8_t val)
{
  d_record.push_back(val);
}

void DNSPacketWriter::xfrText(const string& text, bool)
{
  escaped_list_separator<char> sep('\\', ' ' , '"');
  tokenizer<escaped_list_separator<char> > tok(text, sep);

  tokenizer<escaped_list_separator<char> >::iterator beg=tok.begin();

  if(beg==tok.end()) {
    d_record.push_back(0);
  }
  else 
    for(; beg!=tok.end(); ++beg){
      d_record.push_back(beg->length());
      const uint8_t* ptr=(uint8_t*)(beg->c_str());
      d_record.insert(d_record.end(), ptr, ptr+beg->length());
    }
}

DNSPacketWriter::lmap_t::iterator find(DNSPacketWriter::lmap_t& lmap, const string& label)
{
  DNSPacketWriter::lmap_t::iterator ret;
  for(ret=lmap.begin(); ret != lmap.end(); ++ret)
    if(iequals(ret->first,label))
      break;
  return ret;
}

typedef vector<pair<string::size_type, string::size_type> > parts_t;

bool labeltokUnescape(parts_t& parts, const string& label)
{
  string::size_type epos = label.size(), lpos(0), pos;
  bool unescapedSomething = false;
  const char* ptr=label.c_str();

  parts.clear();

  for(pos = 0 ; pos < epos; ++pos) {
    if(ptr[pos]=='\\') {
      pos++;
      unescapedSomething = true;
      continue;
    }
    if(ptr[pos]=='.') {
      parts.push_back(make_pair(lpos, pos));
      lpos=pos+1;
    }
  }
  
  if(lpos < pos)
    parts.push_back(make_pair(lpos, pos));
  return unescapedSomething;
}

// this is the absolute hottest function in the pdns recursor 
void DNSPacketWriter::xfrLabel(const string& label, bool compress)
{
  parts_t parts;

  if(label.size()==1 && label[0]=='.') { // otherwise we encode '..'
    d_record.push_back(0);
    return;
  }

  bool unescaped=labeltokUnescape(parts, label); 
  
  // d_stuff is amount of stuff that is yet to be written out - the dnsrecordheader for example
  unsigned int pos=d_content.size() + d_record.size() + d_stuff; 
  string chopped;
  for(parts_t::const_iterator i=parts.begin(); i!=parts.end(); ++i) {
    chopped.assign(label.c_str() + i->first);
    lmap_t::iterator li=d_labelmap.end();
    // see if we've written out this domain before
    if(compress && (li=find(d_labelmap, chopped))!=d_labelmap.end()) {   
      uint16_t offset=li->second;
      offset|=0xc000;
      d_record.push_back((char)(offset >> 8));
      d_record.push_back((char)(offset & 0xff));
      goto out;                                 // skip trailing 0 in case of compression
    }

    if(li==d_labelmap.end() && pos< 16384)
      d_labelmap.push_back(make_pair(chopped, pos));                       //  if untrue, we need to count - also, don't store offsets > 16384, won't work

    if(unescaped) {
      string part(label.c_str() + i -> first, i->second - i->first);
      replace_all(part, "\\.", ".");
      d_record.push_back(part.size());
      unsigned int len=d_record.size();
      d_record.resize(len + part.size());

      memcpy(((&*d_record.begin()) + len), part.c_str(), part.size());
      pos+=(part.size())+1;			 
    }
    else {
      d_record.push_back((char)(i->second - i->first));
      unsigned int len=d_record.size();
      d_record.resize(len + i->second - i->first);
      memcpy(((&*d_record.begin()) + len), label.c_str() + i-> first, i->second - i->first);
      pos+=(i->second - i->first)+1;
    }
  }
  d_record.push_back(0);

 out:;
}

void DNSPacketWriter::xfrBlob(const string& blob, int  )
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

  // write out pending d_record
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






