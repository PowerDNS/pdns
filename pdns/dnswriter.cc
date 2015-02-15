#include "dnswriter.hh"
#include "misc.hh"
#include "dnsparser.hh"
#include <boost/foreach.hpp>
#include <limits.h>

DNSPacketWriter::DNSPacketWriter(vector<uint8_t>& content, const string& qname, uint16_t  qtype, uint16_t qclass, uint8_t opcode)
  : d_pos(0), d_content(content), d_qname(qname), d_canonic(false), d_lowerCase(false)
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
  d_truncatemarker=d_content.size();
}

dnsheader* DNSPacketWriter::getHeader()
{
  return (dnsheader*)&*d_content.begin();
}

void DNSPacketWriter::startRecord(const string& name, uint16_t qtype, uint32_t ttl, uint16_t qclass, Place place, bool compress)
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

  if(compress && !d_recordqname.empty() && pdns_iequals(d_qname, d_recordqname)) {  // don't do the whole label compression thing if we *know* we can get away with "see question" - except when compressing the root
    static unsigned char marker[2]={0xc0, 0x0c};
    d_content.insert(d_content.end(), (const char *) &marker[0], (const char *) &marker[2]);
  }
  else {
    xfrLabel(d_recordqname, compress);
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
  
  startRecord("", QType::OPT, ttl, udpsize, ADDITIONAL, false);
  for(optvect_t::const_iterator iter = options.begin(); iter != options.end(); ++iter) {
    xfr16BitInt(iter->first);
    xfr16BitInt(iter->second.length());
    xfrBlob(iter->second);
  } 
}

void DNSPacketWriter::xfr48BitInt(uint64_t val)
{
  unsigned char bytes[6];
  uint16_t theLeft = htons((val >> 32)&0xffffU);
  uint32_t theRight = htonl(val & 0xffffffffU);
  memcpy(bytes, (void*)&theLeft, 2);
  memcpy(bytes+2, (void*)&theRight, 4);

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


/* input: 
  "" -> 0
  "blah" -> 4blah
  "blah" "blah" -> output 4blah4blah
  "verylongstringlongerthan256....characters" \xffverylongstring\x23characters (autosplit)
  "blah\"blah" -> 9blah"blah
  "blah\97" -> 5blahb
  */
void DNSPacketWriter::xfrText(const string& text, bool)
{
  if(text.empty()) {
    d_record.push_back(0);
    return;
  }
  vector<string> segments = segmentDNSText(text);
  BOOST_FOREACH(const string& str, segments) {
    d_record.push_back(str.length());
    d_record.insert(d_record.end(), str.c_str(), str.c_str() + str.length());
  }
}

DNSPacketWriter::lmap_t::iterator find(DNSPacketWriter::lmap_t& lmap, const string& label)
{
  DNSPacketWriter::lmap_t::iterator ret;
  for(ret=lmap.begin(); ret != lmap.end(); ++ret)
    if(pdns_iequals(ret->first ,label))
      break;
  return ret;
}

//! tokenize a label into parts, the parts describe a begin offset and an end offset
bool labeltokUnescape(labelparts_t& parts, const string& label)
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
void DNSPacketWriter::xfrLabel(const string& Label, bool compress)
{
  string label = d_lowerCase ? toLower(Label) : Label;
  labelparts_t parts;

  if(d_canonic)
    compress=false;

  string::size_type labellen = label.size();
  if(labellen==1 && label[0]=='.') { // otherwise we encode '..'
    d_record.push_back(0);
    return;
  }
  bool unescaped=labeltokUnescape(parts, label); 
  
  // d_stuff is amount of stuff that is yet to be written out - the dnsrecordheader for example
  unsigned int pos=d_content.size() + d_record.size() + d_stuff; 
  string chopped;
  bool deDot = labellen && (label[labellen-1]=='.'); // make sure we don't store trailing dots in the labelmap

  unsigned int startRecordSize=d_record.size();
  unsigned int startPos;

  for(labelparts_t::const_iterator i=parts.begin(); i!=parts.end(); ++i) {
    if(deDot)
      chopped.assign(label.c_str() + i->first, labellen - i->first -1);
    else
      chopped.assign(label.c_str() + i->first);

    lmap_t::iterator li=d_labelmap.end();
    // see if we've written out this domain before
    // cerr<<"Searching for compression pointer to '"<<chopped<<"', "<<d_labelmap.size()<<" cmp-records"<<endl;
    if(compress && (li=find(d_labelmap, chopped))!=d_labelmap.end()) {
      // cerr<<"\tFound a compression pointer to '"<<chopped<<"': "<<li->second<<endl;
      if (d_record.size() - startRecordSize + chopped.size() > 253) // chopped does not include a length octet for the first label and the root label
        throw MOADNSException("DNSPacketWriter::xfrLabel() found overly large (compressed) name");
      uint16_t offset=li->second;
      offset|=0xc000;
      d_record.push_back((char)(offset >> 8));
      d_record.push_back((char)(offset & 0xff));
      goto out;                                 // skip trailing 0 in case of compression
    }

    if(li==d_labelmap.end() && pos< 16384) {
      //      cerr<<"\tStoring a compression pointer to '"<<chopped<<"': "<<pos<<endl;
      d_labelmap.push_back(make_pair(chopped, pos));                       //  if untrue, we need to count - also, don't store offsets > 16384, won't work
    }

    startPos=pos;

    if(unescaped) {
      string part(label.c_str() + i -> first, i->second - i->first);

      // FIXME: this relies on the semi-canonical escaped output from getLabelFromContent
      boost::replace_all(part, "\\.", ".");
      boost::replace_all(part, "\\032", " ");
      boost::replace_all(part, "\\\\", "\\"); 

      d_record.push_back(part.size());
      unsigned int len=d_record.size();
      d_record.resize(len + part.size());
      memcpy(((&*d_record.begin()) + len), part.c_str(), part.size());
      pos+=(part.size())+1;
    }
    else {
      char labelsize=(char)(i->second - i->first);
      d_record.push_back(labelsize);
      unsigned int len=d_record.size();
      d_record.resize(len + i->second - i->first);
      memcpy(((&*d_record.begin()) + len), label.c_str() + i-> first, i->second - i->first);
      pos+=(i->second - i->first)+1;
    }

    if(pos - startPos == 1)
      throw MOADNSException("DNSPacketWriter::xfrLabel() found empty label in the middle of name");
    if(pos - startPos > 64)
      throw MOADNSException("DNSPacketWriter::xfrLabel() found overly large label in name");
  }
  d_record.push_back(0); // insert root label

  if (d_record.size() - startRecordSize > 255)
    throw MOADNSException("DNSPacketWriter::xfrLabel() found overly large name");

  out:;
}

void DNSPacketWriter::xfrBlob(const string& blob, int  )
{
  const uint8_t* ptr=reinterpret_cast<const uint8_t*>(blob.c_str());
  d_record.insert(d_record.end(), ptr, ptr+blob.size());
}

void DNSPacketWriter::xfrBlobNoSpaces(const string& blob, int  )
{
  xfrBlob(blob);
}

void DNSPacketWriter::xfrHexBlob(const string& blob, bool keepReading)
{
  xfrBlob(blob);
}

void DNSPacketWriter::getRecords(string& records)
{
  records.assign(d_content.begin() + d_sor, d_content.end());
}

uint32_t DNSPacketWriter::size()
{
  return d_content.size() + d_stuff + d_record.size();
}

void DNSPacketWriter::rollback()
{
  d_content.resize(d_rollbackmarker);
  d_record.clear();
  d_stuff=0;
}

void DNSPacketWriter::truncate()
{
  d_content.resize(d_truncatemarker);
  d_record.clear();
  d_stuff=0;
  dnsheader* dh=reinterpret_cast<dnsheader*>( &*d_content.begin());
  dh->ancount = dh->nscount = dh->arcount = 0;
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






