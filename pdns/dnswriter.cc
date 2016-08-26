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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/container/static_vector.hpp>
#include "dnswriter.hh"
#include "misc.hh"
#include "dnsparser.hh"

#include <limits.h>

DNSPacketWriter::DNSPacketWriter(vector<uint8_t>& content, const DNSName& qname, uint16_t  qtype, uint16_t qclass, uint8_t opcode)
  : d_content(content), d_qname(qname), d_canonic(false), d_lowerCase(false)
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
  d_namepositions.reserve(16);
  xfrName(qname, false);

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
  d_truncatemarker=d_content.size();
  d_sor = 0;
  d_rollbackmarker = 0;
  d_recordttl = 0;
  d_recordqtype = 0;
  d_recordqclass = QClass::IN;
  d_recordplace = DNSResourceRecord::ANSWER;
}

dnsheader* DNSPacketWriter::getHeader()
{
  return reinterpret_cast<dnsheader*>(&*d_content.begin());
}

void DNSPacketWriter::startRecord(const DNSName& name, uint16_t qtype, uint32_t ttl, uint16_t qclass, DNSResourceRecord::Place place, bool compress)
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

  if(compress && d_recordqname.countLabels() && d_qname==d_recordqname) {  // don't do the whole label compression thing if we *know* we can get away with "see question" - except when compressing the root
    static unsigned char marker[2]={0xc0, 0x0c};
    d_content.insert(d_content.end(), (const char *) &marker[0], (const char *) &marker[2]);
  }
  else {
    xfrName(d_recordqname, compress);
    d_content.insert(d_content.end(), d_record.begin(), d_record.end());
    d_record.clear();
  }

  d_stuff = sizeof(dnsrecordheader); // this is needed to get compressed label offsets right, the dnsrecordheader will be interspersed
  d_sor=d_content.size() + d_stuff; // start of real record
}

void DNSPacketWriter::addOpt(uint16_t udpsize, int extRCode, int Z, const vector<pair<uint16_t,string> >& options)
{
  uint32_t ttl=0;

  EDNS0Record stuff;

  stuff.extRCode=extRCode;
  stuff.version=0;
  stuff.Z=htons(Z);

  static_assert(sizeof(EDNS0Record) == sizeof(ttl), "sizeof(EDNS0Record) must match sizeof(ttl)");
  memcpy(&ttl, &stuff, sizeof(stuff));

  ttl=ntohl(ttl); // will be reversed later on

  startRecord(g_rootdnsname, QType::OPT, ttl, udpsize, DNSResourceRecord::ADDITIONAL, false);
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
  memcpy(bytes, (void*)&theLeft, sizeof(theLeft));
  memcpy(bytes+2, (void*)&theRight, sizeof(theRight));

  d_record.insert(d_record.end(), bytes, bytes + sizeof(bytes));
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
 if lenField is true
  "" -> 0
  "blah" -> 4blah
  "blah" "blah" -> output 4blah4blah
  "verylongstringlongerthan256....characters" \xffverylongstring\x23characters (autosplit)
  "blah\"blah" -> 9blah"blah
  "blah\97" -> 5blahb

 if lenField is false
  "blah" -> blah
  "blah\"blah" -> blah"blah
  */
void DNSPacketWriter::xfrText(const string& text, bool, bool lenField)
{
  if(text.empty()) {
    d_record.push_back(0);
    return;
  }
  vector<string> segments = segmentDNSText(text);
  for(const string& str :  segments) {
    if(lenField)
      d_record.push_back(str.length());
    d_record.insert(d_record.end(), str.c_str(), str.c_str() + str.length());
  }
}

void DNSPacketWriter::xfrUnquotedText(const string& text, bool lenField)
{
  if(text.empty()) {
    d_record.push_back(0);
    return;
  }
  if(lenField)
    d_record.push_back(text.length());
  d_record.insert(d_record.end(), text.c_str(), text.c_str() + text.length());
}


static constexpr bool l_verbose=false;
uint16_t DNSPacketWriter::lookupName(const DNSName& name, uint16_t* matchLen)
{
  // iterate over the written labels, see if we find a match
  const auto& raw = name.getStorage();

  /* name might be a.root-servers.net, we need to be able to benefit from finding:
     b.root-servers.net, or even:
     b\xc0\x0c 
  */
  unsigned int bestpos=0;
  *matchLen=0;
  boost::container::static_vector<uint16_t, 34> nvect, pvect;

  for(auto riter= raw.cbegin(); riter < raw.cend(); ) {
    if(!*riter)
      break;
    nvect.push_back(riter - raw.cbegin());
    riter+=*riter+1;
  }
  
  if(l_verbose) {
    cout<<"Input vector for lookup "<<name<<": ";
    for(const auto n : nvect) 
      cout << n<<" ";
    cout<<endl;
    cout<<makeHexDump(string(raw.c_str(), raw.c_str()+raw.size()))<<endl;
  }

  if(l_verbose)
    cout<<"Have "<<d_namepositions.size()<<" to ponder"<<endl;
  int counter=1;
  for(auto p : d_namepositions) {
    vector<uint8_t>* source=0;
    if(p < d_content.size())
      source = &d_content;
    else {
      source = &d_record;
      p-= (d_content.size() + d_stuff);

    }
    if(l_verbose) {
      if(source == &d_content) {
        DNSName pname((const char*)&(*source)[0], (*source).size(), p, true); // only for debugging
        cout<<"Looking at '"<<pname<<"' in packet at position "<<p<<"/"<<(*source).size()<<", option "<<counter<<"/"<<d_namepositions.size()<<endl;
      }
      else
      {
        cout<<"Looking at *record* at position "<<p<<"/"<<(*source).size()<<", option "<<counter<<"/"<<d_namepositions.size()<<endl;
      }
      ++counter;
    }
    // memcmp here makes things _slower_
    pvect.clear();
    for(auto iter = (*source).cbegin() + p; iter < (*source).cend();) {

      uint8_t c=*iter;
      if(l_verbose)
        cout<<"Found label length: "<<(int)c<<endl;
      if(c & 0xc0) {

        uint16_t npos = 0x100*(c & (~0xc0)) + *++iter;
        iter = (*source).begin() + npos;
        if(l_verbose)
          cout<<"Is compressed label to newpos "<<npos<<", going there"<<endl;
        // check against going forward here
        continue;
      }
      if(!c)
        break;
      pvect.push_back(iter - (*source).cbegin());
      iter+=*iter+1;
    }
    if(l_verbose) {
      cout<<"Packet vector: "<<endl;
      for(const auto n : pvect) 
        cout << n<<" ";
      cout<<endl;
    }
    auto niter=nvect.crbegin(), piter=pvect.crbegin();
    unsigned int cmatchlen=1;
    for(; niter != nvect.crend() && piter != pvect.crend(); ++niter, ++piter) {
      // niter is an offset in raw, pvect an offset in packet
      uint8_t nlen = raw[*niter], plen=(*source)[*piter];
      if(l_verbose)
        cout<<"nlnen="<<(int)nlen<<", plen="<<(int)plen<<endl;
      if(nlen != plen)
        break;
      if(strncasecmp(raw.c_str()+*niter+1, (const char*)&(*source)[*piter]+1, nlen)) {
        if(l_verbose)
          cout<<"Mismatch: "<<string(raw.c_str()+*niter+1, raw.c_str()+*niter+nlen+1)<< " != "<<string((const char*)&(*source)[*piter]+1, (const char*)&(*source)[*piter]+nlen+1)<<endl;
        break;
      }
      cmatchlen+=nlen+1;
      if(cmatchlen == raw.length()) { // have matched all of it, can't improve
        if(l_verbose)
          cout<<"Stopping search, matched whole name"<<endl;
        *matchLen = cmatchlen;
        return *piter;
      }
    }
    if(piter != pvect.crbegin() && *matchLen < cmatchlen) {
      *matchLen = cmatchlen;
      bestpos=*--piter;
    }
  }
  return bestpos;
}

// this is the absolute hottest function in the pdns recursor
void DNSPacketWriter::xfrName(const DNSName& name, bool compress, bool)
{
  if(l_verbose)
    cout<<"Wants to write "<<name<<", compress="<<compress<<", canonic="<<d_canonic<<", LC="<<d_lowerCase<<endl;
  if(d_canonic || d_lowerCase)   // d_lowerCase implies canonic
    compress=false;

  if(name.empty() || name.isRoot()) { // for speed
    d_record.push_back(0);
    return;
  }

  uint16_t li=0;
  uint16_t matchlen=0;
  if(compress && (li=lookupName(name, &matchlen))) {
    const auto& dns=name.getStorage(); 
    if(l_verbose)
      cout<<"Found a substring of "<<matchlen<<" bytes from the back, offset: "<<li<<", dnslen: "<<dns.size()<<endl;
    // found a substring, if www.powerdns.com matched powerdns.com, we get back matchlen = 13

    unsigned int pos=d_content.size() + d_record.size() + d_stuff;  
    if(pos < 16384 && matchlen != dns.size()) {
      if(l_verbose)
        cout<<"Inserting pos "<<pos<<" for "<<name<<" for compressed case"<<endl;
      d_namepositions.push_back(pos);
    }

    if(l_verbose)
      cout<<"Going to write unique part: '"<<makeHexDump(string(dns.c_str(), dns.c_str() + dns.size() - matchlen)) <<"'"<<endl;
    d_record.insert(d_record.end(), (const unsigned char*)dns.c_str(), (const unsigned char*)dns.c_str() + dns.size() - matchlen);
    uint16_t offset=li;
    offset|=0xc000;

    d_record.push_back((char)(offset >> 8));
    d_record.push_back((char)(offset & 0xff));
  }
  else {
    unsigned int pos=d_content.size() + d_record.size() + d_stuff;
    if(l_verbose)
      cout<<"Found nothing, we are at pos "<<pos<<", inserting whole name"<<endl;
    if(pos < 16384) {
      if(l_verbose)
        cout<<"Inserting pos "<<pos<<" for "<<name<<" for uncompressed case"<<endl;
      d_namepositions.push_back(pos);
    }

    std::unique_ptr<DNSName> lc;
    if(d_lowerCase)
      lc = make_unique<DNSName>(name.makeLowerCase());

    const DNSName::string_t& raw = (lc ? *lc : name).getStorage();
    if(l_verbose)
      cout<<"Writing out the whole thing "<<makeHexDump(string(raw.c_str(),  raw.c_str() + raw.length()))<<endl;
    d_record.insert(d_record.end(), raw.c_str(), raw.c_str() + raw.size());
  }
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
  case DNSResourceRecord::QUESTION:
    dh->qdcount = htons(ntohs(dh->qdcount) + 1);
    break;
  case DNSResourceRecord::ANSWER:
    dh->ancount = htons(ntohs(dh->ancount) + 1);
    break;
  case DNSResourceRecord::AUTHORITY:
    dh->nscount = htons(ntohs(dh->nscount) + 1);
    break;
  case DNSResourceRecord::ADDITIONAL:
    dh->arcount = htons(ntohs(dh->arcount) + 1);
    break;
  }

  d_record.clear();   // clear d_record, ready for next record
}
