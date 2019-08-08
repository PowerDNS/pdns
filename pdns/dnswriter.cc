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
#include <boost/version.hpp>
#if BOOST_VERSION >= 105400
#include <boost/container/static_vector.hpp>
#endif
#include "dnswriter.hh"
#include "misc.hh"
#include "dnsparser.hh"

#include <limits.h>

/* d_content:                                      <---- d_stuff ---->
                                      v d_truncatemarker  
   dnsheader | qname | qtype | qclass | {recordname| dnsrecordheader | record }
                                        ^ d_rollbackmarker           ^ d_sor 
    

*/


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
  d_namepositions.reserve(16);
  xfrName(qname, false);
  xfr16BitInt(qtype);
  xfr16BitInt(qclass);

  d_truncatemarker=d_content.size();
  d_sor = 0;
  d_rollbackmarker = 0;
}

dnsheader* DNSPacketWriter::getHeader()
{
  return reinterpret_cast<dnsheader*>(&*d_content.begin());
}


void DNSPacketWriter::startRecord(const DNSName& name, uint16_t qtype, uint32_t ttl, uint16_t qclass, DNSResourceRecord::Place place, bool compress)
{
  d_compress = compress;
  commit();
  d_rollbackmarker=d_content.size();

  if(compress && !name.isRoot() && d_qname==name) {  // don't do the whole label compression thing if we *know* we can get away with "see question" - except when compressing the root
    static unsigned char marker[2]={0xc0, 0x0c};
    d_content.insert(d_content.end(), (const char *) &marker[0], (const char *) &marker[2]);
  }
  else {
    xfrName(name, compress);
  }
  xfr16BitInt(qtype);
  xfr16BitInt(qclass);
  xfr32BitInt(ttl);
  xfr16BitInt(0); // this will be the record size
  d_recordplace = place;
  d_sor=d_content.size(); // this will remind us where to stuff the record size
}

void DNSPacketWriter::addOpt(const uint16_t udpsize, const uint16_t extRCode, const uint16_t ednsFlags, const optvect_t& options, const uint8_t version)
{
  uint32_t ttl=0;

  EDNS0Record stuff;

  stuff.version = version;
  stuff.extFlags = htons(ednsFlags);

  /* RFC 6891 section 4 on the Extended RCode wire format
   *    EXTENDED-RCODE
   *        Forms the upper 8 bits of extended 12-bit RCODE (together with the
   *        4 bits defined in [RFC1035].  Note that EXTENDED-RCODE value 0
   *        indicates that an unextended RCODE is in use (values 0 through 15).
   */
  // XXX Should be check for extRCode > 1<<12 ?
  stuff.extRCode = extRCode>>4;
  if (extRCode != 0) { // As this trumps the existing RCODE
    getHeader()->rcode = extRCode;
  }

  static_assert(sizeof(EDNS0Record) == sizeof(ttl), "sizeof(EDNS0Record) must match sizeof(ttl)");
  memcpy(&ttl, &stuff, sizeof(stuff));

  ttl=ntohl(ttl); // will be reversed later on

  startRecord(g_rootdnsname, QType::OPT, ttl, udpsize, DNSResourceRecord::ADDITIONAL, false);
  for(auto const &option : options) {
    xfr16BitInt(option.first);
    xfr16BitInt(option.second.length());
    xfrBlob(option.second);
  }
}

void DNSPacketWriter::xfr48BitInt(uint64_t val)
{
  unsigned char bytes[6];
  uint16_t theLeft = htons((val >> 32)&0xffffU);
  uint32_t theRight = htonl(val & 0xffffffffU);
  memcpy(bytes, (void*)&theLeft, sizeof(theLeft));
  memcpy(bytes+2, (void*)&theRight, sizeof(theRight));

  d_content.insert(d_content.end(), bytes, bytes + sizeof(bytes));
}


void DNSPacketWriter::xfr32BitInt(uint32_t val)
{
  uint32_t rval=htonl(val);
  uint8_t* ptr=reinterpret_cast<uint8_t*>(&rval);
  d_content.insert(d_content.end(), ptr, ptr+4);
}

void DNSPacketWriter::xfr16BitInt(uint16_t val)
{
  uint16_t rval=htons(val);
  uint8_t* ptr=reinterpret_cast<uint8_t*>(&rval);
  d_content.insert(d_content.end(), ptr, ptr+2);
}

void DNSPacketWriter::xfr8BitInt(uint8_t val)
{
  d_content.push_back(val);
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
    d_content.push_back(0);
    return;
  }
  vector<string> segments = segmentDNSText(text);
  for(const string& str :  segments) {
    if(lenField)
      d_content.push_back(str.length());
    d_content.insert(d_content.end(), str.c_str(), str.c_str() + str.length());
  }
}

void DNSPacketWriter::xfrUnquotedText(const string& text, bool lenField)
{
  if(text.empty()) {
    d_content.push_back(0);
    return;
  }
  if(lenField)
    d_content.push_back(text.length());
  d_content.insert(d_content.end(), text.c_str(), text.c_str() + text.length());
}


static constexpr bool l_verbose=false;
static constexpr uint16_t maxCompressionOffset=16384;
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
#if BOOST_VERSION >= 105400
  boost::container::static_vector<uint16_t, 34> nvect, pvect;
#else
  vector<uint16_t> nvect, pvect;
#endif

  try {
    for(auto riter= raw.cbegin(); riter < raw.cend(); ) {
      if(!*riter)
        break;
      nvect.push_back(riter - raw.cbegin());
      riter+=*riter+1;
    }
  }
  catch(std::bad_alloc& ba) {
    if(l_verbose)
      cout<<"Domain "<<name<<" too large to compress"<<endl;
    return 0;
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
    if(l_verbose) {
      cout<<"Pos: "<<p<<", "<<d_content.size()<<endl;
      DNSName pname((const char*)&d_content[0], d_content.size(), p, true); // only for debugging
      cout<<"Looking at '"<<pname<<"' in packet at position "<<p<<"/"<<d_content.size()<<", option "<<counter<<"/"<<d_namepositions.size()<<endl;
      ++counter;
    }
    // memcmp here makes things _slower_
    pvect.clear();
    try {
      for(auto iter = d_content.cbegin() + p; iter < d_content.cend();) {
        uint8_t c=*iter;
        if(l_verbose)
          cout<<"Found label length: "<<(int)c<<endl;
        if(c & 0xc0) {
          uint16_t npos = 0x100*(c & (~0xc0)) + *++iter;
          iter = d_content.begin() + npos;
          if(l_verbose)
            cout<<"Is compressed label to newpos "<<npos<<", going there"<<endl;
          // check against going forward here
          continue;
        }
        if(!c)
          break;
        auto offset = iter - d_content.cbegin();
        if (offset >= maxCompressionOffset) break; // compression pointers cannot point here
        pvect.push_back(offset);
        iter+=*iter+1;
      }
    }
    catch(std::bad_alloc& ba) {
      if(l_verbose)
        cout<<"Domain "<<name<<" too large to compress"<<endl;
      continue;
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
      uint8_t nlen = raw[*niter], plen=d_content[*piter];
      if(l_verbose)
        cout<<"nlnen="<<(int)nlen<<", plen="<<(int)plen<<endl;
      if(nlen != plen)
        break;
      if(strncasecmp(raw.c_str()+*niter+1, (const char*)&d_content[*piter]+1, nlen)) {
        if(l_verbose)
          cout<<"Mismatch: "<<string(raw.c_str()+*niter+1, raw.c_str()+*niter+nlen+1)<< " != "<<string((const char*)&d_content[*piter]+1, (const char*)&d_content[*piter]+nlen+1)<<endl;
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
    d_content.push_back(0);
    return;
  }

  uint16_t li=0;
  uint16_t matchlen=0;
  if(d_compress && compress && (li=lookupName(name, &matchlen)) && li < maxCompressionOffset) {
    const auto& dns=name.getStorage(); 
    if(l_verbose)
      cout<<"Found a substring of "<<matchlen<<" bytes from the back, offset: "<<li<<", dnslen: "<<dns.size()<<endl;
    // found a substring, if www.powerdns.com matched powerdns.com, we get back matchlen = 13

    unsigned int pos=d_content.size();
    if(pos < maxCompressionOffset && matchlen != dns.size()) {
      if(l_verbose)
        cout<<"Inserting pos "<<pos<<" for "<<name<<" for compressed case"<<endl;
      d_namepositions.push_back(pos);
    }

    if(l_verbose)
      cout<<"Going to write unique part: '"<<makeHexDump(string(dns.c_str(), dns.c_str() + dns.size() - matchlen)) <<"'"<<endl;
    d_content.insert(d_content.end(), (const unsigned char*)dns.c_str(), (const unsigned char*)dns.c_str() + dns.size() - matchlen);
    uint16_t offset=li;
    offset|=0xc000;

    d_content.push_back((char)(offset >> 8));
    d_content.push_back((char)(offset & 0xff));
  }
  else {
    unsigned int pos=d_content.size();
    if(l_verbose)
      cout<<"Found nothing, we are at pos "<<pos<<", inserting whole name"<<endl;
    if(pos < maxCompressionOffset) {
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
    d_content.insert(d_content.end(), raw.c_str(), raw.c_str() + raw.size());
  }
}

void DNSPacketWriter::xfrBlob(const string& blob, int  )
{
  const uint8_t* ptr=reinterpret_cast<const uint8_t*>(blob.c_str());
  d_content.insert(d_content.end(), ptr, ptr+blob.size());
}

void DNSPacketWriter::xfrBlobNoSpaces(const string& blob, int  )
{
  xfrBlob(blob);
}

void DNSPacketWriter::xfrHexBlob(const string& blob, bool keepReading)
{
  xfrBlob(blob);
}

// call __before commit__
void DNSPacketWriter::getRecordPayload(string& records)
{
  records.assign(d_content.begin() + d_sor, d_content.end());
}

uint32_t DNSPacketWriter::size()
{
  return d_content.size();
}

void DNSPacketWriter::rollback()
{
  d_content.resize(d_rollbackmarker);
  d_sor = 0;
}

void DNSPacketWriter::truncate()
{
  d_content.resize(d_truncatemarker);
  dnsheader* dh=reinterpret_cast<dnsheader*>( &*d_content.begin());
  dh->ancount = dh->nscount = dh->arcount = 0;
}

void DNSPacketWriter::commit()
{
  if(!d_sor)
    return;
  uint16_t rlen = d_content.size() - d_sor;
  d_content[d_sor-2]=rlen >> 8;
  d_content[d_sor-1]=rlen & 0xff;
  d_sor=0;
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

}
