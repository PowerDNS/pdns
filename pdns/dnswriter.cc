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


template <typename Container> GenericDNSPacketWriter<Container>::GenericDNSPacketWriter(Container& content, const DNSName& qname, uint16_t  qtype, uint16_t qclass, uint8_t opcode)
  : d_content(content), d_qname(qname), d_canonic(false), d_lowerCase(false)
{
  d_content.clear();
  dnsheader dnsheader;

  memset(&dnsheader, 0, sizeof(dnsheader));
  dnsheader.id=0;
  dnsheader.qdcount=htons(1);
  dnsheader.opcode=opcode;

  const uint8_t* ptr=(const uint8_t*)&dnsheader;
  d_content.reserve(sizeof(dnsheader) + qname.wirelength() + sizeof(qtype) + sizeof(qclass));
  d_content.resize(sizeof(dnsheader));
  uint8_t* dptr=(&*d_content.begin());

  memcpy(dptr, ptr, sizeof(dnsheader));
  d_namepositions.reserve(16);
  xfrName(qname, false);
  xfr16BitInt(qtype);
  xfr16BitInt(qclass);

  d_truncatemarker=d_content.size();
  d_sor = 0;
  d_rollbackmarker = 0;
}

template <typename Container> dnsheader* GenericDNSPacketWriter<Container>::getHeader()
{
  return reinterpret_cast<dnsheader*>(&*d_content.begin());
}


template <typename Container> void GenericDNSPacketWriter<Container>::startRecord(const DNSName& name, uint16_t qtype, uint32_t ttl, uint16_t qclass, DNSResourceRecord::Place place, bool compress)
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

template <typename Container> void GenericDNSPacketWriter<Container>::addOpt(const uint16_t udpsize, const uint16_t extRCode, const uint16_t ednsFlags, const optvect_t& options, const uint8_t version)
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

template <typename Container> void GenericDNSPacketWriter<Container>::xfr48BitInt(uint64_t val)
{
  unsigned char bytes[6];
  uint16_t theLeft = htons((val >> 32)&0xffffU);
  uint32_t theRight = htonl(val & 0xffffffffU);
  memcpy(bytes, (void*)&theLeft, sizeof(theLeft));
  memcpy(bytes+2, (void*)&theRight, sizeof(theRight));

  d_content.insert(d_content.end(), bytes, bytes + sizeof(bytes));
}

template <typename Container> void GenericDNSPacketWriter<Container>::xfrNodeOrLocatorID(const NodeOrLocatorID& val)
{
  d_content.insert(d_content.end(), val.content, val.content + sizeof(val.content));
}

template <typename Container> void GenericDNSPacketWriter<Container>::xfr32BitInt(uint32_t val)
{
  uint32_t rval=htonl(val);
  uint8_t* ptr=reinterpret_cast<uint8_t*>(&rval);
  d_content.insert(d_content.end(), ptr, ptr+4);
}

template <typename Container> void GenericDNSPacketWriter<Container>::xfr16BitInt(uint16_t val)
{
  uint16_t rval=htons(val);
  uint8_t* ptr=reinterpret_cast<uint8_t*>(&rval);
  d_content.insert(d_content.end(), ptr, ptr+2);
}

template <typename Container> void GenericDNSPacketWriter<Container>::xfr8BitInt(uint8_t val)
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
template <typename Container> void GenericDNSPacketWriter<Container>::xfrText(const string& text, bool, bool lenField)
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

template <typename Container> void GenericDNSPacketWriter<Container>::xfrUnquotedText(const string& text, bool lenField)
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
template <typename Container> uint16_t GenericDNSPacketWriter<Container>::lookupName(const DNSName& name, uint16_t* matchLen)
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
template <typename Container> void GenericDNSPacketWriter<Container>::xfrName(const DNSName& name, bool compress, bool)
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

template <typename Container> void GenericDNSPacketWriter<Container>::xfrBlob(const string& blob, int  )
{
  const uint8_t* ptr=reinterpret_cast<const uint8_t*>(blob.c_str());
  d_content.insert(d_content.end(), ptr, ptr+blob.size());
}

template <typename Container> void GenericDNSPacketWriter<Container>::xfrBlob(const std::vector<uint8_t>& blob)
{
  d_content.insert(d_content.end(), blob.begin(), blob.end());
}

template <typename Container> void GenericDNSPacketWriter<Container>::xfrBlobNoSpaces(const string& blob, int  )
{
  xfrBlob(blob);
}

template <typename Container> void GenericDNSPacketWriter<Container>::xfrHexBlob(const string& blob, bool keepReading)
{
  xfrBlob(blob);
}

template <typename Container> void GenericDNSPacketWriter<Container>::xfrSvcParamKeyVals(const std::set<SvcParam> &kvs)
{
  for (auto const &param : kvs) {
    // Key first!
    xfr16BitInt(param.getKey());

    switch (param.getKey())
    {
    case SvcParam::mandatory:
      xfr16BitInt(2 * param.getMandatory().size());
      for (auto const &m: param.getMandatory()) {
        xfr16BitInt(m);
      }
      break;
    case SvcParam::alpn:
    {
      uint16_t totalSize = param.getALPN().size(); // All 1 octet size headers for each value
      for (auto const &a : param.getALPN()) {
        totalSize += a.length();
      }
      xfr16BitInt(totalSize);
      for (auto const &a : param.getALPN()) {
        xfrUnquotedText(a, true); // will add the 1-byte length field
      }
      break;
    }
    case SvcParam::no_default_alpn:
      xfr16BitInt(0); // no size :)
      break;
    case SvcParam::port:
      xfr16BitInt(2); // size
      xfr16BitInt(param.getPort());
      break;
    case SvcParam::ipv4hint:
      xfr16BitInt(param.getIPHints().size() * 4); // size
      for (auto a: param.getIPHints()) {
        xfrCAWithoutPort(param.getKey(), a);
      }
      break;
    case SvcParam::ipv6hint:
      xfr16BitInt(param.getIPHints().size() * 16); // size
      for (auto a: param.getIPHints()) {
        xfrCAWithoutPort(param.getKey(), a);
      }
      break;
    case SvcParam::ech:
      xfr16BitInt(param.getECH().size()); // size
      xfrBlobNoSpaces(param.getECH());
      break;
    default:
      xfr16BitInt(param.getValue().size());
      xfrBlob(param.getValue());
      break;
    }
  }
}

// call __before commit__
template <typename Container> void GenericDNSPacketWriter<Container>::getRecordPayload(string& records)
{
  records.assign(d_content.begin() + d_sor, d_content.end());
}

template <typename Container> uint32_t GenericDNSPacketWriter<Container>::size() const
{
  return d_content.size();
}

template <typename Container> void GenericDNSPacketWriter<Container>::rollback()
{
  d_content.resize(d_rollbackmarker);
  d_sor = 0;
}

template <typename Container> void GenericDNSPacketWriter<Container>::truncate()
{
  d_content.resize(d_truncatemarker);
  dnsheader* dh=reinterpret_cast<dnsheader*>( &*d_content.begin());
  dh->ancount = dh->nscount = dh->arcount = 0;
}

template <typename Container> void GenericDNSPacketWriter<Container>::commit()
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

template <typename Container> size_t GenericDNSPacketWriter<Container>::getSizeWithOpts(const optvect_t& options) const
{
  size_t result = size() + /* root */ 1 + DNS_TYPE_SIZE + DNS_CLASS_SIZE + DNS_TTL_SIZE + DNS_RDLENGTH_SIZE;

  for(auto const &option : options) {
    result += 4;
    result += option.second.size();
  }

  return result;
}

template class GenericDNSPacketWriter<std::vector<uint8_t>>;
#include "noinitvector.hh"
template class GenericDNSPacketWriter<PacketBuffer>;
