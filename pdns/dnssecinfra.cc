#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "statbag.hh"
#include "iputils.hh"
#include <boost/foreach.hpp>
#include <boost/algorithm/string.hpp>
#include "dnssecinfra.hh" 
#include "dnsseckeeper.hh"

#include <polarssl/sha1.h>
#include <polarssl/sha2.h>
#include <polarssl/sha4.h>
#include <boost/assign/std/vector.hpp> // for 'operator+=()'
#include <boost/assign/list_inserter.hpp>

using namespace boost;
using namespace std;
using namespace boost::assign;

DNSPrivateKey* DNSPrivateKey::makeFromISCFile(DNSKEYRecordContent& drc, const char* fname)
{
  string sline, isc, key, value;
  FILE *fp=fopen(fname, "r");
  if(!fp) {
    throw runtime_error("Unable to read file '"+string(fname)+"' for generating DNS Private Key");
  }
  int algorithm=0;
  while(stringfgets(fp, sline)) {
    tie(key,value)=splitField(sline, ':');
    if(pdns_iequals(key,"algorithm"))
      algorithm = atoi(value.c_str());
    isc.append(sline);
  }
  fclose(fp);

  DNSPrivateKey* dpk=make(algorithm);
  dpk->fromISCString(drc, isc);
  return dpk;
}

DNSPrivateKey* DNSPrivateKey::make(unsigned int algo)
{
  makers_t& makers = getMakers();
  makers_t::const_iterator iter = makers.find(algo);
  if(iter != makers.end())
    return (iter->second)(algo);
  else {
    throw runtime_error("Request to create key object for unknown algorithm number "+lexical_cast<string>(algo));
  }
}

void DNSPrivateKey::report(unsigned int algo, maker_t* maker)
{
  getMakers()[algo]=maker;
}
DNSPrivateKey* DNSPrivateKey::makeFromISCString(DNSKEYRecordContent& drc, const std::string& content)
{
  int algorithm = 0;
  string sline, key, value;
  istringstream str(content);
  while(getline(str, sline)) {
    tie(key,value)=splitField(sline, ':');
    if(pdns_iequals(key,"algorithm")) {
      algorithm = atoi(value.c_str());
      break;
    }
  }
  DNSPrivateKey* dpk=make(algorithm);
  dpk->fromISCString(drc, content);
  return dpk;
}


DNSPrivateKey* DNSPrivateKey::makeFromPEMString(DNSKEYRecordContent& drc, const std::string& raw)
{
  
  BOOST_FOREACH(makers_t::value_type& val, getMakers())
  {
    DNSPrivateKey* ret=0;
    try {
      ret = val.second(val.first);
      ret->fromPEMString(drc, raw);
      return ret;
    }
    catch(...)
    {
      delete ret; // fine if 0
    }
  }
  return 0;
}


bool sharedDNSSECCompare(const shared_ptr<DNSRecordContent>& a, const shared_ptr<DNSRecordContent>& b)
{
  return a->serialize("", true, true) < b->serialize("", true, true);
}

string getHashForRRSET(const std::string& qname, const RRSIGRecordContent& rrc, vector<shared_ptr<DNSRecordContent> >& signRecords) 
{
  sort(signRecords.begin(), signRecords.end(), sharedDNSSECCompare);

  string toHash;
  toHash.append(const_cast<RRSIGRecordContent&>(rrc).serialize("", true, true));
  toHash.resize(toHash.size() - rrc.d_signature.length()); // chop off the end, don't sign the signature!

  BOOST_FOREACH(shared_ptr<DNSRecordContent>& add, signRecords) {
    toHash.append(toLower(simpleCompress(qname, "")));
    uint16_t tmp=htons(rrc.d_type);
    toHash.append((char*)&tmp, 2);
    tmp=htons(1); // class
    toHash.append((char*)&tmp, 2);
    uint32_t ttl=htonl(rrc.d_originalttl);
    toHash.append((char*)&ttl, 4);
    string rdata=add->serialize("", true, true); 
    tmp=htons(rdata.length());
    toHash.append((char*)&tmp, 2);
    toHash.append(rdata);
  }
  
  // algorithm 12 needs special GOST hash
  
  if(rrc.d_algorithm <= 7 ) {  // RSASHA1
    unsigned char hash[20];
    sha1((unsigned char*)toHash.c_str(), toHash.length(), hash);
    return string((char*)hash, sizeof(hash));
  } else if(rrc.d_algorithm == 8 || rrc.d_algorithm == 13) { // RSASHA256 or ECDSAP256
    unsigned char hash[32];
    sha2((unsigned char*)toHash.c_str(), toHash.length(), hash, 0);
    return string((char*)hash, sizeof(hash));
  } else if(rrc.d_algorithm == 10) { // RSASHA512
    unsigned char hash[64];
    sha4((unsigned char*)toHash.c_str(), toHash.length(), hash, 0);
    return string((char*)hash, sizeof(hash));
  } else if(rrc.d_algorithm == 14) { // ECDSAP384
    unsigned char hash[48];
    sha4((unsigned char*)toHash.c_str(), toHash.length(), hash, 1); // == 384
    return string((char*)hash, sizeof(hash));
  }
  else {
    cerr<<"No idea how to hash for algorithm "<<(int)rrc.d_algorithm<<endl;
    exit(1);
  }
}

DSRecordContent makeDSFromDNSKey(const std::string& qname, const DNSKEYRecordContent& drc, int digest)
{
  string toHash;
  toHash.assign(toLower(simpleCompress(qname)));
  toHash.append(const_cast<DNSKEYRecordContent&>(drc).serialize("", true, true));

  unsigned char hash[32];
  if(digest==1)
    sha1((unsigned char*)toHash.c_str(), toHash.length(), hash);
  else
    sha2((unsigned char*)toHash.c_str(), toHash.length(), hash, 0);

  DSRecordContent dsrc;
  dsrc.d_algorithm= drc.d_algorithm;
  dsrc.d_digesttype=digest;
  dsrc.d_tag=const_cast<DNSKEYRecordContent&>(drc).getTag();
  dsrc.d_digest.assign((const char*)hash, digest == 1 ? 20 : 32);
  return dsrc;
}


DNSKEYRecordContent makeDNSKEYFromDNSPrivateKey(const DNSPrivateKey* pk, uint8_t algorithm, uint16_t flags)
{
  DNSKEYRecordContent drc;
  
  drc.d_protocol=3;
  drc.d_algorithm = algorithm;

  drc.d_flags=flags;
  drc.d_key = pk->getPublicKeyString();
  return drc;
}

int countLabels(const std::string& signQName)
{
  int count =1;
  for(string::const_iterator pos = signQName.begin(); pos != signQName.end() ; ++pos) 
    if(*pos == '.' && pos+1 != signQName.end()) 
      count++;

  if(starts_with(signQName, "*."))
    count--;
  return count;
}

uint32_t getCurrentInception()
{
  uint32_t now = time(0);
  now -= (now % (7*86400));
  return now;
}

std::string hashQNameWithSalt(unsigned int times, const std::string& salt, const std::string& qname)
{
  string toHash;
  toHash.assign(simpleCompress(toLower(qname)));
  toHash.append(salt);

//  cerr<<makeHexDump(toHash)<<endl;
  unsigned char hash[20];
  for(;;) {
    sha1((unsigned char*)toHash.c_str(), toHash.length(), hash);
    if(!times--) 
      break;
    toHash.assign((char*)hash, sizeof(hash));
    toHash.append(salt);
  }
  return string((char*)hash, sizeof(hash));
}
DNSKEYRecordContent DNSSECPrivateKey::getDNSKEY() const
{
  return makeDNSKEYFromDNSPrivateKey(getKey(), d_algorithm, d_flags);
}

class DEREater
{
public:
  DEREater(const std::string& str) : d_str(str), d_pos(0)
  {}
  
  struct eof{};
  
  uint8_t getByte()
  {
    if(d_pos >= d_str.length()) {
      throw eof();
    }
    return (uint8_t) d_str[d_pos++];
  }
  
  uint32_t getLength()
  {
    uint8_t first = getByte();
    if(first < 0x80) {
      return first;
    }
    first &= ~0x80;
    
    uint32_t len=0;
    for(int n=0; n < first; ++n) {
      len *= 0x100;
      len += getByte();
    }
    return len;
  }
  
  std::string getBytes(unsigned int len)
  {
    std::string ret;
    for(unsigned int n=0; n < len; ++n)
      ret.append(1, (char)getByte());
    return ret;
  }
  
  std::string::size_type getOffset() 
  {
    return d_pos;
  }
private:
  const std::string& d_str;
  std::string::size_type d_pos;
};

void decodeDERIntegerSequence(const std::string& input, vector<string>& output)
{
  output.clear();
  DEREater de(input);
  if(de.getByte() != 0x30) 
    throw runtime_error("Not a DER sequence");
  
  unsigned int seqlen=de.getLength(); 
  unsigned int startseq=de.getOffset();
  unsigned int len;
  string ret;
  try {
    for(;;) {
      uint8_t kind = de.getByte();
      if(kind != 0x02) 
        throw runtime_error("DER Sequence contained non-INTEGER component: "+lexical_cast<string>((unsigned int)kind) );
      len = de.getLength();
      ret = de.getBytes(len);
      output.push_back(ret);
    }
  }
  catch(DEREater::eof& eof)
  {
    if(de.getOffset() - startseq != seqlen)
      throw runtime_error("DER Sequence ended before end of data");
  }  
}
