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
#include "polarssl/sha1.h"
#include <boost/assign/std/vector.hpp> // for 'operator+=()'
#include <boost/assign/list_inserter.hpp>
#include "base64.hh"

using namespace boost;
using namespace std;
using namespace boost::assign;

DNSCryptoKeyEngine* DNSCryptoKeyEngine::makeFromISCFile(DNSKEYRecordContent& drc, const char* fname)
{
  string sline, isc;
  FILE *fp=fopen(fname, "r");
  if(!fp) {
    throw runtime_error("Unable to read file '"+string(fname)+"' for generating DNS Private Key");
  }
  
  while(stringfgets(fp, sline)) {
    isc += sline;
  }
  fclose(fp);
  return makeFromISCString(drc, isc);
}

DNSCryptoKeyEngine* DNSCryptoKeyEngine::makeFromISCString(DNSKEYRecordContent& drc, const std::string& content)
{
  int algorithm = 0;
  string sline, key, value, raw;
  istringstream str(content);
  map<string, string> stormap;
  while(getline(str, sline)) {
    tie(key,value)=splitField(sline, ':');
    trim(value);
    if(pdns_iequals(key,"algorithm")) {
      algorithm = atoi(value.c_str());
      stormap["algorithm"]=lexical_cast<string>(algorithm);
      continue;
    }
    else if(pdns_iequals(key, "Private-key-format"))
      continue;
    raw.clear();
    B64Decode(value, raw);
    stormap[toLower(key)]=raw;
  }
  DNSCryptoKeyEngine* dpk=make(algorithm);
  dpk->fromISCMap(drc, stormap);
  return dpk;
}

std::string DNSCryptoKeyEngine::convertToISC() const
{
  typedef map<string, string> stormap_t;
  stormap_t stormap = this->convertToISCMap();
  ostringstream ret;
  ret<<"Private-key-format: v1.2\nAlgorithm: "<<stormap["Algorithm"]<<"\n";
  BOOST_FOREACH(const stormap_t::value_type& value, stormap) {
    ret<<value.first<<": "<<Base64Encode(value.second)<<"\n";
  }
  return ret.str();
}

DNSCryptoKeyEngine* DNSCryptoKeyEngine::make(unsigned int algo)
{
  makers_t& makers = getMakers();
  makers_t::const_iterator iter = makers.find(algo);
  if(iter != makers.end())
    return (iter->second)(algo);
  else {
    throw runtime_error("Request to create key object for unknown algorithm number "+lexical_cast<string>(algo));
  }
}

void DNSCryptoKeyEngine::report(unsigned int algo, maker_t* maker, bool fallback)
{
  getAllMakers()[algo].push_back(maker);
  if(getMakers().count(algo) && fallback) {
    return;
  }
  getMakers()[algo]=maker;
}

void DNSCryptoKeyEngine::testAll()
{
  BOOST_FOREACH(const allmakers_t::value_type& value, getAllMakers())
  {
    BOOST_FOREACH(maker_t* signer, value.second) {
      BOOST_FOREACH(maker_t* verifier, value.second) {
        try {
          testMakers(value.first, signer, verifier);
        }
        catch(std::exception& e)
        {
          cerr<<e.what()<<endl;
        }
      }
    }
  }
}

pair<unsigned int, unsigned int> DNSCryptoKeyEngine::testMakers(unsigned int algo, maker_t* signer, maker_t* verifier)
{
  shared_ptr<DNSCryptoKeyEngine> dckeSign(signer(algo));
  shared_ptr<DNSCryptoKeyEngine> dckeVerify(verifier(algo));
  
  cerr<<"Testing algorithm "<<algo<<": '"<<dckeSign->getName()<<"' -> '"<<dckeVerify->getName()<<"' ";
  unsigned int bits;
  if(algo <= 10)
    bits=1024;
  else if(algo == 12 || algo == 13) // GOST or nistp256
    bits=256;
  else 
    bits=384;
    
  dckeSign->create(bits);
  string message("Hi! How is life?");
  
  string signature;
  DTime dt; dt.set();
  signature = dckeSign->sign(message);
  unsigned int udiffSign= dt.udiff(), udiffVerify;
  
  dckeVerify->fromPublicKeyString(dckeSign->getPublicKeyString());
  
  dt.set();
  if(dckeVerify->verify(message, signature)) {
    udiffVerify = dt.udiff();
    cerr<<"Signature & verify ok, signature "<<udiffSign<<"usec, verify "<<udiffVerify<<"usec"<<endl;
  }
  else {
    throw runtime_error("Verification of signer "+dckeSign->getName()+" with verifier "+dckeVerify->getName()+" failed");
  }
  return make_pair(udiffSign, udiffVerify);
}

DNSCryptoKeyEngine* DNSCryptoKeyEngine::makeFromPublicKeyString(unsigned int algorithm, const std::string& content)
{
  DNSCryptoKeyEngine* dpk=make(algorithm);
  dpk->fromPublicKeyString(content);
  return dpk;
}


DNSCryptoKeyEngine* DNSCryptoKeyEngine::makeFromPEMString(DNSKEYRecordContent& drc, const std::string& raw)
{
  
  BOOST_FOREACH(makers_t::value_type& val, getMakers())
  {
    DNSCryptoKeyEngine* ret=0;
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

string getMessageForRRSET(const std::string& qname, const RRSIGRecordContent& rrc, vector<shared_ptr<DNSRecordContent> >& signRecords) 
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
  
  return toHash;
}

DSRecordContent makeDSFromDNSKey(const std::string& qname, const DNSKEYRecordContent& drc, int digest)
{
  string toHash;
  toHash.assign(toLower(simpleCompress(qname)));
  toHash.append(const_cast<DNSKEYRecordContent&>(drc).serialize("", true, true));

  
  DSRecordContent dsrc;
  if(digest==1) {
    shared_ptr<DNSCryptoKeyEngine> dpk(DNSCryptoKeyEngine::make(5)); // gives us SHA1
    dsrc.d_digest = dpk->hash(toHash);
  }
  else if(digest == 2) {
    shared_ptr<DNSCryptoKeyEngine> dpk(DNSCryptoKeyEngine::make(8)); // gives us SHA256
    dsrc.d_digest = dpk->hash(toHash);
  }
  else if(digest == 3) {
    shared_ptr<DNSCryptoKeyEngine> dpk(DNSCryptoKeyEngine::make(12)); // gives us GOST
    dsrc.d_digest = dpk->hash(toHash);
  }
  else if(digest == 4) {
    shared_ptr<DNSCryptoKeyEngine> dpk(DNSCryptoKeyEngine::make(14)); // gives us ECDSAP384
    dsrc.d_digest = dpk->hash(toHash);
  }
  
  dsrc.d_algorithm= drc.d_algorithm;
  dsrc.d_digesttype=digest;
  dsrc.d_tag=const_cast<DNSKEYRecordContent&>(drc).getTag();
  return dsrc;
}


DNSKEYRecordContent makeDNSKEYFromDNSCryptoKeyEngine(const DNSCryptoKeyEngine* pk, uint8_t algorithm, uint16_t flags)
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
  return makeDNSKEYFromDNSCryptoKeyEngine(getKey(), d_algorithm, d_flags);
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
