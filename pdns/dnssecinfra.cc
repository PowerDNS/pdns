#include "dnsparser.hh"
#include "sstuff.hh"
#include "misc.hh"
#include "dnswriter.hh"
#include "dnsrecords.hh"
#include "statbag.hh"
#include "iputils.hh"
#include <boost/foreach.hpp>
#include <boost/algorithm/string.hpp>
#include <polarssl/rsa.h>
#include <polarssl/base64.h>
#include <polarssl/sha1.h>
#include <polarssl/sha2.h>
#include "dnssecinfra.hh" 
#include "dnsseckeeper.hh"
#include <polarssl/havege.h>
#include <polarssl/base64.h>
#include <boost/assign/std/vector.hpp> // for 'operator+=()'
#include <boost/assign/list_inserter.hpp>

using namespace boost;
using namespace std;
using namespace boost::assign;

void RSADNSPrivateKey::create(unsigned int bits)
{
  havege_state hs;
  havege_init( &hs );
  
  rsa_init(&d_context, RSA_PKCS_V15, 0, havege_rand, &hs ); // FIXME this leaks memory
  int ret=rsa_gen_key(&d_context, bits, 65537);
  if(ret < 0) 
    throw runtime_error("Key generation failed");
}

std::string RSADNSPrivateKey::getPubKeyHash() const
{
  unsigned char hash[20];
  unsigned char N[mpi_size(&d_context.N)];
  mpi_write_binary(&d_context.N, N, sizeof(N));
  unsigned char E[mpi_size(&d_context.E)];
  mpi_write_binary(&d_context.E, E, sizeof(E));
  
  sha1_context ctx;
  sha1_starts(&ctx);
  sha1_update(&ctx, N, sizeof(N));
  sha1_update(&ctx, E, sizeof(E));
  sha1_finish(&ctx, hash);
  return string((char*)hash, sizeof(hash));
}

std::string RSADNSPrivateKey::sign(const std::string& hash) const
{
  unsigned char signature[mpi_size(&d_context.N)];
  int ret=rsa_pkcs1_sign(const_cast<rsa_context*>(&d_context), RSA_PRIVATE, 
    hash.size()==20 ? SIG_RSA_SHA1 : SIG_RSA_SHA256, 
    hash.size(),
    (const unsigned char*) hash.c_str(), signature);
  
  if(ret!=0) {
    cerr<<"signing returned: "<<ret<<endl;
    exit(1);
  }
  return string((char*) signature, sizeof(signature));
}

std::string RSADNSPrivateKey::convertToISC(unsigned int algorithm) const
{
  string ret;
  typedef vector<pair<string, const mpi*> > outputs_t;
  outputs_t outputs;
  push_back(outputs)("Modulus", &d_context.N)("PublicExponent",&d_context.E)
    ("PrivateExponent",&d_context.D)
    ("Prime1",&d_context.P)
    ("Prime2",&d_context.Q)
    ("Exponent1",&d_context.DP)
    ("Exponent2",&d_context.DQ)
    ("Coefficient",&d_context.QP);

  ret = "Private-key-format: v1.2\nAlgorithm: "+lexical_cast<string>(algorithm);
  switch(algorithm) {
    case 5:
    case 7 :
      ret+= " (RSASHA1)";
      break;
    case 8:
      ret += " (RSASHA256)";
      break;
  }
  ret += "\n";

  BOOST_FOREACH(outputs_t::value_type value, outputs) {
    ret += value.first;
    ret += ": ";
    unsigned char tmp[mpi_size(value.second)];
    mpi_write_binary(value.second, tmp, sizeof(tmp));
    unsigned char base64tmp[sizeof(tmp)*2];
    int dlen=sizeof(base64tmp);
    base64_encode(base64tmp, &dlen, tmp, sizeof(tmp));
    ret.append((const char*)base64tmp, dlen);
    ret.append(1, '\n');
  }
  return ret;
}


DNSPrivateKey* DNSPrivateKey::fromISCFile(DNSKEYRecordContent& drc, const char* fname)
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

  switch(algorithm) {
    case 5:
    case 7:
    case 8:
    case 10:
      return RSADNSPrivateKey::fromISCString(drc, isc);
      break;
    default: 
      throw runtime_error("Unknown DNSSEC signature algorithm number "+lexical_cast<string>(algorithm));
      break;
  }
  return 0;
}

DNSPrivateKey* DNSPrivateKey::fromISCString(DNSKEYRecordContent& drc, const std::string& content)
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
  switch(algorithm) {
    case 5:
    case 7:
    case 8:
    case 10:
      return RSADNSPrivateKey::fromISCString(drc, content);
      break;
    default: 
      throw runtime_error("Unknown DNSSEC signature algorithm number "+lexical_cast<string>(algorithm));
      break;
  }
  return 0;
}

DNSPrivateKey* RSADNSPrivateKey::fromISCString(DNSKEYRecordContent& drc, const std::string& content)
{
  RSADNSPrivateKey* ret = new RSADNSPrivateKey();
  
  string sline;
  string key,value;
  map<string, mpi*> places;
  
  rsa_init(&ret->d_context, RSA_PKCS_V15, 0, NULL, NULL );

  places["Modulus"]=&ret->d_context.N;
  places["PublicExponent"]=&ret->d_context.E;
  places["PrivateExponent"]=&ret->d_context.D;
  places["Prime1"]=&ret->d_context.P;
  places["Prime2"]=&ret->d_context.Q;
  places["Exponent1"]=&ret->d_context.DP;
  places["Exponent2"]=&ret->d_context.DQ;
  places["Coefficient"]=&ret->d_context.QP;

  string modulus, exponent;
  istringstream str(content);
  unsigned char decoded[1024];
  while(getline(str, sline)) {
    tie(key,value)=splitField(sline, ':');
    trim(value);

    if(places.count(key)) {
      if(places[key]) {
        int len=sizeof(decoded);
        if(base64_decode(decoded, &len, (unsigned char*)value.c_str(), value.length()) < 0) {
          cerr<<"Error base64 decoding '"<<value<<"'\n";
          exit(1);
        }
        //	B64Decode(value, decoded);
        //	cerr<<key<<" decoded.length(): "<<8*len<<endl;
        mpi_read_binary(places[key], decoded, len);
        if(key=="Modulus")
          modulus.assign((const char*)decoded,len);
        if(key=="PublicExponent")
          exponent.assign((const char*)decoded,len);
      }
    }
    else {
      if(key == "Algorithm") 
        drc.d_algorithm = atoi(value.c_str());
      else if(key != "Private-key-format")
        cerr<<"Unknown field '"<<key<<"'\n";
    }
  }
  ret->d_context.len = ( mpi_msb( &ret->d_context.N ) + 7 ) >> 3; // no clue what this does

  if(exponent.length() < 255) 
    drc.d_key.assign(1, (char) (unsigned int) exponent.length());
  else {
    drc.d_key.assign(1, 0);
    uint16_t len=htons(exponent.length());
    drc.d_key.append((char*)&len, 2);
  }
  drc.d_key.append(exponent);
  drc.d_key.append(modulus);
  drc.d_protocol=3;
  
  return ret;
}

DNSPrivateKey* DNSPrivateKey::fromPEMString(DNSKEYRecordContent& drc, const std::string& raw)
{
  return RSADNSPrivateKey::fromPEMString(drc, raw);
}

DNSPrivateKey* RSADNSPrivateKey::fromPEMString(DNSKEYRecordContent& drc, const std::string& raw)
{
  vector<string> integers;
  decodeDERIntegerSequence(raw, integers);
  cerr<<"Got "<<integers.size()<<" integers"<<endl; 
  map<int, mpi*> places;
  
  RSADNSPrivateKey* ret = new RSADNSPrivateKey;
  
  rsa_init(&ret->d_context, RSA_PKCS_V15, 0, NULL, NULL );

  places[1]=&ret->d_context.N;
  places[2]=&ret->d_context.E;
  places[3]=&ret->d_context.D;
  places[4]=&ret->d_context.P;
  places[5]=&ret->d_context.Q;
  places[6]=&ret->d_context.DP;
  places[7]=&ret->d_context.DQ;
  places[8]=&ret->d_context.QP;

  string modulus, exponent;
  
  for(int n = 0; n < 9 ; ++n) {
    if(places.count(n)) {
      if(places[n]) {
        mpi_read_binary(places[n], (const unsigned char*)integers[n].c_str(), integers[n].length());
        if(n==1)
          modulus=integers[n];
        if(n==2)
          exponent=integers[n];
      }
    }
  }
  ret->d_context.len = ( mpi_msb( &ret->d_context.N ) + 7 ) >> 3; // no clue what this does

  if(exponent.length() < 255) 
    drc.d_key.assign(1, (char) (unsigned int) exponent.length());
  else {
    drc.d_key.assign(1, 0);
    uint16_t len=htons(exponent.length());
    drc.d_key.append((char*)&len, 2);
  }
  drc.d_key.append(exponent);
  drc.d_key.append(modulus);
  drc.d_protocol=3;
  
  return ret;
}

void makeRSAPublicKeyFromDNS(rsa_context* rc, const DNSKEYRecordContent& dkrc)
{
  rsa_init(rc, RSA_PKCS_V15, 0, NULL, NULL );

  mpi_read_binary(&rc->E, (unsigned char*)dkrc.getExponent().c_str(), dkrc.getExponent().length());    // exponent
  mpi_read_binary(&rc->N, (unsigned char*)dkrc.getModulus().c_str(), dkrc.getModulus().length());    // modulus
  rc->len = ( mpi_msb( &rc->N ) + 7 ) >> 3; // no clue what this does
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
  
  if(rrc.d_algorithm <= 7 ) {
    unsigned char hash[20];
    sha1((unsigned char*)toHash.c_str(), toHash.length(), hash);
    return string((char*)hash, sizeof(hash));
  } else {
    unsigned char hash[32];
    sha2((unsigned char*)toHash.c_str(), toHash.length(), hash, 0);
    return string((char*)hash, sizeof(hash));
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

string RSADNSPrivateKey::getPublicKeyString()  const
{
  string keystring;
  char tmp[max(mpi_size(&d_context.E), mpi_size(&d_context.N))];

  mpi_write_binary(&d_context.E, (unsigned char*)tmp, mpi_size(&d_context.E) );
  string exponent((char*)tmp, mpi_size(&d_context.E));

  mpi_write_binary(&d_context.N, (unsigned char*)tmp, mpi_size(&d_context.N) );
  string modulus((char*)tmp, mpi_size(&d_context.N));

  if(exponent.length() < 255) 
    keystring.assign(1, (char) (unsigned int) exponent.length());
  else {
    keystring.assign(1, 0);
    uint16_t len=htons(exponent.length());
    keystring.append((char*)&len, 2);
  }
  keystring.append(exponent);
  keystring.append(modulus);
  return keystring;
}

DNSKEYRecordContent makeDNSKEYFromRSAKey(const DNSPrivateKey* pk, uint8_t algorithm, uint16_t flags)
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
  return makeDNSKEYFromRSAKey(getKey(), d_algorithm, d_flags);
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
