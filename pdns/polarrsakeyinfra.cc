#include <polarssl/rsa.h>
#include <polarssl/base64.h>
#include <polarssl/sha1.h>
#include <polarssl/sha2.h>
#include <polarssl/sha4.h>
#include <polarssl/havege.h>
#include <boost/assign/std/vector.hpp> // for 'operator+=()'
#include <boost/foreach.hpp>
#include "dnssecinfra.hh"
using namespace boost::assign;

#define PDNSSEC_MI(x) mpi_init(&d_context.x, 0)
#define PDNSSEC_MC(x) PDNSSEC_MI(x); mpi_copy(&d_context.x, const_cast<mpi*>(&orig.d_context.x))
#define PDNSSEC_MF(x) mpi_free(&d_context.x, 0)

class RSADNSPrivateKey : public DNSPrivateKey
{
public:
  explicit RSADNSPrivateKey(unsigned int algorithm) : d_algorithm(algorithm)
  {
    memset(&d_context, 0, sizeof(d_context));
    PDNSSEC_MI(N); 
    PDNSSEC_MI(E); PDNSSEC_MI(D); PDNSSEC_MI(P); PDNSSEC_MI(Q); PDNSSEC_MI(DP); PDNSSEC_MI(DQ); PDNSSEC_MI(QP); PDNSSEC_MI(RN); PDNSSEC_MI(RP); PDNSSEC_MI(RQ);
  }

  ~RSADNSPrivateKey()
  {
    PDNSSEC_MF(N); 
    PDNSSEC_MF(E); PDNSSEC_MF(D); PDNSSEC_MF(P); PDNSSEC_MF(Q); PDNSSEC_MF(DP); PDNSSEC_MF(DQ); PDNSSEC_MF(QP); PDNSSEC_MF(RN); PDNSSEC_MF(RP); PDNSSEC_MF(RQ);
  }

  bool operator<(const RSADNSPrivateKey& rhs) const
  {
    return tie(d_context.N, d_context.E, d_context.D, d_context.P, d_context.Q, d_context.DP, d_context.DQ, d_context.QP)
    < tie(rhs.d_context.N, rhs.d_context.E, rhs.d_context.D, rhs.d_context.P, rhs.d_context.Q, rhs.d_context.DP, rhs.d_context.DQ, rhs.d_context.QP);
  }

  RSADNSPrivateKey(const RSADNSPrivateKey& orig) 
  {
    d_algorithm = orig.d_algorithm;
    
    d_context.ver = orig.d_context.ver;
    d_context.len = orig.d_context.len;

    d_context.padding = orig.d_context.padding;
    d_context.hash_id = orig.d_context.hash_id;
    d_context.f_rng = orig.d_context.f_rng;
    d_context.p_rng = orig.d_context.p_rng;
    
    PDNSSEC_MC(N); 
    PDNSSEC_MC(E); PDNSSEC_MC(D); PDNSSEC_MC(P); PDNSSEC_MC(Q); PDNSSEC_MC(DP); PDNSSEC_MC(DQ); PDNSSEC_MC(QP); PDNSSEC_MC(RN); PDNSSEC_MC(RP); PDNSSEC_MC(RQ);
  }

  RSADNSPrivateKey& operator=(const RSADNSPrivateKey& orig) 
  {
    d_algorithm = orig.d_algorithm;
    
    d_context.ver = orig.d_context.ver;
    d_context.len = orig.d_context.len;

    d_context.padding = orig.d_context.padding;
    d_context.hash_id = orig.d_context.hash_id;
    d_context.f_rng = orig.d_context.f_rng;
    d_context.p_rng = orig.d_context.p_rng;
    
    PDNSSEC_MF(N); 
    PDNSSEC_MF(E); PDNSSEC_MF(D); PDNSSEC_MF(P); PDNSSEC_MF(Q); PDNSSEC_MF(DP); PDNSSEC_MF(DQ); PDNSSEC_MF(QP); PDNSSEC_MF(RN); PDNSSEC_MF(RP); PDNSSEC_MF(RQ);
    
    PDNSSEC_MC(N); 
    PDNSSEC_MC(E); PDNSSEC_MC(D); PDNSSEC_MC(P); PDNSSEC_MC(Q); PDNSSEC_MC(DP); PDNSSEC_MC(DQ); PDNSSEC_MC(QP); PDNSSEC_MC(RN); PDNSSEC_MC(RP); PDNSSEC_MC(RQ);
    return *this;
  }

  const rsa_context& getConstContext() const
  {
    return d_context;
  }

  rsa_context& getContext() 
  {
    return d_context;
  }

  void create(unsigned int bits);
  std::string convertToISC(unsigned int algorithm) const;
  std::string getPubKeyHash() const;
  std::string sign(const std::string& hash) const; 
  std::string hash(const std::string& hash) const; 
  bool verify(const std::string& hash, const std::string& signature) const;
  std::string getPublicKeyString() const;
  int getBits() const
  {
    return mpi_size(&d_context.N)*8;
  }
  void fromISCString(DNSKEYRecordContent& drc, const std::string& content);
  void fromPEMString(DNSKEYRecordContent& drc, const std::string& raw);
  void fromPublicKeyString(unsigned int algorithm, const std::string& raw);
  static DNSPrivateKey* maker(unsigned int algorithm)
  {
    return new RSADNSPrivateKey(algorithm);
  }

private:
  rsa_context d_context;
  unsigned int d_algorithm;
};

// see above
#undef PDNSSEC_MC
#undef PDNSSEC_MI
#undef PDNSSEC_MF


inline bool operator<(const mpi& a, const mpi& b)
{
  return mpi_cmp_mpi(&a, &b) < 0;
}


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
  int hashKind;
  if(hash.size()==20)
    hashKind= SIG_RSA_SHA1;
  else if(hash.size()==32) 
    hashKind= SIG_RSA_SHA256;
  else
    hashKind = SIG_RSA_SHA512;
  
  int ret=rsa_pkcs1_sign(const_cast<rsa_context*>(&d_context), RSA_PRIVATE, 
    hashKind,
    hash.size(),
    (const unsigned char*) hash.c_str(), signature);
  
  if(ret!=0) {
    cerr<<"signing returned: "<<ret<<endl;
    exit(1);
  }
  return string((char*) signature, sizeof(signature));
}

bool RSADNSPrivateKey::verify(const std::string& hash, const std::string& signature) const
{
  int hashKind;
  if(hash.size()==20)
    hashKind= SIG_RSA_SHA1;
  else if(hash.size()==32) 
    hashKind= SIG_RSA_SHA256;
  else
    hashKind = SIG_RSA_SHA512;
  
  int ret=rsa_pkcs1_verify(const_cast<rsa_context*>(&d_context), RSA_PUBLIC, 
    hashKind,
    hash.size(),
    (const unsigned char*) hash.c_str(), (unsigned char*) signature.c_str());
  cerr<<"verification returned: "<<ret<<endl;
  return ret==0; // 0 really IS ok ;-)
}


std::string RSADNSPrivateKey::hash(const std::string& toHash) const
{
  if(d_algorithm <= 7 ) {  // RSASHA1
    unsigned char hash[20];
    sha1((unsigned char*)toHash.c_str(), toHash.length(), hash);
    return string((char*)hash, sizeof(hash));
  } 
  else if(d_algorithm == 8) { // RSASHA256
    unsigned char hash[32];
    sha2((unsigned char*)toHash.c_str(), toHash.length(), hash, 0);
    return string((char*)hash, sizeof(hash));
  } 
  else if(d_algorithm == 10) { // RSASHA512
    unsigned char hash[64];
    sha4((unsigned char*)toHash.c_str(), toHash.length(), hash, 0);
    return string((char*)hash, sizeof(hash));
  }
  throw runtime_error("PolarSSL hashing method can't hash algorithm "+lexical_cast<string>(d_algorithm));
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


void RSADNSPrivateKey::fromISCString(DNSKEYRecordContent& drc, const std::string& content)
{
  string sline;
  string key,value;
  map<string, mpi*> places;
  
  rsa_init(&d_context, RSA_PKCS_V15, 0, NULL, NULL );

  places["Modulus"]=&d_context.N;
  places["PublicExponent"]=&d_context.E;
  places["PrivateExponent"]=&d_context.D;
  places["Prime1"]=&d_context.P;
  places["Prime2"]=&d_context.Q;
  places["Exponent1"]=&d_context.DP;
  places["Exponent2"]=&d_context.DQ;
  places["Coefficient"]=&d_context.QP;

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
  d_context.len = ( mpi_msb( &d_context.N ) + 7 ) >> 3; // no clue what this does

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
}

void RSADNSPrivateKey::fromPEMString(DNSKEYRecordContent& drc, const std::string& raw)
{
  vector<string> integers;
  decodeDERIntegerSequence(raw, integers);
  cerr<<"Got "<<integers.size()<<" integers"<<endl; 
  map<int, mpi*> places;
  
  rsa_init(&d_context, RSA_PKCS_V15, 0, NULL, NULL );

  places[1]=&d_context.N;
  places[2]=&d_context.E;
  places[3]=&d_context.D;
  places[4]=&d_context.P;
  places[5]=&d_context.Q;
  places[6]=&d_context.DP;
  places[7]=&d_context.DQ;
  places[8]=&d_context.QP;

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
  d_context.len = ( mpi_msb( &d_context.N ) + 7 ) >> 3; // no clue what this does

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
}

void RSADNSPrivateKey::fromPublicKeyString(unsigned int algorithm, const std::string& rawString)
{
  rsa_init(&d_context, RSA_PKCS_V15, 0, NULL, NULL );
  string exponent, modulus;
  const unsigned char* raw = (const unsigned char*)rawString.c_str();
  
  if(raw[0] != 0) {
    exponent=rawString.substr(1, raw[0]);
    modulus=rawString.substr(raw[0]+1);
  } else {
    exponent=rawString.substr(3, raw[1]*0xff + raw[2]);
    modulus = rawString.substr(3+ raw[1]*0xff + raw[2]);
  }
  mpi_read_binary(&d_context.E, (unsigned char*)exponent.c_str(), exponent.length());   
  mpi_read_binary(&d_context.N, (unsigned char*)modulus.c_str(), modulus.length());    
  d_context.len = ( mpi_msb( &d_context.N ) + 7 ) >> 3; // no clue what this does
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
namespace {
struct LoaderStruct
{
  LoaderStruct()
  {
    DNSPrivateKey::report(5, &RSADNSPrivateKey::maker);
    DNSPrivateKey::report(7, &RSADNSPrivateKey::maker);
    DNSPrivateKey::report(8, &RSADNSPrivateKey::maker);
    DNSPrivateKey::report(10, &RSADNSPrivateKey::maker);
  }
} loader;
}
