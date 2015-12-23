#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef HAVE_MBEDTLS2
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/rsa.h>
#include <mbedtls/base64.h>
#else
#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>
#include <polarssl/ecdsa.h>
#include <polarssl/rsa.h>
#include <polarssl/base64.h>
#include "mbedtlscompat.hh"
#endif
#include <boost/assign/std/vector.hpp> // for 'operator+=()'

#include "sha.hh"
#include "dnssecinfra.hh"
using namespace boost::assign;

#define PDNSSEC_MI(x) mbedtls_mpi_init(&d_context.x)
#define PDNSSEC_MC(x) PDNSSEC_MI(x); mbedtls_mpi_copy(&d_context.x, const_cast<mbedtls_mpi*>(&orig.d_context.x))
#define PDNSSEC_MF(x) mbedtls_mpi_free(&d_context.x)

class RSADNSCryptoKeyEngine : public DNSCryptoKeyEngine
{
public:
  string getName() const { return "mbedTLS RSA"; }

  explicit RSADNSCryptoKeyEngine(unsigned int algorithm) : DNSCryptoKeyEngine(algorithm)
  {
    memset(&d_context, 0, sizeof(d_context));
    PDNSSEC_MI(N); 
    PDNSSEC_MI(E); PDNSSEC_MI(D); PDNSSEC_MI(P); PDNSSEC_MI(Q); PDNSSEC_MI(DP); PDNSSEC_MI(DQ); PDNSSEC_MI(QP); PDNSSEC_MI(RN); PDNSSEC_MI(RP); PDNSSEC_MI(RQ);
  }

  ~RSADNSCryptoKeyEngine()
  {
    PDNSSEC_MF(N); 
    PDNSSEC_MF(E); PDNSSEC_MF(D); PDNSSEC_MF(P); PDNSSEC_MF(Q); PDNSSEC_MF(DP); PDNSSEC_MF(DQ); PDNSSEC_MF(QP); PDNSSEC_MF(RN); PDNSSEC_MF(RP); PDNSSEC_MF(RQ);
  }

  bool operator<(const RSADNSCryptoKeyEngine& rhs) const
  {
    return tie(d_context.N, d_context.E, d_context.D, d_context.P, d_context.Q, d_context.DP, d_context.DQ, d_context.QP)
    < tie(rhs.d_context.N, rhs.d_context.E, rhs.d_context.D, rhs.d_context.P, rhs.d_context.Q, rhs.d_context.DP, rhs.d_context.DQ, rhs.d_context.QP);
  }

  RSADNSCryptoKeyEngine(const RSADNSCryptoKeyEngine& orig) : DNSCryptoKeyEngine(orig.d_algorithm)
  {
    // this part is a little bit scary.. we make a 'deep copy' of an RSA state, and mbedtls isn't helping us so we delve into thr struct
    d_context.ver = orig.d_context.ver; 
    d_context.len = orig.d_context.len;

    d_context.padding = orig.d_context.padding;
    d_context.hash_id = orig.d_context.hash_id;
    
    PDNSSEC_MC(N); 
    PDNSSEC_MC(E); PDNSSEC_MC(D); PDNSSEC_MC(P); PDNSSEC_MC(Q); PDNSSEC_MC(DP); PDNSSEC_MC(DQ); PDNSSEC_MC(QP); PDNSSEC_MC(RN); PDNSSEC_MC(RP); PDNSSEC_MC(RQ);
  }

  RSADNSCryptoKeyEngine& operator=(const RSADNSCryptoKeyEngine& orig) 
  {
    *this = RSADNSCryptoKeyEngine(orig);
    return *this;
  }

  const mbedtls_rsa_context& getConstContext() const
  {
    return d_context;
  }

  mbedtls_rsa_context& getContext() 
  {
    return d_context;
  }

  void create(unsigned int bits);
  storvector_t convertToISCVector() const;
  std::string getPubKeyHash() const;
  std::string sign(const std::string& hash) const; 
  std::string hash(const std::string& hash) const; 
  bool verify(const std::string& hash, const std::string& signature) const;
  std::string getPublicKeyString() const;
  int getBits() const
  {
    return mbedtls_mpi_size(&d_context.N)*8;
  }
  void fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap);
  void fromPEMString(DNSKEYRecordContent& drc, const std::string& raw);
  void fromPublicKeyString(const std::string& raw);
  static DNSCryptoKeyEngine* maker(unsigned int algorithm)
  {
    return new RSADNSCryptoKeyEngine(algorithm);
  }

private:
  mbedtls_rsa_context d_context;
};

// see above
#undef PDNSSEC_MC
#undef PDNSSEC_MI
#undef PDNSSEC_MF


inline bool operator<(const mbedtls_mpi& a, const mbedtls_mpi& b)
{
  return mbedtls_mpi_cmp_mpi(&a, &b) < 0;
}


void RSADNSCryptoKeyEngine::create(unsigned int bits)
{
  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context ctr_drbg;
  
  mbedtls_entropy_init( &entropy );
  mbedtls_ctr_drbg_init( &ctr_drbg );
  int ret=mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy, (unsigned char *) "PowerDNS", 8);
  if(ret < 0) 
    throw runtime_error("Entropy gathering for key generation failed");
  mbedtls_rsa_init(&d_context, MBEDTLS_RSA_PKCS_V15, 0); // FIXME this leaks memory (it does?)
  ret=mbedtls_rsa_gen_key(&d_context, mbedtls_ctr_drbg_random, &ctr_drbg, bits, 65537);
  if(ret < 0) 
    throw runtime_error("Key generation failed");
}

std::string RSADNSCryptoKeyEngine::getPubKeyHash() const
{
  unsigned char hash[20];
  unsigned char N[mbedtls_mpi_size(&d_context.N)];
  mbedtls_mpi_write_binary(&d_context.N, N, sizeof(N));
  unsigned char E[mbedtls_mpi_size(&d_context.E)];
  mbedtls_mpi_write_binary(&d_context.E, E, sizeof(E));
  
  mbedtls_sha1_context ctx;
  mbedtls_sha1_starts(&ctx);
  mbedtls_sha1_update(&ctx, N, sizeof(N));
  mbedtls_sha1_update(&ctx, E, sizeof(E));
  mbedtls_sha1_finish(&ctx, hash);
  return string((char*)hash, sizeof(hash));
}

std::string RSADNSCryptoKeyEngine::sign(const std::string& msg) const
{
  string hash = this->hash(msg);
  unsigned char signature[mbedtls_mpi_size(&d_context.N)];
  mbedtls_md_type_t hashKind;

  if(hash.size()==20)
    hashKind= MBEDTLS_MD_SHA1;
  else if(hash.size()==32) 
    hashKind= MBEDTLS_MD_SHA256;
  else
    hashKind = MBEDTLS_MD_SHA512;
  
  int ret=mbedtls_rsa_pkcs1_sign(const_cast<mbedtls_rsa_context*>(&d_context), NULL, NULL, MBEDTLS_RSA_PRIVATE,
    hashKind,
    hash.size(),
    (const unsigned char*) hash.c_str(), signature);
  
  if(ret!=0) {
    cerr<<"signing returned: "<<ret<<endl;
    exit(1);
  }
  return string((char*) signature, sizeof(signature));
}

bool RSADNSCryptoKeyEngine::verify(const std::string& msg, const std::string& signature) const
{
  mbedtls_md_type_t hashKind;
  string hash=this->hash(msg);
  if(hash.size()==20)
    hashKind= MBEDTLS_MD_SHA1;
  else if(hash.size()==32) 
    hashKind= MBEDTLS_MD_SHA256;
  else
    hashKind = MBEDTLS_MD_SHA512;
  
  int ret=mbedtls_rsa_pkcs1_verify(const_cast<mbedtls_rsa_context*>(&d_context),
    NULL, NULL,
    MBEDTLS_RSA_PUBLIC,
    hashKind,
    hash.size(),
    (const unsigned char*) hash.c_str(), (unsigned char*) signature.c_str());
  
  return ret==0; // 0 really IS ok ;-)
}

std::string RSADNSCryptoKeyEngine::hash(const std::string& toHash) const
{
  if(d_algorithm <= 7 ) {  // RSASHA1
    unsigned char hash[20];
    mbedtls_sha1((unsigned char*)toHash.c_str(), toHash.length(), hash);
    return string((char*)hash, sizeof(hash));
  } 
  else if(d_algorithm == 8) { // RSASHA256
    unsigned char hash[32];
    mbedtls_sha256((unsigned char*)toHash.c_str(), toHash.length(), hash, 0);
    return string((char*)hash, sizeof(hash));
  } 
  else if(d_algorithm == 10) { // RSASHA512
    unsigned char hash[64];
    mbedtls_sha512((unsigned char*)toHash.c_str(), toHash.length(), hash, 0);
    return string((char*)hash, sizeof(hash));
  }
  throw runtime_error("mbed TLS hashing method can't hash algorithm "+std::to_string(d_algorithm));
}


DNSCryptoKeyEngine::storvector_t RSADNSCryptoKeyEngine::convertToISCVector() const
{
  storvector_t storvect;
  typedef vector<pair<string, const mbedtls_mpi*> > outputs_t;
  outputs_t outputs;
  push_back(outputs)("Modulus", &d_context.N)("PublicExponent",&d_context.E)
    ("PrivateExponent",&d_context.D)
    ("Prime1",&d_context.P)
    ("Prime2",&d_context.Q)
    ("Exponent1",&d_context.DP)
    ("Exponent2",&d_context.DQ)
    ("Coefficient",&d_context.QP);

  string algorithm=std::to_string(d_algorithm);
  switch(d_algorithm) {
    case 5:
    case 7 :
      algorithm+= " (RSASHA1)";
      break;
    case 8:
      algorithm += " (RSASHA256)";
      break;
  }
  storvect.push_back(make_pair("Algorithm", algorithm));

  for(outputs_t::value_type value :  outputs) {
    unsigned char tmp[mbedtls_mpi_size(value.second)];
    mbedtls_mpi_write_binary(value.second, tmp, sizeof(tmp));
    storvect.push_back(make_pair(value.first, string((char*)tmp, sizeof(tmp))));
  }
  return storvect;
}


void RSADNSCryptoKeyEngine::fromISCMap(DNSKEYRecordContent& drc,  std::map<std::string, std::string>& stormap)
{
  string sline;
  string key,value;
  typedef map<string, mbedtls_mpi*> places_t;
  places_t places;
  
  mbedtls_rsa_init(&d_context, MBEDTLS_RSA_PKCS_V15, 0);

  places["Modulus"]=&d_context.N;
  places["PublicExponent"]=&d_context.E;
  places["PrivateExponent"]=&d_context.D;
  places["Prime1"]=&d_context.P;
  places["Prime2"]=&d_context.Q;
  places["Exponent1"]=&d_context.DP;
  places["Exponent2"]=&d_context.DQ;
  places["Coefficient"]=&d_context.QP;
  
  drc.d_algorithm = pdns_stou(stormap["algorithm"]);
  
  string raw;
  for(const places_t::value_type& val :  places) {
    raw=stormap[toLower(val.first)];
    mbedtls_mpi_read_binary(val.second, (unsigned char*) raw.c_str(), raw.length());
  }

  d_context.len = ( mbedtls_mpi_bitlen( &d_context.N ) + 7 ) >> 3; // no clue what this does
  drc.d_key = this->getPublicKeyString();
  drc.d_protocol=3;
}

void RSADNSCryptoKeyEngine::fromPEMString(DNSKEYRecordContent& drc, const std::string& raw)
{
  vector<string> integers;
  decodeDERIntegerSequence(raw, integers);
  cerr<<"Got "<<integers.size()<<" integers"<<endl; 
  map<int, mbedtls_mpi*> places;
  
  mbedtls_rsa_init(&d_context, MBEDTLS_RSA_PKCS_V15, 0);

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
        mbedtls_mpi_read_binary(places[n], (const unsigned char*)integers[n].c_str(), integers[n].length());
        if(n==1)
          modulus=integers[n];
        if(n==2)
          exponent=integers[n];
      }
    }
  }
  d_context.len = ( mbedtls_mpi_bitlen( &d_context.N ) + 7 ) >> 3; // no clue what this does

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

void RSADNSCryptoKeyEngine::fromPublicKeyString(const std::string& rawString)
{
  mbedtls_rsa_init(&d_context, MBEDTLS_RSA_PKCS_V15, 0);
  string exponent, modulus;
  const unsigned char* raw = (const unsigned char*)rawString.c_str();
  
  if(raw[0] != 0) {
    exponent=rawString.substr(1, raw[0]);
    modulus=rawString.substr(raw[0]+1);
  } else {
    exponent=rawString.substr(3, raw[1]*0xff + raw[2]);
    modulus = rawString.substr(3+ raw[1]*0xff + raw[2]);
  }
  mbedtls_mpi_read_binary(&d_context.E, (unsigned char*)exponent.c_str(), exponent.length());   
  mbedtls_mpi_read_binary(&d_context.N, (unsigned char*)modulus.c_str(), modulus.length());    
  d_context.len = ( mbedtls_mpi_bitlen( &d_context.N ) + 7 ) >> 3; // no clue what this does
}

string RSADNSCryptoKeyEngine::getPublicKeyString()  const
{
  string keystring;
  char tmp[std::max(mbedtls_mpi_size(&d_context.E), mbedtls_mpi_size(&d_context.N))];

  mbedtls_mpi_write_binary(&d_context.E, (unsigned char*)tmp, mbedtls_mpi_size(&d_context.E) );
  string exponent((char*)tmp, mbedtls_mpi_size(&d_context.E));

  mbedtls_mpi_write_binary(&d_context.N, (unsigned char*)tmp, mbedtls_mpi_size(&d_context.N) );
  string modulus((char*)tmp, mbedtls_mpi_size(&d_context.N));

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

class MbedECDSADNSCryptoKeyEngine : public DNSCryptoKeyEngine
{
public:
  explicit MbedECDSADNSCryptoKeyEngine(unsigned int algo) : DNSCryptoKeyEngine(algo)
  {
    static const unsigned char custom[] = "PowerDNS";
    mbedtls_ecdsa_init(&d_ctx);
    mbedtls_entropy_init(&d_entropy);
    mbedtls_ctr_drbg_init(&d_ctr_drbg);

    int ret = mbedtls_ctr_drbg_seed(&d_ctr_drbg, mbedtls_entropy_func, &d_entropy, custom, sizeof(custom) - 1);
    if (ret != 0) {
      throw runtime_error("Entropy gathering for key generation failed");
    }

    mbedtls_ecp_group_id groupId;

    if(d_algorithm == 13) {
      groupId = MBEDTLS_ECP_DP_SECP256R1;
    }
    else if(d_algorithm == 14){
      groupId = MBEDTLS_ECP_DP_SECP384R1;
    }
    else {
      throw runtime_error("Unknown algo "+std::to_string(d_algorithm)+" from ECDSA class");
    }

    int res = mbedtls_ecp_group_load(&d_ctx.grp, groupId);
    if (res != 0) {
      throw runtime_error("Error loading EC group for algo "+std::to_string(d_algorithm));
    }
  }

  MbedECDSADNSCryptoKeyEngine(const MbedECDSADNSCryptoKeyEngine& orig) : MbedECDSADNSCryptoKeyEngine(orig.d_algorithm)
  {
    mbedtls_ecp_point_init(&d_ctx.Q);
    int ret = mbedtls_ecp_copy(&d_ctx.Q, &orig.d_ctx.Q);

    if (ret != 0) {
      throw runtime_error("EC point copy failed");
    }

    mbedtls_mpi_init(&d_ctx.d);
    ret = mbedtls_mpi_copy(&d_ctx.d, &orig.d_ctx.d);

    if (ret != 0) {
      throw runtime_error("ECDSA key copy failed");
    }
  }

  ~MbedECDSADNSCryptoKeyEngine()
  {
    mbedtls_ctr_drbg_free(&d_ctr_drbg);
    mbedtls_entropy_free(&d_entropy);
    mbedtls_ecdsa_free(&d_ctx);
  }

  string getName() const { return "mbedTLS ECDSA"; }
  void create(unsigned int bits);
  storvector_t convertToISCVector() const;
  std::string getPubKeyHash() const;
  std::string sign(const std::string& hash) const;
  std::string hash(const std::string& hash) const;
  bool verify(const std::string& hash, const std::string& signature) const;
  std::string getPublicKeyString() const;
  int getBits() const;
  void fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap);
  void fromPublicKeyString(const std::string& content);
  void fromPEMString(DNSKEYRecordContent& drc, const std::string& raw)
  {}

  static DNSCryptoKeyEngine* maker(unsigned int algorithm)
  {
    return new MbedECDSADNSCryptoKeyEngine(algorithm);
  }

private:
  mbedtls_ecdsa_context d_ctx;
  mbedtls_entropy_context d_entropy;
  mbedtls_ctr_drbg_context d_ctr_drbg;
};

void MbedECDSADNSCryptoKeyEngine::create(unsigned int bits)
{
  mbedtls_ecp_group_id groupId;

  if(bits == 256) {
    groupId = MBEDTLS_ECP_DP_SECP256R1;
  }
  else if(bits == 384){
    groupId = MBEDTLS_ECP_DP_SECP384R1;
  }
  else {
    throw runtime_error("Unknown key length of "+std::to_string(bits)+" bits requested from ECDSA class");
  }

  int res = mbedtls_ecdsa_genkey(&d_ctx, groupId, &mbedtls_ctr_drbg_random, &d_ctr_drbg);
  if (res != 0) {
    throw runtime_error("Key generation failed");
  }
}

int MbedECDSADNSCryptoKeyEngine::getBits() const
{
  if (d_algorithm == 13) {
    return 256;
  }
  else if (d_algorithm == 14) {
    return 384;
  }

  return -1;
}

DNSCryptoKeyEngine::storvector_t MbedECDSADNSCryptoKeyEngine::convertToISCVector() const
{
  storvector_t storvect;
  string algorithm;

  if(d_algorithm == 13)  {
    algorithm = "13 (ECDSAP256SHA256)";
  }
  else if(d_algorithm == 14) {
    algorithm ="14 (ECDSAP384SHA384)";
  }
  else {
    algorithm =" ? (?)";
  }

  storvect.push_back(make_pair("Algorithm", algorithm));

  unsigned char tmp[mbedtls_mpi_size(&d_ctx.d)];
  int ret = mbedtls_mpi_write_binary(&d_ctx.d, tmp, sizeof(tmp));

  if (ret != 0) {
    throw runtime_error("Error converting ECDSA Private Key to binary");
  }

  storvect.push_back(make_pair("PrivateKey", string((char*) tmp, sizeof(tmp))));

  return storvect;
}

void MbedECDSADNSCryptoKeyEngine::fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap)
{
  drc.d_algorithm = atoi(stormap["algorithm"].c_str());

  if (drc.d_algorithm != d_algorithm) {
    throw runtime_error("Tried to feed an algorithm "+std::to_string(drc.d_algorithm)+" to a "+std::to_string(d_algorithm)+" key!");
  }

  string privateKey = stormap["privatekey"];
  int ret = mbedtls_mpi_read_binary(&d_ctx.d, (unsigned char*) privateKey.c_str(), privateKey.length());
  if (ret != 0)  {
    throw runtime_error("Reading ECDSA private key from binary failed");
  }

  /* compute the public key */
  ret = mbedtls_ecp_mul(&d_ctx.grp, &d_ctx.Q, &d_ctx.d, &d_ctx.grp.G, &mbedtls_ctr_drbg_random, &d_ctr_drbg);

  if (ret != 0)  {
    throw runtime_error("Computing ECDSA public key from private failed");
  }
}

std::string MbedECDSADNSCryptoKeyEngine::getPubKeyHash() const
{
  unsigned char binaryPoint[MBEDTLS_ECP_MAX_PT_LEN];
  size_t binaryPointLen = 0;
  unsigned char hash[20];
  int ret = mbedtls_ecp_point_write_binary(&d_ctx.grp, &d_ctx.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &binaryPointLen, binaryPoint, sizeof(binaryPoint));

  if (ret != 0) {
    throw runtime_error("Exporting ECP point to binary failed");
  }

  mbedtls_sha1_context ctx;
  mbedtls_sha1_starts(&ctx);
  /* we skip the first byte as the other backends use
     raw field elements, as opposed to the format described in
     SEC1: "2.3.3 Elliptic-Curve-Point-to-Octet-String Conversion" */
  mbedtls_sha1_update(&ctx, binaryPoint + 1, binaryPointLen - 1);
  mbedtls_sha1_finish(&ctx, hash);

  return string((char*)hash, sizeof(hash));
}

std::string MbedECDSADNSCryptoKeyEngine::getPublicKeyString() const
{
  unsigned char binaryPoint[MBEDTLS_ECP_MAX_PT_LEN];
  size_t binaryPointLen = 0;
  int ret = mbedtls_ecp_point_write_binary(&d_ctx.grp, &d_ctx.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &binaryPointLen, binaryPoint, sizeof(binaryPoint));

  if (ret != 0) {
    throw runtime_error("Exporting ECP point to binary failed");
  }

  /* we skip the first byte as the other signers use
     raw field elements, as opposed to the format described in
     SEC1: "2.3.3 Elliptic-Curve-Point-to-Octet-String Conversion" */
  return string((const char *)(binaryPoint + 1), binaryPointLen - 1);
}

void MbedECDSADNSCryptoKeyEngine::fromPublicKeyString(const std::string&input)
{
  /* uncompressed point, from SEC1:
     "2.3.4 Octet-String-to-Elliptic-Curve-Point Conversion" */
  static const unsigned char uncompressed[] = { 0x04 };
  string ecdsaPoint;
  ecdsaPoint.assign((const char*) uncompressed, sizeof(uncompressed));
  ecdsaPoint.append(input);

  int ret = mbedtls_ecp_point_read_binary(&d_ctx.grp, &d_ctx.Q, (unsigned char*) ecdsaPoint.c_str(), ecdsaPoint.length());

  if (ret != 0) {
    throw runtime_error("Reading ECP point from binary failed");
  }
}

std::string MbedECDSADNSCryptoKeyEngine::sign(const std::string& msg) const
{
  string hash = this->hash(msg);
  mbedtls_md_type_t hashKind;
  if (hash.size() == 32) {
    hashKind = MBEDTLS_MD_SHA256;
  }
  else {
    hashKind = MBEDTLS_MD_SHA384;
  }

  mbedtls_mpi r, s;

  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);

  mbedtls_ecp_group tempGroup;
  mbedtls_ecp_group_init(&tempGroup);

  int ret = mbedtls_ecp_group_copy(&tempGroup, &d_ctx.grp);

  if (ret != 0) {
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecp_group_free(&tempGroup);
    throw runtime_error("Error copying ECDSA group");
  }

  ret = mbedtls_ecdsa_sign_det(&tempGroup, &r, &s, &d_ctx.d, (const unsigned char*) hash.c_str(), hash.length(), hashKind);

  mbedtls_ecp_group_free(&tempGroup);

  if (ret != 0) {
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    throw runtime_error("ECDSA signature failed");
  }

  /* SEC1: 4.1.3 Signing Operation */
  const size_t mpiLen = mbedtls_mpi_size(&d_ctx.grp.P);
  const size_t sigLen = mpiLen * 2;

  unsigned char sig[sigLen];

  ret = mbedtls_mpi_write_binary(&r, sig, mpiLen);

  if (ret != 0) {
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    throw runtime_error("Error converting ECDSA signature part R to binary");
  }

  ret = mbedtls_mpi_write_binary(&s, sig + mpiLen, mpiLen);

  if (ret != 0) {
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    throw runtime_error("Error converting ECDSA signature part S to binary");
  }

  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);

  return string((char *) sig, sigLen);
}

std::string MbedECDSADNSCryptoKeyEngine::hash(const std::string& orig) const
{
  if(getBits() == 256) {
    unsigned char hash[32];
    mbedtls_sha256((unsigned char*) orig.c_str(), orig.length(), hash, 0);
    return string((char*) hash, sizeof(hash));
  }
  else if(getBits() == 384) {
    unsigned char hash[48];
    // mbedtls_sha512() with the last parameter as 1 computes sha384
    mbedtls_sha512((unsigned char*) orig.c_str(), orig.length(), hash, 1);
    return string((char*) hash, sizeof(hash));
  }

  throw runtime_error("mbedTLS ECDSA does not support hash size of "+std::to_string(getBits()));
}

bool MbedECDSADNSCryptoKeyEngine::verify(const std::string& msg, const std::string& signature) const
{
  string hash = this->hash(msg);
  const size_t mpiLen = mbedtls_mpi_size(&d_ctx.grp.P);
  mbedtls_mpi r, s;

  /* SEC1: 4.1.4 Verifying Operation */
  mbedtls_mpi_init(&r);
  mbedtls_mpi_init(&s);

  if (signature.length() < (mpiLen * 2)) {
    throw runtime_error("Invalid ECDSA signature size");
  }

  int ret = mbedtls_mpi_read_binary(&r, (unsigned char*) signature.c_str(), mpiLen);
  if (ret != 0)  {
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    throw runtime_error("Reading ECDSA signature part R from binary failed");
  }

  ret = mbedtls_mpi_read_binary(&s, (unsigned char*) signature.c_str() + mpiLen, mpiLen);
  if (ret != 0)  {
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    throw runtime_error("Reading ECDSA signature part S from binary failed");
  }

  mbedtls_ecp_group tempGroup;
  mbedtls_ecp_group_init(&tempGroup);

  ret = mbedtls_ecp_group_copy(&tempGroup, &d_ctx.grp);

  if (ret != 0) {
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecp_group_free(&tempGroup);
    throw runtime_error("Error copying ECDSA group");
  }

  ret = mbedtls_ecdsa_verify(&tempGroup, (const unsigned char*) hash.c_str(), hash.length(), &d_ctx.Q, &r, &s);

  mbedtls_ecp_group_free(&tempGroup);
  mbedtls_mpi_free(&r);
  mbedtls_mpi_free(&s);

  return (ret == 0);
}

namespace {
struct LoaderStruct
{
  LoaderStruct()
  {
    DNSCryptoKeyEngine::report(5, &RSADNSCryptoKeyEngine::maker, true);
    DNSCryptoKeyEngine::report(7, &RSADNSCryptoKeyEngine::maker, true);
    DNSCryptoKeyEngine::report(8, &RSADNSCryptoKeyEngine::maker, true);
    DNSCryptoKeyEngine::report(10, &RSADNSCryptoKeyEngine::maker, true);
    DNSCryptoKeyEngine::report(13, &MbedECDSADNSCryptoKeyEngine::maker, true);
    DNSCryptoKeyEngine::report(14, &MbedECDSADNSCryptoKeyEngine::maker, true);
  }
} loaderMbed;
}
