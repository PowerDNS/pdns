// utf-8 UTF-8 utf8 UTF8
#include <botan/botan.h>
#include <botan/ecdsa.h>
#include <botan/gost_3410.h>
#include <botan/gost_3411.h>
#include <botan/sha2_32.h>
#include <botan/sha2_64.h>
#include <botan/pubkey.h>
#include <botan/look_pk.h>
#include "dnssecinfra.hh"

using namespace Botan;

/*  Государственный гимн Российской Федерации
    (Gosudarstvenny Gimn Rossiyskoy Federatsii)
    "The National Anthem of the Russian Federation"
    
 ~  Rossiya - svyashchennaya nasha derzhava,  ~
 ~  Rossiya - lyubimaya nasha strana.         ~
 ~  Moguchaya volya, velikaya slava -         ~
 ~  Tvoyo dostoyanye na vse vremena!          ~
 */

class GOSTDNSPrivateKey : public DNSPrivateKey
{
public:
  void create(unsigned int bits);
  std::string convertToISC(unsigned int algorithm) const;
  std::string getPubKeyHash() const;
  std::string sign(const std::string& hash) const; 
  std::string hash(const std::string& hash) const; 
  bool verify(const std::string& hash, const std::string& signature) const;
  std::string getPublicKeyString() const;
  int getBits() const;
  void fromISCString(DNSKEYRecordContent& drc, const std::string& content);
  void fromPublicKeyString(unsigned int algorithm, const std::string& content);
  void fromPEMString(DNSKEYRecordContent& drc, const std::string& raw)
  {}

  static DNSPrivateKey* maker(unsigned int algorithm)
  {
    return new GOSTDNSPrivateKey();
  }

private:
  shared_ptr<GOST_3410_PrivateKey> d_key;
  shared_ptr<GOST_3410_PublicKey> d_pubkey;
};

/*
 ~ Slav'sya, Otechestvo nashe svobodnoye, ~
 ~ Bratskikh narodov soyuz vekovoy,       ~
 ~ Predkami dannaya mudrost' narodnaya!   ~
 ~ Slav'sya, strana! My gordimsya toboy!  ~
*/


void GOSTDNSPrivateKey::create(unsigned int bits)
{
  AutoSeeded_RNG rng;
  EC_Domain_Params params("1.2.643.2.2.35.1");
  d_key = shared_ptr<GOST_3410_PrivateKey>(new GOST_3410_PrivateKey(rng, params));
  cerr<<"Made a key!"<<endl;
}

int GOSTDNSPrivateKey::getBits() const
{
  return 256;
}

/*
 ~ Ot yuzhnykh morey do polyarnogo kraya ~
 ~ Raskinulis' nashi lesa i polya.       ~
 ~ Odna ty na svete! Odna ty takaya -    ~
 ~ Khranimaya Bogom rodnaya zemlya!      ~
*/


std::string GOSTDNSPrivateKey::convertToISC(unsigned int algorithm) const
{ 
  ostringstream ret;
  ret<<"Private-key-format: v1.2\nAlgorithm: 12 (ECC-GOST)\n";
  ret<<"GostAsn1: "; //XXX ??
  unsigned char asn1Prefix[]=
  {0x30, 0x45, 0x02, 0x01, 0x00, 0x30, 0x1c, 0x06, 0x06, 0x2a, 0x85, 0x03, 0x02, 0x02, 
   0x13, 0x30, 0x12, 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01, 0x06, 0x07, 
   0x2a, 0x85, 0x03, 0x02, 0x02, 0x1e, 0x01, 0x04, 0x22, 0x04, 0x20}; // this is DER, fixed for a 32 byte key

  SecureVector<byte> buffer=BigInt::encode(d_key->private_value());
  
  Pipe pipe(new Base64_Encoder);
  pipe.start_msg();
  pipe.write(asn1Prefix, sizeof(asn1Prefix));
  pipe.write(buffer);
  pipe.end_msg();
  ret<<pipe.read_all_as_string()<<"\n";
  return ret.str();
}

/*
 ~ Slav'sya, Otechestvo nashe svobodnoye, ~
 ~ Bratskikh narodov soyuz vekovoy,       ~
 ~ Predkami dannaya mudrost' narodnaya!   ~
 ~ Slav'sya, strana! My gordimsya toboy!  ~
*/


void GOSTDNSPrivateKey::fromISCString(DNSKEYRecordContent& drc, const std::string& content )
{ 
  istringstream input(content);
  string sline, key, value, privateKey;
  while(getline(input, sline)) {
    tie(key,value)=splitField(sline, ':');
    trim(value);
    if(pdns_iequals(key,"Private-key-format")) {}
    else if(key=="Algorithm")
      drc.d_algorithm = atoi(value.c_str());
    else if(key=="GostAsn1") {
      Pipe pipe(new Base64_Decoder);
      pipe.process_msg(value);
      privateKey=pipe.read_all_as_string();
    }
    else
      throw runtime_error("Unknown field '"+key+"' in Private Key Representation of GOST");
  }
  //cerr<<"PrivateKey.size() = "<<privateKey.size()<<endl;
  //cerr<<makeHexDump(string(privateKey.c_str(), 39))<<endl;
  string rawKey(privateKey.c_str()+39, privateKey.length()-39);
  
  for(size_t i = 0; i < rawKey.size() / 2; ++i)
  {
    std::swap(rawKey[i], rawKey[rawKey.size()-1-i]);
  }
  
  BigInt bigint((byte*)rawKey.c_str(), rawKey.size());
 
  EC_Domain_Params params("1.2.643.2.2.35.1");
  d_key=shared_ptr<GOST_3410_PrivateKey>(new GOST_3410_PrivateKey(params, bigint));
  
  //cerr<<"Is the just imported key on the curve? " << d_key->public_point().on_the_curve()<<endl;
  //cerr<<"Is the just imported key zero? " << d_key->public_point().is_zero()<<endl;
  
  const BigInt&x = d_key->private_value();
  SecureVector<byte> buffer=BigInt::encode(x);
 // cerr<<"And out again! "<<makeHexDump(string((const char*)buffer.begin(), (const char*)buffer.end()))<<endl;
}
namespace {

BigInt decode_le(const byte msg[], size_t msg_len)
   {
   SecureVector<byte> msg_le(msg, msg_len);

   for(size_t i = 0; i != msg_le.size() / 2; ++i)
      std::swap(msg_le[i], msg_le[msg_le.size()-1-i]);

   return BigInt(&msg_le[0], msg_le.size());
   }

}
void GOSTDNSPrivateKey::fromPublicKeyString(unsigned int algorithm, const std::string& input)
{
  BigInt x, y;
  
  x=decode_le((const byte*)input.c_str(), input.length()/2);
  y=decode_le((const byte*)input.c_str() + input.length()/2, input.length()/2);

  EC_Domain_Params params("1.2.643.2.2.35.1");
  PointGFp point(params.get_curve(), x,y);
  d_pubkey = shared_ptr<GOST_3410_PublicKey>(new GOST_3410_PublicKey(params, point));
  d_key.reset();
}

std::string GOSTDNSPrivateKey::getPubKeyHash() const
{
  const BigInt&x = d_key->private_value();
  SecureVector<byte> buffer=BigInt::encode(x);
  return string((const char*)buffer.begin(), (const char*)buffer.end());
}

std::string GOSTDNSPrivateKey::getPublicKeyString() const
{
  const BigInt&x =d_key->public_point().get_affine_x();
  const BigInt&y =d_key->public_point().get_affine_y();
  
  size_t part_size = std::max(x.bytes(), y.bytes());
 
  MemoryVector<byte> bits(2*part_size);
 
  x.binary_encode(&bits[part_size - x.bytes()]);
  y.binary_encode(&bits[2*part_size - y.bytes()]);

  // Keys are stored in little endian format (WTF)
  for(size_t i = 0; i != part_size / 2; ++i)
  {
    std::swap(bits[i], bits[part_size-1-i]);
    std::swap(bits[part_size+i], bits[2*part_size-1-i]);
  }
 
  return string((const char*)bits.begin(), (const char*)bits.end());
}

/*
 ~ Shirokiy prostor dlya mechty i dlya zhizni. ~ 
 ~ Gryadushchiye nam otkryvayut goda.          ~
 ~ Nam silu dayot nasha vernost' Otchizne.     ~
 ~ Tak bylo, tak yest' i tak budet vsegda!     ~  
 */

std::string GOSTDNSPrivateKey::sign(const std::string& hash) const
{
  GOST_3410_Signature_Operation ops(*d_key);
  AutoSeeded_RNG rng;
  SecureVector<byte> signature=ops.sign((byte*)hash.c_str(), hash.length(), rng);
  
  return string((const char*)signature.begin(), (const char*) signature.end());
}

std::string GOSTDNSPrivateKey::hash(const std::string& orig) const
{
  SecureVector<byte> result;
  
  GOST_34_11 hasher;
  result= hasher.process(orig);
  return string((const char*)result.begin(), (const char*) result.end());
}


bool GOSTDNSPrivateKey::verify(const std::string& hash, const std::string& signature) const
{
  GOST_3410_PublicKey* pk;
  if(d_pubkey) {
    cerr<<"Worked from the public key"<<endl;
    pk =d_pubkey.get();
  }
  else
    pk = d_key.get();
    
  GOST_3410_Verification_Operation ops(*pk);
  /* 
  string rhash(hash);
  for(string::size_type pos = 0 ; pos < rhash.size()/2; ++pos)
    swap(rhash[pos], rhash[rhash.size()-1-pos]);
  */
  return ops.verify ((byte*)hash.c_str(), hash.length(), (byte*)signature.c_str(), signature.length());
}

/*
 ~ Slav'sya, Otechestvo nashe svobodnoye, ~
 ~ Bratskikh narodov soyuz vekovoy,       ~
 ~ Predkami dannaya mudrost' narodnaya!   ~
 ~ Slav'sya, strana! My gordimsya toboy!  ~
*/


//////////////////////////////

class ECDSADNSPrivateKey : public DNSPrivateKey
{
public:
  explicit ECDSADNSPrivateKey(unsigned int algo) :d_algorithm(algo)
  {}
  void create(unsigned int bits);
  std::string convertToISC(unsigned int algorithm) const;
  std::string getPubKeyHash() const;
  std::string sign(const std::string& hash) const; 
  std::string hash(const std::string& hash) const; 
  bool verify(const std::string& hash, const std::string& signature) const;
  std::string getPublicKeyString() const;
  int getBits() const;
  void fromISCString(DNSKEYRecordContent& drc, const std::string& content);
  void fromPublicKeyString(unsigned int algorithm, const std::string& content);
  void fromPEMString(DNSKEYRecordContent& drc, const std::string& raw)
  {}

  static DNSPrivateKey* maker(unsigned int algorithm)
  {
    return new ECDSADNSPrivateKey(algorithm);
  }

private:
  static EC_Domain_Params getECParams(unsigned int algorithm);
  shared_ptr<ECDSA_PrivateKey> d_key;
  shared_ptr<ECDSA_PublicKey> d_pubkey;
  unsigned int d_algorithm;
};

EC_Domain_Params ECDSADNSPrivateKey::getECParams(unsigned int algorithm) 
{
  if(algorithm==13)
    return EC_Domain_Params("1.2.840.10045.3.1.7");
  else if(algorithm == 14)
    return EC_Domain_Params("1.3.132.0.34");
  else
    throw runtime_error("Requested for unknown EC domain parameters for algorithm "+lexical_cast<string>(algorithm));
}

void ECDSADNSPrivateKey::create(unsigned int bits)
{
  AutoSeeded_RNG rng;
  EC_Domain_Params params;
  if(bits==256) {
    params = getECParams(13);
  } 
  else if(bits == 384){
    params = getECParams(14);
  }
  else {
    throw runtime_error("Unknown key length of "+lexical_cast<string>(bits)+" bits requested from ECDSA class");
  }
  d_key = shared_ptr<ECDSA_PrivateKey>(new ECDSA_PrivateKey(rng, params));
}

int ECDSADNSPrivateKey::getBits() const
{
  if(d_algorithm == 13)
    return 256;
  else if(d_algorithm == 14)
    return 384;
  return -1;
}

std::string ECDSADNSPrivateKey::convertToISC(unsigned int algorithm) const
{
  /*Private-key-format: v1.2
   Algorithm: 13 (ECDSAP256SHA256)
   PrivateKey: GU6SnQ/Ou+xC5RumuIUIuJZteXT2z0O/ok1s38Et6mQ= */
   
  ostringstream ret;
  ret<<"Private-key-format: v1.2\nAlgorithm: ";
  if(getBits()==256) 
    ret << "13 (ECDSAP256SHA256)\n";
  else if(getBits()==384) 
    ret << "14 (ECDSAP384SHA384)\n";
  else 
    ret <<" ? (?)\n";
  
  ret<<"PrivateKey: ";
  
  const BigInt&x = d_key->private_value();
  SecureVector<byte> buffer=BigInt::encode(x);
  
  Pipe pipe(new Base64_Encoder);
  pipe.process_msg(buffer);
  ret<<pipe.read_all_as_string()<<"\n";
  return ret.str();
}

void ECDSADNSPrivateKey::fromISCString(DNSKEYRecordContent& drc, const std::string& content )
{
  /*Private-key-format: v1.2
   Algorithm: 13 (ECDSAP256SHA256)
   PrivateKey: GU6SnQ/Ou+xC5RumuIUIuJZteXT2z0O/ok1s38Et6mQ= */
  
  istringstream input(content);
  string sline, key, value, privateKey;
  while(getline(input, sline)) {
    tie(key,value)=splitField(sline, ':');
    trim(value);
    if(pdns_iequals(key,"Private-key-format")) {}
    else if(key=="Algorithm")
      drc.d_algorithm = atoi(value.c_str());
    else if(key=="PrivateKey") {
      Pipe pipe(new Base64_Decoder);
      pipe.process_msg(value);
      privateKey=pipe.read_all_as_string();
    }
    else
      throw runtime_error("Unknown field '"+key+"' in Private Key Representation of ECDSA");
  }
  d_algorithm = drc.d_algorithm;
  BigInt bigint((byte*)privateKey.c_str(), privateKey.length());
  
  EC_Domain_Params params=getECParams(drc.d_algorithm);
  d_key=shared_ptr<ECDSA_PrivateKey>(new ECDSA_PrivateKey(params, bigint));
  
}

std::string ECDSADNSPrivateKey::getPubKeyHash() const
{
  const BigInt&x = d_key->private_value();
  SecureVector<byte> buffer=BigInt::encode(x);
  return string((const char*)buffer.begin(), (const char*)buffer.end());
}

std::string ECDSADNSPrivateKey::getPublicKeyString() const
{
  const BigInt&x =d_key->public_point().get_affine_x();
  const BigInt&y =d_key->public_point().get_affine_y();
  
  size_t part_size = std::max(x.bytes(), y.bytes());
  MemoryVector<byte> bits(2*part_size);
  
  x.binary_encode(&bits[part_size - x.bytes()]);
  y.binary_encode(&bits[2*part_size - y.bytes()]);
  return string((const char*)bits.begin(), (const char*)bits.end());
}

void ECDSADNSPrivateKey::fromPublicKeyString(unsigned int algorithm, const std::string&input) 
{
  BigInt x, y;
  
  x.binary_decode((const byte*)input.c_str(), input.length()/2);
  y.binary_decode((const byte*)input.c_str() + input.length()/2, input.length()/2);

  d_algorithm = algorithm;

  EC_Domain_Params params=getECParams(algorithm);
  PointGFp point(params.get_curve(), x,y);
  d_pubkey = shared_ptr<ECDSA_PublicKey>(new ECDSA_PublicKey(params, point));
  d_key.reset();
}


std::string ECDSADNSPrivateKey::sign(const std::string& hash) const
{
  ECDSA_Signature_Operation ops(*d_key);
  AutoSeeded_RNG rng;
  SecureVector<byte> signature=ops.sign((byte*)hash.c_str(), hash.length(), rng);
  
  return string((const char*)signature.begin(), (const char*) signature.end());
}

std::string ECDSADNSPrivateKey::hash(const std::string& orig) const
{
  SecureVector<byte> result;
  if(getBits() == 256) { // SHA256
    SHA_256 hasher;
    result= hasher.process(orig);
  }
  else { // SHA384
    SHA_384 hasher;
    result = hasher.process(orig);
  }
  
  return string((const char*)result.begin(), (const char*) result.end());
}


bool ECDSADNSPrivateKey::verify(const std::string& hash, const std::string& signature) const
{
  ECDSA_PublicKey* key;
  if(d_key)
    key = d_key.get();
  else
    key = d_pubkey.get();
  ECDSA_Verification_Operation ops(*key);
  return ops.verify ((byte*)hash.c_str(), hash.length(), (byte*)signature.c_str(), signature.length());
}

namespace {
struct LoaderStruct
{
  LoaderStruct()
  {
    DNSPrivateKey::report(12, &GOSTDNSPrivateKey::maker);
    DNSPrivateKey::report(13, &ECDSADNSPrivateKey::maker);
    DNSPrivateKey::report(14, &ECDSADNSPrivateKey::maker);
  }
} loader;
}
