#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <botan/botan.h>
#include <botan/gost_3410.h>
#include <botan/gost_3411.h>
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

class GOSTDNSCryptoKeyEngine : public DNSCryptoKeyEngine
{
public:
  explicit GOSTDNSCryptoKeyEngine(unsigned int algorithm) : DNSCryptoKeyEngine(algorithm) {}
  // XXX FIXME NEEDS COPY CONSTRUCTOR SO WE DON'T SHARE KEYS
  ~GOSTDNSCryptoKeyEngine(){}
  void create(unsigned int bits);
  string getName() const { return "Botan 1.10 GOST"; }
  storvector_t convertToISCVector() const;
  std::string getPubKeyHash() const;
  std::string sign(const std::string& hash) const; 
  std::string hash(const std::string& hash) const; 
  bool verify(const std::string& hash, const std::string& signature) const;
  std::string getPublicKeyString() const;
  int getBits() const;
  void fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& content);
  void fromPublicKeyString(const std::string& content);
  void fromPEMString(DNSKEYRecordContent& drc, const std::string& raw)
  {}

  static DNSCryptoKeyEngine* maker(unsigned int algorithm)
  {
    return new GOSTDNSCryptoKeyEngine(algorithm);
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


void GOSTDNSCryptoKeyEngine::create(unsigned int bits)
{
  AutoSeeded_RNG rng;
  EC_Domain_Params params("1.2.643.2.2.35.1");
  d_key = shared_ptr<GOST_3410_PrivateKey>(new GOST_3410_PrivateKey(rng, params));
}

int GOSTDNSCryptoKeyEngine::getBits() const
{
  return 256;
}

/*
 ~ Ot yuzhnykh morey do polyarnogo kraya ~
 ~ Raskinulis' nashi lesa i polya.       ~
 ~ Odna ty na svete! Odna ty takaya -    ~
 ~ Khranimaya Bogom rodnaya zemlya!      ~
*/

DNSCryptoKeyEngine::storvector_t GOSTDNSCryptoKeyEngine::convertToISCVector() const
{ 
  storvector_t storvect;
  storvect.push_back(make_pair("Algorithm", "12 (ECC-GOST)"));
  
  unsigned char asn1Prefix[]=
  {0x30, 0x45, 0x02, 0x01, 0x00, 0x30, 0x1c, 0x06, 0x06, 0x2a, 0x85, 0x03, 0x02, 0x02, 
   0x13, 0x30, 0x12, 0x06, 0x07, 0x2a, 0x85, 0x03, 0x02, 0x02, 0x23, 0x01, 0x06, 0x07, 
   0x2a, 0x85, 0x03, 0x02, 0x02, 0x1e, 0x01, 0x04, 0x22, 0x04, 0x20}; // this is DER, fixed for a 32 byte key

  SecureVector<byte> buffer=BigInt::encode(d_key->private_value());
  string gostasn1((const char*)asn1Prefix, sizeof(asn1Prefix));
  gostasn1.append((const char*)&*buffer.begin(), (const char*)&*buffer.end());
  storvect.push_back(make_pair("GostAsn1", gostasn1));
  return storvect;
}

/*
 ~ Slav'sya, Otechestvo nashe svobodnoye, ~
 ~ Bratskikh narodov soyuz vekovoy,       ~
 ~ Predkami dannaya mudrost' narodnaya!   ~
 ~ Slav'sya, strana! My gordimsya toboy!  ~
*/

void GOSTDNSCryptoKeyEngine::fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap )
{ 
  drc.d_algorithm = pdns_stou(stormap["algorithm"]);
  string privateKey=stormap["gostasn1"];
  //cerr<<"PrivateKey.size() = "<<privateKey.size()<<endl;
  //cerr<<makeHexDump(string(privateKey.c_str(), 39))<<endl;
  string rawKey(privateKey.c_str()+39, privateKey.length()-39);
  
  for(size_t i = 0; i < rawKey.size() / 2; ++i)
  {
    std::swap(rawKey[i], rawKey[rawKey.size()-1-i]);
  }
  
  BigInt bigint((byte*)rawKey.c_str(), rawKey.size());
 
  EC_Group params("1.2.643.2.2.35.1");
  AutoSeeded_RNG rng;
  d_key=shared_ptr<GOST_3410_PrivateKey>(new GOST_3410_PrivateKey(rng, params, bigint));
  
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
void GOSTDNSCryptoKeyEngine::fromPublicKeyString(const std::string& input)
{
  BigInt x, y;
  
  x=decode_le((const byte*)input.c_str(), input.length()/2);
  y=decode_le((const byte*)input.c_str() + input.length()/2, input.length()/2);

  EC_Domain_Params params("1.2.643.2.2.35.1");
  PointGFp point(params.get_curve(), x,y);
  d_pubkey = shared_ptr<GOST_3410_PublicKey>(new GOST_3410_PublicKey(params, point));
  d_key.reset();
}

std::string GOSTDNSCryptoKeyEngine::getPubKeyHash() const
{
  const BigInt&x = d_key->private_value();
  SecureVector<byte> buffer=BigInt::encode(x);
  return string((const char*)buffer.begin(), (const char*)buffer.end());
}

std::string GOSTDNSCryptoKeyEngine::getPublicKeyString() const
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

std::string GOSTDNSCryptoKeyEngine::sign(const std::string& msg) const
{
  GOST_3410_Signature_Operation ops(*d_key);
  AutoSeeded_RNG rng;
  
  string hash= this->hash(msg);
  
  SecureVector<byte> signature=ops.sign((byte*)hash.c_str(), hash.length(), rng);

#if BOTAN_VERSION_CODE <= BOTAN_VERSION_CODE_FOR(1,9,12)  // see http://bit.ly/gTytUf
  string reversed((const char*)signature.begin()+ signature.size()/2, signature.size()/2);
  reversed.append((const char*)signature.begin(), signature.size()/2);
  return reversed;
#else  
  return string((const char*)signature.begin(), (const char*) signature.end());
#endif
}

std::string GOSTDNSCryptoKeyEngine::hash(const std::string& orig) const
{
  SecureVector<byte> result;
  
  GOST_34_11 hasher;
  result= hasher.process(orig);
  return string((const char*)result.begin(), (const char*) result.end());
}


bool GOSTDNSCryptoKeyEngine::verify(const std::string& message, const std::string& signature) const
{
  string hash = this->hash(message);
  GOST_3410_PublicKey* pk;
  if(d_pubkey) {
    pk =d_pubkey.get();
  }
  else
    pk = d_key.get();
    
  GOST_3410_Verification_Operation ops(*pk);
#if BOTAN_VERSION_CODE <= BOTAN_VERSION_CODE_FOR(1,9,12)  // see http://bit.ly/gTytUf
  string rsignature(signature.substr(32));
  rsignature.append(signature.substr(0,32));
  return ops.verify ((byte*)hash.c_str(), hash.length(), (byte*)rsignature.c_str(), rsignature.length());
#else
  return ops.verify ((byte*)hash.c_str(), hash.length(), (byte*)signature.c_str(), signature.length());
#endif
}

/*
 ~ Slav'sya, Otechestvo nashe svobodnoye, ~
 ~ Bratskikh narodov soyuz vekovoy,       ~
 ~ Predkami dannaya mudrost' narodnaya!   ~
 ~ Slav'sya, strana! My gordimsya toboy!  ~
*/


//////////////////////////////

namespace {
struct LoaderStruct
{
  LoaderStruct()
  {
    new Botan::LibraryInitializer("thread_safe=true");
    // this leaks, but is fine
    Botan::global_state().set_default_allocator("malloc"); // the other Botan allocator slows down for us

    DNSCryptoKeyEngine::report(12, &GOSTDNSCryptoKeyEngine::maker);
  }
} loaderBotan110;
}
