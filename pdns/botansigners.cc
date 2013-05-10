#include <botan/botan.h>
#include <botan/sha160.h>
#include <botan/sha2_32.h>
#include <botan/sha2_64.h>
#include <botan/emsa3.h>
#include <botan/rsa.h>
#include <botan/pubkey.h>
#include <botan/look_pk.h>
#include <botan/numthry.h>
#include "dnssecinfra.hh"

using namespace Botan;

class BotanRSADNSCryptoKeyEngine : public DNSCryptoKeyEngine
{
public:
  explicit BotanRSADNSCryptoKeyEngine(unsigned int algo) : DNSCryptoKeyEngine(algo)
  {
  //  cerr<<"Called"<<endl;
  }

  ~BotanRSADNSCryptoKeyEngine(){}

  string getName() const { return "Botan RSA"; }
  void create(unsigned int bits);
  storvector_t convertToISCVector() const;
  std::string getPubKeyHash() const;
  std::string sign(const std::string& msg) const;
  std::string hash(const std::string& hash) const;
  bool verify(const std::string& msg, const std::string& signature) const;
  std::string getPublicKeyString() const;
  int getBits() const;
  void fromISCMap(DNSKEYRecordContent& drc, stormap_t& stormap);
  void fromPublicKeyString(const std::string& content);
  void fromPEMString(DNSKEYRecordContent& drc, const std::string& raw)
  {}

  static DNSCryptoKeyEngine* maker(unsigned int algorithm)
  {
    return new BotanRSADNSCryptoKeyEngine(algorithm);
  }

private:
  shared_ptr<RSA_PrivateKey> d_key;
  shared_ptr<RSA_PublicKey> d_pubkey;
};

void BotanRSADNSCryptoKeyEngine::create(unsigned int bits)
{
  AutoSeeded_RNG rng;
  d_key = shared_ptr<RSA_PrivateKey>(new RSA_PrivateKey(rng, bits));
}

int BotanRSADNSCryptoKeyEngine::getBits() const
{
  return d_key->max_input_bits() + 1;
}

namespace {
string asRaw(const BigInt& x)
{
  SecureVector<byte> buffer=BigInt::encode(x);
  return string((const char*)&*buffer.begin(), (const char*)&*buffer.end());
}

BigInt fromRaw(const std::string& raw)
{
  if(raw.empty())
    throw runtime_error("Unable to decode empty value");
  return BigInt::decode((byte*)raw.c_str(), raw.length());
}
}

DNSCryptoKeyEngine::storvector_t BotanRSADNSCryptoKeyEngine::convertToISCVector() const
{
  storvector_t storvect;
  string algorithm =  lexical_cast<string>(d_algorithm);
  if(d_algorithm == 5 || d_algorithm ==7 )
    algorithm += " (RSASHA1)";
  else if(d_algorithm == 8)
    algorithm += " (RSASHA256)";
  else if(d_algorithm == 10)
    algorithm += " (RSASHA512)";
  else
    algorithm += " (?)";
  storvect.push_back(make_pair("Algorithm", algorithm));
  storvect.push_back(make_pair("Modulus", asRaw(d_key->get_n())));
  storvect.push_back(make_pair("PublicExponent",asRaw(d_key->get_e())));
  storvect.push_back(make_pair("PrivateExponent",asRaw(d_key->get_d())));
  storvect.push_back(make_pair("Prime1",asRaw(d_key->get_p())));
  storvect.push_back(make_pair("Prime2",asRaw(d_key->get_q())));

#if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR(1,9,0)
  BigInt d1 = d_key->get_d() % (d_key->get_p() - 1);
  BigInt d2 = d_key->get_d() % (d_key->get_q() - 1);
  BigInt c = inverse_mod(d_key->get_q(), d_key->get_p());
#else
  BigInt d1 = d_key->get_d1();
  BigInt d2 = d_key->get_d2();
  BigInt c = d_key->get_c();
#endif
  storvect.push_back(make_pair("Exponent1", asRaw(d1)));
  storvect.push_back(make_pair("Exponent2", asRaw(d2)));
  storvect.push_back(make_pair("Coefficient", asRaw(c)));
  return storvect;
}

void BotanRSADNSCryptoKeyEngine::fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap )
{
  // wants p (Prime1), q (Prime2), d (PrivateExponent), e (PublicExponent) & n Modulus
  BigInt n, e, d, p, q;

  p=fromRaw(stormap["prime1"]);
  q=fromRaw(stormap["prime2"]);
  d=fromRaw(stormap["privateexponent"]);
  e=fromRaw(stormap["publicexponent"]);
  n=fromRaw(stormap["modulus"]);

  drc.d_algorithm = atoi(stormap["algorithm"].c_str());
  if(drc.d_algorithm != d_algorithm)
    throw runtime_error("Unpossible, loaded a key from storage with wrong algorithm!");

  AutoSeeded_RNG rng;
  d_key = shared_ptr<RSA_PrivateKey>(new RSA_PrivateKey(rng, p, q, e, d, n)); // this calculates d1, d2 & other stuff, plus does load checks..

  d_pubkey.reset();
}

std::string BotanRSADNSCryptoKeyEngine::getPubKeyHash() const
{
  const BigInt& n = d_key->get_n();
  const BigInt& e = d_key->get_e();
  SecureVector<byte> buffer=BigInt::encode(n);

  SHA_160 hasher;
  hasher.update(buffer);
  buffer=BigInt::encode(e);
  hasher.update(buffer);
  SecureVector<byte> hash=hasher.final();
  return string((const char*)hash.begin(), (const char*)hash.end());
}

std::string BotanRSADNSCryptoKeyEngine::getPublicKeyString() const
{
  MemoryVector<byte> bits = BigInt::encode(d_key->get_e());
  string exponent(&*bits.begin(), &*bits.end());
  bits = BigInt::encode(d_key->get_n());
  string modulus(&*bits.begin(), &*bits.end());

  string keystring;
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

void BotanRSADNSCryptoKeyEngine::fromPublicKeyString(const std::string& rawString)
{
  string exponent, modulus;
  const unsigned char* raw = (const unsigned char*)rawString.c_str();

  if(raw[0] != 0) {
    exponent=rawString.substr(1, raw[0]);
    modulus=rawString.substr(raw[0]+1);
  } else {
    exponent=rawString.substr(3, raw[1]*0xff + raw[2]);
    modulus = rawString.substr(3+ raw[1]*0xff + raw[2]);
  }
  BigInt e = BigInt::decode((const byte*)exponent.c_str(), exponent.length());
  BigInt n = BigInt::decode((const byte*)modulus.c_str(), modulus.length());

  d_pubkey = shared_ptr<RSA_PublicKey>(new RSA_PublicKey(n, e));
  d_key.reset();
}

std::string BotanRSADNSCryptoKeyEngine::sign(const std::string& msg) const
{
#if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR(1,9,0)
  EMSA* emsaptr;
  if(d_algorithm == 5 || d_algorithm ==7)
    emsaptr=new EMSA3(new SHA_160);
  else if(d_algorithm==8)
    emsaptr=new EMSA3(new SHA_256);
  else
    emsaptr=new EMSA3(new SHA_512);
  PK_Signer pks(*d_key, emsaptr);
#else
  string emsa;
  if(d_algorithm == 5 || d_algorithm ==7)
    emsa="EMSA3(SHA-160)";
  else if(d_algorithm==8)
    emsa="EMSA3(SHA-256)";
  else
    emsa="EMSA3(SHA-512)";
  PK_Signer pks(*d_key, emsa);
#endif

  AutoSeeded_RNG rng;
  SecureVector<byte> signature= pks.sign_message((byte*)msg.c_str(), msg.length(), rng);
  return string((const char*)signature.begin(), (const char*) signature.end());
}

std::string BotanRSADNSCryptoKeyEngine::hash(const std::string& orig) const
{
  SecureVector<byte> result;
  if(d_algorithm == 5 || d_algorithm ==7 ) { // SHA160
    SHA_160 hasher;
    result= hasher.process(orig);
  }
  if(d_algorithm == 8) { // SHA256
    SHA_256 hasher;
    result= hasher.process(orig);
  }
  else if(d_algorithm==10) { // SHA512
    SHA_512 hasher;
    result = hasher.process(orig);
  }

  return string((const char*)result.begin(), (const char*) result.end());
}


bool BotanRSADNSCryptoKeyEngine::verify(const std::string& msg, const std::string& signature) const
{
  RSA_PublicKey* key = d_key ? d_key.get() : d_pubkey.get();

  string emsa;

  if(d_algorithm == 5 || d_algorithm ==7)
    emsa = "EMSA3(SHA-1)";
  else if(d_algorithm==8)
    emsa = "EMSA3(SHA-256)";
  else
    emsa = "EMSA3(SHA-512)";

#if BOTAN_VERSION_CODE < BOTAN_VERSION_CODE_FOR(1,9,0)
  std::auto_ptr<PK_Verifier> ver(get_pk_verifier(*key, emsa));
  return ver->verify_message((byte*)msg.c_str(), msg.length(), (byte*)signature.c_str(), signature.length());
#else
  PK_Verifier pkv(*key, emsa);
  return pkv.verify_message((byte*)msg.c_str(), msg.length(), (byte*)signature.c_str(), signature.length());
#endif
}

namespace {
struct LoaderBotanStruct
{
  LoaderBotanStruct()
  {
    new Botan::LibraryInitializer("thread_safe=true");
    // this leaks, but is fine
    DNSCryptoKeyEngine::report(5, &BotanRSADNSCryptoKeyEngine::maker);
    DNSCryptoKeyEngine::report(7, &BotanRSADNSCryptoKeyEngine::maker);
    DNSCryptoKeyEngine::report(8, &BotanRSADNSCryptoKeyEngine::maker);
    DNSCryptoKeyEngine::report(10, &BotanRSADNSCryptoKeyEngine::maker);
  }
} loaderBotan;
}

