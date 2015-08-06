// utf-8 UTF-8 utf8 UTF8
extern "C" {
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "ext/ed25519/crypto_sign.h"
#include "ext/ed25519/crypto_hash_sha512.h"
}
#include "dnssecinfra.hh"

#define SECRETBYTES SECRETKEYBYTES-PUBLICKEYBYTES

class ED25519DNSCryptoKeyEngine : public DNSCryptoKeyEngine
{
public:
  explicit ED25519DNSCryptoKeyEngine(unsigned int algo) : DNSCryptoKeyEngine(algo)
  {}
  string getName() const { return "Ref10 ED25519"; }
  void create(unsigned int bits);
  storvector_t convertToISCVector() const;
  std::string getPubKeyHash() const;
  std::string sign(const std::string& hash) const; 
  std::string hash(const std::string& hash) const; 
  bool verify(const std::string& msg, const std::string& signature) const;
  std::string getPublicKeyString() const;
  int getBits() const;
  void fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap);
  void fromPublicKeyString(const std::string& content);
  void fromPEMString(DNSKEYRecordContent& drc, const std::string& raw)
  {}

  static DNSCryptoKeyEngine* maker(unsigned int algorithm)
  {
    return new ED25519DNSCryptoKeyEngine(algorithm);
  }

private:
  unsigned char d_pubkey[PUBLICKEYBYTES];
  unsigned char d_seckey[SECRETKEYBYTES];
            
};

void ED25519DNSCryptoKeyEngine::create(unsigned int bits)
{
  if(bits != 256) {
    throw runtime_error("Unknown key length of "+lexical_cast<string>(bits)+" bits requested from ED25519 class");
  }
  crypto_sign_keypair(d_pubkey, d_seckey);
}

int ED25519DNSCryptoKeyEngine::getBits() const
{
  return 256;
}

DNSCryptoKeyEngine::storvector_t ED25519DNSCryptoKeyEngine::convertToISCVector() const
{
  /*
    Private-key-format: v1.2
    Algorithm: 250 (ED25519SHA512)
    PrivateKey: GU6SnQ/Ou+xC5RumuIUIuJZteXT2z0O/ok1s38Et6mQ=
  */

  storvector_t storvector;
  string algorithm = "250 (ED25519SHA512)";

  storvector.push_back(make_pair("Algorithm", algorithm));

  vector<unsigned char> buffer;
  storvector.push_back(make_pair("PrivateKey", string((char*)d_seckey, SECRETBYTES)));
  return storvector;
}

void ED25519DNSCryptoKeyEngine::fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap )
{
  /*
    Private-key-format: v1.2
    Algorithm: 250 (ED25519SHA512)
    PrivateKey: GU6SnQ/Ou+xC5RumuIUIuJZteXT2z0O/ok1s38Et6mQ=
  */

  drc.d_algorithm = atoi(stormap["algorithm"].c_str());
  string privateKey = stormap["privatekey"];

  memcpy(d_seckey, privateKey.c_str(), SECRETBYTES);
  crypto_sign_publickey(d_pubkey, d_seckey, d_seckey);
  //memcpy(d_pubkey, privateKey.c_str() + SECRETBYTES, PUBLICKEYBYTES);
}

// used for the cache, nothing external
std::string ED25519DNSCryptoKeyEngine::getPubKeyHash() const
{
  return string((const char*)d_pubkey, PUBLICKEYBYTES);
}

std::string ED25519DNSCryptoKeyEngine::getPublicKeyString() const
{
  return string((char*)d_pubkey, PUBLICKEYBYTES);
}

void ED25519DNSCryptoKeyEngine::fromPublicKeyString(const std::string&input) 
{
  memcpy(d_pubkey, input.c_str(), PUBLICKEYBYTES);
}

std::string ED25519DNSCryptoKeyEngine::sign(const std::string& msg) const
{
  string hash=this->hash(msg);
  unsigned long long smlen = hash.length() + SIGNATUREBYTES;
  std::unique_ptr<unsigned char[]> sm(new unsigned char[smlen]);

  crypto_sign(sm.get(), &smlen, (const unsigned char*)hash.c_str(), hash.length(), d_seckey);

  return string((const char*)sm.get(), SIGNATUREBYTES);
}

std::string ED25519DNSCryptoKeyEngine::hash(const std::string& orig) const
{
  std::unique_ptr<unsigned char[]> out(new unsigned char[crypto_hash_sha512_BYTES]);

  crypto_hash_sha512(out.get(), (const unsigned char*)orig.c_str(), orig.length());

  return string((const char*)out.get(), crypto_hash_sha512_BYTES);
}

bool ED25519DNSCryptoKeyEngine::verify(const std::string& msg, const std::string& signature) const
{
  string hash=this->hash(msg);
  unsigned long long smlen = hash.length() + SIGNATUREBYTES;
  std::unique_ptr<unsigned char[]> sm(new unsigned char[smlen]);

  memcpy(sm.get(), signature.c_str(), SIGNATUREBYTES);
  memcpy(sm.get() + SIGNATUREBYTES, hash.c_str(), hash.length());

  std::unique_ptr<unsigned char[]> m(new unsigned char[smlen]);

  return crypto_sign_open(m.get(), &smlen, sm.get(), smlen, d_pubkey) == 0;
}

namespace {
struct LoaderED25519Struct
{
  LoaderED25519Struct()
  {
    DNSCryptoKeyEngine::report(250, &ED25519DNSCryptoKeyEngine::maker);
  }
} loadered25519;
}
