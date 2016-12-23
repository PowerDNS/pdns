extern "C" {
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <sodium.h>
}
#include "dnssecinfra.hh"

class SodiumED25519DNSCryptoKeyEngine : public DNSCryptoKeyEngine
{
public:
  explicit SodiumED25519DNSCryptoKeyEngine(unsigned int algo) : DNSCryptoKeyEngine(algo)
  {}
  string getName() const { return "Sodium ED25519"; }
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
    return new SodiumED25519DNSCryptoKeyEngine(algorithm);
  }

private:
  unsigned char d_pubkey[crypto_sign_ed25519_PUBLICKEYBYTES];
  unsigned char d_seckey[crypto_sign_ed25519_SECRETKEYBYTES];
};

void SodiumED25519DNSCryptoKeyEngine::create(unsigned int bits)
{
  if(bits != crypto_sign_ed25519_SEEDBYTES * 8) {
    throw runtime_error("Unsupported key length of "+std::to_string(bits)+" bits requested, SodiumED25519 class");
  }
  crypto_sign_ed25519_keypair(d_pubkey, d_seckey);
}

int SodiumED25519DNSCryptoKeyEngine::getBits() const
{
  return crypto_sign_ed25519_SEEDBYTES * 8;
}

DNSCryptoKeyEngine::storvector_t SodiumED25519DNSCryptoKeyEngine::convertToISCVector() const
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
  storvector.push_back(make_pair("PrivateKey", string((char*)d_seckey, crypto_sign_ed25519_SEEDBYTES)));
  return storvector;
}

void SodiumED25519DNSCryptoKeyEngine::fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap )
{
  /*
    Private-key-format: v1.2
    Algorithm: 250 (ED25519SHA512)
    PrivateKey: GU6SnQ/Ou+xC5RumuIUIuJZteXT2z0O/ok1s38Et6mQ=
  */

  drc.d_algorithm = pdns_stou(stormap["algorithm"]);
  string privateKey = stormap["privatekey"];

  if (privateKey.length() != crypto_sign_ed25519_SEEDBYTES)
    throw runtime_error("Seed size mismatch in ISCMap, SodiumED25519 class");

  std::unique_ptr<unsigned char[]> seed(new unsigned char[crypto_sign_ed25519_SEEDBYTES]);

  memcpy(seed.get(), privateKey.c_str(), crypto_sign_ed25519_SEEDBYTES);
  crypto_sign_ed25519_seed_keypair(d_pubkey, d_seckey, seed.get());
}

std::string SodiumED25519DNSCryptoKeyEngine::getPubKeyHash() const
{
  return this->getPublicKeyString();
}

std::string SodiumED25519DNSCryptoKeyEngine::getPublicKeyString() const
{
  return string((char*)d_pubkey, crypto_sign_ed25519_PUBLICKEYBYTES);
}

void SodiumED25519DNSCryptoKeyEngine::fromPublicKeyString(const std::string& input)
{
  if (input.length() != crypto_sign_ed25519_PUBLICKEYBYTES)
    throw runtime_error("Public key size mismatch, SodiumED25519 class");

  memcpy(d_pubkey, input.c_str(), crypto_sign_ed25519_PUBLICKEYBYTES);
}

std::string SodiumED25519DNSCryptoKeyEngine::sign(const std::string& msg) const
{
  string hash=this->hash(msg);
  unsigned long long smlen = hash.length() + crypto_sign_ed25519_BYTES;
  std::unique_ptr<unsigned char[]> sm(new unsigned char[smlen]);

  crypto_sign_ed25519(sm.get(), &smlen, (const unsigned char*)hash.c_str(), hash.length(), d_seckey);

  return string((const char*)sm.get(), crypto_sign_ed25519_BYTES);
}

std::string SodiumED25519DNSCryptoKeyEngine::hash(const std::string& orig) const
{
  std::unique_ptr<unsigned char[]> out(new unsigned char[crypto_hash_sha512_BYTES]);

  crypto_hash_sha512(out.get(), (const unsigned char*)orig.c_str(), orig.length());

  return string((const char*)out.get(), crypto_hash_sha512_BYTES);
}

bool SodiumED25519DNSCryptoKeyEngine::verify(const std::string& msg, const std::string& signature) const
{
  if (signature.length() != crypto_sign_ed25519_BYTES)
    return false;

  string hash=this->hash(msg);
  unsigned long long smlen = hash.length() + crypto_sign_ed25519_BYTES;
  std::unique_ptr<unsigned char[]> sm(new unsigned char[smlen]);

  memcpy(sm.get(), signature.c_str(), crypto_sign_ed25519_BYTES);
  memcpy(sm.get() + crypto_sign_ed25519_BYTES, hash.c_str(), hash.length());

  std::unique_ptr<unsigned char[]> m(new unsigned char[smlen]);

  return crypto_sign_ed25519_open(m.get(), &smlen, sm.get(), smlen, d_pubkey) == 0;
}

namespace {
struct LoaderSodiumStruct
{
  LoaderSodiumStruct()
  {
    DNSCryptoKeyEngine::report(250, &SodiumED25519DNSCryptoKeyEngine::maker);
  }
} loadersodium;
}
