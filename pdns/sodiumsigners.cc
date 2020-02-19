extern "C"
{
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <sodium.h>
}
#include "dnssecinfra.hh"

class SodiumED25519DNSCryptoKeyEngine : public DNSCryptoKeyEngine
{
public:
  explicit SodiumED25519DNSCryptoKeyEngine(unsigned int algo) :
    DNSCryptoKeyEngine(algo)
  {
  }
  string getName() const override { return "Sodium ED25519"; }
  void create(unsigned int bits) override;
  storvector_t convertToISCVector() const override;
  std::string getPubKeyHash() const override;
  std::string sign(const std::string& msg) const override;
  bool verify(const std::string& msg, const std::string& signature) const override;
  std::string getPublicKeyString() const override;
  int getBits() const override;
  void fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap) override;
  void fromPublicKeyString(const std::string& content) override;
  void fromPEMString(DNSKEYRecordContent& drc, const std::string& raw) override
  {
  }

  static std::shared_ptr<DNSCryptoKeyEngine> maker(unsigned int algorithm)
  {
    return std::make_shared<SodiumED25519DNSCryptoKeyEngine>(algorithm);
  }

private:
  unsigned char d_pubkey[crypto_sign_ed25519_PUBLICKEYBYTES];
  unsigned char d_seckey[crypto_sign_ed25519_SECRETKEYBYTES];
};

void SodiumED25519DNSCryptoKeyEngine::create(unsigned int bits)
{
  if (bits != crypto_sign_ed25519_SEEDBYTES * 8) {
    throw runtime_error("Unsupported key length of " + std::to_string(bits) + " bits requested, SodiumED25519 class");
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
    Algorithm: 15 (ED25519)
    PrivateKey: GU6SnQ/Ou+xC5RumuIUIuJZteXT2z0O/ok1s38Et6mQ=
  */

  storvector_t storvector;
  string algorithm = "15 (ED25519)";

  storvector.push_back(make_pair("Algorithm", algorithm));

  vector<unsigned char> buffer;
  storvector.push_back(make_pair("PrivateKey", string((char*)d_seckey, crypto_sign_ed25519_SEEDBYTES)));
  return storvector;
}

void SodiumED25519DNSCryptoKeyEngine::fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap)
{
  /*
    Private-key-format: v1.2
    Algorithm: 15 (ED25519)
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
  unsigned long long smlen = msg.length() + crypto_sign_ed25519_BYTES;
  std::unique_ptr<unsigned char[]> sm(new unsigned char[smlen]);

  crypto_sign_ed25519(sm.get(), &smlen, (const unsigned char*)msg.c_str(), msg.length(), d_seckey);

  return string((const char*)sm.get(), crypto_sign_ed25519_BYTES);
}

bool SodiumED25519DNSCryptoKeyEngine::verify(const std::string& msg, const std::string& signature) const
{
  if (signature.length() != crypto_sign_ed25519_BYTES)
    return false;

  unsigned long long smlen = msg.length() + crypto_sign_ed25519_BYTES;
  std::unique_ptr<unsigned char[]> sm(new unsigned char[smlen]);

  memcpy(sm.get(), signature.c_str(), crypto_sign_ed25519_BYTES);
  memcpy(sm.get() + crypto_sign_ed25519_BYTES, msg.c_str(), msg.length());

  std::unique_ptr<unsigned char[]> m(new unsigned char[smlen]);

  return crypto_sign_ed25519_open(m.get(), &smlen, sm.get(), smlen, d_pubkey) == 0;
}

namespace
{
struct LoaderSodiumStruct
{
  LoaderSodiumStruct()
  {
    DNSCryptoKeyEngine::report(15, &SodiumED25519DNSCryptoKeyEngine::maker);
  }
} loadersodium;
}
