#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <decaf.hxx>
#include <decaf/eddsa.hxx>
#include <decaf/spongerng.hxx>

#include "dnssecinfra.hh"

using namespace decaf;

class DecafED25519DNSCryptoKeyEngine : public DNSCryptoKeyEngine
{
public:
  explicit DecafED25519DNSCryptoKeyEngine(unsigned int algo) :
    DNSCryptoKeyEngine(algo)
  {
  }
  string getName() const override { return "Decaf ED25519"; }
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
    return std::make_shared<DecafED25519DNSCryptoKeyEngine>(algorithm);
  }

private:
  unsigned char d_pubkey[DECAF_EDDSA_25519_PUBLIC_BYTES];
  unsigned char d_seckey[DECAF_EDDSA_25519_PRIVATE_BYTES];
};

void DecafED25519DNSCryptoKeyEngine::create(unsigned int bits)
{
  if (bits != (unsigned int)getBits()) {
    throw runtime_error("Unsupported key length of " + std::to_string(bits) + " bits requested, DecafED25519 class");
  }

  SpongeRng rng("/dev/urandom");

  typename EdDSA<IsoEd25519>::PrivateKey priv(rng);
  typename EdDSA<IsoEd25519>::PublicKey pub(priv);

  priv.serialize_into(d_seckey);
  pub.serialize_into(d_pubkey);
}

int DecafED25519DNSCryptoKeyEngine::getBits() const
{
  return DECAF_EDDSA_25519_PRIVATE_BYTES << 3;
}

DNSCryptoKeyEngine::storvector_t DecafED25519DNSCryptoKeyEngine::convertToISCVector() const
{
  /*
    Private-key-format: v1.2
    Algorithm: 15 (ED25519)
    PrivateKey: ODIyNjAzODQ2MjgwODAxMjI2NDUxOTAyMDQxNDIyNjI=
  */

  storvector_t storvector;

  storvector.push_back(make_pair("Algorithm", "15 (ED25519)"));
  storvector.push_back(make_pair("PrivateKey", string((char*)d_seckey, DECAF_EDDSA_25519_PRIVATE_BYTES)));

  return storvector;
}

void DecafED25519DNSCryptoKeyEngine::fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap)
{
  /*
    Private-key-format: v1.2
    Algorithm: 15 (ED25519)
    PrivateKey: ODIyNjAzODQ2MjgwODAxMjI2NDUxOTAyMDQxNDIyNjI=
  */

  drc.d_algorithm = pdns_stou(stormap["algorithm"]);
  string privateKey = stormap["privatekey"];

  if (privateKey.length() != DECAF_EDDSA_25519_PRIVATE_BYTES)
    throw runtime_error("Private key size mismatch in ISCMap, DecafED25519 class");

  typename EdDSA<IsoEd25519>::PrivateKey priv(Block((const unsigned char*)privateKey.c_str(), DECAF_EDDSA_25519_PRIVATE_BYTES));
  typename EdDSA<IsoEd25519>::PublicKey pub(priv);

  priv.serialize_into(d_seckey);
  pub.serialize_into(d_pubkey);
}

std::string DecafED25519DNSCryptoKeyEngine::getPubKeyHash() const
{
  return this->getPublicKeyString();
}

std::string DecafED25519DNSCryptoKeyEngine::getPublicKeyString() const
{
  return string((char*)d_pubkey, DECAF_EDDSA_25519_PUBLIC_BYTES);
}

void DecafED25519DNSCryptoKeyEngine::fromPublicKeyString(const std::string& input)
{
  if (input.length() != DECAF_EDDSA_25519_PUBLIC_BYTES)
    throw runtime_error("Public key size mismatch, DecafED25519 class");

  memcpy(d_pubkey, input.c_str(), DECAF_EDDSA_25519_PUBLIC_BYTES);
}

std::string DecafED25519DNSCryptoKeyEngine::sign(const std::string& msg) const
{
  typename EdDSA<IsoEd25519>::PrivateKey priv(Block(d_seckey, DECAF_EDDSA_25519_PRIVATE_BYTES));

  SecureBuffer message(msg.begin(), msg.end());

  SecureBuffer sig = priv.sign(message);

  return string(sig.begin(), sig.end());
}

bool DecafED25519DNSCryptoKeyEngine::verify(const std::string& msg, const std::string& signature) const
{
  if (signature.length() != DECAF_EDDSA_25519_SIGNATURE_BYTES)
    return false;

  typename EdDSA<IsoEd25519>::PublicKey pub(Block(d_pubkey, DECAF_EDDSA_25519_PUBLIC_BYTES));

  SecureBuffer sig(signature.begin(), signature.end());
  SecureBuffer message(msg.begin(), msg.end());

  try {
    pub.verify(sig, message);
  }
  catch (CryptoException) {
    return false;
  }

  return true;
}

class DecafED448DNSCryptoKeyEngine : public DNSCryptoKeyEngine
{
public:
  explicit DecafED448DNSCryptoKeyEngine(unsigned int algo) :
    DNSCryptoKeyEngine(algo)
  {
  }
  string getName() const override { return "Decaf ED448"; }
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
    return std::make_shared<DecafED448DNSCryptoKeyEngine>(algorithm);
  }

private:
  unsigned char d_pubkey[DECAF_EDDSA_448_PUBLIC_BYTES];
  unsigned char d_seckey[DECAF_EDDSA_448_PRIVATE_BYTES];
};

void DecafED448DNSCryptoKeyEngine::create(unsigned int bits)
{
  if (bits != (unsigned int)getBits()) {
    throw runtime_error("Unsupported key length of " + std::to_string(bits) + " bits requested, DecafED448 class");
  }

  SpongeRng rng("/dev/urandom");

  typename EdDSA<Ed448Goldilocks>::PrivateKey priv(rng);
  typename EdDSA<Ed448Goldilocks>::PublicKey pub(priv);

  priv.serialize_into(d_seckey);
  pub.serialize_into(d_pubkey);
}

int DecafED448DNSCryptoKeyEngine::getBits() const
{
  return DECAF_EDDSA_448_PRIVATE_BYTES << 3;
}

DNSCryptoKeyEngine::storvector_t DecafED448DNSCryptoKeyEngine::convertToISCVector() const
{
  /*
    Private-key-format: v1.2
    Algorithm: 16 (ED448)
    PrivateKey: xZ+5Cgm463xugtkY5B0Jx6erFTXp13rYegst0qRtNsOYnaVpMx0Z/c5EiA9x8wWbDDct/U3FhYWA
  */

  storvector_t storvector;

  storvector.push_back(make_pair("Algorithm", "16 (ED448)"));
  storvector.push_back(make_pair("PrivateKey", string((char*)d_seckey, DECAF_EDDSA_448_PRIVATE_BYTES)));

  return storvector;
}

void DecafED448DNSCryptoKeyEngine::fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap)
{
  /*
    Private-key-format: v1.2
    Algorithm: 16 (ED448)
    PrivateKey: xZ+5Cgm463xugtkY5B0Jx6erFTXp13rYegst0qRtNsOYnaVpMx0Z/c5EiA9x8wWbDDct/U3FhYWA
  */

  drc.d_algorithm = pdns_stou(stormap["algorithm"]);
  string privateKey = stormap["privatekey"];

  if (privateKey.length() != DECAF_EDDSA_448_PRIVATE_BYTES)
    throw runtime_error("Private key size mismatch in ISCMap, DecafED448 class");

  typename EdDSA<Ed448Goldilocks>::PrivateKey priv(Block((const unsigned char*)privateKey.c_str(), DECAF_EDDSA_448_PRIVATE_BYTES));
  typename EdDSA<Ed448Goldilocks>::PublicKey pub(priv);

  priv.serialize_into(d_seckey);
  pub.serialize_into(d_pubkey);
}

std::string DecafED448DNSCryptoKeyEngine::getPubKeyHash() const
{
  return this->getPublicKeyString();
}

std::string DecafED448DNSCryptoKeyEngine::getPublicKeyString() const
{
  return string((char*)d_pubkey, DECAF_EDDSA_448_PUBLIC_BYTES);
}

void DecafED448DNSCryptoKeyEngine::fromPublicKeyString(const std::string& input)
{
  if (input.length() != DECAF_EDDSA_448_PUBLIC_BYTES)
    throw runtime_error("Public key size mismatch, DecafED448 class");

  memcpy(d_pubkey, input.c_str(), DECAF_EDDSA_448_PUBLIC_BYTES);
}

std::string DecafED448DNSCryptoKeyEngine::sign(const std::string& msg) const
{
  typename EdDSA<Ed448Goldilocks>::PrivateKey priv(Block(d_seckey, DECAF_EDDSA_448_PRIVATE_BYTES));

  SecureBuffer message(msg.begin(), msg.end());

  SecureBuffer sig = priv.sign(message);

  return string(sig.begin(), sig.end());
}

bool DecafED448DNSCryptoKeyEngine::verify(const std::string& msg, const std::string& signature) const
{
  if (signature.length() != DECAF_EDDSA_448_SIGNATURE_BYTES)
    return false;

  typename EdDSA<Ed448Goldilocks>::PublicKey pub(Block(d_pubkey, DECAF_EDDSA_448_PUBLIC_BYTES));

  SecureBuffer sig(signature.begin(), signature.end());
  SecureBuffer message(msg.begin(), msg.end());

  try {
    pub.verify(sig, message);
  }
  catch (CryptoException) {
    return false;
  }

  return true;
}

namespace
{
struct LoaderDecafStruct
{
  LoaderDecafStruct()
  {
    DNSCryptoKeyEngine::report(15, &DecafED25519DNSCryptoKeyEngine::maker, true);
    DNSCryptoKeyEngine::report(16, &DecafED448DNSCryptoKeyEngine::maker);
  }
} loaderdecaf;
}
