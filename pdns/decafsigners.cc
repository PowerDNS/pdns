#include <openssl/err.h>
#include <openssl/pem.h>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <decaf.hxx>
#include <decaf/eddsa.hxx>
#include <decaf/spongerng.hxx>
#include "dnsseckeeper.hh"

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

#if defined(HAVE_LIBCRYPTO_ED25519)
  /**
   * \brief Creates an ED25519 key engine from a PEM file.
   *
   * Receives an open file handle with PEM contents and creates an ED25519 key engine.
   *
   * \param[in] drc Key record contents to be populated.
   *
   * \param[in] inputFile An open file handle to a file containing ED25519 PEM contents.
   *
   * \param[in] filename Only used for providing filename information in error messages.
   *
   * \return An ED25519 key engine populated with the contents of the PEM file.
   */
  void createFromPEMFile(DNSKEYRecordContent& drc, std::FILE& inputFile, std::optional<std::reference_wrapper<const std::string>> filename = std::nullopt) override;

  /**
   * \brief Writes this key's contents to a file.
   *
   * Receives an open file handle and writes this key's contents to the
   * file.
   *
   * \param[in] outputFile An open file handle for writing.
   *
   * \exception std::runtime_error In case of OpenSSL errors.
   */
  void convertToPEMFile(std::FILE& outputFile) const override;
#endif

  [[nodiscard]] storvector_t convertToISCVector() const override;
  [[nodiscard]] std::string sign(const std::string& msg) const override;
  [[nodiscard]] bool verify(const std::string& msg, const std::string& signature) const override;
  [[nodiscard]] std::string getPublicKeyString() const override;
  [[nodiscard]] int getBits() const override;
  void fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap) override;
  void fromPublicKeyString(const std::string& content) override;

  static std::unique_ptr<DNSCryptoKeyEngine> maker(unsigned int algorithm)
  {
    return make_unique<DecafED25519DNSCryptoKeyEngine>(algorithm);
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

#if defined(HAVE_LIBCRYPTO_ED25519)
void DecafED25519DNSCryptoKeyEngine::createFromPEMFile(DNSKEYRecordContent& drc, std::FILE& inputFile, std::optional<std::reference_wrapper<const std::string>> filename)
{
  drc.d_algorithm = d_algorithm;
  auto key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(PEM_read_PrivateKey(&inputFile, nullptr, nullptr, nullptr), &EVP_PKEY_free);
  if (key == nullptr) {
    if (filename.has_value()) {
      throw runtime_error(getName() + ": Failed to read private key from PEM file `" + filename->get() + "`");
    }

    throw runtime_error(getName() + ": Failed to read private key from PEM contents");
  }

  std::size_t keylen = DECAF_EDDSA_25519_PRIVATE_BYTES;
  int ret = EVP_PKEY_get_raw_private_key(key.get(), d_seckey, &keylen);
  if (ret == 0) {
    if (filename.has_value()) {
      throw runtime_error(getName() + ": Failed to get private key from PEM file contents `" + filename->get() + "`");
    }

    throw runtime_error(getName() + ": Failed to get private key from PEM contents");
  }

  keylen = DECAF_EDDSA_25519_PUBLIC_BYTES;
  ret = EVP_PKEY_get_raw_public_key(key.get(), d_pubkey, &keylen);
  if (ret == 0) {
    if (filename.has_value()) {
      throw runtime_error(getName() + ": Failed to get public key from PEM file contents `" + filename->get() + "`");
    }

    throw runtime_error(getName() + ": Failed to get public key from PEM contents");
  }
}

void DecafED25519DNSCryptoKeyEngine::convertToPEMFile(std::FILE& outputFile) const
{
  auto key = std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY*)>(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, d_seckey, DECAF_EDDSA_25519_PRIVATE_BYTES), EVP_PKEY_free);
  if (key == nullptr) {
    throw runtime_error(getName() + ": Could not create private key from buffer");
  }

  auto ret = PEM_write_PrivateKey(&outputFile, key.get(), nullptr, nullptr, 0, nullptr, nullptr);
  if (ret == 0) {
    throw runtime_error(getName() + ": Could not convert private key to PEM");
  }
}
#endif

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

  auto storvector = storvector_t{
    {"Algorithm", "15 (ED25519)"},
    {"PrivateKey", string((char*)d_seckey, DECAF_EDDSA_25519_PRIVATE_BYTES)},
  };

  return storvector;
}

void DecafED25519DNSCryptoKeyEngine::fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap)
{
  /*
    Private-key-format: v1.2
    Algorithm: 15 (ED25519)
    PrivateKey: ODIyNjAzODQ2MjgwODAxMjI2NDUxOTAyMDQxNDIyNjI=
  */

  pdns::checked_stoi_into(drc.d_algorithm, stormap["algorithm"]);
  string privateKey = stormap["privatekey"];

  if (privateKey.length() != DECAF_EDDSA_25519_PRIVATE_BYTES)
    throw runtime_error("Private key size mismatch in ISCMap, DecafED25519 class");

  typename EdDSA<IsoEd25519>::PrivateKey priv(Block((const unsigned char*)privateKey.c_str(), DECAF_EDDSA_25519_PRIVATE_BYTES));
  typename EdDSA<IsoEd25519>::PublicKey pub(priv);

  priv.serialize_into(d_seckey);
  pub.serialize_into(d_pubkey);
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
  catch (const CryptoException& e) {
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

#if defined(HAVE_LIBCRYPTO_ED448)
  /**
   * \brief Creates an ED448 key engine from a PEM file.
   *
   * Receives an open file handle with PEM contents and creates an ED448 key engine.
   *
   * \param[in] drc Key record contents to be populated.
   *
   * \param[in] inputFile An open file handle to a file containing ED448 PEM contents.
   *
   * \param[in] filename Only used for providing filename information in error messages.
   *
   * \return An ED448 key engine populated with the contents of the PEM file.
   */
  void createFromPEMFile(DNSKEYRecordContent& drc, std::FILE& inputFile, std::optional<std::reference_wrapper<const std::string>> filename = std::nullopt) override;

  /**
   * \brief Writes this key's contents to a file.
   *
   * Receives an open file handle and writes this key's contents to the
   * file.
   *
   * \param[in] outputFile An open file handle for writing.
   *
   * \exception std::runtime_error In case of OpenSSL errors.
   */
  void convertToPEMFile(std::FILE& outputFile) const override;
#endif

  storvector_t convertToISCVector() const override;
  std::string sign(const std::string& msg) const override;
  bool verify(const std::string& msg, const std::string& signature) const override;
  std::string getPublicKeyString() const override;
  int getBits() const override;
  void fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap) override;
  void fromPublicKeyString(const std::string& content) override;

  static std::unique_ptr<DNSCryptoKeyEngine> maker(unsigned int algorithm)
  {
    return make_unique<DecafED448DNSCryptoKeyEngine>(algorithm);
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

#if defined(HAVE_LIBCRYPTO_ED448)
void DecafED448DNSCryptoKeyEngine::createFromPEMFile(DNSKEYRecordContent& drc, std::FILE& inputFile, std::optional<std::reference_wrapper<const std::string>> filename)
{
  drc.d_algorithm = d_algorithm;
  auto key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(PEM_read_PrivateKey(&inputFile, nullptr, nullptr, nullptr), &EVP_PKEY_free);
  if (key == nullptr) {
    if (filename.has_value()) {
      throw runtime_error(getName() + ": Failed to read private key from PEM file `" + filename->get() + "`");
    }

    throw runtime_error(getName() + ": Failed to read private key from PEM contents");
  }

  std::size_t keylen = DECAF_EDDSA_448_PRIVATE_BYTES;
  int ret = EVP_PKEY_get_raw_private_key(key.get(), d_seckey, &keylen);
  if (ret == 0) {
    if (filename.has_value()) {
      throw runtime_error(getName() + ": Failed to get private key from PEM file contents `" + filename->get() + "`");
    }

    throw runtime_error(getName() + ": Failed to get private key from PEM contents");
  }

  keylen = DECAF_EDDSA_448_PUBLIC_BYTES;
  ret = EVP_PKEY_get_raw_public_key(key.get(), d_pubkey, &keylen);
  if (ret == 0) {
    if (filename.has_value()) {
      throw runtime_error(getName() + ": Failed to get public key from PEM file contents `" + filename->get() + "`");
    }

    throw runtime_error(getName() + ": Failed to get public key from PEM contents");
  }
}

void DecafED448DNSCryptoKeyEngine::convertToPEMFile(std::FILE& outputFile) const
{
  auto key = std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY*)>(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED448, nullptr, d_seckey, DECAF_EDDSA_448_PRIVATE_BYTES), EVP_PKEY_free);
  if (key == nullptr) {
    throw runtime_error(getName() + ": Could not create private key from buffer");
  }

  auto ret = PEM_write_PrivateKey(&outputFile, key.get(), nullptr, nullptr, 0, nullptr, nullptr);
  if (ret == 0) {
    throw runtime_error(getName() + ": Could not convert private key to PEM");
  }
}
#endif

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

  auto storvector = storvector_t{
    {"Algorithm", "16 (ED448)"},
    {"PrivateKey", string((char*)d_seckey, DECAF_EDDSA_448_PRIVATE_BYTES)},
  };

  return storvector;
}

void DecafED448DNSCryptoKeyEngine::fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap)
{
  /*
    Private-key-format: v1.2
    Algorithm: 16 (ED448)
    PrivateKey: xZ+5Cgm463xugtkY5B0Jx6erFTXp13rYegst0qRtNsOYnaVpMx0Z/c5EiA9x8wWbDDct/U3FhYWA
  */

  pdns::checked_stoi_into(drc.d_algorithm, stormap["algorithm"]);
  string privateKey = stormap["privatekey"];

  if (privateKey.length() != DECAF_EDDSA_448_PRIVATE_BYTES)
    throw runtime_error("Private key size mismatch in ISCMap, DecafED448 class");

  typename EdDSA<Ed448Goldilocks>::PrivateKey priv(Block((const unsigned char*)privateKey.c_str(), DECAF_EDDSA_448_PRIVATE_BYTES));
  typename EdDSA<Ed448Goldilocks>::PublicKey pub(priv);

  priv.serialize_into(d_seckey);
  pub.serialize_into(d_pubkey);
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
  catch (const CryptoException& e) {
    return false;
  }

  return true;
}

namespace
{
const struct LoaderDecafStruct
{
  LoaderDecafStruct()
  {
    DNSCryptoKeyEngine::report(DNSSECKeeper::ED25519, &DecafED25519DNSCryptoKeyEngine::maker, true);
    DNSCryptoKeyEngine::report(DNSSECKeeper::ED448, &DecafED448DNSCryptoKeyEngine::maker);
  }
} loaderdecaf;
}
