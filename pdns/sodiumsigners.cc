#include <openssl/evp.h>
#include <openssl/pem.h>
extern "C"
{
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <sodium.h>
}
#include "dnssecinfra.hh"
#include "dnsseckeeper.hh"

class SodiumED25519DNSCryptoKeyEngine : public DNSCryptoKeyEngine
{
public:
  explicit SodiumED25519DNSCryptoKeyEngine(unsigned int algo) :
    DNSCryptoKeyEngine(algo)
  {}
  string getName() const override { return "Sodium ED25519"; }
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
    return make_unique<SodiumED25519DNSCryptoKeyEngine>(algorithm);
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

#if defined(HAVE_LIBCRYPTO_ED25519)
void SodiumED25519DNSCryptoKeyEngine::createFromPEMFile(DNSKEYRecordContent& drc, std::FILE& inputFile, std::optional<std::reference_wrapper<const std::string>> filename)
{
  drc.d_algorithm = d_algorithm;
  auto key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(PEM_read_PrivateKey(&inputFile, nullptr, nullptr, nullptr), &EVP_PKEY_free);
  if (key == nullptr) {
    if (filename.has_value()) {
      throw runtime_error(getName() + ": Failed to read private key from PEM file `" + filename->get() + "`");
    }

    throw runtime_error(getName() + ": Failed to read private key from PEM contents");
  }

  // The secret key is 64 bytes according to libsodium. But OpenSSL returns 32 in
  // secKeyLen. Perhaps secret key means private key + public key in libsodium terms.
  std::size_t secKeyLen = crypto_sign_ed25519_SECRETKEYBYTES;
  int ret = EVP_PKEY_get_raw_private_key(key.get(), d_seckey, &secKeyLen);
  if (ret == 0) {
    if (filename.has_value()) {
      throw runtime_error(getName() + ": Failed to get private key from PEM file contents `" + filename->get() + "`");
    }

    throw runtime_error(getName() + ": Failed to get private key from PEM contents");
  }

  std::size_t pubKeyLen = crypto_sign_ed25519_PUBLICKEYBYTES;
  ret = EVP_PKEY_get_raw_public_key(key.get(), d_pubkey, &pubKeyLen);
  if (ret == 0) {
    if (filename.has_value()) {
      throw runtime_error(getName() + ": Failed to get public key from PEM file contents `" + filename->get() + "`");
    }

    throw runtime_error(getName() + ": Failed to get public key from PEM contents");
  }

  // It looks like libsodium expects the public key to be appended to the private key,
  // creating the "secret key" mentioned above.
  memcpy(d_seckey + secKeyLen, d_pubkey, pubKeyLen);
}

void SodiumED25519DNSCryptoKeyEngine::convertToPEMFile(std::FILE& outputFile) const
{
  auto key = std::unique_ptr<EVP_PKEY, void (*)(EVP_PKEY*)>(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, d_seckey, crypto_sign_ed25519_SEEDBYTES), EVP_PKEY_free);
  if (key == nullptr) {
    throw runtime_error(getName() + ": Could not create private key from buffer");
  }

  auto ret = PEM_write_PrivateKey(&outputFile, key.get(), nullptr, nullptr, 0, nullptr, nullptr);
  if (ret == 0) {
    throw runtime_error(getName() + ": Could not convert private key to PEM");
  }
}
#endif

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

  storvector.emplace_back("Algorithm", algorithm);

  storvector.emplace_back("PrivateKey", string((char*)d_seckey, crypto_sign_ed25519_SEEDBYTES));
  return storvector;
}

void SodiumED25519DNSCryptoKeyEngine::fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap)
{
  /*
    Private-key-format: v1.2
    Algorithm: 15 (ED25519)
    PrivateKey: GU6SnQ/Ou+xC5RumuIUIuJZteXT2z0O/ok1s38Et6mQ=
  */

  pdns::checked_stoi_into(drc.d_algorithm, stormap["algorithm"]);
  string privateKey = stormap["privatekey"];

  if (privateKey.length() != crypto_sign_ed25519_SEEDBYTES)
    throw runtime_error("Seed size mismatch in ISCMap, SodiumED25519 class");

  auto seed = std::make_unique<unsigned char[]>(crypto_sign_ed25519_SEEDBYTES);

  memcpy(seed.get(), privateKey.c_str(), crypto_sign_ed25519_SEEDBYTES);
  crypto_sign_ed25519_seed_keypair(d_pubkey, d_seckey, seed.get());
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
  unsigned char signature[crypto_sign_ed25519_BYTES];

  // https://doc.libsodium.org/public-key_cryptography/public-key_signatures#detached-mode:
  // It is safe to ignore siglen and always consider a signature as crypto_sign_BYTES
  // bytes long; shorter signatures will be transparently padded with zeros if necessary.
  crypto_sign_ed25519_detached(signature, nullptr, (const unsigned char*)msg.c_str(), msg.length(), d_seckey);

  return {(const char*)signature, crypto_sign_ed25519_BYTES};
}

bool SodiumED25519DNSCryptoKeyEngine::verify(const std::string& msg, const std::string& signature) const
{
  if (signature.length() != crypto_sign_ed25519_BYTES) {
    return false;
  }

  return crypto_sign_ed25519_verify_detached((const unsigned char*)signature.c_str(), (const unsigned char*)msg.c_str(), msg.length(), d_pubkey) == 0;
}

namespace
{
const struct LoaderSodiumStruct
{
  LoaderSodiumStruct()
  {
    DNSCryptoKeyEngine::report(DNSSECKeeper::ED25519, &SodiumED25519DNSCryptoKeyEngine::maker);
  }
} loadersodium;
}
