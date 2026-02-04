/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#include "misc.hh"
#include <memory>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <optional>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <openssl/obj_mac.h>
#ifdef HAVE_LIBCRYPTO_ECDSA
#include <openssl/ecdsa.h>
#endif
#if defined(HAVE_LIBCRYPTO_ED25519) || defined(HAVE_LIBCRYPTO_ED448)
#include <openssl/evp.h>
#endif
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#if OPENSSL_VERSION_MAJOR >= 3
#include <openssl/types.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#endif
#include <openssl/opensslv.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include "opensslsigners.hh"
#include "dnssecinfra.hh"
#include "dnsseckeeper.hh"

#if (OPENSSL_VERSION_NUMBER < 0x1010000fL || (defined LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x2090100fL)
/* OpenSSL < 1.1.0 needs support for threading/locking in the calling application. */

#include "lock.hh"
static std::vector<std::mutex> openssllocks;

extern "C"
{
  static void openssl_pthreads_locking_callback(int mode, int type, const char* file, int line)
  {
    if (mode & CRYPTO_LOCK) {
      openssllocks.at(type).lock();
    }
    else {
      openssllocks.at(type).unlock();
    }
  }

  static unsigned long openssl_pthreads_id_callback(void)
  {
    return (unsigned long)pthread_self();
  }
}

void openssl_thread_setup()
{
  openssllocks = std::vector<std::mutex>(CRYPTO_num_locks());
  CRYPTO_set_id_callback(&openssl_pthreads_id_callback);
  CRYPTO_set_locking_callback(&openssl_pthreads_locking_callback);
}

void openssl_thread_cleanup()
{
  CRYPTO_set_locking_callback(nullptr);
  openssllocks.clear();
}

#ifndef HAVE_RSA_GET0_KEY
/* those symbols are defined in LibreSSL 2.7.0+ */
/* compat helpers. These DO NOT do any of the checking that the libssl 1.1 functions do. */
static inline void RSA_get0_key(const RSA* rsakey, const BIGNUM** n, const BIGNUM** e, const BIGNUM** d)
{
  *n = rsakey->n;
  *e = rsakey->e;
  *d = rsakey->d;
}

static inline int RSA_set0_key(RSA* rsakey, BIGNUM* n, BIGNUM* e, BIGNUM* d)
{
  if (n) {
    BN_clear_free(rsakey->n);
    rsakey->n = n;
  }
  if (e) {
    BN_clear_free(rsakey->e);
    rsakey->e = e;
  }
  if (d) {
    BN_clear_free(rsakey->d);
    rsakey->d = d;
  }
  return 1;
}

static inline void RSA_get0_factors(const RSA* rsakey, const BIGNUM** p, const BIGNUM** q)
{
  *p = rsakey->p;
  *q = rsakey->q;
}

static inline int RSA_set0_factors(RSA* rsakey, BIGNUM* p, BIGNUM* q)
{
  BN_clear_free(rsakey->p);
  rsakey->p = p;
  BN_clear_free(rsakey->q);
  rsakey->q = q;
  return 1;
}

static inline void RSA_get0_crt_params(const RSA* rsakey, const BIGNUM** dmp1, const BIGNUM** dmq1, const BIGNUM** iqmp)
{
  *dmp1 = rsakey->dmp1;
  *dmq1 = rsakey->dmq1;
  *iqmp = rsakey->iqmp;
}

static inline int RSA_set0_crt_params(RSA* rsakey, BIGNUM* dmp1, BIGNUM* dmq1, BIGNUM* iqmp)
{
  BN_clear_free(rsakey->dmp1);
  rsakey->dmp1 = dmp1;
  BN_clear_free(rsakey->dmq1);
  rsakey->dmq1 = dmq1;
  BN_clear_free(rsakey->iqmp);
  rsakey->iqmp = iqmp;
  return 1;
}

#ifdef HAVE_LIBCRYPTO_ECDSA
static inline void ECDSA_SIG_get0(const ECDSA_SIG* signature, const BIGNUM** pr, const BIGNUM** ps)
{
  *pr = signature->r;
  *ps = signature->s;
}

static inline int ECDSA_SIG_set0(ECDSA_SIG* signature, BIGNUM* pr, BIGNUM* ps)
{
  BN_clear_free(signature->r);
  BN_clear_free(signature->s);
  signature->r = pr;
  signature->s = ps;
  return 1;
}
#endif /* HAVE_LIBCRYPTO_ECDSA */

#endif /* HAVE_RSA_GET0_KEY */

#else
void openssl_thread_setup() {}
void openssl_thread_cleanup() {}
#endif

/* seeding PRNG */
void openssl_seed()
{
  std::string entropy;
  entropy.reserve(1024);

  unsigned int r;
  for (int i = 0; i < 1024; i += 4) {
    r = dns_random_uint32();
    entropy.append((const char*)&r, 4);
  }

  RAND_seed((const unsigned char*)entropy.c_str(), 1024);
}

using BigNum = unique_ptr<BIGNUM, decltype(&BN_clear_free)>;

static auto mapToBN(const std::string& componentName, const std::map<std::string, std::string>& stormap, const std::string& key) -> BigNum
{
  const std::string& value = stormap.at(key);

  // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
  const auto* valueCStr = reinterpret_cast<const unsigned char*>(value.c_str());
  auto number = BigNum{BN_bin2bn(valueCStr, static_cast<int>(value.length()), nullptr), BN_clear_free};
  if (number == nullptr) {
    throw pdns::OpenSSL::error(componentName, "Failed to parse key `" + key + "`");
  }

  return number;
}

class OpenSSLRSADNSCryptoKeyEngine : public DNSCryptoKeyEngine
{
public:
  explicit OpenSSLRSADNSCryptoKeyEngine(unsigned int algo);

  [[nodiscard]] string getName() const override { return "OpenSSL RSA"; }
  [[nodiscard]] int getBits() const override;
  void create(unsigned int bits) override;

  /**
   * \brief Creates an RSA key engine from a PEM file.
   *
   * Receives an open file handle with PEM contents and creates an RSA key engine.
   *
   * \param[in] drc Key record contents to be populated.
   *
   * \param[in] inputFile An open file handle to a file containing RSA PEM contents.
   *
   * \param[in] filename Only used for providing filename information in error messages.
   *
   * \return An RSA key engine populated with the contents of the PEM file.
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

  [[nodiscard]] storvector_t convertToISCVector() const override;

  // TODO Fred: hash() can probably be completely removed. See #12464.
  [[nodiscard]] std::string hash(const std::string& message) const override;
  [[nodiscard]] std::string sign(const std::string& message) const override;
  [[nodiscard]] bool verify(const std::string& message, const std::string& signature) const override;
  [[nodiscard]] std::string getPublicKeyString() const override;

  void fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap) override;
  void fromPublicKeyString(const std::string& content) override;
  [[nodiscard]] bool checkKey(std::optional<std::reference_wrapper<std::vector<std::string>>> errorMessages) const override;

  static std::unique_ptr<DNSCryptoKeyEngine> maker(unsigned int algorithm)
  {
    return make_unique<OpenSSLRSADNSCryptoKeyEngine>(algorithm);
  }

private:
#if OPENSSL_VERSION_MAJOR >= 3
  [[nodiscard]] BigNum getKeyParamModulus() const;
  [[nodiscard]] BigNum getKeyParamPublicExponent() const;
  [[nodiscard]] BigNum getKeyParamPrivateExponent() const;
  [[nodiscard]] BigNum getKeyParamPrime1() const;
  [[nodiscard]] BigNum getKeyParamPrime2() const;
  [[nodiscard]] BigNum getKeyParamDmp1() const;
  [[nodiscard]] BigNum getKeyParamDmq1() const;
  [[nodiscard]] BigNum getKeyParamIqmp() const;

  using Params = std::unique_ptr<OSSL_PARAM, decltype(&OSSL_PARAM_free)>;
  auto makeKeyParams(const BIGNUM* modulus, const BIGNUM* publicExponent, const BIGNUM* privateExponent, const BIGNUM* prime1, const BIGNUM* prime2, const BIGNUM* dmp1, const BIGNUM* dmq1, const BIGNUM* iqmp) const -> Params;
#endif

  // TODO Fred: hashSize(), hasher() and hashSizeToKind() can probably be completely
  // removed along with hash(). See #12464.
  [[nodiscard]] std::size_t hashSize() const;
  [[nodiscard]] const EVP_MD* hasher() const;
  static int hashSizeToKind(size_t hashSize);

#if OPENSSL_VERSION_MAJOR >= 3
  using KeyContext = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
  using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
  using MessageDigestContext = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
  using ParamsBuilder = std::unique_ptr<OSSL_PARAM_BLD, decltype(&OSSL_PARAM_BLD_free)>;
  using MessageDigest = std::unique_ptr<EVP_MD, decltype(&EVP_MD_free)>;
#else
  using Key = std::unique_ptr<RSA, decltype(&RSA_free)>;
#endif

  Key d_key;
};

OpenSSLRSADNSCryptoKeyEngine::OpenSSLRSADNSCryptoKeyEngine(unsigned int algo) :
  DNSCryptoKeyEngine(algo),
#if OPENSSL_VERSION_MAJOR >= 3
  d_key(Key(nullptr, EVP_PKEY_free))
#else
  d_key(Key(nullptr, RSA_free))
#endif
{
  int ret = RAND_status();
  if (ret != 1) {
    throw runtime_error(getName() + " insufficient entropy");
  }
}

int OpenSSLRSADNSCryptoKeyEngine::getBits() const
{
#if OPENSSL_VERSION_MAJOR >= 3
  return EVP_PKEY_get_bits(d_key.get());
#else
  return RSA_size(d_key.get()) << 3;
#endif
}

void OpenSSLRSADNSCryptoKeyEngine::create(unsigned int bits)
{
  // When changing the bitsizes, also edit them in ::checkKey
  if ((d_algorithm == DNSSECKeeper::RSASHA1 || d_algorithm == DNSSECKeeper::RSASHA1NSEC3SHA1) && (bits < 512 || bits > 4096)) {
    /* RFC3110 */
    throw runtime_error(getName() + " RSASHA1 key generation failed for invalid bits size " + std::to_string(bits));
  }
  if (d_algorithm == DNSSECKeeper::RSASHA256 && (bits < 512 || bits > 4096)) {
    /* RFC5702 */
    throw runtime_error(getName() + " RSASHA256 key generation failed for invalid bits size " + std::to_string(bits));
  }
  if (d_algorithm == DNSSECKeeper::RSASHA512 && (bits < 1024 || bits > 4096)) {
    /* RFC5702 */
    throw runtime_error(getName() + " RSASHA512 key generation failed for invalid bits size " + std::to_string(bits));
  }

  auto exponent = BigNum(BN_new(), BN_clear_free);
  if (!exponent) {
    throw runtime_error(getName() + " key generation failed, unable to allocate e");
  }

  /* RSA_F4 is a public exponent value of 65537 */
  int res = BN_set_word(exponent.get(), RSA_F4);

  if (res == 0) {
    throw runtime_error(getName() + " key generation failed while setting e");
  }

#if OPENSSL_VERSION_MAJOR >= 3
  auto ctx = KeyContext(EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr), EVP_PKEY_CTX_free);
  if (ctx == nullptr) {
    throw pdns::OpenSSL::error(getName(), "Could not initialize context");
  }

  if (EVP_PKEY_keygen_init(ctx.get()) != 1) {
    throw pdns::OpenSSL::error(getName(), "Could not initialize keygen");
  }

  if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), (int)bits) <= 0) {
    throw pdns::OpenSSL::error(getName(), "Could not set keygen bits to " + std::to_string(bits));
  }

  if (EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx.get(), exponent.get()) <= 0) {
    throw pdns::OpenSSL::error(getName(), "Could not set keygen public exponent");
  }

  EVP_PKEY* key = nullptr;
  if (EVP_PKEY_generate(ctx.get(), &key) != 1) {
    throw pdns::OpenSSL::error(getName(), "Could not generate key");
  }

  d_key.reset(key);
#else
  auto key = Key(RSA_new(), RSA_free);
  if (!key) {
    throw runtime_error(getName() + " allocation of key structure failed");
  }

  res = RSA_generate_key_ex(key.get(), bits, exponent.get(), nullptr);
  if (res == 0) {
    throw runtime_error(getName() + " key generation failed");
  }

  d_key = std::move(key);
#endif
}

void OpenSSLRSADNSCryptoKeyEngine::createFromPEMFile(DNSKEYRecordContent& drc, std::FILE& inputFile, const std::optional<std::reference_wrapper<const std::string>> filename)
{
  drc.d_algorithm = d_algorithm;

#if OPENSSL_VERSION_MAJOR >= 3
  EVP_PKEY* key = nullptr;
  if (PEM_read_PrivateKey(&inputFile, &key, nullptr, nullptr) == nullptr) {
    if (filename.has_value()) {
      throw pdns::OpenSSL::error(getName(), "Could not read private key from PEM file `" + filename->get() + "`");
    }

    throw pdns::OpenSSL::error(getName(), "Could not read private key from PEM contents");
  }

  d_key.reset(key);
#else
  d_key = Key(PEM_read_RSAPrivateKey(&inputFile, nullptr, nullptr, nullptr), &RSA_free);
  if (d_key == nullptr) {
    if (filename.has_value()) {
      throw runtime_error(getName() + ": Failed to read private key from PEM file `" + filename->get() + "`");
    }

    throw runtime_error(getName() + ": Failed to read private key from PEM contents");
  }
#endif
}

void OpenSSLRSADNSCryptoKeyEngine::convertToPEMFile(std::FILE& outputFile) const
{
#if OPENSSL_VERSION_MAJOR >= 3
  if (PEM_write_PrivateKey(&outputFile, d_key.get(), nullptr, nullptr, 0, nullptr, nullptr) == 0) {
    throw pdns::OpenSSL::error(getName(), "Could not convert private key to PEM");
  }
#else
  auto ret = PEM_write_RSAPrivateKey(&outputFile, d_key.get(), nullptr, nullptr, 0, nullptr, nullptr);
  if (ret == 0) {
    throw runtime_error(getName() + ": Could not convert private key to PEM");
  }
#endif
}

#if OPENSSL_VERSION_MAJOR >= 3
BigNum OpenSSLRSADNSCryptoKeyEngine::getKeyParamModulus() const
{
  BIGNUM* modulus = nullptr;
  if (EVP_PKEY_get_bn_param(d_key.get(), OSSL_PKEY_PARAM_RSA_N, &modulus) == 0) {
    throw pdns::OpenSSL::error(getName(), "Could not get key's modulus (n) parameter");
  }
  return BigNum{modulus, BN_clear_free};
}

BigNum OpenSSLRSADNSCryptoKeyEngine::getKeyParamPublicExponent() const
{
  BIGNUM* publicExponent = nullptr;
  if (EVP_PKEY_get_bn_param(d_key.get(), OSSL_PKEY_PARAM_RSA_E, &publicExponent) == 0) {
    throw pdns::OpenSSL::error(getName(), "Could not get key's public exponent (e) parameter");
  }
  return BigNum{publicExponent, BN_clear_free};
}

BigNum OpenSSLRSADNSCryptoKeyEngine::getKeyParamPrivateExponent() const
{
  BIGNUM* privateExponent = nullptr;
  if (EVP_PKEY_get_bn_param(d_key.get(), OSSL_PKEY_PARAM_RSA_D, &privateExponent) == 0) {
    throw pdns::OpenSSL::error(getName(), "Could not get key's private exponent (d) parameter");
  }
  return BigNum{privateExponent, BN_clear_free};
}

BigNum OpenSSLRSADNSCryptoKeyEngine::getKeyParamPrime1() const
{
  BIGNUM* prime1 = nullptr;
  if (EVP_PKEY_get_bn_param(d_key.get(), OSSL_PKEY_PARAM_RSA_FACTOR1, &prime1) == 0) {
    throw pdns::OpenSSL::error(getName(), "Could not get key's first prime (p) parameter");
  }
  return BigNum{prime1, BN_clear_free};
}

BigNum OpenSSLRSADNSCryptoKeyEngine::getKeyParamPrime2() const
{
  BIGNUM* prime2 = nullptr;
  if (EVP_PKEY_get_bn_param(d_key.get(), OSSL_PKEY_PARAM_RSA_FACTOR2, &prime2) == 0) {
    throw pdns::OpenSSL::error(getName(), "Could not get key's second prime (q) parameter");
  }
  return BigNum{prime2, BN_clear_free};
}

BigNum OpenSSLRSADNSCryptoKeyEngine::getKeyParamDmp1() const
{
  BIGNUM* dmp1 = nullptr;
  if (EVP_PKEY_get_bn_param(d_key.get(), OSSL_PKEY_PARAM_RSA_EXPONENT1, &dmp1) == 0) {
    throw pdns::OpenSSL::error(getName(), "Could not get key's first exponent parameter");
  }
  return BigNum{dmp1, BN_clear_free};
}

BigNum OpenSSLRSADNSCryptoKeyEngine::getKeyParamDmq1() const
{
  BIGNUM* dmq1 = nullptr;
  if (EVP_PKEY_get_bn_param(d_key.get(), OSSL_PKEY_PARAM_RSA_EXPONENT2, &dmq1) == 0) {
    throw pdns::OpenSSL::error(getName(), "Could not get key's second exponent parameter");
  }
  return BigNum{dmq1, BN_clear_free};
}

BigNum OpenSSLRSADNSCryptoKeyEngine::getKeyParamIqmp() const
{
  BIGNUM* iqmp = nullptr;
  if (EVP_PKEY_get_bn_param(d_key.get(), OSSL_PKEY_PARAM_RSA_COEFFICIENT1, &iqmp) == 0) {
    throw pdns::OpenSSL::error(getName(), "Could not get key's first coefficient parameter");
  }
  return BigNum{iqmp, BN_clear_free};
}
#endif

#if OPENSSL_VERSION_MAJOR >= 3
auto OpenSSLRSADNSCryptoKeyEngine::makeKeyParams(const BIGNUM* modulus, const BIGNUM* publicExponent, const BIGNUM* privateExponent, const BIGNUM* prime1, const BIGNUM* prime2, const BIGNUM* dmp1, const BIGNUM* dmq1, const BIGNUM* iqmp) const -> Params
{
  auto params_build = ParamsBuilder(OSSL_PARAM_BLD_new(), OSSL_PARAM_BLD_free);
  if (params_build == nullptr) {
    throw pdns::OpenSSL::error(getName(), "Could not create key's parameters builder");
  }

  if ((modulus != nullptr) && OSSL_PARAM_BLD_push_BN(params_build.get(), OSSL_PKEY_PARAM_RSA_N, modulus) == 0) {
    throw pdns::OpenSSL::error(getName(), "Could not create key's modulus parameter");
  }

  if ((publicExponent != nullptr) && OSSL_PARAM_BLD_push_BN(params_build.get(), OSSL_PKEY_PARAM_RSA_E, publicExponent) == 0) {
    throw pdns::OpenSSL::error(getName(), "Could not create key's public exponent parameter");
  }

  if ((privateExponent != nullptr) && OSSL_PARAM_BLD_push_BN(params_build.get(), OSSL_PKEY_PARAM_RSA_D, privateExponent) == 0) {
    throw pdns::OpenSSL::error(getName(), "Could not create key's private exponent parameter");
  }

  if ((prime1 != nullptr) && OSSL_PARAM_BLD_push_BN(params_build.get(), OSSL_PKEY_PARAM_RSA_FACTOR1, prime1) == 0) {
    throw pdns::OpenSSL::error(getName(), "Could not create key's first prime parameter");
  }

  if ((prime2 != nullptr) && OSSL_PARAM_BLD_push_BN(params_build.get(), OSSL_PKEY_PARAM_RSA_FACTOR2, prime2) == 0) {
    throw pdns::OpenSSL::error(getName(), "Could not create key's second prime parameter");
  }

  if ((dmp1 != nullptr) && OSSL_PARAM_BLD_push_BN(params_build.get(), OSSL_PKEY_PARAM_RSA_EXPONENT1, dmp1) == 0) {
    throw pdns::OpenSSL::error(getName(), "Could not create key's first exponent parameter");
  }

  if ((dmq1 != nullptr) && OSSL_PARAM_BLD_push_BN(params_build.get(), OSSL_PKEY_PARAM_RSA_EXPONENT2, dmq1) == 0) {
    throw pdns::OpenSSL::error(getName(), "Could not create key's second exponent parameter");
  }

  if ((iqmp != nullptr) && OSSL_PARAM_BLD_push_BN(params_build.get(), OSSL_PKEY_PARAM_RSA_COEFFICIENT1, iqmp) == 0) {
    throw pdns::OpenSSL::error(getName(), "Could not create key's first coefficient parameter");
  }

  auto params = Params(OSSL_PARAM_BLD_to_param(params_build.get()), OSSL_PARAM_free);
  if (params == nullptr) {
    throw pdns::OpenSSL::error(getName(), "Could not create key's parameters");
  }

  return params;
}
#endif

DNSCryptoKeyEngine::storvector_t OpenSSLRSADNSCryptoKeyEngine::convertToISCVector() const
{
  storvector_t storvect;
  using outputs_t = vector<pair<string, const BIGNUM*>>;
  outputs_t outputs;

#if OPENSSL_VERSION_MAJOR >= 3
  // If any of those calls throw, we correctly free the BIGNUMs allocated before it.
  BigNum modulusPtr = getKeyParamModulus();
  BigNum publicExponentPtr = getKeyParamPublicExponent();
  BigNum privateExponentPtr = getKeyParamPrivateExponent();
  BigNum prime1Ptr = getKeyParamPrime1();
  BigNum prime2Ptr = getKeyParamPrime2();
  BigNum dmp1Ptr = getKeyParamDmp1();
  BigNum dmq1Ptr = getKeyParamDmq1();
  BigNum iqmpPtr = getKeyParamIqmp();

  // All the calls succeeded, we can take references to the BIGNUM pointers.
  BIGNUM* modulus = modulusPtr.get();
  BIGNUM* publicExponent = publicExponentPtr.get();
  BIGNUM* privateExponent = privateExponentPtr.get();
  BIGNUM* prime1 = prime1Ptr.get();
  BIGNUM* prime2 = prime2Ptr.get();
  BIGNUM* dmp1 = dmp1Ptr.get();
  BIGNUM* dmq1 = dmq1Ptr.get();
  BIGNUM* iqmp = iqmpPtr.get();
#else
  const BIGNUM* modulus = nullptr;
  const BIGNUM* publicExponent = nullptr;
  const BIGNUM* privateExponent = nullptr;
  const BIGNUM* prime1 = nullptr;
  const BIGNUM* prime2 = nullptr;
  const BIGNUM* dmp1 = nullptr;
  const BIGNUM* dmq1 = nullptr;
  const BIGNUM* iqmp = nullptr;
  RSA_get0_key(d_key.get(), &modulus, &publicExponent, &privateExponent);
  RSA_get0_factors(d_key.get(), &prime1, &prime2);
  RSA_get0_crt_params(d_key.get(), &dmp1, &dmq1, &iqmp);
#endif

  outputs.emplace_back("Modulus", modulus);
  outputs.emplace_back("PublicExponent", publicExponent);
  outputs.emplace_back("PrivateExponent", privateExponent);
  outputs.emplace_back("Prime1", prime1);
  outputs.emplace_back("Prime2", prime2);
  outputs.emplace_back("Exponent1", dmp1);
  outputs.emplace_back("Exponent2", dmq1);
  outputs.emplace_back("Coefficient", iqmp);

  string algorithm = std::to_string(d_algorithm);
  switch (d_algorithm) {
  case DNSSECKeeper::RSASHA1:
  case DNSSECKeeper::RSASHA1NSEC3SHA1:
    algorithm += " (RSASHA1)";
    break;
  case DNSSECKeeper::RSASHA256:
    algorithm += " (RSASHA256)";
    break;
  case DNSSECKeeper::RSASHA512:
    algorithm += " (RSASHA512)";
    break;
  default:
    algorithm += " (?)";
  }
  storvect.emplace_back("Algorithm", algorithm);

  for (const outputs_t::value_type& value : outputs) {
    std::string tmp;
    tmp.resize(BN_num_bytes(value.second));
    // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
    int len = BN_bn2bin(value.second, reinterpret_cast<unsigned char*>(tmp.data()));
    if (len >= 0) {
      tmp.resize(len);
      storvect.emplace_back(value.first, tmp);
    }
  }

  return storvect;
}

std::size_t OpenSSLRSADNSCryptoKeyEngine::hashSize() const
{
  switch (d_algorithm) {
  case DNSSECKeeper::RSASHA1:
  case DNSSECKeeper::RSASHA1NSEC3SHA1:
    return SHA_DIGEST_LENGTH;
  case DNSSECKeeper::RSASHA256:
    return SHA256_DIGEST_LENGTH;
  case DNSSECKeeper::RSASHA512:
    return SHA512_DIGEST_LENGTH;
  default:
    throw runtime_error(getName() + " does not support hash operations for algorithm " + std::to_string(d_algorithm));
  }
}

const EVP_MD* OpenSSLRSADNSCryptoKeyEngine::hasher() const
{
  const EVP_MD* messageDigest = nullptr;

  switch (d_algorithm) {
  case DNSSECKeeper::RSASHA1:
  case DNSSECKeeper::RSASHA1NSEC3SHA1:
    messageDigest = EVP_sha1();
    break;
  case DNSSECKeeper::RSASHA256:
    messageDigest = EVP_sha256();
    break;
  case DNSSECKeeper::RSASHA512:
    messageDigest = EVP_sha512();
    break;
  default:
    throw runtime_error(getName() + " does not support hash operations for algorithm " + std::to_string(d_algorithm));
  }

  if (messageDigest == nullptr) {
    throw std::runtime_error("Could not retrieve a SHA implementation of size " + std::to_string(hashSize()) + " from OpenSSL");
  }

  return messageDigest;
}

std::string OpenSSLRSADNSCryptoKeyEngine::hash(const std::string& message) const
{
  if (d_algorithm == DNSSECKeeper::RSASHA1 || d_algorithm == DNSSECKeeper::RSASHA1NSEC3SHA1) {
    std::string l_hash{};
    l_hash.resize(SHA_DIGEST_LENGTH);
    // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
    SHA1(reinterpret_cast<unsigned char*>(const_cast<char*>(message.c_str())), message.length(), reinterpret_cast<unsigned char*>(l_hash.data()));
    return l_hash;
  }

  if (d_algorithm == DNSSECKeeper::RSASHA256) {
    std::string l_hash{};
    l_hash.resize(SHA256_DIGEST_LENGTH);
    // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
    SHA256(reinterpret_cast<unsigned char*>(const_cast<char*>(message.c_str())), message.length(), reinterpret_cast<unsigned char*>(l_hash.data()));
    return l_hash;
  }

  if (d_algorithm == DNSSECKeeper::RSASHA512) {
    std::string l_hash{};
    l_hash.resize(SHA512_DIGEST_LENGTH);
    // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
    SHA512(reinterpret_cast<unsigned char*>(const_cast<char*>(message.c_str())), message.length(), reinterpret_cast<unsigned char*>(l_hash.data()));
    return l_hash;
  }

  throw runtime_error(getName() + " does not support hash operation for algorithm " + std::to_string(d_algorithm));
}

int OpenSSLRSADNSCryptoKeyEngine::hashSizeToKind(const size_t hashSize)
{
  switch (hashSize) {
  case SHA_DIGEST_LENGTH:
    return NID_sha1;
  case SHA256_DIGEST_LENGTH:
    return NID_sha256;
  case SHA384_DIGEST_LENGTH:
    return NID_sha384;
  case SHA512_DIGEST_LENGTH:
    return NID_sha512;
  default:
    throw runtime_error("OpenSSL RSA does not handle hash of size " + std::to_string(hashSize));
  }
}

std::string OpenSSLRSADNSCryptoKeyEngine::sign(const std::string& message) const
{
  std::string signature;

#if OPENSSL_VERSION_MAJOR >= 3
  auto ctx = MessageDigestContext(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (ctx == nullptr) {
    throw pdns::OpenSSL::error(getName(), "Could not create context for signing");
  }

  if (EVP_DigestSignInit(ctx.get(), nullptr, hasher(), nullptr, d_key.get()) == 0) {
    throw pdns::OpenSSL::error(getName(), "Could not initialize context for signing");
  }

  std::size_t signatureLen = 0;
  // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
  const auto* messageData = reinterpret_cast<const unsigned char*>(message.data());
  if (EVP_DigestSign(ctx.get(), nullptr, &signatureLen, messageData, message.size()) == 0) {
    throw pdns::OpenSSL::error(getName(), "Could not get message signature length");
  }

  signature.resize(signatureLen);

  // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
  auto* signatureData = reinterpret_cast<unsigned char*>(signature.data());
  if (EVP_DigestSign(ctx.get(), signatureData, &signatureLen, messageData, message.size()) == 0) {
    throw pdns::OpenSSL::error(getName(), "Could not sign message");
  }
#else
  unsigned int signatureLen = 0;
  string l_hash = this->hash(message);
  int hashKind = hashSizeToKind(l_hash.size());
  signature.resize(RSA_size(d_key.get()));

  // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
  int res = RSA_sign(hashKind, reinterpret_cast<unsigned char*>(&l_hash.at(0)), l_hash.length(), reinterpret_cast<unsigned char*>(&signature.at(0)), &signatureLen, d_key.get());
  if (res != 1) {
    throw runtime_error(getName() + " failed to generate signature");
  }

  signature.resize(signatureLen);
#endif

  return signature;
}

bool OpenSSLRSADNSCryptoKeyEngine::verify(const std::string& message, const std::string& signature) const
{
#if OPENSSL_VERSION_MAJOR >= 3
  auto ctx = MessageDigestContext(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (ctx == nullptr) {
    throw pdns::OpenSSL::error(getName(), "Failed to create context for verifying signature");
  }

  if (EVP_DigestVerifyInit(ctx.get(), nullptr, hasher(), nullptr, d_key.get()) == 0) {
    throw pdns::OpenSSL::error(getName(), "Failed to initialize context for verifying signature");
  }

  // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
  const int ret = EVP_DigestVerify(ctx.get(), reinterpret_cast<const unsigned char*>(signature.data()), signature.size(), reinterpret_cast<const unsigned char*>(message.data()), message.size());
  if (ret < 0) {
    throw pdns::OpenSSL::error(getName(), "Failed to verify message signature");
  }

  return (ret == 1);
#else
  string l_hash = this->hash(message);
  int hashKind = hashSizeToKind(l_hash.size());

  int ret = RSA_verify(hashKind, (const unsigned char*)l_hash.c_str(), l_hash.length(), (unsigned char*)signature.c_str(), signature.length(), d_key.get());

  return (ret == 1);
#endif
}

std::string OpenSSLRSADNSCryptoKeyEngine::getPublicKeyString() const
{
#if OPENSSL_VERSION_MAJOR >= 3
  // If any of those calls throw, we correctly free the BIGNUMs allocated before it.
  BigNum modulusPtr = getKeyParamModulus();
  BigNum publicExponentPtr = getKeyParamPublicExponent();

  // All the calls succeeded, we can take references to the BIGNUM pointers.
  BIGNUM* modulus = modulusPtr.get();
  BIGNUM* publicExponent = publicExponentPtr.get();
#else
  const BIGNUM* modulus = nullptr;
  const BIGNUM* publicExponent = nullptr;
  const BIGNUM* privateExponent = nullptr;
  RSA_get0_key(d_key.get(), &modulus, &publicExponent, &privateExponent);
#endif

  string keystring;
  std::string tmp;
  tmp.resize(std::max(BN_num_bytes(publicExponent), BN_num_bytes(modulus)));

  // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
  int len = BN_bn2bin(publicExponent, reinterpret_cast<unsigned char*>(&tmp.at(0)));
  if (len < 255) {
    keystring.assign(1, (char)(unsigned int)len);
  }
  else {
    keystring.assign(1, 0);
    uint16_t tempLen = len;
    tempLen = htons(tempLen);
    keystring.append((char*)&tempLen, 2);
  }
  keystring.append(&tmp.at(0), len);

  // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
  len = BN_bn2bin(modulus, reinterpret_cast<unsigned char*>(&tmp.at(0)));
  keystring.append(&tmp.at(0), len);

  return keystring;
}

void OpenSSLRSADNSCryptoKeyEngine::fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap)
{
  auto modulus = mapToBN(getName(), stormap, "modulus");
  auto publicExponent = mapToBN(getName(), stormap, "publicexponent");
  auto privateExponent = mapToBN(getName(), stormap, "privateexponent");

  auto prime1 = mapToBN(getName(), stormap, "prime1");
  auto prime2 = mapToBN(getName(), stormap, "prime2");

  auto dmp1 = mapToBN(getName(), stormap, "exponent1");
  auto dmq1 = mapToBN(getName(), stormap, "exponent2");
  auto iqmp = mapToBN(getName(), stormap, "coefficient");

  pdns::checked_stoi_into(drc.d_algorithm, stormap["algorithm"]);

  if (drc.d_algorithm != d_algorithm) {
    throw runtime_error(getName() + " tried to feed an algorithm " + std::to_string(drc.d_algorithm) + " to a " + std::to_string(d_algorithm) + " key");
  }

#if OPENSSL_VERSION_MAJOR >= 3
  auto params = makeKeyParams(modulus.get(), publicExponent.get(), privateExponent.get(), prime1.get(), prime2.get(), dmp1.get(), dmq1.get(), iqmp.get());

  auto ctx = KeyContext(EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr), EVP_PKEY_CTX_free);
  if (ctx == nullptr) {
    throw pdns::OpenSSL::error(getName(), "Could not create key context");
  }

  if (EVP_PKEY_fromdata_init(ctx.get()) <= 0) {
    throw pdns::OpenSSL::error(getName(), "Could not initialize key context for loading data from ISC");
  }

  EVP_PKEY* key = nullptr;
  if (EVP_PKEY_fromdata(ctx.get(), &key, EVP_PKEY_KEYPAIR, params.get()) <= 0) {
    throw pdns::OpenSSL::error(getName(), "Could not create key from parameters");
  }

  d_key.reset(key);
#else
  auto key = Key(RSA_new(), RSA_free);
  if (!key) {
    throw runtime_error(getName() + " allocation of key structure failed");
  }

  // Everything OK, we're releasing ownership since the RSA_* functions want it
  RSA_set0_key(key.get(), modulus.release(), publicExponent.release(), privateExponent.release());
  RSA_set0_factors(key.get(), prime1.release(), prime2.release());
  RSA_set0_crt_params(key.get(), dmp1.release(), dmq1.release(), iqmp.release());

  d_key = std::move(key);
#endif
}

bool OpenSSLRSADNSCryptoKeyEngine::checkKey(std::optional<std::reference_wrapper<std::vector<std::string>>> errorMessages) const
{
  bool retval = true;
  // When changing the bitsizes, also edit them in ::create
  if ((d_algorithm == DNSSECKeeper::RSASHA1 || d_algorithm == DNSSECKeeper::RSASHA1NSEC3SHA1 || d_algorithm == DNSSECKeeper::RSASHA256) && (getBits() < 512 || getBits() > 4096)) {
    retval = false;
    if (errorMessages.has_value()) {
      errorMessages->get().push_back("key is " + std::to_string(getBits()) + " bytes, should be between 512 and 4096");
    }
  }
  if (d_algorithm == DNSSECKeeper::RSASHA512 && (getBits() < 1024 || getBits() > 4096)) {
    retval = false;
    if (errorMessages.has_value()) {
      errorMessages->get().push_back("key is " + std::to_string(getBits()) + " bytes, should be between 1024 and 4096");
    }
  }

#if OPENSSL_VERSION_MAJOR >= 3
  auto ctx = KeyContext(EVP_PKEY_CTX_new_from_pkey(nullptr, d_key.get(), nullptr), EVP_PKEY_CTX_free);
  if (ctx == nullptr) {
    throw pdns::OpenSSL::error(getName(), "Cannot create context to check key");
  }

  if (EVP_PKEY_pairwise_check(ctx.get()) != 1) {
#else
  if (RSA_check_key(d_key.get()) != 1) {
#endif
    retval = false;
    if (errorMessages.has_value()) {
      const auto* errmsg = ERR_error_string(ERR_get_error(), nullptr);
      if (errmsg == nullptr) {
        errmsg = "Unknown OpenSSL error";
      }
      errorMessages->get().emplace_back(errmsg);
    }
  }
  return retval;
}

void OpenSSLRSADNSCryptoKeyEngine::fromPublicKeyString(const std::string& content)
{
  string publicExponent;
  string modulus;
  const size_t contentLen = content.length();

  // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
  const auto* raw = reinterpret_cast<const unsigned char*>(content.c_str());

  if (contentLen < 1) {
    throw runtime_error(getName() + " invalid input size for the public key");
  }

  if (raw[0] != 0) {
    const size_t exponentSize = raw[0];
    if (contentLen < (exponentSize + 2)) {
      throw runtime_error(getName() + " invalid input size for the public key");
    }
    publicExponent = content.substr(1, exponentSize);
    modulus = content.substr(exponentSize + 1);
  }
  else {
    if (contentLen < 3) {
      throw runtime_error(getName() + " invalid input size for the public key");
    }
    const size_t exponentSize = (static_cast<size_t>(raw[1])) * 0x100 + raw[2];
    if (contentLen < (exponentSize + 4)) {
      throw runtime_error(getName() + " invalid input size for the public key");
    }
    publicExponent = content.substr(3, exponentSize);
    modulus = content.substr(exponentSize + 3);
  }

  // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
  auto publicExponentBN = BigNum(BN_bin2bn(reinterpret_cast<unsigned char*>(const_cast<char*>(publicExponent.c_str())), static_cast<int>(publicExponent.length()), nullptr), BN_clear_free);
  if (!publicExponentBN) {
    throw runtime_error(getName() + " error loading public exponent (e) value of public key");
  }

  // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
  auto modulusBN = BigNum(BN_bin2bn(reinterpret_cast<unsigned char*>(const_cast<char*>(modulus.c_str())), static_cast<int>(modulus.length()), nullptr), BN_clear_free);
  if (!modulusBN) {
    throw runtime_error(getName() + " error loading modulus (n) value of public key");
  }

#if OPENSSL_VERSION_MAJOR >= 3
  auto params = makeKeyParams(modulusBN.get(), publicExponentBN.get(), nullptr, nullptr, nullptr, nullptr, nullptr, nullptr);

  auto ctx = KeyContext(EVP_PKEY_CTX_new_from_name(nullptr, "RSA", nullptr), EVP_PKEY_CTX_free);
  if (ctx == nullptr) {
    throw pdns::OpenSSL::error(getName(), "Cannot create context to load key from public key data");
  }

  if (EVP_PKEY_fromdata_init(ctx.get()) <= 0) {
    throw pdns::OpenSSL::error(getName(), "Could not initialize key context for loading data to check key");
  }

  EVP_PKEY* key = nullptr;
  if (EVP_PKEY_fromdata(ctx.get(), &key, EVP_PKEY_PUBLIC_KEY, params.get()) <= 0) {
    throw pdns::OpenSSL::error(getName(), "Could not create public key from parameters");
  }

  d_key.reset(key);
#else
  auto key = Key(RSA_new(), RSA_free);
  if (!key) {
    throw runtime_error(getName() + " allocation of key structure failed");
  }

  RSA_set0_key(key.get(), modulusBN.release(), publicExponentBN.release(), nullptr);
  d_key = std::move(key);
#endif
}

#ifdef HAVE_LIBCRYPTO_ECDSA
class OpenSSLECDSADNSCryptoKeyEngine : public DNSCryptoKeyEngine
{
public:
  explicit OpenSSLECDSADNSCryptoKeyEngine(unsigned int algo);

  [[nodiscard]] string getName() const override { return "OpenSSL ECDSA"; }
  [[nodiscard]] int getBits() const override;

  void create(unsigned int bits) override;

  /**
   * \brief Creates an ECDSA key engine from a PEM file.
   *
   * Receives an open file handle with PEM contents and creates an ECDSA key engine.
   *
   * \param[in] drc Key record contents to be populated.
   *
   * \param[in] inputFile An open file handle to a file containing ECDSA PEM contents.
   *
   * \param[in] filename Only used for providing filename information in error messages.
   *
   * \return An ECDSA key engine populated with the contents of the PEM file.
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

  [[nodiscard]] storvector_t convertToISCVector() const override;
  [[nodiscard]] std::string hash(const std::string& message) const override;
  [[nodiscard]] std::string sign(const std::string& message) const override;
  [[nodiscard]] bool verify(const std::string& message, const std::string& signature) const override;
  [[nodiscard]] std::string getPublicKeyString() const override;
  void fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap) override;
  void fromPublicKeyString(const std::string& content) override;
  [[nodiscard]] bool checkKey(std::optional<std::reference_wrapper<std::vector<std::string>>> errorMessages) const override;

  // TODO Fred: hashSize() and hasher() can probably be completely removed along with
  // hash(). See #12464.
  [[nodiscard]] std::size_t hashSize() const;
  [[nodiscard]] const EVP_MD* hasher() const;

  static std::unique_ptr<DNSCryptoKeyEngine> maker(unsigned int algorithm)
  {
    return make_unique<OpenSSLECDSADNSCryptoKeyEngine>(algorithm);
  }

private:
#if OPENSSL_VERSION_MAJOR >= 3
  using BigNumContext = std::unique_ptr<BN_CTX, decltype(&BN_CTX_free)>;
  using ParamsBuilder = std::unique_ptr<OSSL_PARAM_BLD, decltype(&OSSL_PARAM_BLD_free)>;
  using Params = std::unique_ptr<OSSL_PARAM, decltype(&OSSL_PARAM_free)>;
  auto makeKeyParams(const std::string& group_name, const BIGNUM* privateKey, const std::optional<std::string>& publicKey) const -> Params;
  [[nodiscard]] auto getPrivateKey() const -> BigNum;
#endif

#if OPENSSL_VERSION_MAJOR >= 3
  using Key = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
  using MessageDigestContext = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;
#else
  using Key = std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)>;
#endif

  using KeyContext = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
  using Group = std::unique_ptr<EC_GROUP, decltype(&EC_GROUP_free)>;
  using Point = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;
  using Signature = std::unique_ptr<ECDSA_SIG, decltype(&ECDSA_SIG_free)>;

  int d_len{0};
  std::string d_group_name{};
  Group d_group{nullptr, EC_GROUP_free};

#if OPENSSL_VERSION_MAJOR >= 3
  Key d_eckey{Key(nullptr, EVP_PKEY_free)};
#else
  Key d_eckey{Key(nullptr, EC_KEY_free)};
#endif
};

int OpenSSLECDSADNSCryptoKeyEngine::getBits() const
{
  return d_len << 3;
}

OpenSSLECDSADNSCryptoKeyEngine::OpenSSLECDSADNSCryptoKeyEngine(unsigned int algo) :
  DNSCryptoKeyEngine(algo)
#if OPENSSL_VERSION_MAJOR < 3
  ,
  d_eckey(Key(EC_KEY_new(), EC_KEY_free))
#endif
{
  int ret = RAND_status();
  if (ret != 1) {
    throw runtime_error(getName() + " insufficient entropy");
  }

#if OPENSSL_VERSION_MAJOR < 3
  if (!d_eckey) {
    throw runtime_error(getName() + " allocation of key structure failed");
  }
#endif

  int d_id{0};

  if (d_algorithm == 13) {
    d_group_name = "P-256";
    d_len = 32;
    d_id = NID_X9_62_prime256v1;
  }
  else if (d_algorithm == 14) {
    d_group_name = "P-384";
    d_len = 48;
    d_id = NID_secp384r1;
  }
  else {
    throw runtime_error(getName() + " unknown algorithm " + std::to_string(d_algorithm));
  }

  d_group = Group(EC_GROUP_new_by_curve_name(d_id), EC_GROUP_free);
  if (d_group == nullptr) {
    throw pdns::OpenSSL::error(getName(), std::string() + "Failed to create EC group `" + d_group_name + "` to export public key");
  }

#if OPENSSL_VERSION_MAJOR < 3
  ret = EC_KEY_set_group(d_eckey.get(), d_group.get());
  if (ret != 1) {
    throw runtime_error(getName() + " setting key group failed");
  }
#endif
}

void OpenSSLECDSADNSCryptoKeyEngine::create(unsigned int bits)
{
  if (bits >> 3 != static_cast<unsigned int>(d_len)) {
    throw runtime_error(getName() + " unknown key length of " + std::to_string(bits) + " bits requested");
  }

#if OPENSSL_VERSION_MAJOR >= 3
  // NOLINTNEXTLINE(*-vararg): Using OpenSSL C APIs.
  EVP_PKEY* key = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", d_group_name.c_str());
  if (key == nullptr) {
    throw pdns::OpenSSL::error(getName(), "Failed to generate key");
  }

  d_eckey.reset(key);
#else
  int res = EC_KEY_generate_key(d_eckey.get());
  if (res == 0) {
    throw runtime_error(getName() + " key generation failed");
  }

  EC_KEY_set_asn1_flag(d_eckey.get(), OPENSSL_EC_NAMED_CURVE);
#endif
}

void OpenSSLECDSADNSCryptoKeyEngine::createFromPEMFile(DNSKEYRecordContent& drc, std::FILE& inputFile, std::optional<std::reference_wrapper<const std::string>> filename)
{
  drc.d_algorithm = d_algorithm;

#if OPENSSL_VERSION_MAJOR >= 3
  EVP_PKEY* key = nullptr;
  if (PEM_read_PrivateKey(&inputFile, &key, nullptr, nullptr) == nullptr) {
    if (filename.has_value()) {
      throw pdns::OpenSSL::error(getName(), "Failed to read private key from PEM file `" + filename->get() + "`");
    }

    throw pdns::OpenSSL::error(getName(), "Failed to read private key from PEM contents");
  }

  d_eckey.reset(key);
#else
  d_eckey = Key(PEM_read_ECPrivateKey(&inputFile, nullptr, nullptr, nullptr), &EC_KEY_free);
  if (d_eckey == nullptr) {
    if (filename.has_value()) {
      throw runtime_error(getName() + ": Failed to read private key from PEM file `" + filename->get() + "`");
    }

    throw runtime_error(getName() + ": Failed to read private key from PEM contents");
  }

  int ret = EC_KEY_set_group(d_eckey.get(), d_group.get());
  if (ret != 1) {
    throw runtime_error(getName() + " setting key group failed");
  }

  const BIGNUM* privateKeyBN = EC_KEY_get0_private_key(d_eckey.get());

  auto pub_key = Point(EC_POINT_new(d_group.get()), EC_POINT_free);
  if (!pub_key) {
    throw runtime_error(getName() + " allocation of public key point failed");
  }

  ret = EC_POINT_mul(d_group.get(), pub_key.get(), privateKeyBN, nullptr, nullptr, nullptr);
  if (ret != 1) {
    throw runtime_error(getName() + " computing public key from private failed");
  }

  ret = EC_KEY_set_public_key(d_eckey.get(), pub_key.get());
  if (ret != 1) {
    ERR_print_errors_fp(stderr);
    throw runtime_error(getName() + " setting public key failed");
  }

  EC_KEY_set_asn1_flag(d_eckey.get(), OPENSSL_EC_NAMED_CURVE);
#endif
}

void OpenSSLECDSADNSCryptoKeyEngine::convertToPEMFile(std::FILE& outputFile) const
{
#if OPENSSL_VERSION_MAJOR >= 3
  if (PEM_write_PrivateKey(&outputFile, d_eckey.get(), nullptr, nullptr, 0, nullptr, nullptr) == 0) {
    throw pdns::OpenSSL::error(getName(), "Failed to convert private key to PEM");
  }
#else
  auto ret = PEM_write_ECPrivateKey(&outputFile, d_eckey.get(), nullptr, nullptr, 0, nullptr, nullptr);
  if (ret == 0) {
    throw runtime_error(getName() + ": Could not convert private key to PEM");
  }
#endif
}

#if OPENSSL_VERSION_MAJOR >= 3
auto OpenSSLECDSADNSCryptoKeyEngine::getPrivateKey() const -> BigNum
{
  BIGNUM* privateKey = nullptr;
  if (EVP_PKEY_get_bn_param(d_eckey.get(), OSSL_PKEY_PARAM_PRIV_KEY, &privateKey) == 0) {
    throw pdns::OpenSSL::error(getName(), "Could not get private key parameter");
  }
  return BigNum{privateKey, BN_clear_free};
}
#endif

DNSCryptoKeyEngine::storvector_t OpenSSLECDSADNSCryptoKeyEngine::convertToISCVector() const
{
  storvector_t storvect;
  string algorithm;

  if (d_algorithm == 13) {
    algorithm = "13 (ECDSAP256SHA256)";
  }
  else if (d_algorithm == 14) {
    algorithm = "14 (ECDSAP384SHA384)";
  }
  else {
    algorithm = " ? (?)";
  }

  storvect.emplace_back("Algorithm", algorithm);

#if OPENSSL_VERSION_MAJOR >= 3
  auto privateKeyBN = getPrivateKey();

  std::string privateKey;
  privateKey.resize(BN_num_bytes(privateKeyBN.get()));
  // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
  int len = BN_bn2bin(privateKeyBN.get(), reinterpret_cast<unsigned char*>(privateKey.data()));
  if (len >= 0) {
    privateKey.resize(len);

    std::string prefix;
    if (d_len - len != 0) {
      prefix.append(d_len - len, 0x00);
    }

    storvect.emplace_back("PrivateKey", prefix + privateKey);
  }
#else
  const BIGNUM* key = EC_KEY_get0_private_key(d_eckey.get());
  if (key == nullptr) {
    throw runtime_error(getName() + " private key not set");
  }

  std::string tmp;
  tmp.resize(BN_num_bytes(key));
  int len = BN_bn2bin(key, reinterpret_cast<unsigned char*>(&tmp.at(0)));

  string prefix;
  if (d_len - len) {
    prefix.append(d_len - len, 0x00);
  }

  storvect.emplace_back("PrivateKey", prefix + tmp);
#endif

  return storvect;
}

std::string OpenSSLECDSADNSCryptoKeyEngine::hash(const std::string& message) const
{
  if (getBits() == 256) {
    std::string l_hash{};
    l_hash.resize(SHA256_DIGEST_LENGTH);
    // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
    SHA256(reinterpret_cast<unsigned char*>(const_cast<char*>(message.c_str())), message.length(), reinterpret_cast<unsigned char*>(l_hash.data()));
    return l_hash;
  }

  if (getBits() == 384) {
    std::string l_hash{};
    l_hash.resize(SHA384_DIGEST_LENGTH);
    // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
    SHA384(reinterpret_cast<unsigned char*>(const_cast<char*>(message.c_str())), message.length(), reinterpret_cast<unsigned char*>(l_hash.data()));
    return l_hash;
  }

  throw runtime_error(getName() + " does not support a hash size of " + std::to_string(getBits()) + " bits");
}

const EVP_MD* OpenSSLECDSADNSCryptoKeyEngine::hasher() const
{
  const EVP_MD* messageDigest = nullptr;

  switch (d_algorithm) {
  case DNSSECKeeper::ECDSA256:
    messageDigest = EVP_sha256();
    break;
  case DNSSECKeeper::ECDSA384:
    messageDigest = EVP_sha384();
    break;
  default:
    throw runtime_error(getName() + " does not support hash operations for algorithm " + std::to_string(d_algorithm));
  }

  if (messageDigest == nullptr) {
    throw std::runtime_error("Could not retrieve a SHA implementation of size " + std::to_string(hashSize()) + " from OpenSSL");
  }

  return messageDigest;
}

std::size_t OpenSSLECDSADNSCryptoKeyEngine::hashSize() const
{
  switch (d_algorithm) {
  case DNSSECKeeper::ECDSA256:
    return SHA256_DIGEST_LENGTH;
  case DNSSECKeeper::ECDSA384:
    return SHA384_DIGEST_LENGTH;
  default:
    throw runtime_error(getName() + " does not support hash operations for algorithm " + std::to_string(d_algorithm));
  }
}

std::string OpenSSLECDSADNSCryptoKeyEngine::sign(const std::string& message) const
{
#if OPENSSL_VERSION_MAJOR >= 3
  auto ctx = MessageDigestContext(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (ctx == nullptr) {
    throw pdns::OpenSSL::error(getName(), "Could not create context for signing");
  }

  if (EVP_DigestSignInit(ctx.get(), nullptr, hasher(), nullptr, d_eckey.get()) == 0) {
    throw pdns::OpenSSL::error(getName(), "Could not initialize context for signing");
  }

  std::size_t signatureLen = 0;

  // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
  const auto* messageData = reinterpret_cast<const unsigned char*>(message.data());
  if (EVP_DigestSign(ctx.get(), nullptr, &signatureLen, messageData, message.size()) == 0) {
    throw pdns::OpenSSL::error(getName(), "Could not get message signature length");
  }

  std::string signatureBuffer;
  signatureBuffer.resize(signatureLen);

  // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
  auto* signatureData = reinterpret_cast<unsigned char*>(signatureBuffer.data());
  if (EVP_DigestSign(ctx.get(), signatureData, &signatureLen, messageData, message.size()) == 0) {
    throw pdns::OpenSSL::error(getName(), "Could not sign message");
  }

  signatureBuffer.resize(signatureLen);

  // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
  auto signature = Signature(d2i_ECDSA_SIG(nullptr, const_cast<const unsigned char**>(&signatureData), (long)signatureLen), ECDSA_SIG_free);
  if (signature == nullptr) {
    throw pdns::OpenSSL::error(getName(), "Failed to convert DER signature to internal structure");
  }
#else
  string l_hash = this->hash(message);

  auto signature = Signature(ECDSA_do_sign((unsigned char*)l_hash.c_str(), l_hash.length(), d_eckey.get()), ECDSA_SIG_free);
  if (!signature) {
    throw runtime_error(getName() + " failed to generate signature");
  }
#endif

  string ret;
  std::string tmp;
  tmp.resize(d_len);

  const BIGNUM* prComponent = nullptr;
  const BIGNUM* psComponent = nullptr;
  ECDSA_SIG_get0(signature.get(), &prComponent, &psComponent);
  // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
  int len = BN_bn2bin(prComponent, reinterpret_cast<unsigned char*>(&tmp.at(0)));
  if ((d_len - len) != 0) {
    ret.append(d_len - len, 0x00);
  }
  ret.append(&tmp.at(0), len);

  // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
  len = BN_bn2bin(psComponent, reinterpret_cast<unsigned char*>(&tmp.at(0)));
  if ((d_len - len) != 0) {
    ret.append(d_len - len, 0x00);
  }
  ret.append(&tmp.at(0), len);

  return ret;
}

bool OpenSSLECDSADNSCryptoKeyEngine::verify(const std::string& message, const std::string& signature) const
{
  if (signature.length() != (static_cast<unsigned long>(d_len) * 2)) {
    throw runtime_error(getName() + " invalid signature size " + std::to_string(signature.length()));
  }

  // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
  auto* signatureCStr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(signature.c_str()));
  auto rComponent = BigNum(BN_bin2bn(signatureCStr, d_len, nullptr), BN_free);
  auto sComponent = BigNum(BN_bin2bn(signatureCStr + d_len, d_len, nullptr), BN_free);
  if (!rComponent || !sComponent) {
    throw runtime_error(getName() + " invalid signature");
  }

  auto sig = Signature(ECDSA_SIG_new(), ECDSA_SIG_free);
  if (!sig) {
    throw runtime_error(getName() + " allocation of signature structure failed");
  }
  ECDSA_SIG_set0(sig.get(), rComponent.release(), sComponent.release());

#if OPENSSL_VERSION_MAJOR >= 3
  unsigned char* derBufferPointer = nullptr;
  const int derBufferSize = i2d_ECDSA_SIG(sig.get(), &derBufferPointer);
  if (derBufferSize < 0) {
    throw pdns::OpenSSL::error(getName(), "Failed to convert signature to DER");
  }
  // Because OPENSSL_free() is a macro.
  auto derBuffer = unique_ptr<unsigned char, void (*)(unsigned char*)>{derBufferPointer, [](auto* buffer) { OPENSSL_free(buffer); }};

  auto ctx = MessageDigestContext(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (ctx == nullptr) {
    throw pdns::OpenSSL::error(getName(), "Could not create message digest context for signing");
  }

  if (EVP_DigestVerifyInit(ctx.get(), nullptr, hasher(), nullptr, d_eckey.get()) == 0) {
    throw pdns::OpenSSL::error(getName(), "Could not initialize context for verifying signature");
  }

  // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
  const auto ret = EVP_DigestVerify(ctx.get(), derBuffer.get(), derBufferSize, reinterpret_cast<const unsigned char*>(message.data()), message.size());
  if (ret < 0) {
    throw pdns::OpenSSL::error(getName(), "Could not verify message signature");
  }

  return (ret == 1);
#else
  string l_hash = this->hash(message);

  int ret = ECDSA_do_verify((unsigned char*)l_hash.c_str(), l_hash.length(), sig.get(), d_eckey.get());
  if (ret == -1) {
    throw runtime_error(getName() + " verify error");
  }

  return (ret == 1);
#endif
}

std::string OpenSSLECDSADNSCryptoKeyEngine::getPublicKeyString() const
{
#if OPENSSL_VERSION_MAJOR >= 3
  size_t bufsize = 0;
  if (EVP_PKEY_get_octet_string_param(d_eckey.get(), OSSL_PKEY_PARAM_PUB_KEY, nullptr, 0, &bufsize) == 0) {
    throw pdns::OpenSSL::error(getName(), "Failed to get public key buffer size");
  }

  std::string publicKey{};
  publicKey.resize(bufsize);

  // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
  auto* publicKeyCStr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(publicKey.c_str()));
  if (EVP_PKEY_get_octet_string_param(d_eckey.get(), OSSL_PKEY_PARAM_PUB_KEY, publicKeyCStr, bufsize, &bufsize) == 0) {
    throw pdns::OpenSSL::error(getName(), "Failed to get public key");
  }

  publicKey.resize(bufsize);

  auto publicKeyECPoint = Point(EC_POINT_new(d_group.get()), EC_POINT_free);
  if (publicKeyECPoint == nullptr) {
    throw pdns::OpenSSL::error(getName(), "Failed to create public key point for export");
  }

  auto ctx = BigNumContext(BN_CTX_new(), BN_CTX_free);

  // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
  publicKeyCStr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(publicKey.c_str()));
  if (EC_POINT_oct2point(d_group.get(), publicKeyECPoint.get(), publicKeyCStr, publicKey.length(), ctx.get()) == 0) {
    throw pdns::OpenSSL::error(getName(), "Failed to export public key to point");
  }

  std::string publicKeyUncompressed{};
  bufsize = EC_POINT_point2oct(d_group.get(), publicKeyECPoint.get(), POINT_CONVERSION_UNCOMPRESSED, nullptr, 0, nullptr);
  if (bufsize == 0) {
    throw pdns::OpenSSL::error(getName(), "Failed to get public key binary buffer size");
  }
  publicKeyUncompressed.resize(bufsize);

  // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
  auto* publicKeyUncompressedCStr = const_cast<unsigned char*>(reinterpret_cast<const unsigned char*>(publicKeyUncompressed.c_str()));
  bufsize = EC_POINT_point2oct(d_group.get(), publicKeyECPoint.get(), POINT_CONVERSION_UNCOMPRESSED, publicKeyUncompressedCStr, publicKeyUncompressed.length(), nullptr);
  if (bufsize == 0) {
    throw pdns::OpenSSL::error(getName(), "Failed to convert public key to oct");
  }

  /* We skip the first byte as the other backends use raw field elements, as opposed to
   * the format described in SEC1: "2.3.3 Elliptic-Curve-Point-to-Octet-String
   * Conversion" */
  publicKeyUncompressed.erase(0, 1);

  return publicKeyUncompressed;
#else
  std::string binaryPoint;
  binaryPoint.resize((d_len * 2) + 1);

  int ret = EC_POINT_point2oct(d_group.get(), EC_KEY_get0_public_key(d_eckey.get()), POINT_CONVERSION_UNCOMPRESSED, reinterpret_cast<unsigned char*>(&binaryPoint.at(0)), binaryPoint.size(), nullptr);
  if (ret == 0) {
    throw runtime_error(getName() + " exporting point to binary failed");
  }

  /* we skip the first byte as the other backends use
     raw field elements, as opposed to the format described in
     SEC1: "2.3.3 Elliptic-Curve-Point-to-Octet-String Conversion" */
  binaryPoint.erase(0, 1);
  return binaryPoint;
#endif
}

#if OPENSSL_VERSION_MAJOR >= 3
auto OpenSSLECDSADNSCryptoKeyEngine::makeKeyParams(const std::string& group_name, const BIGNUM* privateKey, const std::optional<std::string>& publicKey) const -> Params
{
  auto params_build = ParamsBuilder(OSSL_PARAM_BLD_new(), OSSL_PARAM_BLD_free);
  if (params_build == nullptr) {
    throw pdns::OpenSSL::error(getName(), "Failed to create key's parameters builder");
  }

  if ((!group_name.empty()) && OSSL_PARAM_BLD_push_utf8_string(params_build.get(), OSSL_PKEY_PARAM_GROUP_NAME, group_name.c_str(), group_name.length()) == 0) {
    throw pdns::OpenSSL::error(getName(), "Failed to create key's group parameter");
  }

  if ((privateKey != nullptr) && OSSL_PARAM_BLD_push_BN(params_build.get(), OSSL_PKEY_PARAM_PRIV_KEY, privateKey) == 0) {
    throw pdns::OpenSSL::error(getName(), "Failed to create private key parameter");
  }

  if (publicKey.has_value()) {
    if (OSSL_PARAM_BLD_push_octet_string(params_build.get(), OSSL_PKEY_PARAM_PUB_KEY, publicKey->c_str(), publicKey->length()) == 0) {
      throw pdns::OpenSSL::error(getName(), "Failed to create public key parameter");
    }
  }

  auto params = Params(OSSL_PARAM_BLD_to_param(params_build.get()), OSSL_PARAM_free);
  if (params == nullptr) {
    throw pdns::OpenSSL::error(getName(), "Failed to create key's parameters");
  }

  return params;
}
#endif

void OpenSSLECDSADNSCryptoKeyEngine::fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap)
{
  drc.d_algorithm = atoi(stormap["algorithm"].c_str());

  if (drc.d_algorithm != d_algorithm) {
    throw runtime_error(getName() + " tried to feed an algorithm " + std::to_string(drc.d_algorithm) + " to a " + std::to_string(d_algorithm) + " key");
  }

  auto privateKey = mapToBN(getName(), stormap, "privatekey");

#if OPENSSL_VERSION_MAJOR >= 3
  auto publicKeyECPoint = Point(EC_POINT_new(d_group.get()), EC_POINT_free);
  if (publicKeyECPoint == nullptr) {
    throw pdns::OpenSSL::error(getName(), "Failed to create public key point to import from ISC");
  }

  if (EC_POINT_mul(d_group.get(), publicKeyECPoint.get(), privateKey.get(), nullptr, nullptr, nullptr) == 0) {
    throw pdns::OpenSSL::error(getName(), "Failed to derive public key from ISC private key");
  }

  std::string publicKey{};
  size_t bufsize = EC_POINT_point2oct(d_group.get(), publicKeyECPoint.get(), POINT_CONVERSION_COMPRESSED, nullptr, 0, nullptr);
  if (bufsize == 0) {
    throw pdns::OpenSSL::error(getName(), "Failed to get public key binary buffer size");
  }
  publicKey.resize(bufsize);

  // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
  auto* publicKeyData = reinterpret_cast<unsigned char*>(publicKey.data());
  bufsize = EC_POINT_point2oct(d_group.get(), publicKeyECPoint.get(), POINT_CONVERSION_COMPRESSED, publicKeyData, publicKey.length(), nullptr);
  if (bufsize == 0) {
    throw pdns::OpenSSL::error(getName(), "Failed to convert public key to oct");
  }

  auto params = makeKeyParams(d_group_name, privateKey.get(), std::make_optional(publicKey));

  auto ctx = KeyContext(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr), EVP_PKEY_CTX_free);
  if (ctx == nullptr) {
    throw pdns::OpenSSL::error(getName(), "Could not create key context");
  }

  if (EVP_PKEY_fromdata_init(ctx.get()) <= 0) {
    throw pdns::OpenSSL::error(getName(), "Could not initialize key context for loading data from ISC");
  }

  EVP_PKEY* key = nullptr;
  if (EVP_PKEY_fromdata(ctx.get(), &key, EVP_PKEY_KEYPAIR, params.get()) <= 0) {
    throw pdns::OpenSSL::error(getName(), "Could not create key from parameters");
  }

  d_eckey.reset(key);
#else
  int ret = EC_KEY_set_private_key(d_eckey.get(), privateKey.get());
  if (ret != 1) {
    throw runtime_error(getName() + " setting private key failed");
  }

  auto pub_key = Point(EC_POINT_new(d_group.get()), EC_POINT_free);
  if (!pub_key) {
    throw runtime_error(getName() + " allocation of public key point failed");
  }

  ret = EC_POINT_mul(d_group.get(), pub_key.get(), privateKey.get(), nullptr, nullptr, nullptr);
  if (ret != 1) {
    throw runtime_error(getName() + " computing public key from private failed");
  }

  ret = EC_KEY_set_public_key(d_eckey.get(), pub_key.get());
  if (ret != 1) {
    throw runtime_error(getName() + " setting public key failed");
  }

  EC_KEY_set_asn1_flag(d_eckey.get(), OPENSSL_EC_NAMED_CURVE);
#endif
}

bool OpenSSLECDSADNSCryptoKeyEngine::checkKey(std::optional<std::reference_wrapper<std::vector<std::string>>> errorMessages) const
{
#if OPENSSL_VERSION_MAJOR >= 3
  auto ctx = KeyContext{EVP_PKEY_CTX_new_from_pkey(nullptr, d_eckey.get(), nullptr), EVP_PKEY_CTX_free};
  if (ctx == nullptr) {
    throw pdns::OpenSSL::error(getName(), "Failed to create context to check key");
  }

  bool retval = true;

  auto addOpenSSLErrorMessageOnFail = [errorMessages, &retval](const int errorCode, const auto defaultErrorMessage) {
    // Error code of -2 means the check is not supported for the algorithm, which is fine.
    if (errorCode != 1 && errorCode != -2) {
      retval = false;

      if (errorMessages.has_value()) {
        const auto* errorMessage = ERR_reason_error_string(ERR_get_error());
        if (errorMessage == nullptr) {
          errorMessages->get().push_back(defaultErrorMessage);
        }
        else {
          errorMessages->get().emplace_back(errorMessage);
        }
      }
    }
  };

  addOpenSSLErrorMessageOnFail(EVP_PKEY_param_check(ctx.get()), getName() + "Unknown OpenSSL error during key param check");
  addOpenSSLErrorMessageOnFail(EVP_PKEY_public_check(ctx.get()), getName() + "Unknown OpenSSL error during public key check");
  addOpenSSLErrorMessageOnFail(EVP_PKEY_private_check(ctx.get()), getName() + "Unknown OpenSSL error during private key check");
  addOpenSSLErrorMessageOnFail(EVP_PKEY_pairwise_check(ctx.get()), getName() + "Unknown OpenSSL error during key pairwise check");

  return retval;
#else
  bool retval = true;
  if (EC_KEY_check_key(d_eckey.get()) != 1) {
    retval = false;
    if (errorMessages.has_value()) {
      const auto* errmsg = ERR_reason_error_string(ERR_get_error());
      if (errmsg == nullptr) {
        errmsg = "Unknown OpenSSL error";
      }
      errorMessages->get().push_back(errmsg);
    }
  }
  return retval;
#endif
}

void OpenSSLECDSADNSCryptoKeyEngine::fromPublicKeyString(const std::string& content)
{
#if OPENSSL_VERSION_MAJOR >= 3
  /* uncompressed point, from SEC1: "2.3.4 Octet-String-to-Elliptic-Curve-Point
   * Conversion"
   */
  std::string publicKey = "\x04";
  publicKey.append(content);

  auto params = makeKeyParams(d_group_name, nullptr, std::make_optional(publicKey));

  auto ctx = KeyContext(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr), EVP_PKEY_CTX_free);
  if (ctx == nullptr) {
    throw pdns::OpenSSL::error(getName(), "Failed to create key context");
  }

  if (EVP_PKEY_fromdata_init(ctx.get()) <= 0) {
    throw pdns::OpenSSL::error(getName(), "Failed to initialize key context for loading data from ISC");
  }

  EVP_PKEY* key = nullptr;
  if (EVP_PKEY_fromdata(ctx.get(), &key, EVP_PKEY_PUBLIC_KEY, params.get()) <= 0) {
    throw pdns::OpenSSL::error(getName(), "Failed to create key from parameters");
  }

  d_eckey.reset(key);
#else
  /* uncompressed point, from SEC1: "2.3.4 Octet-String-to-Elliptic-Curve-Point
   * Conversion"
   */
  string ecdsaPoint = "\x04";
  ecdsaPoint.append(content);

  auto pub_key = Point(EC_POINT_new(d_group.get()), EC_POINT_free);
  if (!pub_key) {
    throw runtime_error(getName() + " allocation of point structure failed");
  }

  int ret = EC_POINT_oct2point(d_group.get(), pub_key.get(), (unsigned char*)ecdsaPoint.c_str(), ecdsaPoint.length(), nullptr);
  if (ret != 1) {
    throw runtime_error(getName() + " reading ECP point from binary failed");
  }

  ret = EC_KEY_set_private_key(d_eckey.get(), nullptr);
  if (ret == 1) {
    throw runtime_error(getName() + " setting private key failed");
  }

  ret = EC_KEY_set_public_key(d_eckey.get(), pub_key.get());
  if (ret != 1) {
    throw runtime_error(getName() + " setting public key failed");
  }
#endif
}
#endif

#ifdef HAVE_LIBCRYPTO_EDDSA
class OpenSSLEDDSADNSCryptoKeyEngine : public DNSCryptoKeyEngine
{
public:
  explicit OpenSSLEDDSADNSCryptoKeyEngine(unsigned int algo);

  [[nodiscard]] string getName() const override { return "OpenSSL EdDSA"; }
  [[nodiscard]] int getBits() const override;

  void create(unsigned int bits) override;

  /**
   * \brief Creates an EDDSA key engine from a PEM file.
   *
   * Receives an open file handle with PEM contents and creates an EDDSA key engine.
   *
   * \param[in] drc Key record contents to be populated.
   *
   * \param[in] inputFile An open file handle to a file containing EDDSA PEM contents.
   *
   * \param[in] filename Only used for providing filename information in error messages.
   *
   * \return An EDDSA key engine populated with the contents of the PEM file.
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

  [[nodiscard]] storvector_t convertToISCVector() const override;
  [[nodiscard]] std::string sign(const std::string& msg) const override;
  [[nodiscard]] bool verify(const std::string& message, const std::string& signature) const override;
  [[nodiscard]] std::string getPublicKeyString() const override;
  void fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap) override;
  void fromPublicKeyString(const std::string& content) override;
  [[nodiscard]] bool checkKey(std::optional<std::reference_wrapper<std::vector<std::string>>> errorMessages) const override;

  static std::unique_ptr<DNSCryptoKeyEngine> maker(unsigned int algorithm)
  {
    return make_unique<OpenSSLEDDSADNSCryptoKeyEngine>(algorithm);
  }

  using Key = unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
  using KeyContext = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;
  using MessageDigestContext = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

private:
  size_t d_len{0};
  int d_id{0};

  Key d_edkey;
};

OpenSSLEDDSADNSCryptoKeyEngine::OpenSSLEDDSADNSCryptoKeyEngine(unsigned int algo) :
  DNSCryptoKeyEngine(algo),
  d_edkey(Key(nullptr, EVP_PKEY_free))
{
  int ret = RAND_status();
  if (ret != 1) {
    throw runtime_error(getName() + " insufficient entropy");
  }

#ifdef HAVE_LIBCRYPTO_ED25519
  if (d_algorithm == 15) {
    d_len = 32;
    d_id = NID_ED25519;
  }
#endif
#ifdef HAVE_LIBCRYPTO_ED448
  if (d_algorithm == 16) {
    d_len = 57;
    d_id = NID_ED448;
  }
#endif
  if (d_len == 0) {
    throw runtime_error(getName() + " unknown algorithm " + std::to_string(d_algorithm));
  }
}

int OpenSSLEDDSADNSCryptoKeyEngine::getBits() const
{
  return (int)d_len << 3;
}

bool OpenSSLEDDSADNSCryptoKeyEngine::checkKey([[maybe_unused]] std::optional<std::reference_wrapper<std::vector<std::string>>> errorMessages) const
{
#if OPENSSL_VERSION_MAJOR >= 3
  auto ctx = KeyContext{EVP_PKEY_CTX_new_from_pkey(nullptr, d_edkey.get(), nullptr), EVP_PKEY_CTX_free};
  if (ctx == nullptr) {
    throw pdns::OpenSSL::error(getName(), "Failed to create context to check key");
  }

  bool retval = true;

  auto addOpenSSLErrorMessageOnFail = [errorMessages, &retval](const int errorCode, const auto defaultErrorMessage) {
    // Error code of -2 means the check is not supported for the algorithm, which is fine.
    if (errorCode != 1 && errorCode != -2) {
      retval = false;

      if (errorMessages.has_value()) {
        const auto* errorMessage = ERR_reason_error_string(ERR_get_error());
        if (errorMessage == nullptr) {
          errorMessages->get().push_back(defaultErrorMessage);
        }
        else {
          errorMessages->get().emplace_back(errorMessage);
        }
      }
    }
  };

  addOpenSSLErrorMessageOnFail(EVP_PKEY_param_check(ctx.get()), getName() + "Unknown OpenSSL error during key param check");
  addOpenSSLErrorMessageOnFail(EVP_PKEY_public_check(ctx.get()), getName() + "Unknown OpenSSL error during public key check");
  addOpenSSLErrorMessageOnFail(EVP_PKEY_private_check(ctx.get()), getName() + "Unknown OpenSSL error during private key check");
  addOpenSSLErrorMessageOnFail(EVP_PKEY_pairwise_check(ctx.get()), getName() + "Unknown OpenSSL error during key pairwise check");

  return retval;
#else
  return (d_edkey ? true : false);
#endif
}

void OpenSSLEDDSADNSCryptoKeyEngine::create(unsigned int /* bits */)
{
  auto pctx = KeyContext(EVP_PKEY_CTX_new_id(d_id, nullptr), EVP_PKEY_CTX_free);
  if (!pctx) {
    throw pdns::OpenSSL::error(getName(), "Context initialization failed");
  }

  if (EVP_PKEY_keygen_init(pctx.get()) < 1) {
    throw pdns::OpenSSL::error(getName(), "Keygen initialization failed");
  }

  EVP_PKEY* newKey = nullptr;
  if (EVP_PKEY_keygen(pctx.get(), &newKey) < 1) {
    throw pdns::OpenSSL::error(getName(), "Key generation failed");
  }

  d_edkey.reset(newKey);
}

void OpenSSLEDDSADNSCryptoKeyEngine::createFromPEMFile(DNSKEYRecordContent& drc, std::FILE& inputFile, std::optional<std::reference_wrapper<const std::string>> filename)
{
  drc.d_algorithm = d_algorithm;
  d_edkey = Key(PEM_read_PrivateKey(&inputFile, nullptr, nullptr, nullptr), &EVP_PKEY_free);
  if (d_edkey == nullptr) {
    if (filename.has_value()) {
      throw pdns::OpenSSL::error(getName(), "Failed to read private key from PEM file `" + filename->get() + "`");
    }

    throw pdns::OpenSSL::error(getName(), "Failed to read private key from PEM contents");
  }
}

void OpenSSLEDDSADNSCryptoKeyEngine::convertToPEMFile(std::FILE& outputFile) const
{
  auto ret = PEM_write_PrivateKey(&outputFile, d_edkey.get(), nullptr, nullptr, 0, nullptr, nullptr);
  if (ret == 0) {
    throw pdns::OpenSSL::error(getName(), "Could not convert private key to PEM");
  }
}

DNSCryptoKeyEngine::storvector_t OpenSSLEDDSADNSCryptoKeyEngine::convertToISCVector() const
{
  storvector_t storvect;
  string algorithm;

#ifdef HAVE_LIBCRYPTO_ED25519
  if (d_algorithm == 15) {
    algorithm = "15 (ED25519)";
  }
#endif
#ifdef HAVE_LIBCRYPTO_ED448
  if (d_algorithm == 16) {
    algorithm = "16 (ED448)";
  }
#endif
  if (algorithm.empty()) {
    algorithm = " ? (?)";
  }

  storvect.emplace_back("Algorithm", algorithm);

  string buf;
  size_t len = d_len;
  buf.resize(len);

  // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
  if (EVP_PKEY_get_raw_private_key(d_edkey.get(), reinterpret_cast<unsigned char*>(&buf.at(0)), &len) < 1) {
    throw pdns::OpenSSL::error(getName(), "Could not get private key from d_edkey");
  }
  storvect.emplace_back("PrivateKey", buf);
  return storvect;
}

std::string OpenSSLEDDSADNSCryptoKeyEngine::sign(const std::string& msg) const
{
  auto mdctx = MessageDigestContext(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (!mdctx) {
    throw pdns::OpenSSL::error(getName(), "MD context initialization failed");
  }
  if (EVP_DigestSignInit(mdctx.get(), nullptr, nullptr, nullptr, d_edkey.get()) < 1) {
    throw pdns::OpenSSL::error(getName(), "Unable to initialize signer");
  }

  string msgToSign = msg;

  size_t siglen = d_len * 2;
  string signature;
  signature.resize(siglen);

  if (EVP_DigestSign(mdctx.get(),
                     // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
                     reinterpret_cast<unsigned char*>(&signature.at(0)), &siglen,
                     // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
                     reinterpret_cast<unsigned char*>(&msgToSign.at(0)), msgToSign.length())
      < 1) {
    throw pdns::OpenSSL::error(getName(), "Signing error");
  }

  return signature;
}

bool OpenSSLEDDSADNSCryptoKeyEngine::verify(const std::string& message, const std::string& signature) const
{
  auto ctx = MessageDigestContext(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (!ctx) {
    throw pdns::OpenSSL::error(getName(), "MD context initialization failed");
  }
  if (EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, d_edkey.get()) < 1) {
    throw pdns::OpenSSL::error(getName(), "Unable to initialize signer");
  }

  auto ret = EVP_DigestVerify(ctx.get(),
                              // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
                              reinterpret_cast<const unsigned char*>(&signature.at(0)), signature.length(),
                              // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
                              reinterpret_cast<const unsigned char*>(&message.at(0)), message.length());
  if (ret < 0) {
    throw pdns::OpenSSL::error(getName(), "Verification failure");
  }

  return (ret == 1);
}

std::string OpenSSLEDDSADNSCryptoKeyEngine::getPublicKeyString() const
{
  string buf;
  size_t len = d_len;
  buf.resize(len);

  // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
  if (EVP_PKEY_get_raw_public_key(d_edkey.get(), reinterpret_cast<unsigned char*>(&buf.at(0)), &len) < 1) {
    throw pdns::OpenSSL::error(getName(), "Unable to get public key from key struct");
  }

  return buf;
}

void OpenSSLEDDSADNSCryptoKeyEngine::fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap)
{
  drc.d_algorithm = atoi(stormap["algorithm"].c_str());
  if (drc.d_algorithm != d_algorithm) {
    throw runtime_error(getName() + " tried to feed an algorithm " + std::to_string(drc.d_algorithm) + " to a " + std::to_string(d_algorithm) + " key");
  }

  // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
  d_edkey = Key(EVP_PKEY_new_raw_private_key(d_id, nullptr, reinterpret_cast<unsigned char*>(&stormap["privatekey"].at(0)), stormap["privatekey"].length()), EVP_PKEY_free);
  if (!d_edkey) {
    throw pdns::OpenSSL::error(getName(), "Could not create key structure from private key");
  }
}

void OpenSSLEDDSADNSCryptoKeyEngine::fromPublicKeyString(const std::string& content)
{
  if (content.length() != d_len) {
    throw runtime_error(getName() + " wrong public key length for algorithm " + std::to_string(d_algorithm));
  }

  // NOLINTNEXTLINE(*-cast): Using OpenSSL C APIs.
  const auto* raw = reinterpret_cast<const unsigned char*>(content.c_str());

  d_edkey = Key(EVP_PKEY_new_raw_public_key(d_id, nullptr, raw, d_len), EVP_PKEY_free);
  if (!d_edkey) {
    throw pdns::OpenSSL::error(getName(), "Allocation of public key structure failed");
  }
}
#endif // HAVE_LIBCRYPTO_EDDSA

namespace
{
const struct LoaderStruct
{
  LoaderStruct()
  {
    DNSCryptoKeyEngine::report(DNSSECKeeper::RSASHA1, &OpenSSLRSADNSCryptoKeyEngine::maker);
    DNSCryptoKeyEngine::report(DNSSECKeeper::RSASHA1NSEC3SHA1, &OpenSSLRSADNSCryptoKeyEngine::maker);
    DNSCryptoKeyEngine::report(DNSSECKeeper::RSASHA256, &OpenSSLRSADNSCryptoKeyEngine::maker);
    DNSCryptoKeyEngine::report(DNSSECKeeper::RSASHA512, &OpenSSLRSADNSCryptoKeyEngine::maker);
#ifdef HAVE_LIBCRYPTO_ECDSA
    DNSCryptoKeyEngine::report(DNSSECKeeper::ECDSA256, &OpenSSLECDSADNSCryptoKeyEngine::maker);
    DNSCryptoKeyEngine::report(DNSSECKeeper::ECDSA384, &OpenSSLECDSADNSCryptoKeyEngine::maker);
#endif
#ifdef HAVE_LIBCRYPTO_ED25519
    DNSCryptoKeyEngine::report(DNSSECKeeper::ED25519, &OpenSSLEDDSADNSCryptoKeyEngine::maker);
#endif
#ifdef HAVE_LIBCRYPTO_ED448
    DNSCryptoKeyEngine::report(DNSSECKeeper::ED448, &OpenSSLEDDSADNSCryptoKeyEngine::maker);
#endif
  }
} loaderOpenSSL;
}
