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
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/opensslv.h>
#include <openssl/err.h>
#include "opensslsigners.hh"
#include "dnssecinfra.hh"
#include "dnsseckeeper.hh"

#if (OPENSSL_VERSION_NUMBER < 0x1010000fL || defined LIBRESSL_VERSION_NUMBER)
/* OpenSSL < 1.1.0 needs support for threading/locking in the calling application. */
static pthread_mutex_t *openssllocks;

extern "C" {
void openssl_pthreads_locking_callback(int mode, int type, const char *file, int line)
{
  if (mode & CRYPTO_LOCK) {
    pthread_mutex_lock(&(openssllocks[type]));

  }else {
    pthread_mutex_unlock(&(openssllocks[type]));
  }
}

unsigned long openssl_pthreads_id_callback()
{
  return (unsigned long)pthread_self();
}
}

void openssl_thread_setup()
{
  openssllocks = (pthread_mutex_t*)OPENSSL_malloc(CRYPTO_num_locks() * sizeof(pthread_mutex_t));

  for (int i = 0; i < CRYPTO_num_locks(); i++)
    pthread_mutex_init(&(openssllocks[i]), NULL);

  CRYPTO_set_id_callback(openssl_pthreads_id_callback);
  CRYPTO_set_locking_callback(openssl_pthreads_locking_callback);
}

void openssl_thread_cleanup()
{
  CRYPTO_set_locking_callback(NULL);

  for (int i=0; i<CRYPTO_num_locks(); i++) {
    pthread_mutex_destroy(&(openssllocks[i]));
  }

  OPENSSL_free(openssllocks);
}

#if !defined(LIBRESSL_VERSION_NUMBER) || LIBRESSL_VERSION_NUMBER < 0x2070000fL
/* those symbols are defined in LibreSSL 2.7.0+ */
/* compat helpers. These DO NOT do any of the checking that the libssl 1.1 functions do. */
static inline void RSA_get0_key(const RSA* rsakey, const BIGNUM** n, const BIGNUM** e, const BIGNUM** d) {
  *n = rsakey->n;
  *e = rsakey->e;
  *d = rsakey->d;
}

static inline int RSA_set0_key(RSA* rsakey, BIGNUM* n, BIGNUM* e, BIGNUM* d) {
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

static inline void RSA_get0_factors(const RSA* rsakey, const BIGNUM** p, const BIGNUM** q) {
  *p = rsakey->p;
  *q = rsakey->q;
}

static inline int RSA_set0_factors(RSA* rsakey, BIGNUM* p, BIGNUM* q) {
  BN_clear_free(rsakey->p);
  rsakey->p = p;
  BN_clear_free(rsakey->q);
  rsakey->q = q;
  return 1;
}

static inline void RSA_get0_crt_params(const RSA* rsakey, const BIGNUM** dmp1, const BIGNUM** dmq1, const BIGNUM** iqmp) {
  *dmp1 = rsakey->dmp1;
  *dmq1 = rsakey->dmq1;
  *iqmp = rsakey->iqmp;
}

static inline int RSA_set0_crt_params(RSA* rsakey, BIGNUM* dmp1, BIGNUM* dmq1, BIGNUM* iqmp) {
  BN_clear_free(rsakey->dmp1);
  rsakey->dmp1 = dmp1;
  BN_clear_free(rsakey->dmq1);
  rsakey->dmq1 = dmq1;
  BN_clear_free(rsakey->iqmp);
  rsakey->iqmp = iqmp;
  return 1;
}

#ifdef HAVE_LIBCRYPTO_ECDSA
static inline void ECDSA_SIG_get0(const ECDSA_SIG* signature, const BIGNUM** pr, const BIGNUM** ps) {
  *pr = signature->r;
  *ps = signature->s;
}

static inline int ECDSA_SIG_set0(ECDSA_SIG* signature, BIGNUM* pr, BIGNUM* ps) {
  BN_clear_free(signature->r);
  BN_clear_free(signature->s);
  signature->r = pr;
  signature->s = ps;
  return 1;
}
#endif /* HAVE_LIBCRYPTO_ECDSA */

#endif /* !defined(LIBRESSL_VERSION_NUMBER) || LIBRESSL_VERSION_NUMBER < 0x2070000fL */

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
  for(int i=0; i<1024; i+=4) {
    r=dns_random(0xffffffff);
    entropy.append((const char*)&r, 4);
  }

  RAND_seed((const unsigned char*)entropy.c_str(), 1024);
}


class OpenSSLRSADNSCryptoKeyEngine : public DNSCryptoKeyEngine
{
public:
  explicit OpenSSLRSADNSCryptoKeyEngine(unsigned int algo): DNSCryptoKeyEngine(algo), d_key(std::unique_ptr<RSA, void(*)(RSA*)>(nullptr, RSA_free))
  {
    int ret = RAND_status();
    if (ret != 1) {
      throw runtime_error(getName()+" insufficient entropy");
    }
  }

  ~OpenSSLRSADNSCryptoKeyEngine()
  {
  }

  string getName() const override { return "OpenSSL RSA"; }
  int getBits() const override { return RSA_size(d_key.get()) << 3; }

  void create(unsigned int bits) override;
  storvector_t convertToISCVector() const override;
  std::string hash(const std::string& hash) const override;
  std::string sign(const std::string& hash) const override;
  bool verify(const std::string& hash, const std::string& signature) const override;
  std::string getPubKeyHash() const override;
  std::string getPublicKeyString() const override;
  void fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap) override;
  void fromPublicKeyString(const std::string& content) override;
  bool checkKey(vector<string> *errorMessages) const override;

  static std::shared_ptr<DNSCryptoKeyEngine> maker(unsigned int algorithm)
  {
    return std::make_shared<OpenSSLRSADNSCryptoKeyEngine>(algorithm);
  }

private:
  static int hashSizeToKind(size_t hashSize);

  std::unique_ptr<RSA, void(*)(RSA*)> d_key;
};


void OpenSSLRSADNSCryptoKeyEngine::create(unsigned int bits)
{
  // When changing the bitsizes, also edit them in ::checkKey
  if ((d_algorithm == DNSSECKeeper::RSASHA1 || d_algorithm == DNSSECKeeper::RSASHA1NSEC3SHA1) && (bits < 512 || bits > 4096)) {
    /* RFC3110 */
    throw runtime_error(getName()+" RSASHA1 key generation failed for invalid bits size " + std::to_string(bits));
  }
  if (d_algorithm == DNSSECKeeper::RSASHA256 && (bits < 512 || bits > 4096)) {
    /* RFC5702 */
    throw runtime_error(getName()+" RSASHA256 key generation failed for invalid bits size " + std::to_string(bits));
  }
  if (d_algorithm == DNSSECKeeper::RSASHA512 && (bits < 1024 || bits > 4096)) {
    /* RFC5702 */
    throw runtime_error(getName()+" RSASHA512 key generation failed for invalid bits size " + std::to_string(bits));
  }

  auto e = std::unique_ptr<BIGNUM, void(*)(BIGNUM*)>(BN_new(), BN_clear_free);
  if (!e) {
    throw runtime_error(getName()+" key generation failed, unable to allocate e");
  }

  /* RSA_F4 is a public exponent value of 65537 */
  int res = BN_set_word(e.get(), RSA_F4);

  if (res == 0) {
    throw runtime_error(getName()+" key generation failed while setting e");
  }

  auto key = std::unique_ptr<RSA, void(*)(RSA*)>(RSA_new(), RSA_free);
  if (!key) {
    throw runtime_error(getName()+" allocation of key structure failed");
  }

  res = RSA_generate_key_ex(key.get(), bits, e.get(), nullptr);
  if (res == 0) {
    throw runtime_error(getName()+" key generation failed");
  }

  d_key = std::move(key);
}


DNSCryptoKeyEngine::storvector_t OpenSSLRSADNSCryptoKeyEngine::convertToISCVector() const
{
  storvector_t storvect;
  typedef vector<pair<string, const BIGNUM*> > outputs_t;
  outputs_t outputs;
  const BIGNUM *n, *e, *d, *p, *q, *dmp1, *dmq1, *iqmp;
  RSA_get0_key(d_key.get(), &n, &e, &d);
  RSA_get0_factors(d_key.get(), &p, &q);
  RSA_get0_crt_params(d_key.get(), &dmp1, &dmq1, &iqmp);
  outputs.push_back(make_pair("Modulus", n));
  outputs.push_back(make_pair("PublicExponent", e));
  outputs.push_back(make_pair("PrivateExponent", d));
  outputs.push_back(make_pair("Prime1", p));
  outputs.push_back(make_pair("Prime2", q));
  outputs.push_back(make_pair("Exponent1", dmp1));
  outputs.push_back(make_pair("Exponent2", dmq1));
  outputs.push_back(make_pair("Coefficient", iqmp));

  string algorithm=std::to_string(d_algorithm);
  switch(d_algorithm) {
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
  storvect.push_back(make_pair("Algorithm", algorithm));

  for(outputs_t::value_type value :  outputs) {
    std::string tmp;
    tmp.resize(BN_num_bytes(value.second));
    int len = BN_bn2bin(value.second, reinterpret_cast<unsigned char*>(&tmp.at(0)));
    if (len >= 0) {
      tmp.resize(len);
      storvect.push_back(make_pair(value.first, tmp));
    }
  }

  return storvect;
}


std::string OpenSSLRSADNSCryptoKeyEngine::hash(const std::string& orig) const
{
  if (d_algorithm == DNSSECKeeper::RSASHA1 || d_algorithm == DNSSECKeeper::RSASHA1NSEC3SHA1) {
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char*) orig.c_str(), orig.length(), hash);
    return string((char*) hash, sizeof(hash));
  }
  else if (d_algorithm == DNSSECKeeper::RSASHA256) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*) orig.c_str(), orig.length(), hash);
    return string((char*) hash, sizeof(hash));
  }
  else if (d_algorithm == DNSSECKeeper::RSASHA512) {
    unsigned char hash[SHA512_DIGEST_LENGTH];
    SHA512((unsigned char*) orig.c_str(), orig.length(), hash);
    return string((char*) hash, sizeof(hash));
  }

  throw runtime_error(getName()+" does not support hash operation for algorithm "+std::to_string(d_algorithm));
}

int OpenSSLRSADNSCryptoKeyEngine::hashSizeToKind(const size_t hashSize)
{
  switch(hashSize) {
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

std::string OpenSSLRSADNSCryptoKeyEngine::sign(const std::string& msg) const
{
  string hash = this->hash(msg);
  int hashKind = hashSizeToKind(hash.size());
  std::string signature;
  signature.resize(RSA_size(d_key.get()));
  unsigned int signatureLen = 0;

  int res = RSA_sign(hashKind, reinterpret_cast<unsigned char*>(&hash.at(0)), hash.length(), reinterpret_cast<unsigned char*>(&signature.at(0)), &signatureLen, d_key.get());
  if (res != 1) {
    throw runtime_error(getName()+" failed to generate signature");
  }

  signature.resize(signatureLen);
  return signature;
}


bool OpenSSLRSADNSCryptoKeyEngine::verify(const std::string& msg, const std::string& signature) const
{
  string hash = this->hash(msg);
  int hashKind = hashSizeToKind(hash.size());

  int ret = RSA_verify(hashKind, (const unsigned char*) hash.c_str(), hash.length(), (unsigned char*) signature.c_str(), signature.length(), d_key.get());

  return (ret == 1);
}


std::string OpenSSLRSADNSCryptoKeyEngine::getPubKeyHash() const
{
  const BIGNUM *n, *e, *d;
  RSA_get0_key(d_key.get(), &n, &e, &d);
  std::vector<unsigned char> tmp;
  tmp.resize(std::max(BN_num_bytes(e), BN_num_bytes(n)));
  unsigned char hash[SHA_DIGEST_LENGTH];
  SHA_CTX ctx;

  int res = SHA1_Init(&ctx);

  if (res != 1) {
    throw runtime_error(getName()+" failed to init hash context for generating the public key hash");
  }

  int len = BN_bn2bin(e, tmp.data());
  res = SHA1_Update(&ctx, tmp.data(), len);
  if (res != 1) {
    throw runtime_error(getName()+" failed to update hash context for generating the public key hash");
  }

  len = BN_bn2bin(n, tmp.data());
  res = SHA1_Update(&ctx, tmp.data(), len);
  if (res != 1) {
    throw runtime_error(getName()+" failed to update hash context for generating the public key hash");
  }

  res = SHA1_Final(hash, &ctx);
  if (res != 1) {
    throw runtime_error(getName()+" failed to finish hash context for generating the public key hash");
  }

  return string((char*) hash, sizeof(hash));
}


std::string OpenSSLRSADNSCryptoKeyEngine::getPublicKeyString() const
{
  const BIGNUM *n, *e, *d;
  RSA_get0_key(d_key.get(), &n, &e, &d);
  string keystring;
  std::string tmp;
  tmp.resize(std::max(BN_num_bytes(e), BN_num_bytes(n)));

  int len = BN_bn2bin(e, reinterpret_cast<unsigned char*>(&tmp.at(0)));
  if (len < 255) {
    keystring.assign(1, (char) (unsigned int) len);
  } else {
    keystring.assign(1, 0);
    uint16_t tempLen = len;
    tempLen = htons(tempLen);
    keystring.append((char*)&tempLen, 2);
  }
  keystring.append(&tmp.at(0), len);

  len = BN_bn2bin(n, reinterpret_cast<unsigned char*>(&tmp.at(0)));
  keystring.append(&tmp.at(0), len);

  return keystring;
}


void OpenSSLRSADNSCryptoKeyEngine::fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap)
{
  typedef map<string, BIGNUM**> places_t;
  places_t places;
  auto key = std::unique_ptr<RSA, void(*)(RSA*)>(RSA_new(), RSA_free);
  if (!key) {
    throw runtime_error(getName()+" allocation of key structure failed");
  }

  BIGNUM *n, *e, *d, *p, *q, *dmp1, *dmq1, *iqmp;
  n = BN_new();
  if (n == nullptr) {
    throw runtime_error(getName()+" allocation of BIGNUM n failed");
  }
  e = BN_new();
  if (e == nullptr) {
    BN_clear_free(n);
    throw runtime_error(getName()+" allocation of BIGNUM e failed");
  }
  d = BN_new();
  if (d == nullptr) {
    BN_clear_free(n);
    BN_clear_free(e);
    throw runtime_error(getName()+" allocation of BIGNUM d failed");
  }
  RSA_set0_key(key.get(), n, e, d);

  p = BN_new();
  if (p == nullptr) {
    throw runtime_error(getName()+" allocation of BIGNUM p failed");
  }
  q = BN_new();
  if (q == nullptr) {
    BN_clear_free(p);
    throw runtime_error(getName()+" allocation of BIGNUM q failed");
  }
  RSA_set0_factors(key.get(), p, q);

  dmp1 = BN_new();
  if (dmp1 == nullptr) {
    throw runtime_error(getName()+" allocation of BIGNUM dmp1 failed");
  }
  dmq1 = BN_new();
  if (dmq1 == nullptr) {
    BN_clear_free(dmp1);
    throw runtime_error(getName()+" allocation of BIGNUM dmq1 failed");
  }
  iqmp = BN_new();
  if (iqmp == nullptr) {
    BN_clear_free(dmq1);
    BN_clear_free(dmp1);
    throw runtime_error(getName()+" allocation of BIGNUM iqmp failed");
  }
  RSA_set0_crt_params(key.get(), dmp1, dmq1, iqmp);

  places["Modulus"]=&n;
  places["PublicExponent"]=&e;
  places["PrivateExponent"]=&d;
  places["Prime1"]=&p;
  places["Prime2"]=&q;
  places["Exponent1"]=&dmp1;
  places["Exponent2"]=&dmq1;
  places["Coefficient"]=&iqmp;

  drc.d_algorithm = pdns_stou(stormap["algorithm"]);

  string raw;
  for(const places_t::value_type& val :  places) {
    raw=stormap[toLower(val.first)];

    if (!val.second)
      continue;

    *val.second = BN_bin2bn((unsigned char*) raw.c_str(), raw.length(), *val.second);
    if (!*val.second) {
      throw runtime_error(getName()+" error loading " + val.first);
    }
  }

  if (drc.d_algorithm != d_algorithm) {
    throw runtime_error(getName()+" tried to feed an algorithm "+std::to_string(drc.d_algorithm)+" to a "+std::to_string(d_algorithm)+" key");
  }

  d_key = std::move(key);
}

bool OpenSSLRSADNSCryptoKeyEngine::checkKey(vector<string> *errorMessages) const
{
  bool retval = true;
  // When changing the bitsizes, also edit them in ::create
  if ((d_algorithm == DNSSECKeeper::RSASHA1 || d_algorithm == DNSSECKeeper::RSASHA1NSEC3SHA1 || d_algorithm == DNSSECKeeper::RSASHA256) && (getBits() < 512 || getBits()> 4096)) {
    retval = false;
    if (errorMessages != nullptr) {
      errorMessages->push_back("key is " + std::to_string(getBits()) + " bytes, should be between 512 and 4096");
    }
  }
  if (d_algorithm == DNSSECKeeper::RSASHA512 && (getBits() < 1024 || getBits() > 4096)) {
    retval = false;
    if (errorMessages != nullptr) {
      errorMessages->push_back("key is " + std::to_string(getBits()) + " bytes, should be between 1024 and 4096");
    }
  }
  if (RSA_check_key(d_key.get()) != 1) {
    retval = false;
    if (errorMessages != nullptr) {
      errorMessages->push_back(ERR_reason_error_string(ERR_get_error()));
    }
  }
  return retval;
}

void OpenSSLRSADNSCryptoKeyEngine::fromPublicKeyString(const std::string& input)
{
  string exponent, modulus;
  const size_t inputLen = input.length();
  const unsigned char* raw = (const unsigned char*)input.c_str();

  if (inputLen < 1) {
    throw runtime_error(getName()+" invalid input size for the public key");
  }

  if (raw[0] != 0) {
    const size_t exponentSize = raw[0];
    if (inputLen < (exponentSize + 2)) {
      throw runtime_error(getName()+" invalid input size for the public key");
    }
    exponent = input.substr(1, exponentSize);
    modulus = input.substr(exponentSize + 1);
  } else {
    if (inputLen < 3) {
      throw runtime_error(getName()+" invalid input size for the public key");
    }
    const size_t exponentSize = raw[1]*0xff + raw[2];
    if (inputLen < (exponentSize + 4)) {
      throw runtime_error(getName()+" invalid input size for the public key");
    }
    exponent = input.substr(3, exponentSize);
    modulus = input.substr(exponentSize + 3);
  }

  auto key = std::unique_ptr<RSA, void(*)(RSA*)>(RSA_new(), RSA_free);
  if (!key) {
    throw runtime_error(getName()+" allocation of key structure failed");
  }

  auto e = std::unique_ptr<BIGNUM, void(*)(BIGNUM*)>(BN_bin2bn((unsigned char*)exponent.c_str(), exponent.length(), nullptr), BN_clear_free);
  if (!e) {
    throw runtime_error(getName()+" error loading e value of public key");
  }
  auto n = std::unique_ptr<BIGNUM, void(*)(BIGNUM*)>(BN_bin2bn((unsigned char*)modulus.c_str(), modulus.length(), nullptr), BN_clear_free);
  if (!n) {
    throw runtime_error(getName()+" error loading n value of public key");
  }

  RSA_set0_key(key.get(), n.release(), e.release(), nullptr);
  d_key = std::move(key);
}

#ifdef HAVE_LIBCRYPTO_ECDSA
class OpenSSLECDSADNSCryptoKeyEngine : public DNSCryptoKeyEngine
{
public:
  explicit OpenSSLECDSADNSCryptoKeyEngine(unsigned int algo) : DNSCryptoKeyEngine(algo), d_eckey(std::unique_ptr<EC_KEY, void(*)(EC_KEY*)>(EC_KEY_new(), EC_KEY_free)), d_ecgroup(std::unique_ptr<EC_GROUP, void(*)(EC_GROUP*)>(nullptr, EC_GROUP_clear_free))
  {

    int ret = RAND_status();
    if (ret != 1) {
      throw runtime_error(getName()+" insufficient entropy");
    }

    if (!d_eckey) {
      throw runtime_error(getName()+" allocation of key structure failed");
    }

    if(d_algorithm == 13) {
      d_ecgroup = std::unique_ptr<EC_GROUP, void(*)(EC_GROUP*)>(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1), EC_GROUP_clear_free);
      d_len = 32;
    } else if (d_algorithm == 14) {
      d_ecgroup = std::unique_ptr<EC_GROUP, void(*)(EC_GROUP*)>(EC_GROUP_new_by_curve_name(NID_secp384r1), EC_GROUP_clear_free);
      d_len = 48;
    } else {
      throw runtime_error(getName()+" unknown algorithm "+std::to_string(d_algorithm));
    }

    if (!d_ecgroup) {
      throw runtime_error(getName()+" allocation of group structure failed");
    }

    ret = EC_KEY_set_group(d_eckey.get(), d_ecgroup.get());
    if (ret != 1) {
      throw runtime_error(getName()+" setting key group failed");
    }
  }

  ~OpenSSLECDSADNSCryptoKeyEngine()
  {
  }

  string getName() const override { return "OpenSSL ECDSA"; }
  int getBits() const override { return d_len << 3; }

  void create(unsigned int bits) override;
  storvector_t convertToISCVector() const override;
  std::string hash(const std::string& hash) const override;
  std::string sign(const std::string& hash) const override;
  bool verify(const std::string& hash, const std::string& signature) const override;
  std::string getPubKeyHash() const override;
  std::string getPublicKeyString() const override;
  void fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap) override;
  void fromPublicKeyString(const std::string& content) override;
  bool checkKey(vector<string> *errorMessages) const override;

  static std::shared_ptr<DNSCryptoKeyEngine> maker(unsigned int algorithm)
  {
    return std::make_shared<OpenSSLECDSADNSCryptoKeyEngine>(algorithm);
  }

private:
  unsigned int d_len;

  std::unique_ptr<EC_KEY, void(*)(EC_KEY*)> d_eckey;
  std::unique_ptr<EC_GROUP, void(*)(EC_GROUP*)> d_ecgroup;
};


void OpenSSLECDSADNSCryptoKeyEngine::create(unsigned int bits)
{
  if (bits >> 3 != d_len) {
    throw runtime_error(getName()+" unknown key length of "+std::to_string(bits)+" bits requested");
  }

  int res = EC_KEY_generate_key(d_eckey.get());
  if (res == 0) {
    throw runtime_error(getName()+" key generation failed");
  }
}


DNSCryptoKeyEngine::storvector_t OpenSSLECDSADNSCryptoKeyEngine::convertToISCVector() const
{
  storvector_t storvect;
  string algorithm;

  if(d_algorithm == 13)
    algorithm = "13 (ECDSAP256SHA256)";
  else if(d_algorithm == 14)
    algorithm = "14 (ECDSAP384SHA384)";
  else
    algorithm = " ? (?)";

  storvect.push_back(make_pair("Algorithm", algorithm));

  const BIGNUM *key = EC_KEY_get0_private_key(d_eckey.get());
  if (key == nullptr) {
    throw runtime_error(getName()+" private key not set");
  }

  std::string tmp;
  tmp.resize(BN_num_bytes(key));
  int len = BN_bn2bin(key, reinterpret_cast<unsigned char*>(&tmp.at(0)));

  string prefix;
  if (d_len - len)
    prefix.append(d_len - len, 0x00);

  storvect.push_back(make_pair("PrivateKey", prefix + tmp));

  return storvect;
}


std::string OpenSSLECDSADNSCryptoKeyEngine::hash(const std::string& orig) const
{
  if(getBits() == 256) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*) orig.c_str(), orig.length(), hash);
    return string((char*) hash, sizeof(hash));
  }
  else if(getBits() == 384) {
    unsigned char hash[SHA384_DIGEST_LENGTH];
    SHA384((unsigned char*) orig.c_str(), orig.length(), hash);
    return string((char*) hash, sizeof(hash));
  }

  throw runtime_error(getName()+" does not support a hash size of "+std::to_string(getBits())+" bits");
}


std::string OpenSSLECDSADNSCryptoKeyEngine::sign(const std::string& msg) const
{
  string hash = this->hash(msg);

  auto signature = std::unique_ptr<ECDSA_SIG, void(*)(ECDSA_SIG*)>(ECDSA_do_sign((unsigned char*) hash.c_str(), hash.length(), d_eckey.get()), ECDSA_SIG_free);
  if (!signature) {
    throw runtime_error(getName()+" failed to generate signature");
  }

  string ret;
  std::string tmp;
  tmp.resize(d_len);

  const BIGNUM *pr, *ps;
  ECDSA_SIG_get0(signature.get(), &pr, &ps);
  int len = BN_bn2bin(pr, reinterpret_cast<unsigned char*>(&tmp.at(0)));
  if (d_len - len)
    ret.append(d_len - len, 0x00);
  ret.append(&tmp.at(0), len);

  len = BN_bn2bin(ps, reinterpret_cast<unsigned char*>(&tmp.at(0)));
  if (d_len - len)
    ret.append(d_len - len, 0x00);
  ret.append(&tmp.at(0), len);

  return ret;
}


bool OpenSSLECDSADNSCryptoKeyEngine::verify(const std::string& msg, const std::string& signature) const
{
  if (signature.length() != (d_len * 2)) {
    throw runtime_error(getName()+" invalid signature size "+std::to_string(signature.length()));
  }

  string hash = this->hash(msg);

  auto sig = std::unique_ptr<ECDSA_SIG, void(*)(ECDSA_SIG*)>(ECDSA_SIG_new(), ECDSA_SIG_free);
  if (!sig) {
    throw runtime_error(getName()+" allocation of signature structure failed");
  }

  auto r = std::unique_ptr<BIGNUM, void(*)(BIGNUM*)>(BN_bin2bn((unsigned char*) signature.c_str(), d_len, nullptr), BN_clear_free);
  auto s = std::unique_ptr<BIGNUM, void(*)(BIGNUM*)>(BN_bin2bn((unsigned char*) signature.c_str() + d_len, d_len, nullptr), BN_clear_free);
  if (!r || !s) {
    throw runtime_error(getName()+" invalid signature");
  }

  ECDSA_SIG_set0(sig.get(), r.release(), s.release());
  int ret = ECDSA_do_verify((unsigned char*) hash.c_str(), hash.length(), sig.get(), d_eckey.get());

  if (ret == -1){
    throw runtime_error(getName()+" verify error");
  }

  return (ret == 1);
}


std::string OpenSSLECDSADNSCryptoKeyEngine::getPubKeyHash() const
{
  string pubKey = getPublicKeyString();
  unsigned char hash[SHA_DIGEST_LENGTH];
  SHA1((unsigned char*) pubKey.c_str(), pubKey.length(), hash);
  return string((char*) hash, sizeof(hash));
}


std::string OpenSSLECDSADNSCryptoKeyEngine::getPublicKeyString() const
{
  std::string binaryPoint;
  binaryPoint.resize((d_len * 2) + 1);

  int ret = EC_POINT_point2oct(d_ecgroup.get(), EC_KEY_get0_public_key(d_eckey.get()), POINT_CONVERSION_UNCOMPRESSED, reinterpret_cast<unsigned char*>(&binaryPoint.at(0)), binaryPoint.size(), nullptr);
  if (ret == 0) {
    throw runtime_error(getName()+" exporting point to binary failed");
  }

  /* we skip the first byte as the other backends use
     raw field elements, as opposed to the format described in
     SEC1: "2.3.3 Elliptic-Curve-Point-to-Octet-String Conversion" */
  binaryPoint.erase(0, 1);
  return binaryPoint;
}


void OpenSSLECDSADNSCryptoKeyEngine::fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap)
{
  drc.d_algorithm = atoi(stormap["algorithm"].c_str());

  if (drc.d_algorithm != d_algorithm) {
    throw runtime_error(getName()+" tried to feed an algorithm "+std::to_string(drc.d_algorithm)+" to a "+std::to_string(d_algorithm)+" key");
  }

  string privateKey = stormap["privatekey"];

  auto prv_key = std::unique_ptr<BIGNUM, void(*)(BIGNUM*)>(BN_bin2bn((unsigned char*) privateKey.c_str(), privateKey.length(), nullptr), BN_clear_free);
  if (!prv_key) {
    throw runtime_error(getName()+" reading private key from binary failed");
  }

  int ret = EC_KEY_set_private_key(d_eckey.get(), prv_key.get());
  if (ret != 1) {
    throw runtime_error(getName()+" setting private key failed");
  }

  auto pub_key = std::unique_ptr<EC_POINT, void(*)(EC_POINT*)>(EC_POINT_new(d_ecgroup.get()), EC_POINT_free);
  if (!pub_key) {
    throw runtime_error(getName()+" allocation of public key point failed");
  }

  ret = EC_POINT_mul(d_ecgroup.get(), pub_key.get(), prv_key.get(), nullptr, nullptr, nullptr);
  if (ret != 1) {
    throw runtime_error(getName()+" computing public key from private failed");
  }

  ret = EC_KEY_set_public_key(d_eckey.get(), pub_key.get());
  if (ret != 1) {
    throw runtime_error(getName()+" setting public key failed");
  }
}

bool OpenSSLECDSADNSCryptoKeyEngine::checkKey(vector<string> *errorMessages) const
{
  bool retval = true;
  if (EC_KEY_check_key(d_eckey.get()) != 1) {
    retval = false;
    if (errorMessages != nullptr) {
      errorMessages->push_back(ERR_reason_error_string(ERR_get_error()));
    }
  }
  return retval;
}

void OpenSSLECDSADNSCryptoKeyEngine::fromPublicKeyString(const std::string& input)
{
  /* uncompressed point, from SEC1:
     "2.3.4 Octet-String-to-Elliptic-Curve-Point Conversion" */
  string ecdsaPoint= "\x04";
  ecdsaPoint.append(input);

  auto pub_key = std::unique_ptr<EC_POINT, void(*)(EC_POINT*)>(EC_POINT_new(d_ecgroup.get()), EC_POINT_free);
  if (!pub_key) {
    throw runtime_error(getName()+" allocation of point structure failed");
  }

  int ret = EC_POINT_oct2point(d_ecgroup.get(), pub_key.get(), (unsigned char*) ecdsaPoint.c_str(), ecdsaPoint.length(), nullptr);
  if (ret != 1) {
    throw runtime_error(getName()+" reading ECP point from binary failed");
  }

  ret = EC_KEY_set_private_key(d_eckey.get(), nullptr);
  if (ret == 1) {
    throw runtime_error(getName()+" setting private key failed");
  }

  ret = EC_KEY_set_public_key(d_eckey.get(), pub_key.get());
  if (ret != 1) {
    throw runtime_error(getName()+" setting public key failed");
  }
}
#endif

#ifdef HAVE_LIBCRYPTO_EDDSA
class OpenSSLEDDSADNSCryptoKeyEngine : public DNSCryptoKeyEngine
{
public:
  explicit OpenSSLEDDSADNSCryptoKeyEngine(unsigned int algo) : DNSCryptoKeyEngine(algo), d_edkey(std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)>(nullptr, EVP_PKEY_free))
  {

    int ret = RAND_status();
    if (ret != 1) {
      throw runtime_error(getName()+" insufficient entropy");
    }

#ifdef HAVE_LIBCRYPTO_ED25519
    if(d_algorithm == 15) {
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
      throw runtime_error(getName()+" unknown algorithm "+std::to_string(d_algorithm));
    }
  }

  ~OpenSSLEDDSADNSCryptoKeyEngine()
  {
  }

  string getName() const override { return "OpenSSL EDDSA"; }
  int getBits() const override { return d_len << 3; }

  void create(unsigned int bits) override;
  storvector_t convertToISCVector() const override;
  std::string sign(const std::string& hash) const override;
  bool verify(const std::string& msg, const std::string& signature) const override;
  std::string getPubKeyHash() const override;
  std::string getPublicKeyString() const override;
  void fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap) override;
  void fromPublicKeyString(const std::string& content) override;
  bool checkKey(vector<string> *errorMessages) const override;

  static std::shared_ptr<DNSCryptoKeyEngine> maker(unsigned int algorithm)
  {
    return std::make_shared<OpenSSLEDDSADNSCryptoKeyEngine>(algorithm);
  }

private:
  size_t d_len{0};
  int d_id{0};

  std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)> d_edkey;
};

bool OpenSSLEDDSADNSCryptoKeyEngine::checkKey(vector<string> *errorMessages) const
{
  return (d_edkey ? true : false);
}

void OpenSSLEDDSADNSCryptoKeyEngine::create(unsigned int bits)
{
  auto pctx = std::unique_ptr<EVP_PKEY_CTX, void(*)(EVP_PKEY_CTX*)>(EVP_PKEY_CTX_new_id(d_id, nullptr), EVP_PKEY_CTX_free);
  if (!pctx) {
    throw runtime_error(getName()+" context initialization failed");
  }
  if (EVP_PKEY_keygen_init(pctx.get()) < 1) {
    throw runtime_error(getName()+" keygen initialization failed");
  }
  EVP_PKEY* newKey = nullptr;
  if (EVP_PKEY_keygen(pctx.get(), &newKey) < 1) {
    throw runtime_error(getName()+" key generation failed");
  }
  d_edkey = std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)>(newKey, EVP_PKEY_free);
}

DNSCryptoKeyEngine::storvector_t OpenSSLEDDSADNSCryptoKeyEngine::convertToISCVector() const
{
  storvector_t storvect;
  string algorithm;

#ifdef HAVE_LIBCRYPTO_ED25519
  if(d_algorithm == 15) {
    algorithm = "15 (ED25519)";
  }
#endif
#ifdef HAVE_LIBCRYPTO_ED448
  if(d_algorithm == 16) {
    algorithm = "16 (ED448)";
  }
#endif
  if (algorithm.empty()) {
    algorithm = " ? (?)";
  }

  storvect.push_back(make_pair("Algorithm", algorithm));

  string buf;
  size_t len = d_len;
  buf.resize(len);
  if (EVP_PKEY_get_raw_private_key(d_edkey.get(), reinterpret_cast<unsigned char*>(&buf.at(0)), &len) < 1) {
    throw runtime_error(getName() + " Could not get private key from d_edkey");
  }
  storvect.push_back(make_pair("PrivateKey", buf));
  return storvect;
}

std::string OpenSSLEDDSADNSCryptoKeyEngine::sign(const std::string& msg) const
{
  auto mdctx = std::unique_ptr<EVP_MD_CTX, void(*)(EVP_MD_CTX*)>(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (!mdctx) {
    throw runtime_error(getName()+" MD context initialization failed");
  }
  if(EVP_DigestSignInit(mdctx.get(), nullptr, nullptr, nullptr, d_edkey.get()) < 1) {
    throw runtime_error(getName()+" unable to initialize signer");
  }

  string msgToSign = msg;

  size_t siglen = d_len * 2;
  string signature;
  signature.resize(siglen);

  if (EVP_DigestSign(mdctx.get(),
        reinterpret_cast<unsigned char*>(&signature.at(0)), &siglen,
        reinterpret_cast<unsigned char*>(&msgToSign.at(0)), msgToSign.length()) < 1) {
    throw runtime_error(getName()+" signing error");
  }

  return signature;
}

bool OpenSSLEDDSADNSCryptoKeyEngine::verify(const std::string& msg, const std::string& signature) const
{
  auto mdctx = std::unique_ptr<EVP_MD_CTX, void(*)(EVP_MD_CTX*)>(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  if (!mdctx) {
    throw runtime_error(getName()+" MD context initialization failed");
  }
  if(EVP_DigestVerifyInit(mdctx.get(), nullptr, nullptr, nullptr, d_edkey.get()) < 1) {
    throw runtime_error(getName()+" unable to initialize signer");
  }

  string checkSignature = signature;
  string checkMsg = msg;

  auto r = EVP_DigestVerify(mdctx.get(),
      reinterpret_cast<unsigned char*>(&checkSignature.at(0)), checkSignature.length(),
      reinterpret_cast<unsigned char*>(&checkMsg.at(0)), checkMsg.length());
  if (r < 0) {
    throw runtime_error(getName()+" verification failure");
  }

  return (r == 1);
}

std::string OpenSSLEDDSADNSCryptoKeyEngine::getPubKeyHash() const
{
  return this->getPublicKeyString();
}

std::string OpenSSLEDDSADNSCryptoKeyEngine::getPublicKeyString() const
{
  string buf;
  size_t len = d_len;
  buf.resize(len);
  if (EVP_PKEY_get_raw_public_key(d_edkey.get(), reinterpret_cast<unsigned char*>(&buf.at(0)), &len) < 1) {
    throw std::runtime_error(getName() + " unable to get public key from key struct");
  }
  return buf;
}

void OpenSSLEDDSADNSCryptoKeyEngine::fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap) {
  drc.d_algorithm = atoi(stormap["algorithm"].c_str());
  if (drc.d_algorithm != d_algorithm) {
    throw runtime_error(getName()+" tried to feed an algorithm "+std::to_string(drc.d_algorithm)+" to a "+std::to_string(d_algorithm)+" key");
  }

  d_edkey = std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)>(EVP_PKEY_new_raw_private_key(d_id, nullptr, reinterpret_cast<unsigned char*>(&stormap["privatekey"].at(0)), stormap["privatekey"].length()), EVP_PKEY_free);
  if (!d_edkey) {
    throw std::runtime_error(getName() + " could not create key structure from private key");
  }
}

void OpenSSLEDDSADNSCryptoKeyEngine::fromPublicKeyString(const std::string& content)
{
  if (content.length() != d_len) {
    throw runtime_error(getName() + " wrong public key length for algorithm " + std::to_string(d_algorithm));
  }

  const unsigned char* raw = reinterpret_cast<const unsigned char*>(content.c_str());

  d_edkey = std::unique_ptr<EVP_PKEY, void(*)(EVP_PKEY*)>(EVP_PKEY_new_raw_public_key(d_id, nullptr, raw, d_len), EVP_PKEY_free);
  if (!d_edkey) {
    throw runtime_error(getName()+" allocation of public key structure failed");
  }
}
#endif // HAVE_LIBCRYPTO_EDDSA

namespace {
  struct LoaderStruct
  {
    LoaderStruct()
    {
      DNSCryptoKeyEngine::report(5, &OpenSSLRSADNSCryptoKeyEngine::maker);
      DNSCryptoKeyEngine::report(7, &OpenSSLRSADNSCryptoKeyEngine::maker);
      DNSCryptoKeyEngine::report(8, &OpenSSLRSADNSCryptoKeyEngine::maker);
      DNSCryptoKeyEngine::report(10, &OpenSSLRSADNSCryptoKeyEngine::maker);
#ifdef HAVE_LIBCRYPTO_ECDSA
      DNSCryptoKeyEngine::report(13, &OpenSSLECDSADNSCryptoKeyEngine::maker);
      DNSCryptoKeyEngine::report(14, &OpenSSLECDSADNSCryptoKeyEngine::maker);
#endif
#ifdef HAVE_LIBCRYPTO_ED25519
      DNSCryptoKeyEngine::report(15, &OpenSSLEDDSADNSCryptoKeyEngine::maker);
#endif
#ifdef HAVE_LIBCRYPTO_ED448
      DNSCryptoKeyEngine::report(16, &OpenSSLEDDSADNSCryptoKeyEngine::maker);
#endif
    }
  } loaderOpenSSL;
}
