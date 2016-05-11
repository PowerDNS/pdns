#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <openssl/obj_mac.h>
#ifdef HAVE_OPENSSL_ECDSA
#include <openssl/ecdsa.h>
#endif
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include "opensslsigners.hh"
#include "dnssecinfra.hh"


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
  cout<<"Thread cleanup!"<<endl;
  CRYPTO_set_locking_callback(NULL);

  for (int i=0; i<CRYPTO_num_locks(); i++) {
    pthread_mutex_destroy(&(openssllocks[i]));
  }

  OPENSSL_free(openssllocks);
}


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
  explicit OpenSSLRSADNSCryptoKeyEngine(unsigned int algo) : DNSCryptoKeyEngine(algo)
  {
    int ret = RAND_status();
    if (ret != 1) {
      throw runtime_error(getName()+" insufficient entropy");
    }
  }

  ~OpenSSLRSADNSCryptoKeyEngine()
  {
    if (d_key)
      RSA_free(d_key);
  }

  string getName() const { return "OpenSSL RSA"; }
  int getBits() const { return RSA_size(d_key) << 3; }

  void create(unsigned int bits);
  storvector_t convertToISCVector() const;
  std::string hash(const std::string& hash) const;
  std::string sign(const std::string& hash) const;
  bool verify(const std::string& hash, const std::string& signature) const;
  std::string getPubKeyHash() const;
  std::string getPublicKeyString() const;
  void fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap);
  void fromPublicKeyString(const std::string& content);
  bool checkKey() const override;

  static DNSCryptoKeyEngine* maker(unsigned int algorithm)
  {
    return new OpenSSLRSADNSCryptoKeyEngine(algorithm);
  }

private:
  static int hashSizeToKind(size_t hashSize);

  RSA* d_key{NULL};
};


void OpenSSLRSADNSCryptoKeyEngine::create(unsigned int bits)
{
  BIGNUM *e = BN_new();
  if (!e) {
    throw runtime_error(getName()+" key generation failed, unable to allocate e");
  }

  /* RSA_F4 is a public exponent value of 65537 */
  int res = BN_set_word(e, RSA_F4);

  if (res == 0) {
    BN_free(e);
    throw runtime_error(getName()+" key generation failed while setting e");
  }

  RSA* key = RSA_new();
  if (key == NULL) {
    BN_free(e);
    throw runtime_error(getName()+" allocation of key structure failed");
  }

  res = RSA_generate_key_ex(key, bits, e, NULL);
  BN_free(e);
  if (res == 0) {
    RSA_free(key);
    throw runtime_error(getName()+" key generation failed");
  }

  if (d_key)
    RSA_free(d_key);

  d_key = key;
}


DNSCryptoKeyEngine::storvector_t OpenSSLRSADNSCryptoKeyEngine::convertToISCVector() const
{
  storvector_t storvect;
  typedef vector<pair<string, const BIGNUM*> > outputs_t;
  outputs_t outputs;
  outputs.push_back(make_pair("Modulus", d_key->n));
  outputs.push_back(make_pair("PublicExponent",d_key->e));
  outputs.push_back(make_pair("PrivateExponent",d_key->d));
  outputs.push_back(make_pair("Prime1",d_key->p));
  outputs.push_back(make_pair("Prime2",d_key->q));
  outputs.push_back(make_pair("Exponent1",d_key->dmp1));
  outputs.push_back(make_pair("Exponent2",d_key->dmq1));
  outputs.push_back(make_pair("Coefficient",d_key->iqmp));

  string algorithm=std::to_string(d_algorithm);
  switch(d_algorithm) {
    case 5:
    case 7:
      algorithm += " (RSASHA1)";
      break;
    case 8:
      algorithm += " (RSASHA256)";
      break;
    case 10:
      algorithm += " (RSASHA512)";
      break;
    default:
      algorithm += " (?)";
  }
  storvect.push_back(make_pair("Algorithm", algorithm));

  for(outputs_t::value_type value :  outputs) {
    unsigned char tmp[BN_num_bytes(value.second)];
    int len = BN_bn2bin(value.second, tmp);
    storvect.push_back(make_pair(value.first, string((char*) tmp, len)));
  }

  return storvect;
}


std::string OpenSSLRSADNSCryptoKeyEngine::hash(const std::string& orig) const
{
  if (d_algorithm == 5 || d_algorithm == 7) {
    /* RSA SHA1 */
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1((unsigned char*) orig.c_str(), orig.length(), hash);
    return string((char*) hash, sizeof(hash));
  }
  else if (d_algorithm == 8) {
    /* RSA SHA256 */
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char*) orig.c_str(), orig.length(), hash);
    return string((char*) hash, sizeof(hash));
  }
  else if (d_algorithm == 10) {
    /* RSA SHA512 */
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
  unsigned char signature[RSA_size(d_key)];
  unsigned int signatureLen = 0;

  int res = RSA_sign(hashKind, (unsigned char*) hash.c_str(), hash.length(), signature, &signatureLen, d_key);
  if (res != 1) {
    throw runtime_error(getName()+" failed to generate signature");
  }

  return string((char*) signature, signatureLen);
}


bool OpenSSLRSADNSCryptoKeyEngine::verify(const std::string& msg, const std::string& signature) const
{
  string hash = this->hash(msg);
  int hashKind = hashSizeToKind(hash.size());

  int ret = RSA_verify(hashKind, (const unsigned char*) hash.c_str(), hash.length(), (unsigned char*) signature.c_str(), signature.length(), d_key);

  return (ret == 1);
}


std::string OpenSSLRSADNSCryptoKeyEngine::getPubKeyHash() const
{
  unsigned char tmp[std::max(BN_num_bytes(d_key->e), BN_num_bytes(d_key->n))];
  unsigned char hash[SHA_DIGEST_LENGTH];
  SHA_CTX ctx;

  int res = SHA1_Init(&ctx);

  if (res != 1) {
    throw runtime_error(getName()+" failed to init hash context for generating the public key hash");
  }

  int len = BN_bn2bin(d_key->e, tmp);
  res = SHA1_Update(&ctx, tmp, len);
  if (res != 1) {
    throw runtime_error(getName()+" failed to update hash context for generating the public key hash");
  }

  len = BN_bn2bin(d_key->n, tmp);
  res = SHA1_Update(&ctx, tmp, len);
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
  string keystring;
  unsigned char tmp[std::max(BN_num_bytes(d_key->e), BN_num_bytes(d_key->n))];

  int len = BN_bn2bin(d_key->e, tmp);
  if (len < 255) {
    keystring.assign(1, (char) (unsigned int) len);
  } else {
    keystring.assign(1, 0);
    uint16_t tempLen = len;
    tempLen = htons(tempLen);
    keystring.append((char*)&tempLen, 2);
  }
  keystring.append((char *) tmp, len);

  len = BN_bn2bin(d_key->n, tmp);
  keystring.append((char *) tmp, len);

  return keystring;
}


void OpenSSLRSADNSCryptoKeyEngine::fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap)
{
  typedef map<string, BIGNUM**> places_t;
  places_t places;
  RSA* key = RSA_new();
  if (key == NULL) {
    throw runtime_error(getName()+" allocation of key structure failed");
  }

  places["Modulus"]=&key->n;
  places["PublicExponent"]=&key->e;
  places["PrivateExponent"]=&key->d;
  places["Prime1"]=&key->p;
  places["Prime2"]=&key->q;
  places["Exponent1"]=&key->dmp1;
  places["Exponent2"]=&key->dmq1;
  places["Coefficient"]=&key->iqmp;

  drc.d_algorithm = pdns_stou(stormap["algorithm"]);

  string raw;
  for(const places_t::value_type& val :  places) {
    raw=stormap[toLower(val.first)];

    if (!val.second)
      continue;

    if (*val.second)
      BN_clear_free(*val.second);

    *val.second = BN_bin2bn((unsigned char*) raw.c_str(), raw.length(), NULL);
    if (!*val.second) {
      RSA_free(key);
      throw runtime_error(getName()+" error loading " + val.first);
    }
  }

  if (drc.d_algorithm != d_algorithm) {
    RSA_free(key);
    throw runtime_error(getName()+" tried to feed an algorithm "+std::to_string(drc.d_algorithm)+" to a "+std::to_string(d_algorithm)+" key");
  }

  if (d_key)
    RSA_free(d_key);

  d_key = key;
}

bool OpenSSLRSADNSCryptoKeyEngine::checkKey() const
{
  return (RSA_check_key(d_key) == 1);
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

  RSA* key = RSA_new();
  if (key == NULL) {
    throw runtime_error(getName()+" allocation of key structure failed");
  }

  key->e = BN_bin2bn((unsigned char*)exponent.c_str(), exponent.length(), NULL);
  if (!key->e) {
    RSA_free(key);
    throw runtime_error(getName()+" error loading e value of public key");
  }
  key->n = BN_bin2bn((unsigned char*)modulus.c_str(), modulus.length(), NULL);
  if (!key->n) {
    RSA_free(key);
    throw runtime_error(getName()+" error loading n value of public key");
  }

  if (d_key)
    RSA_free(d_key);

  d_key = key;
}

#ifdef HAVE_OPENSSL_ECDSA
class OpenSSLECDSADNSCryptoKeyEngine : public DNSCryptoKeyEngine
{
public:
  explicit OpenSSLECDSADNSCryptoKeyEngine(unsigned int algo) : DNSCryptoKeyEngine(algo)
  {

    int ret = RAND_status();
    if (ret != 1) {
      throw runtime_error(getName()+" insufficient entropy");
    }

    d_eckey = EC_KEY_new();
    if (d_eckey == NULL) {
      throw runtime_error(getName()+" allocation of key structure failed");
    }

    if(d_algorithm == 13) {
      d_ecgroup = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
      d_len = 32;
    } else if (d_algorithm == 14) {
      d_ecgroup = EC_GROUP_new_by_curve_name(NID_secp384r1);
      d_len = 48;
    } else {
      throw runtime_error(getName()+" unknown algorithm "+std::to_string(d_algorithm));
    }
    if (d_ecgroup == NULL) {
      throw runtime_error(getName()+" allocation of group structure failed");
    }

    ret = EC_KEY_set_group(d_eckey,d_ecgroup);
    if (ret != 1) {
      throw runtime_error(getName()+" setting key group failed");
    }

  }

  ~OpenSSLECDSADNSCryptoKeyEngine()
  {
    EC_KEY_free(d_eckey);
    EC_GROUP_free(d_ecgroup);
    BN_CTX_free(d_ctx);
  }

  string getName() const { return "OpenSSL ECDSA"; }
  int getBits() const { return d_len << 3; }

  void create(unsigned int bits);
  storvector_t convertToISCVector() const;
  std::string hash(const std::string& hash) const;
  std::string sign(const std::string& hash) const;
  bool verify(const std::string& hash, const std::string& signature) const;
  std::string getPubKeyHash() const;
  std::string getPublicKeyString() const;
  void fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap);
  void fromPublicKeyString(const std::string& content);
  bool checkKey() const override;

  static DNSCryptoKeyEngine* maker(unsigned int algorithm)
  {
    return new OpenSSLECDSADNSCryptoKeyEngine(algorithm);
  }

private:
  unsigned int d_len;

  EC_KEY *d_eckey = NULL;
  EC_GROUP *d_ecgroup = NULL;
  BN_CTX *d_ctx = NULL;
};


void OpenSSLECDSADNSCryptoKeyEngine::create(unsigned int bits)
{
  if (bits >> 3 != d_len) {
    throw runtime_error(getName()+" unknown key length of "+std::to_string(bits)+" bits requested");
  }

  int res = EC_KEY_generate_key(d_eckey);
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

  const BIGNUM *key = EC_KEY_get0_private_key(d_eckey);
  if (key == NULL) {
    throw runtime_error(getName()+" private key not set");
  }

  unsigned char tmp[BN_num_bytes(key)];
  int len = BN_bn2bin(key, tmp);

  string prefix;
  if (d_len - len)
    prefix.append(d_len - len, 0x00);

  storvect.push_back(make_pair("PrivateKey", prefix + string((char*) tmp, sizeof(tmp))));

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

  ECDSA_SIG *signature = ECDSA_do_sign((unsigned char*) hash.c_str(), hash.length(), d_eckey);
  if (NULL == signature) {
    throw runtime_error(getName()+" failed to generate signature");
  }

  string ret;
  unsigned char tmp[d_len];

  int len = BN_bn2bin(signature->r, tmp);
  if (d_len - len)
    ret.append(d_len - len, 0x00);
  ret.append(string((char*) tmp, len));

  len = BN_bn2bin(signature->s, tmp);
  if (d_len - len)
    ret.append(d_len - len, 0x00);
  ret.append(string((char*) tmp, len));

  ECDSA_SIG_free(signature);

  return ret;
}


bool OpenSSLECDSADNSCryptoKeyEngine::verify(const std::string& msg, const std::string& signature) const
{
  if (signature.length() != (d_len * 2)) {
    throw runtime_error(getName()+" invalid signature size "+std::to_string(signature.length()));
  }

  string hash = this->hash(msg);

  ECDSA_SIG *sig;
  sig = ECDSA_SIG_new();
  if (sig == NULL) {
    throw runtime_error(getName()+" allocation of signature structure failed");
  }

  sig->r = BN_bin2bn((unsigned char*) signature.c_str(), d_len, sig->r);
  sig->s = BN_bin2bn((unsigned char*) signature.c_str() + d_len, d_len, sig->s);
  if (!sig->r || !sig->s) {
    ECDSA_SIG_free(sig);
    throw runtime_error(getName()+" invalid signature");
  }

  int ret = ECDSA_do_verify((unsigned char*) hash.c_str(), hash.length(), sig, d_eckey);

  ECDSA_SIG_free(sig);

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
  unsigned char binaryPoint[(d_len * 2) + 1];

  int ret = EC_POINT_point2oct(d_ecgroup, EC_KEY_get0_public_key(d_eckey), POINT_CONVERSION_UNCOMPRESSED, binaryPoint, sizeof(binaryPoint), d_ctx);
  if (ret == 0) {
    throw runtime_error(getName()+" exporting point to binary failed");
  }

  /* we skip the first byte as the other backends use
     raw field elements, as opposed to the format described in
     SEC1: "2.3.3 Elliptic-Curve-Point-to-Octet-String Conversion" */
  return string((const char *)(binaryPoint + 1), sizeof(binaryPoint) - 1);
}


void OpenSSLECDSADNSCryptoKeyEngine::fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap)
{
  drc.d_algorithm = atoi(stormap["algorithm"].c_str());

  if (drc.d_algorithm != d_algorithm) {
    throw runtime_error(getName()+" tried to feed an algorithm "+std::to_string(drc.d_algorithm)+" to a "+std::to_string(d_algorithm)+" key");
  }

  string privateKey = stormap["privatekey"];

  BIGNUM *prv_key = BN_bin2bn((unsigned char*) privateKey.c_str(), privateKey.length(), NULL);
  if (prv_key == NULL) {
    throw runtime_error(getName()+" reading private key from binary failed");
  }

  int ret = EC_KEY_set_private_key(d_eckey, prv_key);
  if (ret != 1) {
    BN_clear_free(prv_key);
    throw runtime_error(getName()+" setting private key failed");
  }

  EC_POINT *pub_key = EC_POINT_new(d_ecgroup);
  if (pub_key == NULL) {
    BN_clear_free(prv_key);
    throw runtime_error(getName()+" allocation of public key point failed");
  }

  ret = EC_POINT_mul(d_ecgroup, pub_key, prv_key, NULL, NULL, d_ctx);
  if (ret != 1) {
    EC_POINT_free(pub_key);
    BN_clear_free(prv_key);
    throw runtime_error(getName()+" computing public key from private failed");
  }

  BN_clear_free(prv_key);

  ret = EC_KEY_set_public_key(d_eckey, pub_key);
  if (ret != 1) {
    EC_POINT_free(pub_key);
    throw runtime_error(getName()+" setting public key failed");
  }

  EC_POINT_free(pub_key);
}

bool OpenSSLECDSADNSCryptoKeyEngine::checkKey() const
{
  return (EC_KEY_check_key(d_eckey) == 1);
}

void OpenSSLECDSADNSCryptoKeyEngine::fromPublicKeyString(const std::string& input)
{
  /* uncompressed point, from SEC1:
     "2.3.4 Octet-String-to-Elliptic-Curve-Point Conversion" */
  string ecdsaPoint= "\x04";
  ecdsaPoint.append(input);

  EC_POINT *pub_key = EC_POINT_new(d_ecgroup);
  if (pub_key == NULL) {
    throw runtime_error(getName()+" allocation of point structure failed");
  }

  int ret = EC_POINT_oct2point(d_ecgroup, pub_key, (unsigned char*) ecdsaPoint.c_str(), ecdsaPoint.length(), d_ctx);
  if (ret != 1) {
    throw runtime_error(getName()+" reading ECP point from binary failed");
  }

  ret = EC_KEY_set_private_key(d_eckey, NULL);
  if (ret == 1) {
    EC_POINT_free(pub_key);
    throw runtime_error(getName()+" setting private key failed");
  }

  ret = EC_KEY_set_public_key(d_eckey, pub_key);
  if (ret != 1) {
    EC_POINT_free(pub_key);
    throw runtime_error(getName()+" setting public key failed");
  }

  EC_POINT_free(pub_key);
}
#endif


namespace {
  struct LoaderStruct
  {
    LoaderStruct()
    {
      DNSCryptoKeyEngine::report(5, &OpenSSLRSADNSCryptoKeyEngine::maker);
      DNSCryptoKeyEngine::report(7, &OpenSSLRSADNSCryptoKeyEngine::maker);
      DNSCryptoKeyEngine::report(8, &OpenSSLRSADNSCryptoKeyEngine::maker);
      DNSCryptoKeyEngine::report(10, &OpenSSLRSADNSCryptoKeyEngine::maker);
#ifdef HAVE_OPENSSL_ECDSA
      DNSCryptoKeyEngine::report(13, &OpenSSLECDSADNSCryptoKeyEngine::maker);
      DNSCryptoKeyEngine::report(14, &OpenSSLECDSADNSCryptoKeyEngine::maker);
#endif
    }
  } loaderOpenSSL;
}
