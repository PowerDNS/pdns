#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <openssl/obj_mac.h>
#include <openssl/ecdsa.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include "dnssecinfra.hh"


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
    BN_free(prv_key);
    throw runtime_error(getName()+" setting private key failed");
  }

  EC_POINT *pub_key = EC_POINT_new(d_ecgroup);
  if (pub_key == NULL) {
    BN_free(prv_key);
    throw runtime_error(getName()+" allocation of public key point failed");
  }

  ret = EC_POINT_mul(d_ecgroup, pub_key, prv_key, NULL, NULL, d_ctx);
  if (ret != 1) {
    EC_POINT_free(pub_key);
    BN_free(prv_key);
    throw runtime_error(getName()+" computing public key from private failed");
  }

  BN_free(prv_key);

  ret = EC_KEY_set_public_key(d_eckey, pub_key);
  if (ret != 1) {
    EC_POINT_free(pub_key);
    throw runtime_error(getName()+" setting public key failed");
  }

  EC_POINT_free(pub_key);

  ret = EC_KEY_check_key(d_eckey);
  if (ret != 1) {
    throw runtime_error(getName()+" invalid public key");
  }

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

  ret = EC_KEY_check_key(d_eckey);
  if (ret != 1) {
    throw runtime_error(getName()+" invalid public key");
  }
}


namespace {
  struct LoaderStruct
  {
    LoaderStruct()
    {
      DNSCryptoKeyEngine::report(13, &OpenSSLECDSADNSCryptoKeyEngine::maker);
      DNSCryptoKeyEngine::report(14, &OpenSSLECDSADNSCryptoKeyEngine::maker);
    }
  } loaderOpenSSL;
}
