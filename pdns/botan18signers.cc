// utf-8 UTF-8 utf8 UTF8
#include <botan/botan.h>
#include <botan/ecdsa.h>
#include <botan/ecdsa_op.h>
#include <botan/sha2_32.h>
#include <botan/sha2_64.h>
#include <botan/pubkey.h>
#include <botan/look_pk.h>
#include "dnssecinfra.hh"

using namespace Botan;

class ECDSADNSCryptoKeyEngine : public DNSCryptoKeyEngine
{
public:
  explicit ECDSADNSCryptoKeyEngine(unsigned int algo) : DNSCryptoKeyEngine(algo)
  {}
  string getName() const { return "Botan 1.8 ECDSA"; }
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
    return new ECDSADNSCryptoKeyEngine(algorithm);
  }

private:
  static EC_Domain_Params getECParams(unsigned int algorithm);
  shared_ptr<ECDSA_PrivateKey> d_key;
  shared_ptr<ECDSA_PublicKey> d_pubkey;
};

EC_Domain_Params ECDSADNSCryptoKeyEngine::getECParams(unsigned int algorithm)
{
  if(algorithm==13)
    return get_EC_Dom_Pars_by_oid("1.2.840.10045.3.1.7");
  else if(algorithm == 14)
    return get_EC_Dom_Pars_by_oid("1.3.132.0.34");
  else
    throw runtime_error("Requested for unknown EC domain parameters for algorithm "+lexical_cast<string>(algorithm));
}

void ECDSADNSCryptoKeyEngine::create(unsigned int bits)
{
  AutoSeeded_RNG rng;
  if(bits != 256 && bits != 384) {
    throw runtime_error("Unknown key length of "+lexical_cast<string>(bits)+" bits requested from ECDSA class");
  }
  d_key = shared_ptr<ECDSA_PrivateKey>(new ECDSA_PrivateKey(rng, getECParams((bits == 256) ? 13 : 14)));

//  PKCS8_Encoder* pk8e= d_key->pkcs8_encoder();
//  MemoryVector<byte> getbits=pk8e->key_bits();
//  cerr<<makeHexDump(string((char*)&*getbits.begin(), (char*)&*getbits.end()))<<endl;

//  const BigInt&x = d_key->private_value();
//  SecureVector<byte> buffer=BigInt::encode(x);
//   cerr<<makeHexDump(string((char*)&*buffer.begin(), (char*)&*buffer.end()))<<endl;
}

int ECDSADNSCryptoKeyEngine::getBits() const
{
  if(d_algorithm == 13)
    return 256;
  else if(d_algorithm == 14)
    return 384;
  return -1;
}

DNSCryptoKeyEngine::storvector_t ECDSADNSCryptoKeyEngine::convertToISCVector() const
{
  /*Algorithm: 13 (ECDSAP256SHA256)
    PrivateKey: GU6SnQ/Ou+xC5RumuIUIuJZteXT2z0O/ok1s38Et6mQ= */
  storvector_t storvector;
  string algorithm;
  if(getBits()==256)
    algorithm= "13 (ECDSAP256SHA256)";
  else if(getBits()==384)
    algorithm=  "14 (ECDSAP384SHA384)";
  else
    algorithm= " ? (?)";

  storvector.push_back(make_pair("Algorithm", algorithm));

  const BigInt&x = d_key->private_value();
  SecureVector<byte> buffer=BigInt::encode(x);
  storvector.push_back(make_pair("PrivateKey", string((char*)&*buffer.begin(), (char*)&*buffer.end())));
  return storvector;
}

void ECDSADNSCryptoKeyEngine::fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap )
{
  /*Private-key-format: v1.2
   Algorithm: 13 (ECDSAP256SHA256)
   PrivateKey: GU6SnQ/Ou+xC5RumuIUIuJZteXT2z0O/ok1s38Et6mQ= */

  drc.d_algorithm = atoi(stormap["algorithm"].c_str());
  if(drc.d_algorithm != d_algorithm)
    throw runtime_error("Tried to feed an algorithm "+lexical_cast<string>(drc.d_algorithm)+" to a "+lexical_cast<string>(d_algorithm)+" key!");

  string privateKey = stormap["privatekey"];

  BigInt bigint((byte*)privateKey.c_str(), privateKey.length());

  EC_Domain_Params params=getECParams(drc.d_algorithm);

  d_key=shared_ptr<ECDSA_PrivateKey>(new ECDSA_PrivateKey);
  AutoSeeded_RNG rng;

  SecureVector<byte> octstr_secret = BigInt::encode_1363(bigint, getBits()/8);
  SecureVector<byte> octstr_params = encode_der_ec_dompar(params, ENC_EXPLICIT);

  MemoryVector<byte> data = DER_Encoder()
          .start_cons(SEQUENCE)
          .encode(BigInt(1))
          .encode(octstr_secret, OCTET_STRING)
          .end_cons()
          .get_contents();

  PKCS8_Decoder *p8e = d_key->pkcs8_decoder(rng);

  if (d_algorithm == 13)
     p8e->alg_id(AlgorithmIdentifier("1.2.840.10045.3.1.7", octstr_params));
  else
     p8e->alg_id(AlgorithmIdentifier("1.3.132.0.34", octstr_params));

  p8e->key_bits(data);
  delete p8e;
}

std::string ECDSADNSCryptoKeyEngine::getPubKeyHash() const
{
  BigInt x = d_key->private_value();
  SecureVector<byte> buffer=BigInt::encode(x);
  return string((const char*)buffer.begin(), (const char*)buffer.end());
}

std::string ECDSADNSCryptoKeyEngine::getPublicKeyString() const
{
  BigInt x =d_key->public_point().get_affine_x().get_value();
  BigInt y =d_key->public_point().get_affine_y().get_value();

  size_t part_size = std::max(x.bytes(), y.bytes());
  MemoryVector<byte> bits(2*part_size);

  x.binary_encode(&bits[part_size - x.bytes()]);
  y.binary_encode(&bits[2*part_size - y.bytes()]);
  return string((const char*)bits.begin(), (const char*)bits.end());
}

void ECDSADNSCryptoKeyEngine::fromPublicKeyString(const std::string&input)
{
  BigInt x, y;

  x.binary_decode((const byte*)input.c_str(), input.length()/2);
  y.binary_decode((const byte*)input.c_str() + input.length()/2, input.length()/2);

  EC_Domain_Params params=getECParams(d_algorithm);
  GFpElement gfpx(params.get_curve().get_ptr_mod(), x);
  GFpElement gfpy(params.get_curve().get_ptr_mod(), y);
  PointGFp point(params.get_curve(), gfpx,gfpy);
  d_pubkey = shared_ptr<ECDSA_PublicKey>(new ECDSA_PublicKey(params, point));
  d_key.reset();
}

std::string ECDSADNSCryptoKeyEngine::sign(const std::string& msg) const
{
  AutoSeeded_RNG rng;
  string hash = this->hash(msg);
  Default_ECDSA_Op ops(d_key->domain_parameters(), d_key->private_value(), d_key->public_point());
  SecureVector<byte> signature=ops.sign((byte*)hash.c_str(), hash.length(), rng);
  return string((const char*)signature.begin(), (const char*) signature.end());
}

std::string ECDSADNSCryptoKeyEngine::hash(const std::string& orig) const
{
  SecureVector<byte> result;
  if(getBits() == 256) { // SHA256
    SHA_256 hasher;
    result= hasher.process(orig);
  }
  else { // SHA384
    SHA_384 hasher;
    result = hasher.process(orig);
  }

  return string((const char*)result.begin(), (const char*) result.end());
}

bool ECDSADNSCryptoKeyEngine::verify(const std::string& msg, const std::string& signature) const
{
  string hash = this->hash(msg);
  ECDSA_PublicKey* key = d_key ? d_key.get() : d_pubkey.get();
  Default_ECDSA_Op ops(key->domain_parameters(), BigInt(0), key->public_point());
  return ops.verify((byte*)signature.c_str(), signature.length(), (byte*)hash.c_str(), hash.length());
}
namespace {
struct LoaderBotan18Struct
{
  LoaderBotan18Struct()
  {
    // DNSCryptoKeyEngine::report(12, &GOSTDNSCryptoKeyEngine::maker);
    DNSCryptoKeyEngine::report(13, &ECDSADNSCryptoKeyEngine::maker);
    DNSCryptoKeyEngine::report(14, &ECDSADNSCryptoKeyEngine::maker);
  }
} loaderbotan18;
}
