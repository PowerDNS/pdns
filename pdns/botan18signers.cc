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

class ECDSADNSPrivateKey : public DNSPrivateKey
{
public:
  explicit ECDSADNSPrivateKey(unsigned int algo) :d_algorithm(algo)
  {}
  void create(unsigned int bits);
  std::string convertToISC(unsigned int algorithm) const;
  std::string getPubKeyHash() const;
  std::string sign(const std::string& hash) const; 
  std::string hash(const std::string& hash) const; 
  bool verify(const std::string& msg, const std::string& signature) const;
  std::string getPublicKeyString() const;
  int getBits() const;
  void fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap);
  void fromPublicKeyString(unsigned int algorithm, const std::string& content);
  void fromPEMString(DNSKEYRecordContent& drc, const std::string& raw)
  {}

  static DNSPrivateKey* maker(unsigned int algorithm)
  {
    return new ECDSADNSPrivateKey(algorithm);
  }

private:
  static EC_Domain_Params getECParams(unsigned int algorithm);
  shared_ptr<ECDSA_PrivateKey> d_key;
  shared_ptr<ECDSA_PublicKey> d_pubkey;
  unsigned int d_algorithm;
};

EC_Domain_Params ECDSADNSPrivateKey::getECParams(unsigned int algorithm) 
{
  if(algorithm==13)
    return get_EC_Dom_Pars_by_oid("1.2.840.10045.3.1.7");
  else if(algorithm == 14)
    return get_EC_Dom_Pars_by_oid("1.3.132.0.34");
  else
    throw runtime_error("Requested for unknown EC domain parameters for algorithm "+lexical_cast<string>(algorithm));
}

void ECDSADNSPrivateKey::create(unsigned int bits)
{
  AutoSeeded_RNG rng;
  if(bits != 256 && bits != 384) {
    throw runtime_error("Unknown key length of "+lexical_cast<string>(bits)+" bits requested from ECDSA class");
  }
  d_key = shared_ptr<ECDSA_PrivateKey>(new ECDSA_PrivateKey(rng, getECParams((bits == 256) ? 13 : 14)));
  
  PKCS8_Encoder* pk8e= d_key->pkcs8_encoder();
  MemoryVector<byte> getbits=pk8e->key_bits();
  cerr<<makeHexDump(string((char*)&*getbits.begin(), (char*)&*getbits.end()))<<endl;
  
  const BigInt&x = d_key->private_value();
  SecureVector<byte> buffer=BigInt::encode(x);
  cerr<<makeHexDump(string((char*)&*buffer.begin(), (char*)&*buffer.end()))<<endl;
}

int ECDSADNSPrivateKey::getBits() const
{
  if(d_algorithm == 13)
    return 256;
  else if(d_algorithm == 14)
    return 384;
  return -1;
}

std::string ECDSADNSPrivateKey::convertToISC(unsigned int algorithm) const
{
  /*Private-key-format: v1.2
   Algorithm: 13 (ECDSAP256SHA256)
   PrivateKey: GU6SnQ/Ou+xC5RumuIUIuJZteXT2z0O/ok1s38Et6mQ= */
   
  ostringstream ret;
  ret<<"Private-key-format: v1.2\nAlgorithm: ";
  if(getBits()==256) 
    ret << "13 (ECDSAP256SHA256)\n";
  else if(getBits()==384) 
    ret << "14 (ECDSAP384SHA384)\n";
  else 
    ret <<" ? (?)\n";
  
  ret<<"PrivateKey: ";
  
  const BigInt&x = d_key->private_value();
  SecureVector<byte> buffer=BigInt::encode(x);
  
  Pipe pipe(new Base64_Encoder);
  pipe.process_msg(buffer);
  ret<<pipe.read_all_as_string()<<"\n";
  return ret.str();
}

void ECDSADNSPrivateKey::fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap )
{
  /*Private-key-format: v1.2
   Algorithm: 13 (ECDSAP256SHA256)
   PrivateKey: GU6SnQ/Ou+xC5RumuIUIuJZteXT2z0O/ok1s38Et6mQ= */
     
  d_algorithm = drc.d_algorithm = atoi(stormap["algorithm"].c_str());
  string privateKey = stormap["privatekey"];
  
  BigInt bigint((byte*)privateKey.c_str(), privateKey.length());
  
  EC_Domain_Params params=getECParams(drc.d_algorithm);
  
  d_key=shared_ptr<ECDSA_PrivateKey>(new ECDSA_PrivateKey);
  cerr<<"Reading!"<<endl;
  AutoSeeded_RNG rng;
  PKCS8_Decoder* p8e = d_key->pkcs8_decoder(rng);
  unsigned char pkcs8header[]= {0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20};
  if(privateKey.length()*8 == 384) {
    pkcs8header[1]+=0x10;
    pkcs8header[6]+=0x10;
    d_key->set_domain_parameters(getECParams(14));
  }
  else
    d_key->set_domain_parameters(getECParams(13));
  
  string noIdea((char*)pkcs8header, sizeof(pkcs8header));
  noIdea.append(privateKey);
  
  MemoryVector<byte> tmp((byte*)noIdea.c_str(), noIdea.length());
  p8e->key_bits(tmp);
  delete p8e;
}

std::string ECDSADNSPrivateKey::getPubKeyHash() const
{
  const BigInt&x = d_key->private_value();
  SecureVector<byte> buffer=BigInt::encode(x);
  return string((const char*)buffer.begin(), (const char*)buffer.end());
}

std::string ECDSADNSPrivateKey::getPublicKeyString() const
{
  const BigInt&x =d_key->public_point().get_affine_x().get_value();
  const BigInt&y =d_key->public_point().get_affine_y().get_value();
  
  size_t part_size = std::max(x.bytes(), y.bytes());
  MemoryVector<byte> bits(2*part_size);
  
  x.binary_encode(&bits[part_size - x.bytes()]);
  y.binary_encode(&bits[2*part_size - y.bytes()]);
  return string((const char*)bits.begin(), (const char*)bits.end());
}

void ECDSADNSPrivateKey::fromPublicKeyString(unsigned int algorithm, const std::string&input) 
{
  BigInt x, y;
  
  x.binary_decode((const byte*)input.c_str(), input.length()/2);
  y.binary_decode((const byte*)input.c_str() + input.length()/2, input.length()/2);

  d_algorithm = algorithm;

  EC_Domain_Params params=getECParams(algorithm);
  GFpElement gfpx(params.get_curve().get_ptr_mod(), x);
  GFpElement gfpy(params.get_curve().get_ptr_mod(), y);
  PointGFp point(params.get_curve(), gfpx,gfpy);
  d_pubkey = shared_ptr<ECDSA_PublicKey>(new ECDSA_PublicKey(params, point));
  d_key.reset();
}

std::string ECDSADNSPrivateKey::sign(const std::string& msg) const
{
  AutoSeeded_RNG rng;
  string hash = this->hash(msg);
  SecureVector<byte> signature=d_key->sign((byte*)hash.c_str(), hash.length(), rng);
  
  return string((const char*)signature.begin(), (const char*) signature.end());
}

std::string ECDSADNSPrivateKey::hash(const std::string& orig) const
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

bool ECDSADNSPrivateKey::verify(const std::string& msg, const std::string& signature) const
{
  string hash = this->hash(msg);
  ECDSA_PublicKey* key = d_key ? d_key.get() : d_pubkey.get();
  return key->verify((byte*)hash.c_str(), hash.length(), (byte*)signature.c_str(), signature.length());
}
namespace {
struct LoaderStruct
{
  LoaderStruct()
  {
    // DNSPrivateKey::report(12, &GOSTDNSPrivateKey::maker);
    DNSPrivateKey::report(13, &ECDSADNSPrivateKey::maker);
    DNSPrivateKey::report(14, &ECDSADNSPrivateKey::maker);
  }
} loader;
}
