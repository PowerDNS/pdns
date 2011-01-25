#include <botan/botan.h>
#include <botan/ecdsa.h>
#include <botan/pubkey.h>
#include <botan/look_pk.h>
#include "dnssecinfra.hh"

using namespace Botan;

class ECDSADNSPrivateKey : public DNSPrivateKey
{
public:
  void create(unsigned int bits);
  std::string convertToISC(unsigned int algorithm) const;
  std::string getPubKeyHash() const;
  std::string sign(const std::string& hash) const; 
  bool verify(const std::string& hash, const std::string& signature) const;
  std::string getPublicKeyString() const;
  int getBits() const;
  void fromISCString(DNSKEYRecordContent& drc, const std::string& content);
  void fromPEMString(DNSKEYRecordContent& drc, const std::string& raw)
  {}

  static DNSPrivateKey* maker(unsigned int algorithm)
  {
    return new ECDSADNSPrivateKey();
  }

private:
  static EC_Domain_Params getECParams(unsigned int algorithm);
  shared_ptr<ECDSA_PrivateKey> d_key;
};

EC_Domain_Params ECDSADNSPrivateKey::getECParams(unsigned int algorithm) 
{
  if(algorithm==13)
    return EC_Domain_Params("1.2.840.10045.3.1.7");
  else if(algorithm == 14)
    return EC_Domain_Params("1.3.132.0.34");
  else
    throw runtime_error("Requested for unknown EC domain parameters for algorithm "+lexical_cast<string>(algorithm));
}

void ECDSADNSPrivateKey::create(unsigned int bits)
{
  AutoSeeded_RNG rng;
  EC_Domain_Params params;
  if(bits==256) {
    params = getECParams(13);
  } 
  else if(bits == 384){
    params = getECParams(14);
  }
  else {
    throw runtime_error("Unknown key length of "+lexical_cast<string>(bits)+" bits requested from ECDSA class");
  }
  d_key = shared_ptr<ECDSA_PrivateKey>(new ECDSA_PrivateKey(rng, params));
}

int ECDSADNSPrivateKey::getBits() const
{
  if(d_key->domain() == getECParams(13))
    return 256;
  else if(d_key->domain() == getECParams(14))
    return 384;
  else
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

void ECDSADNSPrivateKey::fromISCString(DNSKEYRecordContent& drc, const std::string& content )
{
  /*Private-key-format: v1.2
   Algorithm: 13 (ECDSAP256SHA256)
   PrivateKey: GU6SnQ/Ou+xC5RumuIUIuJZteXT2z0O/ok1s38Et6mQ= */
  
  istringstream input(content);
  string sline, key, value, privateKey;
  while(getline(input, sline)) {
    tie(key,value)=splitField(sline, ':');
    trim(value);
    if(pdns_iequals(key,"Private-key-format")) {}
    else if(key=="Algorithm")
      drc.d_algorithm = atoi(value.c_str());
    else if(key=="PrivateKey") {
      Pipe pipe(new Base64_Decoder);
      pipe.process_msg(value);
      privateKey=pipe.read_all_as_string();
    }
    else
      throw runtime_error("Unknown field '"+key+"' in Private Key Representation of ECDSA");
  }
  
  BigInt bigint((byte*)privateKey.c_str(), privateKey.length());
  
  EC_Domain_Params params=getECParams(drc.d_algorithm);
  d_key=shared_ptr<ECDSA_PrivateKey>(new ECDSA_PrivateKey(params, bigint));
}

std::string ECDSADNSPrivateKey::getPubKeyHash() const
{
  const BigInt&x = d_key->private_value();
  SecureVector<byte> buffer=BigInt::encode(x);
  return string((const char*)buffer.begin(), (const char*)buffer.end());
}

std::string ECDSADNSPrivateKey::getPublicKeyString() const
{
  const BigInt&x =d_key->public_point().get_affine_x();
  const BigInt&y =d_key->public_point().get_affine_y();
  
  size_t part_size = std::max(x.bytes(), y.bytes());
  MemoryVector<byte> bits(2*part_size);

  x.binary_encode(&bits[part_size - x.bytes()]);
  y.binary_encode(&bits[2*part_size - y.bytes()]);
  return string((const char*)bits.begin(), (const char*)bits.end());
}

std::string ECDSADNSPrivateKey::sign(const std::string& hash) const
{
  ECDSA_Signature_Operation ops(*d_key);
  AutoSeeded_RNG rng;
  SecureVector<byte> signature=ops.sign((byte*)hash.c_str(), hash.length(), rng);
  
  return string((const char*)signature.begin(), (const char*) signature.end());
}

bool ECDSADNSPrivateKey::verify(const std::string& hash, const std::string& signature) const
{
  ECDSA_Verification_Operation ops(*d_key);
  return ops.verify ((byte*)hash.c_str(), hash.length(), (byte*)signature.c_str(), signature.length());
}

namespace {
struct LoaderStruct
{
  LoaderStruct()
  {
    //DNSPrivateKey::report(12, &GOSTDNSPrivateKey::maker);
    DNSPrivateKey::report(13, &ECDSADNSPrivateKey::maker);
    DNSPrivateKey::report(14, &ECDSADNSPrivateKey::maker);
  }
} loader;
}
