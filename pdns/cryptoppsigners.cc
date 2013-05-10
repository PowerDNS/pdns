#include <cryptopp/osrng.h>
#include <cryptopp/aes.h>
#include <cryptopp/integer.h>
#include <cryptopp/sha.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/filters.h>
#include "dnssecinfra.hh"
using namespace CryptoPP;

template<class HASHER, class CURVE, int BITS>
class CryptoPPECDSADNSCryptoKeyEngine : public DNSCryptoKeyEngine
{
public:
  explicit CryptoPPECDSADNSCryptoKeyEngine(unsigned int algo) : DNSCryptoKeyEngine(algo)
  {}
  void create(unsigned int bits);
  string getName() const { return "CryptoPP ECDSA"; }
  storvector_t convertToISCVector() const;
  std::string getPubKeyHash() const;
  std::string sign(const std::string& msg) const;
  std::string hash(const std::string& hash) const;
  bool verify(const std::string& msg, const std::string& signature) const;
  std::string getPublicKeyString() const;
  int getBits() const;
  void fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap);
  void fromPublicKeyString(const std::string& content);
  // void fromPEMString(DNSKEYRecordContent& drc, const std::string& raw);

  static DNSCryptoKeyEngine* maker(unsigned int algorithm)
  {
    return new CryptoPPECDSADNSCryptoKeyEngine(algorithm);
  }

private:
  typedef typename ECDSA<ECP, HASHER>::PrivateKey privatekey_t;
  typedef typename ECDSA<ECP, HASHER>::PublicKey publickey_t;
  shared_ptr<privatekey_t> d_key;
  shared_ptr<publickey_t> d_pubkey;
};

template<class HASHER, class CURVE, int BITS> void CryptoPPECDSADNSCryptoKeyEngine<HASHER,CURVE,BITS>::create(unsigned int bits)
{
  if(bits != BITS)
    throw runtime_error("This CryptoPP class can only hosts keys of length "+lexical_cast<string>(BITS));
  AutoSeededRandomPool prng;
  privatekey_t* privateKey = new privatekey_t();
  CryptoPP::OID oid=CURVE();
  privateKey->Initialize( prng, oid);
  d_key= shared_ptr<privatekey_t>(privateKey);

  publickey_t* publicKey = new publickey_t();
  d_key->MakePublicKey(*publicKey);
  d_pubkey = shared_ptr<publickey_t>(publicKey);
}

template<class HASHER, class CURVE, int BITS>
int CryptoPPECDSADNSCryptoKeyEngine<HASHER,CURVE,BITS>::getBits() const
{
  return BITS;
}

template<class HASHER, class CURVE, int BITS>
DNSCryptoKeyEngine::storvector_t CryptoPPECDSADNSCryptoKeyEngine<HASHER,CURVE,BITS>::convertToISCVector() const
{
   /* Algorithm: 13 (ECDSAP256SHA256)
   PrivateKey: GU6SnQ/Ou+xC5RumuIUIuJZteXT2z0O/ok1s38Et6mQ= */
  string algostr=lexical_cast<string>(d_algorithm);
  if(d_algorithm==13)
    algostr+=" (ECDSAP256SHA256)";
  else if(d_algorithm==14)
    algostr+=" (ECDSAP384SHA384)";
  else
    algostr+=" (?)";

  storvector_t storvect;
  storvect.push_back(make_pair("Algorithm", algostr));

  const CryptoPP::Integer& pe=d_key->GetPrivateExponent();
  unsigned char buffer[pe.MinEncodedSize()];
  pe.Encode(buffer, pe.MinEncodedSize());
  storvect.push_back(make_pair("PrivateKey", string((char*)buffer, sizeof(buffer))));
  return storvect;
}

template<class HASHER, class CURVE, int BITS>
void CryptoPPECDSADNSCryptoKeyEngine<HASHER,CURVE,BITS>::fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap )
{
  AutoSeededRandomPool prng;
  privatekey_t* privateKey = new privatekey_t;
  const CryptoPP::Integer x(reinterpret_cast<const unsigned char*>(stormap["privatekey"].c_str()), BITS/8); // well it should be this long
  CryptoPP::OID oid=CURVE();
  privateKey->Initialize(oid, x);
  bool result = privateKey->Validate(prng, 3);
  if (!result) {
      throw runtime_error("Cannot load private key - validation failed!");
  }
  d_key = shared_ptr<privatekey_t>(privateKey);
  publickey_t* publicKey = new publickey_t();
  d_key->MakePublicKey(*publicKey);
  d_pubkey = shared_ptr<publickey_t>(publicKey);
  drc.d_algorithm = atoi(stormap["algorithm"].c_str());
}

template<class HASHER, class CURVE, int BITS>
std::string CryptoPPECDSADNSCryptoKeyEngine<HASHER,CURVE,BITS>::getPubKeyHash() const
{
  return getPublicKeyString(); // sad, hashme please!
}
template<class HASHER, class CURVE, int BITS>
std::string CryptoPPECDSADNSCryptoKeyEngine<HASHER,CURVE,BITS>::getPublicKeyString() const
{
  const ECP::Point& q = d_pubkey->GetPublicElement();

  const CryptoPP::Integer& qx = q.x;
  const CryptoPP::Integer& qy = q.y;

  unsigned char buffer[qx.MinEncodedSize() + qy.MinEncodedSize()];
  qx.Encode(buffer, qx.MinEncodedSize());
  qy.Encode(buffer + qx.MinEncodedSize(), qy.MinEncodedSize());

  return string((char*)buffer, sizeof(buffer));
}
template<class HASHER, class CURVE, int BITS>
void CryptoPPECDSADNSCryptoKeyEngine<HASHER,CURVE,BITS>::fromPublicKeyString(const std::string& rawString)
{
  CryptoPP::Integer x, y;
  x.Decode((byte*)rawString.c_str(), rawString.size()/2);
  y.Decode((byte*)rawString.c_str() + rawString.size()/2, rawString.size()/2);

  ECP::Point q(x,y);

  publickey_t* pubkey = new publickey_t;
  CryptoPP::OID oid=CURVE();
  pubkey->Initialize(oid, q);
  d_pubkey = shared_ptr<publickey_t>(pubkey);
  d_key.reset();
}
template<class HASHER, class CURVE, int BITS>
std::string CryptoPPECDSADNSCryptoKeyEngine<HASHER,CURVE,BITS>::sign(const std::string& msg) const
{
  string signature;
  AutoSeededRandomPool prng;
  StringSource( msg, true /*pump all*/,
    new SignerFilter( prng,
        typename ECDSA<ECP,HASHER>::Signer( *d_key ),
        new StringSink( signature )
    ) // SignerFilter
  ); // StringSource
  return signature;

}
template<class HASHER, class CURVE, int BITS>
std::string CryptoPPECDSADNSCryptoKeyEngine<HASHER,CURVE,BITS>::hash(const std::string& orig) const
{
  string hash;
  HASHER hasher;
  StringSource( orig, true /*pump all*/,
    new HashFilter(hasher, new StringSink( hash )
    ) // HashFilter
  ); // StringSource
  return hash;
}
template<class HASHER, class CURVE, int BITS>
bool CryptoPPECDSADNSCryptoKeyEngine<HASHER,CURVE,BITS>::verify(const std::string& msg, const std::string& signature) const
{
  byte result;
  StringSource( signature+msg, true /*pump all*/,
    new SignatureVerificationFilter(
        typename ECDSA<ECP,HASHER>::Verifier(*d_pubkey),
        new ArraySink( (byte*)&result, sizeof(result) )
    ) // SignatureVerificationFilter
  );
  return result;
}

namespace {
struct WrapperSECP256R1
{
  operator CryptoPP::OID () const  {    return CryptoPP::ASN1::secp256r1();  }
};
struct WrapperSECP384R1
{
  operator CryptoPP::OID () const  {    return CryptoPP::ASN1::secp384r1();  }
};
struct LoaderStruct
{
  LoaderStruct()
  {
    DNSCryptoKeyEngine::report(13, &CryptoPPECDSADNSCryptoKeyEngine<SHA256, WrapperSECP256R1, 256>::maker);
    DNSCryptoKeyEngine::report(14, &CryptoPPECDSADNSCryptoKeyEngine<SHA384, WrapperSECP384R1, 384>::maker);
  }
} loaderCryptoPP;
}
