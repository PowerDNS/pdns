// utf-8 UTF-8 utf8 UTF8
extern "C" {
#include "ed25519/crypto_sign.h"
}
#include "dnssecinfra.hh"
#include <boost/scoped_ptr.hpp>
using boost::scoped_ptr;

class ED25519DNSCryptoKeyEngine : public DNSCryptoKeyEngine
{
public:
  explicit ED25519DNSCryptoKeyEngine(unsigned int algo) : DNSCryptoKeyEngine(algo)
  {}
  string getName() const { return "Ref10 ED25519"; }
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
    return new ED25519DNSCryptoKeyEngine(algorithm);
  }

private:
  unsigned int d_algorithm;
  unsigned char d_pubkey[PUBLICKEYBYTES];
  unsigned char d_seckey[SECRETKEYBYTES];
            
};

void ED25519DNSCryptoKeyEngine::create(unsigned int bits)
{
  if(bits != 256) {
    throw runtime_error("Unknown key length of "+lexical_cast<string>(bits)+" bits requested from ED25519 class");
  }
  crypto_sign_keypair(d_pubkey, d_seckey);
}

int ED25519DNSCryptoKeyEngine::getBits() const
{
  return 256;
}

DNSCryptoKeyEngine::storvector_t ED25519DNSCryptoKeyEngine::convertToISCVector() const
{
  /*Algorithm: 13 (ED25519P256SHA256)
    PrivateKey: GU6SnQ/Ou+xC5RumuIUIuJZteXT2z0O/ok1s38Et6mQ= */
  storvector_t storvector;
  string algorithm = "250 (ED25519)";
  
  storvector.push_back(make_pair("Algorithm", algorithm));

  vector<unsigned char> buffer;
  storvector.push_back(make_pair("PrivateKey", string((char*)d_seckey, (char*)d_seckey+SECRETKEYBYTES)));
  return storvector;
}

void ED25519DNSCryptoKeyEngine::fromISCMap(DNSKEYRecordContent& drc, std::map<std::string, std::string>& stormap )
{
  /*Private-key-format: v1.2
   Algorithm: 250 (ED25519)
   PrivateKey: GU6SnQ/Ou+xC5RumuIUIuJZteXT2z0O/ok1s38Et6mQ= */
     
  d_algorithm = drc.d_algorithm = atoi(stormap["algorithm"].c_str());
  string privateKey = stormap["privatekey"];

  memcpy(d_seckey, privateKey.c_str(), SECRETKEYBYTES);
  memcpy(d_pubkey, privateKey.c_str() + PUBLICKEYBYTES, PUBLICKEYBYTES);
  // need to set d_pubkey too..
}

// used for the cache, nothing external
std::string ED25519DNSCryptoKeyEngine::getPubKeyHash() const
{
  return string((const char*)d_pubkey, PUBLICKEYBYTES);
}

std::string ED25519DNSCryptoKeyEngine::getPublicKeyString() const
{
  return string((char*)d_pubkey, PUBLICKEYBYTES);
}

void ED25519DNSCryptoKeyEngine::fromPublicKeyString(const std::string&input) 
{
  memcpy(d_pubkey, input.c_str(), PUBLICKEYBYTES);
}

std::string ED25519DNSCryptoKeyEngine::sign(const std::string& msg) const
{
  // full signature, including us making the hash from the message
  unsigned long long smlen = msg.length() + SIGNATUREBYTES;
  scoped_ptr<unsigned char> sm(new unsigned char[smlen]);  

  crypto_sign(sm.get(), &smlen, (const unsigned char*)msg.c_str(), msg.length(), d_seckey);
  
  return string((const char*)sm.get(), SIGNATUREBYTES);
}

std::string ED25519DNSCryptoKeyEngine::hash(const std::string& orig) const
{
  throw runtime_error("hash not implemented");
  return ""; // probably SHA512 for ED25519
}

bool ED25519DNSCryptoKeyEngine::verify(const std::string& msg, const std::string& signature) const
{
  // we have to do the hash too
  // full signature, including us making the hash from the message
  unsigned long long smlen = msg.length() + SIGNATUREBYTES;
  scoped_ptr<unsigned char> sm(new unsigned char[smlen]);  

  memcpy(sm.get(), signature.c_str(), SIGNATUREBYTES);
  memcpy(sm.get() + SIGNATUREBYTES, msg.c_str(), msg.length());
  
  scoped_ptr<unsigned char> m(new unsigned char[smlen]);   

  return crypto_sign_open(m.get(), &smlen, sm.get(), smlen, d_pubkey) == 0;
}

namespace {
struct LoaderED25519Struct
{
  LoaderED25519Struct()
  {
    DNSCryptoKeyEngine::report(250, &ED25519DNSCryptoKeyEngine::maker);
  }
} loadered25519;
}
