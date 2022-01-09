#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <boost/assign/std/vector.hpp> // for 'operator+=()'
#include <boost/assign/list_of.hpp>

#include <boost/format.hpp>
#include "boost/lexical_cast.hpp"

#include <p11-kit/p11-kit.h>

#include "pdns/dnssecinfra.hh"
#include "pdns/logger.hh"
#include "pdns/pdnsexception.hh"
#include "pdns/sha.hh"
#include "pdns/lock.hh"

#ifdef HAVE_LIBCRYPTO_ECDSA
#include <openssl/bn.h>
#include <openssl/ec.h>
#endif

#include "pkcs11signers.hh"

#define ECDSA256_PARAMS "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"
#define ECDSA384_PARAMS "\x06\x05\x2b\x81\x04\x00\x22"

using namespace pdns;

// map for signing algorithms
static std::map<unsigned int,CK_MECHANISM_TYPE> dnssec2smech = boost::assign::map_list_of
(5, CKM_SHA1_RSA_PKCS)
(7, CKM_SHA1_RSA_PKCS)
(8, CKM_SHA256_RSA_PKCS)
(10, CKM_SHA512_RSA_PKCS)
(13, CKM_ECDSA)
(14, CKM_ECDSA);

// map for hashing algorithms
static std::map<unsigned int,CK_MECHANISM_TYPE> dnssec2hmech = boost::assign::map_list_of
(5, CKM_SHA_1)
(7, CKM_SHA_1)
(8, CKM_SHA256)
(10, CKM_SHA512)
(13, CKM_SHA256)
(14, CKM_SHA384);

static std::map<unsigned int,CK_MECHANISM_TYPE> dnssec2cmech = boost::assign::map_list_of
(5, CKM_RSA_PKCS_KEY_PAIR_GEN)
(7, CKM_RSA_PKCS_KEY_PAIR_GEN)
(8, CKM_RSA_PKCS_KEY_PAIR_GEN)
(10, CKM_RSA_PKCS_KEY_PAIR_GEN)
(13, CKM_ECDSA_KEY_PAIR_GEN)
(14, CKM_ECDSA_KEY_PAIR_GEN);

PKCS11DNSCryptoKeyEngine::PKCS11DNSCryptoKeyEngine(unsigned int algorithm): DNSCryptoKeyEngine(algorithm) { d_cached_slot_id = UINT_MAX; }
PKCS11DNSCryptoKeyEngine::~PKCS11DNSCryptoKeyEngine() {}
PKCS11DNSCryptoKeyEngine::PKCS11DNSCryptoKeyEngine(const PKCS11DNSCryptoKeyEngine& orig) : DNSCryptoKeyEngine(orig.d_algorithm) {
  copyValues(orig);
}

void PKCS11DNSCryptoKeyEngine::copyValues(const PKCS11DNSCryptoKeyEngine& orig)
{
 d_cached_slot_id = orig.d_cached_slot_id;
 d_slot_id = orig.d_slot_id;
 d_module = orig.d_module;
 d_pin = orig.d_pin;
 d_label = orig.d_label;
 d_pub_label = orig.d_pub_label;
 d_id = orig.d_id;
 d_pub_id = orig.d_pub_id;
 d_token_serial = orig.d_token_serial;
 d_token_label = orig.d_token_label;
}

Pkcs11Slot& PKCS11DNSCryptoKeyEngine::GetSlot() {
  if (d_slot_id < UINT_MAX)
    return d_module->GetSlot(d_slot_id);
  if (d_cached_slot_id < UINT_MAX)
    return d_module->GetSlot(d_cached_slot_id);
  /* no slot id set - try to find it */

  auto& slots = d_module->GetSlots();
  for(auto& slot : slots) {
    if (d_token_label.size() > 0 && d_token_label != slot.second.GetLabel())
      continue;
    if (d_token_serial.size() > 0 && d_token_serial != slot.second.GetSerialNumber())
      continue;
    /* return first matching slot */
    d_cached_slot_id = slot.second.GetSlotID();
    return slot.second;
  }

  throw PDNSException("No slot found");
}

Pkcs11Slot& PKCS11DNSCryptoKeyEngine::GetSlot() const {
  if (d_slot_id < UINT_MAX)
    return d_module->GetSlot(d_slot_id);
  if (d_cached_slot_id < UINT_MAX)
    return d_module->GetSlot(d_cached_slot_id);
  throw PDNSException("No slot available");
}

void PKCS11DNSCryptoKeyEngine::create(unsigned int bits) {
  std::vector<P11KitAttribute> pubAttr;
  std::vector<P11KitAttribute> privAttr;
  CK_MECHANISM mech;
  auto session = GetSlot().GetSession(true);

  if (session->Login(d_pin) == false)
    throw PDNSException("Not logged in to token");

  try {
    mech.mechanism = dnssec2cmech.at(d_algorithm);
  } catch (std::out_of_range& e) {
    throw PDNSException("pkcs11: unsupported algorithm "+std::to_string(d_algorithm)+ " for key pair generation");
  }

  mech.pParameter = nullptr;
  mech.ulParameterLen = 0;

  if (d_label.empty())
    d_label = "Private key for signing";
  if (d_pub_label.empty())
    d_pub_label = "Public key for signing";
  if (d_id.empty())
    d_id = "\x02";

  pubAttr.push_back(P11KitAttribute(CKA_CLASS, (unsigned long)CKO_PUBLIC_KEY));
  pubAttr.push_back(P11KitAttribute(CKA_TOKEN, (char)CK_TRUE));
  pubAttr.push_back(P11KitAttribute(CKA_VERIFY, (char)CK_TRUE));
  pubAttr.push_back(P11KitAttribute(CKA_LABEL, d_pub_label));
  pubAttr.push_back(P11KitAttribute(CKA_ID, d_id));

  privAttr.push_back(P11KitAttribute(CKA_CLASS, (unsigned long)CKO_PRIVATE_KEY));
  privAttr.push_back(P11KitAttribute(CKA_TOKEN, (char)CK_TRUE));
  privAttr.push_back(P11KitAttribute(CKA_PRIVATE, (char)CK_TRUE));
  privAttr.push_back(P11KitAttribute(CKA_SENSITIVE, (char)CK_TRUE));
  privAttr.push_back(P11KitAttribute(CKA_SIGN, (char)CK_TRUE));
  privAttr.push_back(P11KitAttribute(CKA_LABEL, d_label));
  privAttr.push_back(P11KitAttribute(CKA_ID, d_id));
  privAttr.push_back(P11KitAttribute(CKA_SUBJECT, "\x0c\x07\x6b\x65\x79\x70\x61\x69\x72")); // "keypair" in DER

  if (mech.mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN) {
    std::string pubExp("\000\001\000\001", 4); // 65537
    pubAttr.push_back(P11KitAttribute(CKA_KEY_TYPE, (unsigned long)CKK_RSA));
    pubAttr.push_back(P11KitAttribute(CKA_MODULUS_BITS, (unsigned long)bits));
    pubAttr.push_back(P11KitAttribute(CKA_PUBLIC_EXPONENT, pubExp));

    privAttr.push_back(P11KitAttribute(CKA_KEY_TYPE, (unsigned long)CKK_RSA));
  } else if (mech.mechanism == CKM_ECDSA_KEY_PAIR_GEN) {
    pubAttr.push_back(P11KitAttribute(CKA_KEY_TYPE, (unsigned long)CKK_ECDSA));

    if (d_algorithm == 13) pubAttr.push_back(P11KitAttribute(CKA_ECDSA_PARAMS, ECDSA256_PARAMS));
    else if (d_algorithm == 14) pubAttr.push_back(P11KitAttribute(CKA_ECDSA_PARAMS, ECDSA384_PARAMS));
    else throw PDNSException("pkcs11: unknown algorithm "+std::to_string(d_algorithm)+" for ECDSA key pair generation");

    privAttr.push_back(P11KitAttribute(CKA_KEY_TYPE, (unsigned long)CKK_ECDSA));
  } else {
    throw PDNSException("pkcs11: don't know how make key for algorithm "+std::to_string(d_algorithm));
  }

  if (session->GenerateKeyPair(&mech, pubAttr, privAttr) != CKR_OK) {
    throw PDNSException("Keypair generation failed");
  }
};

std::string PKCS11DNSCryptoKeyEngine::sign(const std::string& msg) const {
  CK_RV rv;
  std::string result;
  std::string input = msg;
  CK_MECHANISM mech;
  mech.mechanism = dnssec2smech[d_algorithm];
  mech.pParameter = nullptr;
  mech.ulParameterLen = 0;

  if (mech.mechanism == CKM_ECDSA)
    input = this->hash(msg);

  auto session = GetSlot().GetSession();
  cerr << "Trying to get a lock" << endl;
  std::scoped_lock lock(session->Lock());
  cerr << "Got a lock" << endl;

  cerr << "Logging in" << endl;
  if (session->Login(d_pin) == false)
    throw PDNSException("Not logged in to token");

  cerr << "Loading private key" << endl;
  if (!session->HasPrivateKey())
    session->LoadPrivateKey(d_priv_attr);

  if (session->Login(d_pin) == false)
    throw PDNSException("Not logged in to token");

  cerr << "Signing data" << endl;
  rv = session->Sign(input, result, &mech);
  cerr << "Done signing" << endl;

  if (rv != CKR_OK)
    throw PDNSException("Could not sign data");

  return result;
};

std::string PKCS11DNSCryptoKeyEngine::hash_locked(const std::string& msg, std::shared_ptr<pdns::Pkcs11Session>& session) const {
  std::string result;
  CK_MECHANISM mech;
  mech.mechanism = dnssec2hmech[d_algorithm];
  mech.pParameter = nullptr;
  mech.ulParameterLen = 0;

  if (session->Digest(msg, result, &mech) != CKR_OK) {
    g_log<<Logger::Error<<"Could not digest using PKCS#11 token - using software workaround"<<endl;
    // FINE! I'll do this myself, then, shall I?
    switch(d_algorithm) {
    case 5: {
      return pdns_sha1sum(msg);
    }
    case 8: {
      return pdns_sha256sum(msg);
    }
    case 10: {
      return pdns_sha512sum(msg);
    }
    case 13: {
      return pdns_sha256sum(msg);
    }
    case 14: {
      return pdns_sha384sum(msg);
    }
    };
  };
  return result;
};

std::string PKCS11DNSCryptoKeyEngine::hash(const std::string& msg) const {
  auto session = GetSlot().GetSession();
  const std::scoped_lock lock(session->Lock());

  return hash_locked(msg, session);
}

bool PKCS11DNSCryptoKeyEngine::verify(const std::string& msg, const std::string& signature) const {
  auto session = GetSlot().GetSession();
  const std::scoped_lock lock(session->Lock());

  if (session->Login(d_pin) == false)
    throw PDNSException("Not logged in to token");

  if (!session->HasPrivateKey())
    session->LoadPrivateKey(d_priv_attr);

  CK_MECHANISM mech;
  mech.mechanism = dnssec2smech[d_algorithm];
  mech.pParameter = nullptr;
  mech.ulParameterLen = 0;

  if (mech.mechanism == CKM_ECDSA) {
    return (session->Verify(this->hash(msg), signature, &mech) == CKR_OK);
  } else {
    return (session->Verify(msg, signature, &mech) == CKR_OK);
  }
};

std::string PKCS11DNSCryptoKeyEngine::getPubKeyHash() const {
  // find us a public key
  auto session = GetSlot().GetSession();
  //const std::scoped_lock lock(session->Lock());

  if (!session->HasPublicKey())
    session->LoadPublicKey(d_pub_attr);

  std::string result;
  if (session->DigestKey(result) == CKR_OK)
    return result;

  throw PDNSException("Could not digest key (maybe it's missing?)");
};

std::string PKCS11DNSCryptoKeyEngine::getPublicKeyString() const {
  std::string result("");
  auto session = GetSlot().GetSession();
  //const std::scoped_lock lock(session->Lock());

  if (!session->HasPublicKey())
    session->LoadPublicKey(d_pub_attr);

  if (session->KeyType() == CKK_RSA) {
    if (session->Exponent().length() < 255) {
      result.assign(1, static_cast<char>(static_cast<unsigned int>(session->Exponent().length())));
    } else {
      result.assign(1, '\0');
      uint16_t len=htons(session->Exponent().length());
      result.append(reinterpret_cast<char*>(&len), 2);
    }
    result.append(session->Exponent());
    result.append(session->Modulus());
  } else {
    result.append(session->ECPoint());
  }
  return result;
};

int PKCS11DNSCryptoKeyEngine::getBits() const {
  auto session = GetSlot().GetSession();
  //const std::scoped_lock lock(session->Lock());

  if (!session->HasPublicKey())
    session->LoadPublicKey(d_pub_attr);

  return session->Bits();
};

DNSCryptoKeyEngine::storvector_t PKCS11DNSCryptoKeyEngine::convertToISCVector() const {
  auto storvect = storvector_t{
    {"Algorithm", std::to_string(d_algorithm) },
    {"Engine", d_module->GetName() }
  };
  if (d_slot_id != UINT_MAX)
    storvect.push_back(std::make_pair("Slot", boost::lexical_cast<std::string>(d_slot_id)));
  if (d_pin.size() > 0)
    storvect.push_back(std::make_pair("PIN", d_pin));
  if (d_id.size() > 0)
    storvect.push_back(std::make_pair("ID", d_id));
  if (d_pub_id.size() > 0 && d_id != d_pub_id)
    storvect.push_back(std::make_pair("PublicID", d_pub_id));
  if (d_label.size() > 0)
    storvect.push_back(std::make_pair("Label", d_label));
  if (d_pub_label.size() > 0 && d_pub_label != d_label)
    storvect.push_back(std::make_pair("PublicLabel", d_pub_label));
  if (d_token_label.size() > 0)
    storvect.push_back(std::make_pair("TokenLabel", d_token_label));
  if (d_token_serial.size() > 0)
     storvect.push_back(std::make_pair("TokenSerial", d_token_serial));
  return storvect;
};

void PKCS11DNSCryptoKeyEngine::createAttributes() {
  d_priv_attr.clear();
  d_pub_attr.clear();

  d_priv_attr.push_back(P11KitAttribute(CKA_CLASS, (unsigned long)CKO_PRIVATE_KEY));
  if (d_id.size() > 0)
    d_priv_attr.push_back(P11KitAttribute(CKA_ID, makeBytesFromHex(d_id)));
  if (d_label.size() > 0)
    d_priv_attr.push_back(P11KitAttribute(CKA_LABEL, d_label));

  d_pub_attr.push_back(P11KitAttribute(CKA_CLASS, (unsigned long)CKO_PUBLIC_KEY));
  if (d_pub_id.size() > 0)
    d_pub_attr.push_back(P11KitAttribute(CKA_ID, makeBytesFromHex(d_pub_id)));
  if (d_pub_label.size() > 0)
    d_pub_attr.push_back(P11KitAttribute(CKA_LABEL, d_pub_label));
}

void PKCS11DNSCryptoKeyEngine::fromISCMap(DNSKEYRecordContent& drc, stormap_t& stormap) {
  drc.d_algorithm = pdns_stou(stormap["algorithm"]);
  d_module = std::make_shared<Pkcs11Module>(stormap["engine"]);
  d_module->Initialize();
  if (stormap.count("slot") > 0)
    d_slot_id = boost::lexical_cast<unsigned long>(stormap["slot"]);
  else
    d_slot_id = UINT_MAX;
  if (stormap.count("pin") > 0)
    d_pin = stormap["pin"];
  if (stormap.count("id") > 0)
    d_id = stormap["id"];
  if (stormap.count("label") > 0)
    d_label = stormap["label"];
  if (stormap.count("publicid") > 0)
    d_pub_id = stormap["publicid"];
  else if (stormap.count("id") > 0)
    d_pub_id = d_id;
  if (stormap.count("publiclabel") > 0)
    d_pub_label = stormap["publiclabel"];
  else
    d_pub_label = d_label;
  if (stormap.count("tokenlabel") > 0)
    d_token_label = stormap["tokenlabel"];
  if (stormap.count("tokenserial") > 0)
    d_token_serial = stormap["tokenserial"];

  (void)GetSlot();
  createAttributes();
};

std::unique_ptr<DNSCryptoKeyEngine> PKCS11DNSCryptoKeyEngine::maker(unsigned int algorithm)
{
  return make_unique<PKCS11DNSCryptoKeyEngine>(algorithm);
}
