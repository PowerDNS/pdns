#include <polarssl/rsa.h>
#include <polarssl/base64.h>
#include <sha.hh>
#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>
#include <boost/assign/std/vector.hpp> // for 'operator+=()'
#include <boost/assign/list_of.hpp>
#include <boost/foreach.hpp>
#include <p11-kit/p11-kit.h>

#include "dnssecinfra.hh"
#include "pkcs11signers.hh"
#include "pdnsexception.hh"
#include "logger.hh"

/* TODO

  - list possible tokens and supported modes
  - Engine: <name>, Slot: <slot>, PIN: <pin>
  - fallback if not supported to polarssl (for hashing)
  - ECDSA support (how to test?)
  - Physical token testing?
  - module-slot locking (as they do not support parallel)

NB! If you do use this, here is a simple way to get softhsm working

create /etc/pkcs11/modules/softhsm.module

put 

module: /usr/lib/softhsm/libsofthsm.so
managed: yes

in it. you need to use softhsm tools to manage this all.

*/



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

// p11 handler for modules

class P11KitModule;
class P11KitSlot;

typedef enum { Attribute_Byte, Attribute_Long, Attribute_String } CkaValueType;

#ifdef HAVE_P11KIT1_V2
static CK_FUNCTION_LIST** p11_modules;
#endif

// Attribute handling
class P11KitAttribute {
private:
  CK_ATTRIBUTE_TYPE type;
  CK_BYTE ckByte;
  CK_ULONG ckLong;
  std::string ckString;
  CkaValueType ckType;
  unsigned char *buffer;
  CK_ULONG buflen;
protected:
  void Init() {
    buffer = NULL;
    buflen = 0;
  };
public:
  P11KitAttribute(CK_ATTRIBUTE_TYPE type, const std::string& value) {
    Init();
    this->type = type;
    setString(value);
  }

  P11KitAttribute(CK_ATTRIBUTE_TYPE type, char value) {
    Init();
    this->type = type;
    setByte(value);
  }

  P11KitAttribute(CK_ATTRIBUTE_TYPE type, unsigned char value) {
    Init();
    this->type = type;
    setByte(value);
  }

  P11KitAttribute(CK_ATTRIBUTE_TYPE type, unsigned long value) {
    Init();
    this->type = type;
    setLong(value);
  }

  CkaValueType valueType() const {
    return ckType;
  }

  const std::string &str() const {
    return ckString;
  };

  unsigned char byte() const {
    return ckByte;
  }

  unsigned long ulong() const {
    return ckLong;
  }

  void setString(const std::string& value) {
    this->ckString = value;
    this->ckType = Attribute_String;
  }

  void setByte(char value) {
    this->ckByte = value;
    this->ckType = Attribute_Byte;
  }

  void setByte(unsigned char value) {
    this->ckByte = value;
    this->ckType = Attribute_Byte;
  }

  void setLong(unsigned long value) {
    this->ckLong = value;
    this->ckType = Attribute_Long;
  }

// this bit is used for getting attribute from object
// we provide a pointer for GetAttributeValue to write to
  CK_BYTE_PTR allocate(CK_ULONG amount) {
    buffer = new unsigned char[amount];
    buflen = amount;
    return buffer;
  }

// and here we copy the results back and delete buffer
  void commit(CK_ULONG amount) {
    if (buffer) {
      this->ckString.assign((char*)buffer, amount);
      delete [] buffer;
    }
    buffer = NULL;
    buflen = 0;
  }

// this is *writable* attribute (you write into it)
  void wattr(CK_ATTRIBUTE_PTR attr) {
    attr->type = type;
    switch(ckType) {
      case Attribute_Byte: {
        attr->pValue = (void*)&ckByte;
        attr->ulValueLen = 1;
        break;
      }
      case Attribute_Long: {
        attr->pValue = (void*)&ckLong;
        attr->ulValueLen = sizeof(CK_ULONG);
        break;
      }
      case Attribute_String: {
        attr->pValue = buffer;
        attr->ulValueLen = buflen;
      }
    };
  };

// this is *readable* attribute (you read from it)
  void rattr(CK_ATTRIBUTE_PTR attr) const {
    attr->type = type;
    switch(ckType) {
      case Attribute_Byte: {
        attr->pValue = (void*)&ckByte;
        attr->ulValueLen = 1;
        break;
      }
      case Attribute_Long: {
        attr->pValue = (void*)&ckLong;
        attr->ulValueLen = sizeof(CK_ULONG);
        break;
      }
      case Attribute_String: {
        attr->pValue = (void*)ckString.c_str();
        attr->ulValueLen = ckString.size();
      }
    };
  };
};

// representation of slot
class P11KitSlot {
private:
  CK_SESSION_HANDLE d_session;
  CK_SLOT_ID d_slot;
  P11KitModule *d_module;

public:
  P11KitSlot();
  P11KitSlot(CK_SLOT_ID slot, P11KitModule *module);
  P11KitSlot(const P11KitSlot& rhs);
  ~P11KitSlot();

  void SetSlot(CK_SLOT_ID slot);
  void SetModule(P11KitModule *module);

  CK_RV OpenSession(CK_FLAGS flags);
  CK_RV CloseSession();

  CK_RV GetInfo(CK_SLOT_INFO_PTR info) const;
  CK_RV GetTokenInfo(CK_TOKEN_INFO_PTR info) const;

  CK_RV Login(const std::string& pin, CK_USER_TYPE user);
  CK_RV Logout();

  CK_RV GenerateKeyPair(CK_MECHANISM_PTR mechanism, std::vector<P11KitAttribute>& pubAttributes, std::vector<P11KitAttribute>& privAttributes, CK_OBJECT_HANDLE_PTR pubKey, CK_OBJECT_HANDLE_PTR privKey);
  CK_RV FindObjects(const std::vector<P11KitAttribute>& attributes, std::vector<CK_OBJECT_HANDLE>& objects, CK_ULONG maxobjects) const;
  CK_RV SetAttributeValue(CK_OBJECT_HANDLE object, const std::vector<P11KitAttribute>& attributes);
  CK_RV GetAttributeValue(CK_OBJECT_HANDLE object, std::vector<P11KitAttribute>& attributes) const;

  CK_RV Sign(const std::string& data, std::string& result, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) const;
  CK_RV Verify(const std::string& data, const std::string& result, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) const;

  CK_RV Digest(const std::string& data, std::string& result, CK_MECHANISM_PTR mechanism) const;

  CK_RV DigestInit(CK_MECHANISM_PTR mechanism) const;
  CK_RV DigestUpdate(const std::string& data) const;
  CK_RV DigestUpdate(CK_OBJECT_HANDLE key) const;
  CK_RV DigestFinal(std::string& result) const;
};

// representation of module (or Engine)
class P11KitModule
{
  public:
    std::string d_module;
    CK_FUNCTION_LIST_PTR functions;

    P11KitModule() {}

    P11KitModule(const std::string& module) {
      this->d_module = module;
    }

    P11KitModule(const P11KitModule& rhs) {
      functions = rhs.functions;
      d_module = rhs.d_module;
    }

    void setModule(const std::string& module) {
      this->d_module = module;
    };

// basically get the function list
    bool initialize() {
#ifdef HAVE_P11KIT1_V2
      functions = p11_kit_module_for_name(p11_modules, d_module.c_str());
#else
      functions = p11_kit_registered_name_to_module(d_module.c_str());
#endif
      if (functions == NULL) return false;
      return true;
    };

// convenience method + checking that slot exists
    bool GetSlot(CK_SLOT_ID slotId, P11KitSlot &slot) {
      _CK_SLOT_INFO info;
      if (this->functions->C_GetSlotInfo(slotId, &info)) {
        return false;
      }
      slot.SetSlot(slotId);
      slot.SetModule(this);
      return true;
    };
};

P11KitSlot::P11KitSlot() { d_module = NULL; };

P11KitSlot::P11KitSlot(CK_SLOT_ID slot, P11KitModule *module)
{
  this->d_slot = slot;
  this->d_module = module;
}

P11KitSlot::P11KitSlot(const P11KitSlot &rhs)
{
  this->d_slot = rhs.d_slot;
  this->d_module = rhs.d_module;
  this->d_session = rhs.d_session;
}

P11KitSlot::~P11KitSlot()
{
  if (this->d_module && this->d_session)
    this->d_module->functions->C_CloseSession(this->d_session);
}

// DO NOT CALL THIS ON YOUR OWN
void P11KitSlot::SetSlot(CK_SLOT_ID slot) {
  this->d_slot = slot;
}

// DO NOT CALL THIS ON YOUR OWN
void P11KitSlot::SetModule(P11KitModule *module) {
  this->d_module = module;
}

// Create new session, mostly uses CKF_SERIAL_SESSION (which is mandatory flag)
// Another flag you can pass is CFK_RW_SESSION
CK_RV P11KitSlot::OpenSession(CK_FLAGS flags)
{
  if (!this->d_module) return 0xff;
  return this->d_module->functions->C_OpenSession(this->d_slot, flags, 0, 0, &(this->d_session));
}

CK_RV P11KitSlot::CloseSession()
{
  if (!this->d_module) return 0xff;
  CK_RV rv = this->d_module->functions->C_CloseSession(this->d_session);
  this->d_session = 0;
  return rv;
}

CK_RV P11KitSlot::GetInfo(CK_SLOT_INFO_PTR info) const
{
  if (!this->d_module) return 0xff;
  return this->d_module->functions->C_GetSlotInfo(this->d_slot, info);
}

CK_RV P11KitSlot::GetTokenInfo(CK_TOKEN_INFO_PTR info) const
{  
  if (!this->d_module) return 0xff;
  return this->d_module->functions->C_GetTokenInfo(this->d_slot, info);
}

CK_RV P11KitSlot::Login(const std::string& pin, CK_USER_TYPE user)
{
  if (!this->d_module) return 0xff;
  CK_RV rv;
  unsigned char *pPin;
  pPin = new unsigned char[pin.size()];
  pin.copy(reinterpret_cast<char*>(pPin), pin.size());
  rv = this->d_module->functions->C_Login(this->d_session, user, pPin, pin.size());
  delete [] pPin;
  return rv;
}

CK_RV P11KitSlot::Logout()
{
  if (!this->d_module) return 0xff;
  return this->d_module->functions->C_Logout(this->d_slot);
}

CK_RV P11KitSlot::GenerateKeyPair(CK_MECHANISM_PTR mechanism, std::vector<P11KitAttribute>& pubAttributes, std::vector<P11KitAttribute>& privAttributes, CK_OBJECT_HANDLE_PTR pubKey, CK_OBJECT_HANDLE_PTR privKey) {
  if (!this->d_module) return 0xff;

  CK_RV rv;
  size_t k;
  CK_ATTRIBUTE_PTR pubAttr, privAttr;
  pubAttr = new CK_ATTRIBUTE[pubAttributes.size()];
  privAttr = new CK_ATTRIBUTE[privAttributes.size()];

  k = 0;
  BOOST_FOREACH(P11KitAttribute& attribute, pubAttributes) {
    attribute.rattr(pubAttr+k);
    k++;
  }

  k = 0;
  BOOST_FOREACH(P11KitAttribute& attribute, privAttributes) {
    attribute.rattr(privAttr+k);
    k++;
  }

  rv = this->d_module->functions->C_GenerateKeyPair(d_session, mechanism, pubAttr, pubAttributes.size(), privAttr, privAttributes.size(), pubKey, privKey); 

  delete [] pubAttr;
  delete [] privAttr;

  return rv;
}

// Finds object(s) that match exactly to attributes
CK_RV P11KitSlot::FindObjects(const std::vector<P11KitAttribute>& attributes, std::vector<CK_OBJECT_HANDLE>& objects, unsigned long maxobjects) const 
{
  if (!this->d_module) return 0xff;
  CK_RV rv;
  size_t k;
  unsigned long count;
  CK_ATTRIBUTE_PTR attr;
  CK_OBJECT_HANDLE_PTR handles = new CK_OBJECT_HANDLE[maxobjects];
  attr = new CK_ATTRIBUTE[attributes.size()];

  k = 0;
  BOOST_FOREACH(const P11KitAttribute& attribute, attributes) {
    attribute.rattr(attr+k);
    k++;
  }

  // perform search
  rv = this->d_module->functions->C_FindObjectsInit(d_session, attr, k);

  if (rv) {
    delete [] attr;
    delete [] handles;
    return rv;
  }

  count = maxobjects;
  rv = this->d_module->functions->C_FindObjects(d_session, handles, maxobjects, &count);

  if (!rv) {
    objects.clear();
    for(k=0;k<count;k++) {
      objects.push_back(handles[k]);
    }
  }

  delete [] attr;
  delete [] handles;

  this->d_module->functions->C_FindObjectsFinal(d_session);

  return rv;
};

// TODO: Untested codepath
CK_RV P11KitSlot::SetAttributeValue(CK_OBJECT_HANDLE object, const std::vector<P11KitAttribute>& attributes)
{
  if (!this->d_module) return 0xff;
  CK_RV rv;
  size_t k;
  CK_ATTRIBUTE_PTR attr;
  attr = new CK_ATTRIBUTE[attributes.size()];

  k = 0;
  BOOST_FOREACH(const P11KitAttribute &attribute, attributes) {
    attribute.rattr(attr+k);
    k++;
  }

  rv = this->d_module->functions->C_SetAttributeValue(d_session, object, attr, attributes.size());

  delete [] attr;
  return rv;
}

CK_RV P11KitSlot::GetAttributeValue(CK_OBJECT_HANDLE object, std::vector<P11KitAttribute>& attributes) const
{
  if (!this->d_module) return 0xff;
  CK_RV rv;
  size_t k;
  CK_ATTRIBUTE_PTR attr;
  attr = new CK_ATTRIBUTE[attributes.size()];

  k = 0;
  BOOST_FOREACH(P11KitAttribute &attribute, attributes) {
    attribute.wattr(attr+k);
    k++;
  }

  // round 1 - get attribute sizes
  rv = this->d_module->functions->C_GetAttributeValue(d_session, object, attr, attributes.size());

  if (rv) {
    delete [] attr;
    return rv;
  }

  // then allocate memory
  for(size_t k=0; k < attributes.size(); k++) {
    if (attributes[k].valueType() == Attribute_String) {
      attr[k].pValue = attributes[k].allocate(attr[k].ulValueLen);
    }
  }

  // round 2 - get actual values
  rv = this->d_module->functions->C_GetAttributeValue(d_session, object, attr, attributes.size());

  // copy values to map and release allocated memory
  for(size_t k=0; k < attributes.size(); k++) {
    if (attributes[k].valueType() == Attribute_String) {
      attributes[k].commit(attr[k].ulValueLen);
    }
  }

  delete [] attr;

  return rv;
};

CK_RV P11KitSlot::Sign(const std::string& data, std::string& result, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) const
{
  if (!this->d_module) return 0xff;
  CK_RV rv;
  CK_BYTE buffer[1024];
  CK_ULONG buflen = sizeof buffer; // should be enough for most signatures.

  // perform signature
  if ((rv = this->d_module->functions->C_SignInit(d_session, mechanism, key))) return rv; // well that failed.
  rv = this->d_module->functions->C_Sign(d_session, (unsigned char*)data.c_str(), data.size(), buffer, &buflen);
  if (!rv) {
    result.assign((char*)buffer, buflen);
  }
  memset(buffer,0,sizeof buffer);

  return rv;
};

CK_RV P11KitSlot::Verify(const std::string& data, const std::string& signature, CK_MECHANISM_PTR mechanism, CK_OBJECT_HANDLE key) const
{
  if (!this->d_module) return 0xff;
  CK_RV rv;
  if ((rv = this->d_module->functions->C_VerifyInit(d_session, mechanism, key))) return rv;
  rv = this->d_module->functions->C_Verify(d_session, (unsigned char*)data.c_str(), data.size(), (unsigned char*)signature.c_str(), signature.size());
  return rv;
};

CK_RV P11KitSlot::Digest(const std::string& data, std::string& result, CK_MECHANISM_PTR mechanism) const
{ 
  if (!this->d_module) return 0xff;
  CK_RV rv;
  CK_BYTE buffer[1024];
  CK_ULONG buflen = sizeof buffer; // should be enough for most digests
  if ((rv = this->d_module->functions->C_DigestInit(d_session, mechanism))) return rv;
  rv = this->d_module->functions->C_Digest(d_session, (unsigned char*)data.c_str(), data.size(), buffer, &buflen);
  if (!rv) {
    result.assign((char*)buffer, buflen);
  }
  memset(buffer,0,sizeof buffer);

  return rv;
};

CK_RV P11KitSlot::DigestInit(CK_MECHANISM_PTR mechanism) const
{
  if (!this->d_module) return 0xff;
  return this->d_module->functions->C_DigestInit(d_session, mechanism);
}

CK_RV P11KitSlot::DigestUpdate(const std::string& data) const
{
  if (!this->d_module) return 0xff;
  return this->d_module->functions->C_DigestUpdate(d_session, (unsigned char*)data.c_str(), data.size());
}

CK_RV P11KitSlot::DigestUpdate(CK_OBJECT_HANDLE key) const
{
  if (!this->d_module) return 0xff;
  return this->d_module->functions->C_DigestKey(d_session, key);
}

CK_RV P11KitSlot::DigestFinal(std::string& result) const
{
  if (!this->d_module) return 0xff;
  CK_RV rv;
  CK_BYTE buffer[1024];
  CK_ULONG buflen = sizeof buffer; // should be enough for most digests
  rv = this->d_module->functions->C_DigestFinal(d_session, buffer, &buflen);
  if (!rv) {
    result.assign((char*)buffer, buflen);
  }
  memset(buffer,0,sizeof buffer);
  return rv;
}

// map between engine names and engines
static std::map<std::string, P11KitModule> pkcs11_engines;
// map between engine names and slots (not used now)
//static std::map<std::string, CK_SLOT_ID> pkcs11_slots;

static bool pkcs11_GetSlot(const std::string& engine, CK_SLOT_ID slotId, const std::string& pin, CK_FLAGS flags, P11KitSlot& slot) 
{
  CK_RV rv;
  if (engine.empty()) return false;

  // open module if necessary
  if (pkcs11_engines.find(engine) == pkcs11_engines.end()) {
    P11KitModule module(engine);
    if (module.initialize() == false) {
      throw PDNSException("Cannot initialize or unknown PKCS#11 engine " + engine);
    }
    pkcs11_engines[engine] = module;
  }
  pkcs11_engines[engine].GetSlot(slotId, slot);
  rv = slot.OpenSession(flags);
  if (rv) { 
    return false; 
  };
  rv = slot.Login(pin, CKU_USER);
  if (rv) {
    L<<Logger::Error<<"Login failed for " << engine << " slot " << slotId << ": " << rv <<std::endl;
  };
  return rv == 0;
}

PKCS11DNSCryptoKeyEngine::PKCS11DNSCryptoKeyEngine(unsigned int algorithm): DNSCryptoKeyEngine(algorithm) {}
PKCS11DNSCryptoKeyEngine::~PKCS11DNSCryptoKeyEngine() {}
PKCS11DNSCryptoKeyEngine::PKCS11DNSCryptoKeyEngine(const PKCS11DNSCryptoKeyEngine& orig) : DNSCryptoKeyEngine(orig.d_algorithm) {}

void PKCS11DNSCryptoKeyEngine::create(unsigned int bits) {
  std::vector<P11KitAttribute> pubAttr;
  std::vector<P11KitAttribute> privAttr;
  CK_MECHANISM mech;
  CK_OBJECT_HANDLE pubKey, privKey;
  CK_RV rv;
  P11KitSlot d_slot;
  pkcs11_GetSlot(d_engine, d_slot_id, d_pin, CKF_SERIAL_SESSION|CKF_RW_SESSION, d_slot);
  std::string pubExp("\000\001\000\001", 4); // 65537
  
  pubAttr.push_back(P11KitAttribute(CKA_CLASS, (unsigned long)CKO_PUBLIC_KEY));
  pubAttr.push_back(P11KitAttribute(CKA_KEY_TYPE, (unsigned long)CKK_RSA));
  pubAttr.push_back(P11KitAttribute(CKA_TOKEN, (char)CK_TRUE));
  pubAttr.push_back(P11KitAttribute(CKA_ENCRYPT, (char)CK_TRUE));
  pubAttr.push_back(P11KitAttribute(CKA_VERIFY, (char)CK_TRUE));
  pubAttr.push_back(P11KitAttribute(CKA_WRAP, (char)CK_TRUE));
  pubAttr.push_back(P11KitAttribute(CKA_MODULUS_BITS, (unsigned long)bits));
  pubAttr.push_back(P11KitAttribute(CKA_PUBLIC_EXPONENT, pubExp)); 
  pubAttr.push_back(P11KitAttribute(CKA_LABEL, d_label));

  privAttr.push_back(P11KitAttribute(CKA_CLASS, (unsigned long)CKO_PRIVATE_KEY));
  privAttr.push_back(P11KitAttribute(CKA_KEY_TYPE, (unsigned long)CKK_RSA));
  privAttr.push_back(P11KitAttribute(CKA_TOKEN, (char)CK_TRUE));
  privAttr.push_back(P11KitAttribute(CKA_PRIVATE, (char)CK_TRUE));
//  privAttr.push_back(P11KitAttribute(CKA_SUBJECT, "CN=keygen"));
  privAttr.push_back(P11KitAttribute(CKA_ID, "\x01\x02\x03\x04")); // this is mandatory if you want to export anything
  privAttr.push_back(P11KitAttribute(CKA_SENSITIVE, (char)CK_TRUE));
  privAttr.push_back(P11KitAttribute(CKA_DECRYPT, (char)CK_TRUE));
  privAttr.push_back(P11KitAttribute(CKA_SIGN, (char)CK_TRUE));
  privAttr.push_back(P11KitAttribute(CKA_UNWRAP, (char)CK_TRUE));
  privAttr.push_back(P11KitAttribute(CKA_LABEL, d_label));

  mech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
  mech.pParameter = NULL;
  mech.ulParameterLen = 0;

  if ((rv = d_slot.GenerateKeyPair(&mech, pubAttr, privAttr, &pubKey, &privKey))) {
    std::ostringstream error;
    error << "Keypair generation failed with " << rv;
    throw PDNSException(error.str());
  }
};

std::string PKCS11DNSCryptoKeyEngine::sign(const std::string& msg) const { 
  std::string result;
  std::vector<CK_OBJECT_HANDLE> key;
  std::vector<P11KitAttribute> attr;
  P11KitSlot d_slot;
  pkcs11_GetSlot(d_engine, d_slot_id, d_pin, CKF_SERIAL_SESSION, d_slot);
  // find key that can be used for signing 
  attr.push_back(P11KitAttribute(CKA_SIGN, (char)CK_TRUE));
  attr.push_back(P11KitAttribute(CKA_LABEL, d_label));
  d_slot.FindObjects(attr, key, 1);
  // hopefully we have a key
  if (key.size() == 0) return "";
  // choose mech
  CK_MECHANISM mech;
  mech.mechanism = dnssec2smech[d_algorithm];
  mech.pParameter = NULL;
  mech.ulParameterLen = 0;
  d_slot.Sign(msg, result, &mech, key[0]);
  return result;
};

std::string PKCS11DNSCryptoKeyEngine::hash(const std::string& msg) const {
  std::string result;
  CK_MECHANISM mech;
  mech.mechanism = dnssec2hmech[d_algorithm];
  mech.pParameter = NULL;
  mech.ulParameterLen = 0;
  P11KitSlot d_slot;
  pkcs11_GetSlot(d_engine, d_slot_id, d_pin, CKF_SERIAL_SESSION, d_slot);

  if (d_slot.Digest(msg, result, &mech)) {
    // FINE! I'll do this myself, then, shall I?
    switch(d_algorithm) {
    case 5: {
      SHA1Summer sha;
      sha.feed(msg);
      return sha.get();
    }
    case 8: {
      SHA256Summer sha;
      sha.feed(msg);
      return sha.get();
    }
    case 10: {
      SHA512Summer sha;
      sha.feed(msg);
      return sha.get();
    }
    case 13: {
      SHA256Summer sha;
      sha.feed(msg);
      return sha.get();
    }
    case 14: {
      SHA384Summer sha;
      sha.feed(msg);
      return sha.get();
    }
    };
  };
  return result;
};

bool PKCS11DNSCryptoKeyEngine::verify(const std::string& msg, const std::string& signature) const {
  bool result;
  std::vector<CK_OBJECT_HANDLE> key;
  std::vector<P11KitAttribute> attr;
  // find a key that can be used to verify signatures
  attr.push_back(P11KitAttribute(CKA_VERIFY, (char)CK_TRUE));
  attr.push_back(P11KitAttribute(CKA_LABEL, d_label));
  P11KitSlot d_slot;
  pkcs11_GetSlot(d_engine, d_slot_id, d_pin, CKF_SERIAL_SESSION, d_slot);

  d_slot.FindObjects(attr, key, 1);
  // hopefully we have a key
  if (key.size() == 0) return "";
  // choose mech
  CK_MECHANISM mech;
  mech.mechanism = dnssec2smech[d_algorithm];
  mech.pParameter = NULL;
  mech.ulParameterLen = 0;
  result = d_slot.Verify(msg, signature, &mech, key[0]);
  return result;
};

std::string PKCS11DNSCryptoKeyEngine::getPubKeyHash() const { 
  std::string result = "";
  std::vector<CK_OBJECT_HANDLE> key;
  std::vector<P11KitAttribute> attr;
  // find us a public key
  attr.push_back(P11KitAttribute(CKA_CLASS, CKO_PUBLIC_KEY));
  attr.push_back(P11KitAttribute(CKA_LABEL, d_label));
  P11KitSlot d_slot;
  pkcs11_GetSlot(d_engine, d_slot_id, d_pin, CKF_SERIAL_SESSION, d_slot);

  d_slot.FindObjects(attr, key, 1);
  if (key.size() > 0) {
     attr.clear();
     attr.push_back(P11KitAttribute(CKA_MODULUS, ""));
     attr.push_back(P11KitAttribute(CKA_PUBLIC_EXPONENT, ""));
     if (d_slot.GetAttributeValue(key[0], attr) == 0) {
       CK_MECHANISM mech;
       mech.mechanism = CKM_SHA_1;
       d_slot.DigestInit(&mech);
       d_slot.DigestUpdate(attr[0].str());
       d_slot.DigestUpdate(attr[1].str());
       d_slot.DigestFinal(result);
     }
  }
  return result; 
};

std::string PKCS11DNSCryptoKeyEngine::getPublicKeyString() const {
  std::string result("");
  std::vector<CK_OBJECT_HANDLE> key;
  std::vector<P11KitAttribute> attr;
  attr.push_back(P11KitAttribute(CKA_LABEL, d_label));
  P11KitSlot d_slot;
  pkcs11_GetSlot(d_engine, d_slot_id, d_pin, CKF_SERIAL_SESSION, d_slot);

  d_slot.FindObjects(attr, key, 1);
  if (key.size() > 0) {
     attr.clear();
     attr.push_back(P11KitAttribute(CKA_MODULUS, ""));
     attr.push_back(P11KitAttribute(CKA_PUBLIC_EXPONENT, ""));
     if (d_slot.GetAttributeValue(key[0], attr) == 0) {
       if(attr[1].str().length() < 255)
         result.assign(1, (char) (unsigned int) attr[1].str().length());
       else {
         result.assign(1, 0);
         uint16_t len=htons(attr[1].str().length());
         result.append((char*)&len, 2);
       } 
       result.append(attr[1].str());
       result.append(attr[0].str());
     }
//   } else {
//     std::cerr << "Could not find key" << std::endl;
   }
   return result;
};

int PKCS11DNSCryptoKeyEngine::getBits() const {
  int bits = -1;
  std::vector<CK_OBJECT_HANDLE> key;
  std::vector<P11KitAttribute> attr;
  attr.push_back(P11KitAttribute(CKA_CLASS, CKO_PUBLIC_KEY));
  attr.push_back(P11KitAttribute(CKA_LABEL, d_label));
  P11KitSlot d_slot;
  pkcs11_GetSlot(d_engine, d_slot_id, d_pin, CKF_SERIAL_SESSION, d_slot);

//  std::cerr << "Looking for " << d_label << " from " << d_slot_id << std::endl;

  d_slot.FindObjects(attr, key, 1);
  if (key.size() > 0) {
     attr.clear(); 
     attr.push_back(P11KitAttribute(CKA_MODULUS_BITS, 0UL));
     if (d_slot.GetAttributeValue(key[0], attr) == 0) {
       bits = static_cast<int>(attr[0].ulong());
     }
//  } else {
//     std::cerr << "Could not find key" << std::endl;
  }
  return bits;
};

DNSCryptoKeyEngine::storvector_t PKCS11DNSCryptoKeyEngine::convertToISCVector() const { 
  storvector_t storvect;
  typedef std::vector<std::pair<std::string, std::string> > outputs_t;
  outputs_t outputs;

  boost::assign::push_back(storvect)
   (make_pair("Algorithm", boost::lexical_cast<std::string>(d_algorithm)))
   (make_pair("Engine", d_engine))
   (make_pair("Slot", boost::lexical_cast<std::string>(d_slot_id)))
   (make_pair("PIN", d_pin))
   (make_pair("Label", d_label));
  return storvect;
};

DNSCryptoKeyEngine* PKCS11DNSCryptoKeyEngine::maker(unsigned int algorithm)
{
  return new PKCS11DNSCryptoKeyEngine(algorithm);
}

// this is called during program startup
namespace {
struct LoaderStruct
{
  LoaderStruct()
  {
#ifdef HAVE_P11KIT1_V2
    p11_modules = p11_kit_modules_load(NULL, 0);
#else
    p11_kit_initialize_registered();
#endif
  };
  ~LoaderStruct() {
#ifdef HAVE_P11KIT1_V2
    p11_kit_modules_release(p11_modules);
#else
    p11_kit_finalize_registered();
#endif
  };
} loaderPkcs11;
}
