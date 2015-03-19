#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <polarssl/rsa.h>
#include <polarssl/base64.h>
#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>
#include <boost/assign/std/vector.hpp> // for 'operator+=()'
#include <boost/assign/list_of.hpp>
#include <boost/make_shared.hpp>
#include <boost/foreach.hpp>
#include <p11-kit/p11-kit.h>

#include "pdns/dnssecinfra.hh"
#include "pdns/logger.hh"
#include "pdns/pdnsexception.hh"
#include "pdns/sha.hh"
#include "pdns/lock.hh"

#include "pkcs11signers.hh"
/* TODO

  - list possible tokens and supported modes
  - Engine: <name>, Slot: <slot>, PIN: <pin>
  - ECDSA support (how to test?)

NB! If you do use this, here is a simple way to get softhsm working

create /etc/pkcs11/modules/softhsm.module

put

module: /usr/lib/softhsm/libsofthsm.so
managed: yes

in it. you need to use softhsm tools to manage this all.

*/

#ifdef HAVE_P11KIT1_V2
static CK_FUNCTION_LIST** p11_modules;
#endif

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

typedef enum { Attribute_Byte, Attribute_Long, Attribute_String } CkaValueType;

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


class Pkcs11Slot {
  private:
    bool d_logged_in;
    CK_FUNCTION_LIST* d_functions; // module functions
    CK_SESSION_HANDLE d_session;
    CK_SLOT_ID d_slot;
    CK_RV d_err;
    pthread_mutex_t d_m;

    void logError(const std::string& operation) const {
      if (d_err) {
        L<<Logger::Error<<"PKCS#11 operation " << operation << " failed: " << d_err << endl;
      }
    }
  public:
    Pkcs11Slot(CK_FUNCTION_LIST* functions, const CK_SLOT_ID& slot) {
      CK_TOKEN_INFO tokenInfo;
      d_slot = slot;
      d_functions = functions;
      d_err = 0;
      d_logged_in = false;
      pthread_mutex_init(&(this->d_m), NULL);
      Lock l(&d_m);

      if ((d_err = d_functions->C_OpenSession(this->d_slot, CKF_SERIAL_SESSION|CKF_RW_SESSION, 0, 0, &(this->d_session)))) {
        logError("C_OpenSession");
        throw PDNSException("Could not open session");
      }
      // check if we need to login
      if ((d_err = d_functions->C_GetTokenInfo(d_slot, &tokenInfo)) == 0) {
        d_logged_in = ((tokenInfo.flags && CKF_LOGIN_REQUIRED) == CKF_LOGIN_REQUIRED);
      } else {
        logError("C_GetTokenInfo");
        throw PDNSException("Cannot get token info for slot " + boost::lexical_cast<std::string>(slot));
      }
    }

    bool Login(const std::string& pin) {
      if (d_logged_in) return true;

      unsigned char *uPin = new unsigned char[pin.size()];
      memcpy(uPin, pin.c_str(), pin.size());
      d_err = d_functions->C_Login(this->d_session, CKU_USER, uPin, pin.size());
      memset(uPin, 0, pin.size());
      delete [] uPin;
      logError("C_Login");

      if (d_err == 0) {
        d_logged_in = true;
      }

      return d_logged_in;
    }

    bool LoggedIn() const { return d_logged_in; }

    CK_SESSION_HANDLE& Session() { return d_session; }

    CK_FUNCTION_LIST* f() { return d_functions; }

    pthread_mutex_t *m() { return &d_m; }
};

class Pkcs11Token {
  private:
    boost::shared_ptr<Pkcs11Slot> d_slot;

    CK_OBJECT_HANDLE d_public_key;
    CK_OBJECT_HANDLE d_private_key;
    CK_KEY_TYPE d_key_type;

    CK_ULONG d_bits;
    std::string d_exponent;
    std::string d_modulus;
    std::string d_ec_point;
    std::string d_ecdsa_params;

    std::string d_label;

    CK_RV d_err;

    void logError(const std::string& operation) const {
      if (d_err) {
        L<<Logger::Error<<"PKCS#11 operation " << operation << " failed: " << d_err << endl;
      }
    };

  public:
    Pkcs11Token(const boost::shared_ptr<Pkcs11Slot>& slot, const std::string& label); 
    ~Pkcs11Token();

    bool Login(const std::string& pin) {
      if (pin.empty()) return CKR_PIN_INVALID; // no empty pin.
      Lock l(d_slot->m());

      if (d_slot->Login(pin) == true) {
        LoadAttributes();
      }

      return LoggedIn();
    }

    bool LoggedIn() const { return d_slot->LoggedIn(); }

    void LoadAttributes() {
      std::vector<P11KitAttribute> attr;
      std::vector<CK_OBJECT_HANDLE> key;
      attr.push_back(P11KitAttribute(CKA_CLASS, (unsigned long)CKO_PRIVATE_KEY));
      attr.push_back(P11KitAttribute(CKA_SIGN, (char)CK_TRUE));
      attr.push_back(P11KitAttribute(CKA_LABEL, d_label));
      FindObjects2(attr, key, 1);
      if (key.size() == 0) {
        L<<Logger::Warning<<"Cannot load PCKS#11 private key "<<d_label<<std::endl;;
        return;
      }
      d_private_key = key[0];
      attr.clear();
      attr.push_back(P11KitAttribute(CKA_CLASS, (unsigned long)CKO_PUBLIC_KEY));
      attr.push_back(P11KitAttribute(CKA_VERIFY, (char)CK_TRUE));
      attr.push_back(P11KitAttribute(CKA_LABEL, d_label));
      FindObjects2(attr, key, 1);
      if (key.size() == 0) {
        L<<Logger::Warning<<"Cannot load PCKS#11 public key "<<d_label<<std::endl;
        return;
      }
      d_public_key = key[0];

      attr.clear();
      attr.push_back(P11KitAttribute(CKA_KEY_TYPE, 0UL));

      if (GetAttributeValue2(d_public_key, attr)==0) {
        d_key_type = attr[0].ulong();
        if (d_key_type == CKK_RSA) {
          attr.clear();
          attr.push_back(P11KitAttribute(CKA_MODULUS, ""));
          attr.push_back(P11KitAttribute(CKA_PUBLIC_EXPONENT, ""));
          attr.push_back(P11KitAttribute(CKA_MODULUS_BITS, 0UL));

          if (!GetAttributeValue2(d_public_key, attr)) {
            d_modulus = attr[0].str();
            d_exponent = attr[1].str();
            d_bits = attr[2].ulong();
          } else {
            throw PDNSException("Cannot load attributes for PCKS#11 public key " + d_label);
          }
        } else if (d_key_type == CKK_EC || d_key_type == CKK_ECDSA) {
          attr.clear();
          attr.push_back(P11KitAttribute(CKA_ECDSA_PARAMS, ""));
          attr.push_back(P11KitAttribute(CKA_EC_POINT, ""));
          if (!GetAttributeValue2(d_public_key, attr)) {
            d_ecdsa_params = attr[0].str();
            if (d_ecdsa_params == "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07") d_bits = 256;
            if (d_ecdsa_params == "\x06\x05\x2b\x81\x04\x00\x22") d_bits = 384;
            d_ec_point = attr[1].str();
          } else {
            throw PDNSException("Cannot load attributes for PCKS#11 public key " + d_label);
          }
        } else {
          throw PDNSException("Cannot determine type for PCKS#11 public key " + d_label);
        }
      } else {
        throw PDNSException("Cannot load attributes for PCKS#11 public key " + d_label);
      }
    }

    int GenerateKeyPair(CK_MECHANISM_PTR mechanism, std::vector<P11KitAttribute>& pubAttributes, std::vector<P11KitAttribute>& privAttributes, CK_OBJECT_HANDLE_PTR pubKey, CK_OBJECT_HANDLE_PTR privKey) {
      Lock l(d_slot->m());

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

      d_err = this->d_slot->f()->C_GenerateKeyPair(d_slot->Session(), mechanism, pubAttr, pubAttributes.size(), privAttr, privAttributes.size(), pubKey, privKey);
      logError("C_GenerateKeyPair");
      delete [] pubAttr;
      delete [] privAttr;

      if (d_err == 0) LoadAttributes();

      return d_err;
    }

    int Sign(const std::string& data, std::string& result, CK_MECHANISM_PTR mechanism) {
      Lock l(d_slot->m());

      CK_BYTE buffer[1024];
      CK_ULONG buflen = sizeof buffer; // should be enough for most signatures.

      // perform signature
      if ((d_err = this->d_slot->f()->C_SignInit(d_slot->Session(), mechanism, d_private_key))) { logError("C_SignInit"); return d_err; }
      d_err = this->d_slot->f()->C_Sign(d_slot->Session(), (unsigned char*)data.c_str(), data.size(), buffer, &buflen);

      if (!d_err) {
        result.assign((char*)buffer, buflen);
      }

      memset(buffer,0,sizeof buffer);
      logError("C_Sign");
      return d_err;
    }

    int Verify(const std::string& data, const std::string& signature, CK_MECHANISM_PTR mechanism) {
      Lock l(d_slot->m());

      if ((d_err = this->d_slot->f()->C_VerifyInit(d_slot->Session(), mechanism, d_public_key))) { logError("C_VerifyInit"); return d_err; }
      d_err = this->d_slot->f()->C_Verify(d_slot->Session(), (unsigned char*)data.c_str(), data.size(), (unsigned char*)signature.c_str(), signature.size());
      logError("C_Verify");
      return d_err;
    }

    int Digest(const std::string& data, std::string& result, CK_MECHANISM_PTR mechanism) {
      Lock l(d_slot->m());

      CK_BYTE buffer[1024];
      CK_ULONG buflen = sizeof buffer; // should be enough for most digests
      if ((d_err = this->d_slot->f()->C_DigestInit(d_slot->Session(), mechanism))) { logError("C_DigestInit"); return d_err; }
      d_err = this->d_slot->f()->C_Digest(d_slot->Session(), (unsigned char*)data.c_str(), data.size(), buffer, &buflen);
      if (!d_err) {
        result.assign((char*)buffer, buflen);
      }
      memset(buffer,0,sizeof buffer);
      logError("C_Digest");
      return d_err;
    }

    int DigestInit(CK_MECHANISM_PTR mechanism) {
      d_err = d_slot->f()->C_DigestInit(d_slot->Session(), mechanism);
      logError("C_DigestInit");
      return d_err;
    }

    int DigestUpdate(const std::string& data) {
      d_err = d_slot->f()->C_DigestUpdate(d_slot->Session(), (unsigned char*)data.c_str(), data.size());
      logError("C_DigestUpdate");
      return d_err;
    }

    int DigestKey(std::string& result) {
      Lock l(d_slot->m());
      CK_MECHANISM mech;
      mech.mechanism = CKM_SHA_1;

      DigestInit(&mech);

      if (d_key_type == CKK_RSA) {
        DigestUpdate(d_modulus);
        DigestUpdate(d_exponent);
      } else if (d_key_type == CKK_EC || d_key_type == CKK_ECDSA) {
        DigestUpdate(d_ec_point);
      }

      DigestFinal(result);

      return d_err;
    }

    int DigestFinal(std::string& result) {
      CK_BYTE buffer[1024] = {0};
      CK_ULONG buflen = sizeof buffer; // should be enough for most digests
      d_err = d_slot->f()->C_DigestFinal(d_slot->Session(), buffer, &buflen);
      if (!d_err) {
        result.assign((char*)buffer, buflen);
      }
      memset(buffer,0,sizeof buffer);
      logError("C_DigestFinal");
      return d_err;
    }

    int FindObjects(const std::vector<P11KitAttribute>& attributes, std::vector<CK_OBJECT_HANDLE>& objects, int maxobjects) {
      Lock l(d_slot->m());
      return FindObjects2(attributes, objects, maxobjects);
    }

    int FindObjects2(const std::vector<P11KitAttribute>& attributes, std::vector<CK_OBJECT_HANDLE>& objects, int maxobjects) {
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
      d_err = this->d_slot->f()->C_FindObjectsInit(d_slot->Session(), attr, k);

      if (d_err) {
        delete [] attr;
        delete [] handles;
        logError("C_FindObjectsInit");
        return d_err;
      }

      count = maxobjects;
      rv = d_err = this->d_slot->f()->C_FindObjects(d_slot->Session(), handles, maxobjects, &count);
      objects.clear();

      if (!rv) {
        for(k=0;k<count;k++) {
          objects.push_back(handles[k]);
        }
      }

      logError("C_FindObjects");

      delete [] attr;
      delete [] handles;

      d_err = this->d_slot->f()->C_FindObjectsFinal(d_slot->Session());
      logError("C_FindObjectsFinal");

      return rv;
    }

    int GetAttributeValue(const CK_OBJECT_HANDLE& object, std::vector<P11KitAttribute>& attributes) 
    {
      Lock l(d_slot->m());
      return GetAttributeValue2(object, attributes);
    }

    int GetAttributeValue2(const CK_OBJECT_HANDLE& object, std::vector<P11KitAttribute>& attributes)
    {
      size_t k;
      CK_ATTRIBUTE_PTR attr;
      attr = new CK_ATTRIBUTE[attributes.size()];

      k = 0;
      BOOST_FOREACH(P11KitAttribute &attribute, attributes) {
        attribute.wattr(attr+k);
        k++;
      }

      // round 1 - get attribute sizes
      d_err = d_slot->f()->C_GetAttributeValue(d_slot->Session(), object, attr, attributes.size());
      logError("C_GetAttributeValue");
      if (d_err) {
        delete [] attr;
        return d_err;
      }

      // then allocate memory
      for(size_t k=0; k < attributes.size(); k++) {
        if (attributes[k].valueType() == Attribute_String) {
          attr[k].pValue = attributes[k].allocate(attr[k].ulValueLen);
        }
      }

      // round 2 - get actual values
      d_err = d_slot->f()->C_GetAttributeValue(d_slot->Session(), object, attr, attributes.size());
      logError("C_GetAttributeValue");

      // copy values to map and release allocated memory
      for(size_t k=0; k < attributes.size(); k++) {
        if (attributes[k].valueType() == Attribute_String) {
          attributes[k].commit(attr[k].ulValueLen);
        }
      }

      delete [] attr;

      return d_err;
    };

    const std::string& Modulus() {
      return d_modulus;
    }

    const std::string& Exponent() {
      return d_exponent;
    }

    const std::string& ECPoint() {
      return d_ec_point;
    }

    const std::string& ECParameters() {
      return d_ecdsa_params;
    }

    CK_KEY_TYPE KeyType() {
      return d_key_type;
    }

    CK_ULONG Bits() {
      return d_bits;
    }

    static boost::shared_ptr<Pkcs11Token> GetToken(const std::string& module, const CK_SLOT_ID& slotId, const std::string& label);
};

static std::map<std::string, boost::shared_ptr<Pkcs11Slot> > pkcs11_slots;
static std::map<std::string, boost::shared_ptr<Pkcs11Token> > pkcs11_tokens;

boost::shared_ptr<Pkcs11Token> Pkcs11Token::GetToken(const std::string& module, const CK_SLOT_ID& slotId, const std::string& label) {
  // see if we can find module
  std::string tidx = module;
  tidx.append("|");
  tidx.append(boost::lexical_cast<std::string>(slotId));
  std::string sidx = tidx;
  tidx.append("|");
  tidx.append(label);
  std::map<std::string, boost::shared_ptr<Pkcs11Token> >::iterator tokenIter;
  std::map<std::string, boost::shared_ptr<Pkcs11Slot> >::iterator slotIter;

  CK_FUNCTION_LIST* functions;

  if ((tokenIter = pkcs11_tokens.find(tidx)) != pkcs11_tokens.end()) return tokenIter->second;

  // see if we have slot
  if ((slotIter = pkcs11_slots.find(sidx)) != pkcs11_slots.end()) {
    pkcs11_tokens[tidx] = boost::make_shared<Pkcs11Token>(slotIter->second, label);
    return pkcs11_tokens[tidx];
  }

#ifdef HAVE_P11KIT1_V2
  functions = p11_kit_module_for_name(p11_modules, module.c_str());
#else
  functions = p11_kit_registered_name_to_module(module.c_str());
#endif
  if (functions == NULL) throw PDNSException("Cannot find PKCS#11 module " + module);
  functions->C_Initialize(NULL); // initialize the module in case it hasn't been done yet.

  // try to locate a slot
   _CK_SLOT_INFO info;
  if (functions->C_GetSlotInfo(slotId, &info)) {
    throw PDNSException(std::string("Cannot find PKCS#11 slot ") + boost::lexical_cast<std::string>(slotId) + std::string(" on module ") + module);
  }

  // store slot
  pkcs11_slots[sidx] = boost::make_shared<Pkcs11Slot>(functions, slotId);

  // looks ok to me.
  pkcs11_tokens[tidx] = boost::make_shared<Pkcs11Token>(pkcs11_slots[sidx], label);

  return pkcs11_tokens[tidx];
}

Pkcs11Token::Pkcs11Token(const boost::shared_ptr<Pkcs11Slot>& slot, const std::string& label) {
  // open a session
  this->d_bits = 0;
  this->d_slot = slot;
  this->d_label = label;
  this->d_err = 0;
  Lock l(d_slot->m());
  if (this->d_slot->LoggedIn()) LoadAttributes();
}

Pkcs11Token::~Pkcs11Token() {
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
  boost::shared_ptr<Pkcs11Token> d_slot;
  d_slot = Pkcs11Token::GetToken(d_module, d_slot_id, d_label);
  if (d_slot->LoggedIn() == false)
    if (d_slot->Login(d_pin) == false)
      throw PDNSException("Not logged in to token");

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

  if ((rv = d_slot->GenerateKeyPair(&mech, pubAttr, privAttr, &pubKey, &privKey))) {
    throw PDNSException("Keypair generation failed");
  }
};

std::string PKCS11DNSCryptoKeyEngine::sign(const std::string& msg) const {
  std::string result;
  boost::shared_ptr<Pkcs11Token> d_slot;
  d_slot = Pkcs11Token::GetToken(d_module, d_slot_id, d_label);
  if (d_slot->LoggedIn() == false)
    if (d_slot->Login(d_pin) == false)
      throw PDNSException("Not logged in to token");

  CK_MECHANISM mech;
  mech.mechanism = dnssec2smech[d_algorithm];
  mech.pParameter = NULL;
  mech.ulParameterLen = 0;
  if (d_slot->Sign(msg, result, &mech)) throw PDNSException("Could not sign data");
  return result;
};

std::string PKCS11DNSCryptoKeyEngine::hash(const std::string& msg) const {
  std::string result;
  CK_MECHANISM mech;
  mech.mechanism = dnssec2hmech[d_algorithm];
  mech.pParameter = NULL;
  mech.ulParameterLen = 0;
  boost::shared_ptr<Pkcs11Token> d_slot;
  d_slot = Pkcs11Token::GetToken(d_module, d_slot_id, d_label);
  if (d_slot->LoggedIn() == false)
    if (d_slot->Login(d_pin) == false)
      throw PDNSException("Not logged in to token");

  if (d_slot->Digest(msg, result, &mech)) {
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
  boost::shared_ptr<Pkcs11Token> d_slot;
  d_slot = Pkcs11Token::GetToken(d_module, d_slot_id, d_label);
  if (d_slot->LoggedIn() == false)
    if (d_slot->Login(d_pin) == false)
      throw PDNSException("Not logged in to token");

  CK_MECHANISM mech;
  mech.mechanism = dnssec2smech[d_algorithm];
  mech.pParameter = NULL;
  mech.ulParameterLen = 0;
  return (d_slot->Verify(msg, signature, &mech) == 0);
};

std::string PKCS11DNSCryptoKeyEngine::getPubKeyHash() const {
  // find us a public key
  boost::shared_ptr<Pkcs11Token> d_slot;
  d_slot = Pkcs11Token::GetToken(d_module, d_slot_id, d_label);
  if (d_slot->LoggedIn() == false)
    if (d_slot->Login(d_pin) == false)
      throw PDNSException("Not logged in to token");

  std::string result;
  if (d_slot->DigestKey(result) == 0) return result;
  return "";
};

std::string PKCS11DNSCryptoKeyEngine::getPublicKeyString() const {
  std::string result("");
  boost::shared_ptr<Pkcs11Token> d_slot;
  d_slot = Pkcs11Token::GetToken(d_module, d_slot_id, d_label);
  if (d_slot->LoggedIn() == false)
    if (d_slot->Login(d_pin) == false)
      throw PDNSException("Not logged in to token");

  if (d_slot->KeyType() == CKK_RSA) {
    if (d_slot->Exponent().length() < 255) {
      result.assign(1, (char) (unsigned int) d_slot->Exponent().length());
    } else {
      result.assign(1, 0);
      uint16_t len=htons(d_slot->Exponent().length());
      result.append((char*)&len, 2);
    }
    result.append(d_slot->Exponent());
    result.append(d_slot->Modulus());
  } else {
    result.append(d_slot->ECPoint());
  }
  return result;
};

int PKCS11DNSCryptoKeyEngine::getBits() const {
  boost::shared_ptr<Pkcs11Token> d_slot;
  d_slot = Pkcs11Token::GetToken(d_module, d_slot_id, d_label);
  if (d_slot->LoggedIn() == false)
    if (d_slot->Login(d_pin) == false)
      throw PDNSException("Not logged in to token");

  return d_slot->Bits();
};

DNSCryptoKeyEngine::storvector_t PKCS11DNSCryptoKeyEngine::convertToISCVector() const {
  storvector_t storvect;
  typedef std::vector<std::pair<std::string, std::string> > outputs_t;
  outputs_t outputs;

  boost::assign::push_back(storvect)
   (make_pair("Algorithm", boost::lexical_cast<std::string>(d_algorithm)))
   (make_pair("Engine", d_module))
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
  static struct LoaderStruct
  {
    LoaderStruct()
    {
#ifdef HAVE_P11KIT1_V2
      p11_modules = p11_kit_modules_load_and_initialize(0);
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
