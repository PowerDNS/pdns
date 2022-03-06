/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <stdexcept>
#include <boost/assign/std/vector.hpp> // for 'operator+=()'
#include <boost/assign/list_of.hpp>

#include <boost/format.hpp>
#include <p11-kit/p11-kit.h>
#include <p11-kit/pin.h>

#include "pdns/dnssecinfra.hh"
#include "pdns/logger.hh"
#include "pdns/pdnsexception.hh"
#include "pdns/sha.hh"
#include "pdns/lock.hh"

#ifdef HAVE_LIBCRYPTO_ECDSA
#include <openssl/bn.h>
#include <openssl/ec.h>
#endif

#include "pkcs11infra.hh"

#define ECDSA256_PARAMS "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07" // prime256v1
#define ECDSA384_PARAMS "\x06\x05\x2b\x81\x04\x00\x22" // secp384r1

static std::mutex g_lock;

namespace pdns {

#ifdef HAVE_P11KIT1_V2
static LockGuarded<CK_FUNCTION_LIST_PTR_PTR> p11_modules;
#else
static bool p11_modules_loaded
#endif

Pkcs11Module::Pkcs11Module(const std::string& module)
{
 CK_FUNCTION_LIST_PTR functions;
#ifdef HAVE_P11KIT1_V2
  auto modules = p11_modules.lock();
  if (*modules == NULL)
    *modules = p11_kit_modules_load_and_initialize(0);
  functions = p11_kit_module_for_name(*modules, module.c_str());
#else
  if (!p11_modules_loaded)
    p11_kit_initialize_registered();
  p11_modules_loaded = true;
  functions = p11_kit_registered_name_to_module(module.c_str());
#endif
  if (functions == NULL)
    throw std::invalid_argument("PKCS#11 module '" + module + "' does not exist");
  d_functions = functions;
  d_name = module;
}

void Pkcs11Module::Initialize() {
  CK_RV rv;
  CK_ULONG slotCount;
  if ((rv = d_functions->C_GetSlotList(CK_TRUE, NULL, &slotCount)) != CKR_OK)
    throw PDNSException("Cannot get list of slots");
  auto slots = std::make_unique<CK_SLOT_ID[]>(slotCount);
  if ((rv = d_functions->C_GetSlotList(CK_TRUE, slots.get(), &slotCount)) != CKR_OK)
    throw PDNSException("Cannot get list of slots");

  for (size_t i = 0; i < slotCount; i++) {
    CK_SLOT_ID id = slots.get()[i];
    d_slots[id] = Pkcs11Slot(shared_from_this(), id);
  }
}

Pkcs11Module::~Pkcs11Module() {
}

unsigned int Pkcs11Session::ecparam2bits(const std::string& obj) const {
  // if we can use some library to parse the EC parameters, better use it.
  // otherwise fall back to using hardcoded primev256 and secp384r1
#ifdef HAVE_LIBCRYPTO_ECDSA
  unsigned int bits = 0;
  const unsigned char *in = reinterpret_cast<const unsigned char*>(obj.c_str());
  auto order = std::unique_ptr<BIGNUM, void(*)(BIGNUM*)>(BN_new(), BN_clear_free);
  auto tempKey = d2i_ECParameters(nullptr, &in, obj.size());
  if (tempKey != nullptr) {
    auto key = std::unique_ptr<EC_KEY, void(*)(EC_KEY*)>(tempKey, EC_KEY_free);
    tempKey = nullptr;
    if (EC_GROUP_get_order(EC_KEY_get0_group(key.get()), order.get(), nullptr) == 1) {
      bits = BN_num_bits(order.get());
    }
  }

  if (bits == 0)
    throw PDNSException("Unsupported EC key");

  return bits;
#else
  if (d_ecdsa_params == ECDSA256_PARAMS) return 256;
  else if (d_ecdsa_params == ECDSA384_PARAMS) return 384;
  else throw PDNSException("Unsupported EC key");
#endif
}

std::shared_ptr<Pkcs11Session> Pkcs11Slot::GetSession(bool rw) {
  CK_SESSION_HANDLE handle;
  CK_FLAGS flags = CKF_SERIAL_SESSION | (rw ? CKF_RW_SESSION : 0);
  CK_RV rv;

  if ((rv = d_module->f()->C_OpenSession(this->d_slot, flags, 0, 0, &handle)) != CKR_OK) {
      logError("C_OpenSession", rv);
      throw PDNSException("Could not open session");
  }

  auto session = std::make_shared<Pkcs11Session>(d_module, handle, rw);
  return session;
}

int Pkcs11Session::GetAttributeValue(const CK_OBJECT_HANDLE& object, std::vector<P11KitAttribute>& attributes) {
  CK_RV rv;
  size_t k;
  auto attr = std::make_unique<CK_ATTRIBUTE[]>(attributes.size());

  k = 0;
  for(P11KitAttribute &attribute : attributes) {
    attribute.wattr(attr.get()+k);
    k++;
  }

  // round 1 - get attribute sizes
  rv = f()->C_GetAttributeValue(d_session, object, attr.get(), attributes.size());
  logError("C_GetAttributeValue", rv);

  if (rv != CKR_OK)
    return rv;

  // then allocate memory
  for (size_t idx = 0; idx < attributes.size(); idx++)
    if (attributes[idx].valueType() == Attribute_String)
      (attr.get())[idx].pValue = attributes[idx].allocate((attr.get())[idx].ulValueLen);

  // round 2 - get actual values
  rv = f()->C_GetAttributeValue(d_session, object, attr.get(), attributes.size());
  logError("C_GetAttributeValue", rv);

  if (rv != CKR_OK)
    return rv;

  // copy values to map and release allocated memory
  for (size_t idx = 0; idx < attributes.size(); idx++)
    if (attributes[idx].valueType() == Attribute_String)
      attributes[idx].commit((attr.get())[idx].ulValueLen);

  return rv;
}

bool Pkcs11Session::IsLoggedIn() const {
  if (d_logged_in)
    return true;

  CK_RV rv;
  CK_SESSION_INFO sessionInfo;
  rv = f()->C_GetSessionInfo(d_session, &sessionInfo);
  logError("C_GetSessionInfo", rv);
  if (rv != CKR_OK)
    throw PDNSException("C_GetSessionInfo failed");
  if (sessionInfo.state == CKS_RO_USER_FUNCTIONS ||
      sessionInfo.state == CKS_RW_USER_FUNCTIONS) {
    return true;
  }
  return false;
}

bool Pkcs11Session::Login(const std::string& pin, bool force) {
  CK_RV rv;
  if (!force && this->IsLoggedIn()) {
    return true;
  }
  if (pin.size() == 0)
    throw PDNSException("Empty PIN given");

  /* create pin */

  this->d_pin = pin;
  auto uPin = p11_kit_pin_new_for_string(pin.c_str());
  CK_ULONG len;
  const unsigned char *value = p11_kit_pin_get_value(uPin, &len);
  rv = f()->C_Login(this->d_session, CKU_USER, const_cast<unsigned char*>(value), len);
  p11_kit_pin_unref(uPin);

  logError("C_Login", rv);
  if (rv == CKR_OK)
    d_logged_in = TRUE;
  return d_logged_in;
}

int Pkcs11Session::FindObjects(const std::vector<P11KitAttribute>& attributes, std::vector<CK_OBJECT_HANDLE>& objects) {
  CK_RV rv;
  CK_ULONG count, k = 0;

  auto attr = std::make_unique<CK_ATTRIBUTE[]>(attributes.size());

  for (const P11KitAttribute& attribute : attributes) {
    attribute.rattr(attr.get()+k);
    k++;
  }

  // perform search
  rv = f()->C_FindObjectsInit(d_session, attr.get(), k);

  if (rv != CKR_OK) {
    logError("C_FindObjectsInit", rv);
    return rv;
  }

  // fetch handles one by one
  CK_OBJECT_HANDLE handle;
  while ((rv = f()->C_FindObjects(d_session, &handle, static_cast<CK_ULONG>(1), &count)) == CKR_OK) {
    if (count == 0)
      break;
    objects.push_back(handle);
  }
  logError("C_FindObjects", rv);

  rv = f()->C_FindObjectsFinal(d_session);
  logError("C_FindObjectsFinal", rv);

  return rv;
}

void Pkcs11Session::LoadPrivateKey(const std::vector<P11KitAttribute>& attributes) {
  CK_RV rv;
  std::vector<P11KitAttribute> attr;
  std::vector<CK_OBJECT_HANDLE> objects;
  rv = FindObjects(attributes, objects);
  if (rv != CKR_OK)
    throw PDNSException("Cannot get private key object");
  if (objects.size() == 0)
    throw PDNSException("Cannot find private key object, check mapping");
  d_private_key = objects[0];
}

void Pkcs11Session::LoadPublicKeyAttributes()
{
  std::vector<P11KitAttribute> attr;

  attr.clear();
  attr.push_back(P11KitAttribute(CKA_KEY_TYPE, 0UL));

  if (GetAttributeValue(d_public_key, attr) == CKR_OK) {
    d_key_type = attr[0].ulong();
    if (d_key_type == CKK_RSA) {
      attr.clear();
      attr.push_back(P11KitAttribute(CKA_MODULUS, ""));
      attr.push_back(P11KitAttribute(CKA_PUBLIC_EXPONENT, ""));
      attr.push_back(P11KitAttribute(CKA_MODULUS_BITS, 0UL));

      if (GetAttributeValue(d_public_key, attr) == CKR_OK) {
        d_modulus = attr[0].str();
        d_exponent = attr[1].str();
        d_bits = attr[2].ulong();
      } else {
        throw PDNSException("Cannot load attributes for public key");
      }
    } else if (d_key_type == CKK_EC || d_key_type == CKK_ECDSA) {
      attr.clear();
      attr.push_back(P11KitAttribute(CKA_ECDSA_PARAMS, ""));
      attr.push_back(P11KitAttribute(CKA_EC_POINT, ""));
      if (GetAttributeValue(d_public_key, attr) == CKR_OK) {
        d_ecdsa_params = attr[0].str();
        d_bits = ecparam2bits(d_ecdsa_params);
        if (attr[1].str().length() != (d_bits*2/8 + 3))
          throw PDNSException("EC Point data invalid");
        d_ec_point = attr[1].str().substr(3);
      } else {
        throw PDNSException("Cannot load attributes for public key");
      }
    } else {
      throw PDNSException("Cannot determine type for public key");
    }
  } else {
    throw PDNSException("Cannot load attributes for public key");
  }
}

void Pkcs11Session::LoadPublicKey(const std::vector<P11KitAttribute>& attributes) {
  CK_RV rv;
  std::vector<P11KitAttribute> attr;
  std::vector<CK_OBJECT_HANDLE> objects;
  rv = FindObjects(attributes, objects);
  if (rv != CKR_OK || objects.size() == 0)
    throw PDNSException("Cannot get public key object");
  d_public_key = objects[0];

  LoadPublicKeyAttributes();
}

int Pkcs11Session::GenerateKeyPair(CK_MECHANISM_PTR mechanism, std::vector<P11KitAttribute>& pubAttributes, std::vector<P11KitAttribute>& privAttributes) {
  CK_RV rv;
  size_t k;
  auto pubAttr = std::make_unique<CK_ATTRIBUTE[]>(pubAttributes.size());
  auto privAttr = std::make_unique<CK_ATTRIBUTE[]>(privAttributes.size());

  CK_OBJECT_HANDLE public_key, private_key;

  k = 0;
  for(P11KitAttribute& attribute : pubAttributes) {
    attribute.rattr(pubAttr.get()+k);
    k++;
  }

  k = 0;
  for(P11KitAttribute& attribute : privAttributes) {
    attribute.rattr(privAttr.get()+k);
    k++;
  }

  rv = f()->C_GenerateKeyPair(d_session, mechanism, pubAttr.get(), pubAttributes.size(), privAttr.get(), privAttributes.size(), &public_key, &private_key);
  logError("C_GenerateKeyPair", rv);

  if (rv == CKR_OK) {
    d_public_key = public_key;
    d_private_key = private_key;
    LoadPublicKeyAttributes();
  }

  return rv;
}

std::mutex& Pkcs11Session::Lock() {
  return g_lock;
}


}; // end of namespace

// deinitialize if pkcs11 has been used.
namespace {
  static struct UnloaderStruct
  {
    UnloaderStruct()
    {
    };
    ~UnloaderStruct() {
#ifdef HAVE_P11KIT1_V2
      auto modules = pdns::p11_modules.lock();
      if (*modules != NULL) {
        p11_kit_modules_release(*modules);
        *modules = NULL;
      }
#else
      if (pdns::p11_modules_loaded)
        p11_kit_finalize_registered();
#endif
    };
  } unloaderPkcs11;
}
