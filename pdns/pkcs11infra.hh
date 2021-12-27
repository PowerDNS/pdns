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
#pragma once

#include <p11-kit/p11-kit.h>
#include "boost/lexical_cast.hpp"

namespace pdns {

class Pkcs11Module;
class Pkcs11Slot;
class Pkcs11Session;

typedef enum { Attribute_Byte, Attribute_Long, Attribute_String } CkaValueType;

// Attribute handling
class P11KitAttribute {
private:
  CK_ATTRIBUTE_TYPE type;
  CK_BYTE ckByte;
  CK_ULONG ckLong;
  std::string ckString;
  CkaValueType ckType;
  std::unique_ptr<unsigned char[]> buffer;
  CK_ULONG buflen;
protected:
  void Init() {
    buflen = 0;
  };
public:
  P11KitAttribute(CK_ATTRIBUTE_TYPE type_, const std::string& value) {
    Init();
    this->type = type_;
    setString(value);
  }

  P11KitAttribute(CK_ATTRIBUTE_TYPE type_, char value) {
    Init();
    this->type = type_;
    setByte(value);
  }

  P11KitAttribute(CK_ATTRIBUTE_TYPE type_, unsigned char value) {
    Init();
    this->type = type_;
    setByte(value);
  }

  P11KitAttribute(CK_ATTRIBUTE_TYPE type_, unsigned long value) {
    Init();
    this->type = type_;
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
    buffer = std::make_unique<unsigned char[]>(amount);
    buflen = amount;
    return buffer.get();
  }

// and here we copy the results back and delete buffer
  void commit(CK_ULONG amount) {
    if (buffer) {
      this->ckString.assign((char*)buffer.get(), amount);
    }
    buffer.reset();
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
        attr->pValue = buffer.get();
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

class Pkcs11Module : public std::enable_shared_from_this<Pkcs11Module> {
private:
  std::string d_name;
  CK_FUNCTION_LIST_PTR d_functions;
  std::map<CK_SLOT_ID, Pkcs11Slot> d_slots;
public:
  Pkcs11Module(const std::string& name);

  void Initialize(); 

  CK_FUNCTION_LIST_PTR f() const {
    return std::as_const(d_functions);
  };

  const std::string& GetName() const {
    return d_name;
  }

  std::map<CK_SLOT_ID, Pkcs11Slot>& GetSlots() {
    return d_slots;
  }

  Pkcs11Slot& GetSlot(CK_SLOT_ID slotId) {
    if (d_slots.count(slotId) > 0)
      return d_slots[slotId];
    throw PDNSException("Invalid slot ID " + boost::lexical_cast<std::string>(slotId));
  }

  ~Pkcs11Module();
};

class Pkcs11Slot {
private:
  std::shared_ptr<Pkcs11Module> d_module;
  CK_SLOT_ID d_slot = UINT_MAX;
  CK_TOKEN_INFO d_tokenInfo;

  void logError(const std::string& operation, CK_RV err) const {
    if (err != 0) {
      std::string msg = boost::str( boost::format("%s:PKCS#11 operation %s failed: %s (0x%X) (%s)") % d_module->GetName() % operation % p11_kit_strerror(err) % err % p11_kit_message() );
      g_log << Logger::Error << msg << endl;
    }
  }

  CK_FUNCTION_LIST_PTR f() const {
    return d_module->f();
  }
public:
  Pkcs11Slot() {}
  Pkcs11Slot(std::shared_ptr<Pkcs11Module> module, CK_SLOT_ID slotId) {
    CK_RV rv;
    d_module = module;
    d_slot = slotId;
    if ((rv = f()->C_GetTokenInfo(d_slot, &d_tokenInfo)) != CKR_OK) {
      logError("C_GetTokenInfo", rv);
      throw PDNSException("Cannot get token info");
    }
  }

  std::shared_ptr<Pkcs11Session> GetSession(bool rw = false);

  CK_SLOT_ID GetSlotID() const {
    return d_slot;
  }

  const std::string GetLabel() const {
    return boost::algorithm::trim_right_copy(std::string(reinterpret_cast<const char*>(d_tokenInfo.label), sizeof(d_tokenInfo.label)));
  }

  const std::string GetModel() const {
    return boost::algorithm::trim_right_copy(std::string(reinterpret_cast<const char*>(d_tokenInfo.model), sizeof(d_tokenInfo.model)));
  }

  const std::string GetManufacturer() const {
    return boost::algorithm::trim_right_copy(std::string(reinterpret_cast<const char*>(d_tokenInfo.manufacturerID), sizeof(d_tokenInfo.manufacturerID)));
  }

  const std::string GetSerialNumber() const {
    return boost::algorithm::trim_right_copy(std::string(reinterpret_cast<const char*>(d_tokenInfo.serialNumber), sizeof(d_tokenInfo.serialNumber)));
  }

  bool HasToken() const {
    return ((d_tokenInfo.flags & CKF_TOKEN_PRESENT) == CKF_TOKEN_PRESENT);
  }

  bool HasInitializedToken() const {
    return ((d_tokenInfo.flags & CKF_TOKEN_INITIALIZED) == CKF_TOKEN_INITIALIZED);
  }
};

class Pkcs11Session {
private:
  std::shared_ptr<Pkcs11Module> d_module;
  CK_SESSION_HANDLE d_session;
  bool d_rw;
  bool d_logged_in;

  CK_OBJECT_HANDLE d_private_key;
  CK_OBJECT_HANDLE d_public_key;

  CK_KEY_TYPE d_key_type;

  CK_ULONG d_bits;
  std::string d_exponent;
  std::string d_modulus;
  std::string d_ec_point;
  std::string d_ecdsa_params;

  std::mutex d_lock;

  void logError(const std::string& operation, CK_RV err) const {
    if (err != 0) {
      std::string msg = boost::str( boost::format("%s:PKCS#11 operation %s failed: %s (0x%X) (%s)") % d_module->GetName() % operation % p11_kit_strerror(err) % err % p11_kit_message() );
      g_log << Logger::Error << msg << endl;
    }
  }

  CK_FUNCTION_LIST_PTR f() const {
    return d_module->f();
  };

  unsigned int ecparam2bits(const std::string& obj) const;
  void LoadPublicKeyAttributes();
public:
  Pkcs11Session() = delete;
  Pkcs11Session(Pkcs11Session&) = delete;
  Pkcs11Session& operator=(const Pkcs11Session&) = delete;

  Pkcs11Session(std::shared_ptr<Pkcs11Module> module, CK_SESSION_HANDLE& session, bool rw) {
    d_module = module;
    d_session = session;
    d_rw = rw;
    d_private_key = CK_INVALID_HANDLE;
    d_public_key = CK_INVALID_HANDLE;
    d_logged_in = false;
  };

  std::mutex& Lock() {
    return d_lock;
  }

  int GetAttributeValue(const CK_OBJECT_HANDLE& object, std::vector<P11KitAttribute>& attributes);

  bool IsLoggedIn() const;

  bool Login(const std::string& pin, bool force=false);

  int FindObjects(const std::vector<P11KitAttribute>& attributes, std::vector<CK_OBJECT_HANDLE>& objects);

  bool HasPrivateKey() const {
    return d_private_key != CK_INVALID_HANDLE;
  }

  bool HasPublicKey() const {
    return d_public_key != CK_INVALID_HANDLE;
  }

  void LoadPrivateKey(const std::vector<P11KitAttribute>& attributes);

  void LoadPublicKey(const std::vector<P11KitAttribute>& attributes);

  int Sign(const std::string& data, std::string& result, CK_MECHANISM_PTR mechanism) {
    CK_RV rv;
    CK_BYTE buffer[1024];
    CK_ULONG buflen = sizeof buffer; // should be enough for most signatures.

    // perform signature
    if ((rv = f()->C_SignInit(d_session, mechanism, d_private_key)) != CKR_OK) {
      logError("C_SignInit", rv);
      return rv;
    }
    rv = f()->C_Sign(d_session, reinterpret_cast<unsigned char*>(const_cast<char*>(data.data())), data.size(), buffer, &buflen);
    logError("C_Sign", rv);
    if (rv == CKR_OK)
      result.assign(reinterpret_cast<char*>(buffer), buflen);
    memset(buffer, 0, sizeof buffer);

    return rv;
  }

  int Verify(const std::string& data, const std::string& signature, CK_MECHANISM_PTR mechanism) {
    CK_RV rv;
    if ((rv = f()->C_VerifyInit(d_session, mechanism, d_public_key)) != CKR_OK) {
      logError("C_VerifyInit", rv);
      return rv;
    }
    rv = f()->C_Verify(d_session, reinterpret_cast<unsigned char*>(const_cast<char*>(data.data())), data.size(), reinterpret_cast<unsigned char*>(const_cast<char*>(signature.data())), signature.size());
    logError("C_Verify", rv);

    return rv;
  }

  int Digest(const std::string& data, std::string& result, CK_MECHANISM_PTR mechanism) {
    CK_RV rv;
    /* flow control only */
    if ((rv = DigestInit(mechanism)) == CKR_OK &&
        (rv = DigestUpdate(data)) == CKR_OK &&
        (rv = DigestFinal(result)) == CKR_OK)
          return rv;
     return rv;
  }

  int DigestInit(CK_MECHANISM_PTR mechanism) {
    CK_RV rv;
    rv = f()->C_DigestInit(d_session, mechanism);
    logError("C_DigestInit", rv);

    return rv;
  }

  int DigestUpdate(const std::string& data) {
    CK_RV rv;
    rv = f()->C_DigestUpdate(d_session, reinterpret_cast<unsigned char*>(const_cast<char*>(data.data())), data.size());
    logError("C_DigestUpdate", rv);
    return rv;
  }

  int DigestFinal(std::string& result) {
    CK_RV rv;
    CK_BYTE buffer[1024] = {0};
    CK_ULONG buflen = sizeof buffer; // should be enough for most digests

    rv = f()->C_DigestFinal(d_session, buffer, &buflen);
    if (rv == CKR_OK)
      result.assign(reinterpret_cast<char*>(buffer), buflen);

    memset(buffer, 0, sizeof buffer);
    logError("C_DigestFinal", rv);
    return rv;
  }

  int DigestKey(std::string& result) {
    CK_RV rv;
    CK_MECHANISM mech;
    mech.mechanism = CKM_SHA_1;

    if ((rv = DigestInit(&mech)) != CKR_OK)
      return rv;

    if (d_key_type == CKK_RSA) {
      DigestUpdate(d_modulus);
      DigestUpdate(d_exponent);
    } else if (d_key_type == CKK_EC || d_key_type == CKK_ECDSA) {
      DigestUpdate(d_ec_point);
    }

    rv = DigestFinal(result);

    return rv;
  }

  int GenerateKeyPair(CK_MECHANISM_PTR mechanism, std::vector<P11KitAttribute>& pubAttributes, std::vector<P11KitAttribute>& privAttributes);

  const std::string& Modulus() const {
    return d_modulus;
  }

  const std::string& Exponent() const {
    return d_exponent;
  }

  const std::string& ECPoint() const {
    return d_ec_point;
  }

  const std::string& ECParameters() const {
    return d_ecdsa_params;
  }

  CK_KEY_TYPE KeyType() const {
    return d_key_type;
  }

  CK_ULONG Bits() const {
    return d_bits;
  }

  ~Pkcs11Session() {
    const std::lock_guard<std::mutex> lock(d_lock);
    if (d_session != CK_INVALID_HANDLE) {
      f()->C_CloseSession(d_session);
      d_session = CK_INVALID_HANDLE;
    }
  }
};

}; // end of namespace
