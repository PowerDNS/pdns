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

#include "pkcs11infra.hh"

class PKCS11DNSCryptoKeyEngine : public DNSCryptoKeyEngine
{
  private:
    pdns::Pkcs11Slot& GetSlot();
    pdns::Pkcs11Slot& GetSlot() const;
    void copyValues(const PKCS11DNSCryptoKeyEngine& orig);
    void createAttributes();

  protected:
    std::shared_ptr<pdns::Pkcs11Module> d_module;
    unsigned long d_slot_id;
    std::string d_pin;
    std::string d_label;
    std::string d_id;
    std::string d_pub_id;
    std::string d_pub_label;
    std::string d_token_serial;
    std::string d_token_label;

    std::vector<pdns::P11KitAttribute> d_priv_attr;
    std::vector<pdns::P11KitAttribute> d_pub_attr;

    // cached:
    unsigned long d_cached_slot_id;

    std::string hash_locked(const std::string& msg, std::shared_ptr<pdns::Pkcs11Session>& session) const;

  public:
    PKCS11DNSCryptoKeyEngine(unsigned int algorithm);
    ~PKCS11DNSCryptoKeyEngine();

    bool operator<(const PKCS11DNSCryptoKeyEngine& rhs) const
    {
      return false;
    }
    PKCS11DNSCryptoKeyEngine(const PKCS11DNSCryptoKeyEngine& orig);
    PKCS11DNSCryptoKeyEngine& operator=(const PKCS11DNSCryptoKeyEngine& orig) { copyValues(orig); return *this; };

    string getName() const override { return "P11 Kit PKCS#11"; };

    void create(unsigned int bits) override;

    storvector_t convertToISCVector() const override;

    std::string sign(const std::string& msg) const override;

    std::string hash(const std::string& msg) const override;

    bool verify(const std::string& msg, const std::string& signature) const override;

    std::string getPubKeyHash() const override;

    std::string getPublicKeyString() const override;
    int getBits() const override;

    void fromISCMap(DNSKEYRecordContent& drc, stormap_t& stormap) override;

    void fromPEMString(DNSKEYRecordContent& drc, const std::string& raw) override { throw "Unimplemented"; };
    void fromPublicKeyString(const std::string& content) override { throw "Unimplemented"; };

    static std::unique_ptr<DNSCryptoKeyEngine> maker(unsigned int algorithm);
};
