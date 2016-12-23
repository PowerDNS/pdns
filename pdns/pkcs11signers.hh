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
#ifndef PDNS_PKCS11SIGNERS_HH
#define PDNS_PKCS11SIGNERS_HH

class PKCS11DNSCryptoKeyEngine : public DNSCryptoKeyEngine
{
  protected:
    std::string d_module;
    std::string d_slot_id;
    std::string d_pin;
    std::string d_label;

  public:
    PKCS11DNSCryptoKeyEngine(unsigned int algorithm);
    ~PKCS11DNSCryptoKeyEngine();

    bool operator<(const PKCS11DNSCryptoKeyEngine& rhs) const
    {
      return false;
    }
    PKCS11DNSCryptoKeyEngine(const PKCS11DNSCryptoKeyEngine& orig);

    string getName() const { return "P11 Kit PKCS#11"; };

    void create(unsigned int bits);

    storvector_t convertToISCVector() const;

    std::string sign(const std::string& msg) const;

    std::string hash(const std::string& msg) const;

    bool verify(const std::string& msg, const std::string& signature) const;

    std::string getPubKeyHash() const;

    std::string getPublicKeyString() const;
    int getBits() const;

    void fromISCMap(DNSKEYRecordContent& drc, stormap_t& stormap);

    void fromPEMString(DNSKEYRecordContent& drc, const std::string& raw) { throw "Unimplemented"; };
    void fromPublicKeyString(const std::string& content) { throw "Unimplemented"; };

    static DNSCryptoKeyEngine* maker(unsigned int algorithm);
};

bool PKCS11ModuleSlotLogin(const std::string& module, const string& tokenId, const std::string& pin);

#endif /* PDNS_PKCS11SIGNERS_HH */
