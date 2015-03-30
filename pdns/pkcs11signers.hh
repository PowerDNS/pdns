#ifndef PDNS_PKCS11SIGNERS_HH
#define PDNS_PKCS11SIGNERS_HH

class PKCS11DNSCryptoKeyEngine : public DNSCryptoKeyEngine
{
  protected:
    std::string d_module;
    unsigned long d_slot_id;
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

#endif /* PDNS_PKCS11SIGNERS_HH */
