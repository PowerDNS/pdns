#pragma once

#include "cassandrabackend.h"

class CassandraBackendDNSSec: public CassandraBackend
{
public:
    explicit CassandraBackendDNSSec(const std::string& suffix)
        : CassandraBackend(suffix)
    {}

    virtual bool addDomainKey(const DNSName& name, const KeyData& key, int64_t& id) override;
    virtual bool getDomainKeys(const DNSName& name, std::vector<KeyData>& keys) override;
    virtual bool removeDomainKey(const DNSName& name, unsigned int id) override;

    virtual bool activateDomainKey(const DNSName& name, unsigned int id) override;
    virtual bool deactivateDomainKey(const DNSName& name, unsigned int id) override;

    virtual bool doesDNSSEC() override;

    virtual bool getBeforeAndAfterNamesAbsolute(uint32_t id, const DNSName& qname, DNSName& unhashed, DNSName& before, DNSName& after) override;
    virtual bool updateDNSSECOrderNameAndAuth(uint32_t domain_id, const DNSName& qname, const DNSName& ordername, bool auth, const uint16_t qtype) override;

private:

    void changeActivation(const DNSName& name, unsigned int id, bool active);
};

