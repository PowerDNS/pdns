#pragma once

#include <list>
#include <cassandra.h>

#include "pdns/dnsbackend.hh"

#include "cassptr.h"

class CassandraBackend: public DNSBackend
{
public:
    explicit CassandraBackend(const std::string& suffix);
    ~CassandraBackend();

    virtual bool list(const DNSName& target, int id, bool include_disabled) override;
    virtual void lookup(const QType& type, const DNSName& qdomain, DNSPacket *p, int zoneId) override;
    virtual bool get(DNSResourceRecord &rr) override;

    virtual void getAllDomains(vector<DomainInfo> *domains, bool include_disabled) override;
    virtual bool getDomainInfo(const DNSName &domain, DomainInfo &di, bool getSerial) override;

protected:
    bool getBool(const CassValue* value);
    int getInt(const CassValue* value);
    std::string getString(const CassValue* value);

    bool checkCassFutureError(const CassFuturePtr& future, const std::string& msg, bool throwException = true);
    bool checkError(const CassError err, const std::string& msg, bool throwException = true);

    CassSessionPtr  m_session;
    std::string         m_table;

private:
    CassClusterPtr  m_cluster;
    CassPreparedPtr m_query;

    struct Request
    {
        std::string     domain;
        CassFuturePtr   future;
        CassResultPtr   result;
        CassIteratorPtr record;
    };

    std::list<Request>  m_requests;

    QType               m_requestedType;
    DNSName             m_requestedName;
};
