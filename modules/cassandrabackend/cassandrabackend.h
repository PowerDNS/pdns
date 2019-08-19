#pragma once

#include <list>
#include <cassandra.h>

#include "pdns/dnsbackend.hh"
#include "pdns/logger.hh"

#include "cassptr.h"

#ifdef L
#define g_log L
#endif


class CassandraBackend: public DNSBackend
{
public:
    explicit CassandraBackend(const std::string& suffix);
    ~CassandraBackend();

    virtual bool list(const DNSName& target, int id, bool include_disabled) override;
    virtual void lookup(const QType& type, const DNSName& qdomain, DNSPacket *p, int zoneId) override;
    virtual bool get(DNSResourceRecord &rr) override;

    virtual void getAllDomains(vector<DomainInfo>* domains, bool include_disabled) override;

#if HAVE_DNSBACKEND_DOMAIN_INFO_WITH_SERIAL
    virtual bool getDomainInfo(const DNSName& domain, DomainInfo& di, bool getSerial) override;
#else
    virtual bool getDomainInfo(const DNSName& domain, DomainInfo& di) override;
#endif

protected:

    // helpers
    static bool getBool(const CassValue* value);
    static int getInt(const CassValue* value);
    static std::string getString(const CassValue* value);

    static bool checkCassFutureError(const CassFuturePtr& future, const std::string& msg, bool throwException = true);
    static bool checkError(const CassError err, const std::string& msg, bool throwException = true);

    CassSessionPtr  m_session;
    std::string         m_table;

private:
    void logMetrics();

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

    time_t              m_lastMetricsLog = 0;
    time_t              m_logMetricsInterval = 0;
};
