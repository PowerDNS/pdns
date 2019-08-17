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

private:
    CassClusterPtr  m_cluster;
    CassSessionPtr  m_session;

    struct Request
    {
        std::string     domain;
        CassFuturePtr   future;
        CassResultPtr   result;
        CassIteratorPtr record;
    };

    std::list<Request>  m_requests;

    QType               m_requestedType;
    std::string         m_requestedDomain;
};
