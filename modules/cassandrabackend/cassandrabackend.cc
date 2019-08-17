#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pdns/dnsbackend.hh"
#include "pdns/logger.hh"

#include "cassandrabackend.h"

CassandraBackend::CassandraBackend(const std::string& suffix)
{
    setArgPrefix("cassandra" + suffix);

    auto contactPoints = getArg("contact-points");
    auto keyspace = getArg("keyspace");

    m_cluster = cass_cluster_new();

    CassError err;

    err = cass_cluster_set_contact_points_n(m_cluster, contactPoints.c_str(), contactPoints.size());

    if (err != CASS_OK)
    {
        g_log << Logger::Error << "cass_cluster_set_contact_points_n(): " << cass_error_desc(err) << endl;
        throw PDNSException("cannot set cassandra cluster contact points");
    }

    m_session = cass_session_new();

    CassFuturePtr future {cass_session_connect_keyspace_n(m_session, m_cluster, keyspace.data(), keyspace.size())};

    err = cass_future_error_code(future);

    if (err != CASS_OK)
    {
        g_log << Logger::Error << "cass_session_connect_keyspace_n(): " << cass_error_desc(err) << endl;
        throw PDNSException("cannot connect to keyspace");
    }
}

CassandraBackend::~CassandraBackend()
{
    g_log << Logger::Debug << "[cassandrabackend] closing session";

    CassFuturePtr f  = cass_session_close(m_session);
    cass_future_wait_timed(f, 10'000);
}

bool CassandraBackend::list(const DNSName& target, int id, bool include_disabled)
{
    // not AXFR support
    return false;
}

void CassandraBackend::lookup(const QType& type, const DNSName &qdomain, DNSPacket *p, int zoneId)
{
    g_log << Logger::Info << "[cassandrabackend] lookup " << qdomain << " type: " << type.getName() << endl;

    DNSName domain(qdomain);

    m_requestedDomain = domain.toStringRootDot();

    do
    {

        CassStatementPtr st = cass_statement_new("SELECT record FROM dns WHERE domain = ?", 1);

        if (!st)
        {
            g_log << Logger::Error << "cass_statement_new() error" << endl;
            throw PDNSException("cass_statement_new() error");
        }

        if (qdomain.isWildcard())
        {
            domain.chopOff();

            g_log << Logger::Error << "chopped: " << domain.toStringRootDot() << endl;
        }

        g_log << Logger::Info << "requesting " << domain.toStringRootDot() << endl;

        cass_statement_bind_string(st, 0, domain.toStringRootDot().c_str());

        m_requests.push_back(Request{domain.toStringRootDot(), cass_session_execute(m_session, st)});
        m_requestedType = type;

    } while (type == QType::ANY && domain.chopOff());

}

bool CassandraBackend::get(DNSResourceRecord &rr)
{
    g_log << Logger::Info << "[cassandrabackend] get" << endl;

    if (m_requests.empty())
    {
        g_log << Logger::Info << "[cassandrabackend] no requests" << endl;
        return false;
    }

    while (!m_requests.empty())
    {
        auto& request = m_requests.front();

        if (request.future)
        {
            CassError err = cass_future_error_code(request.future);

            if (err != CASS_OK)
            {
                const char* msg = nullptr;
                size_t size = 0;
                cass_future_error_message(request.future, &msg, &size);

                g_log << Logger::Error << "[cassandrabackend] active request error: " << cass_error_desc(err) << ": " << std::string(msg, size) << endl;

                m_requests.pop_front();
                continue;
            }

            request.result = cass_future_get_result(request.future);
            request.future.reset();

            const CassRow* row = cass_result_first_row(request.result);

            if (!row)
            {
                g_log << Logger::Info << "[cassandrabackend] empty response, no domain found for " << request.domain << endl;
                m_requests.pop_front();
                continue;
            }

            const CassValue* value = cass_row_get_column(row, 0);
            assert(value);

            request.record = cass_iterator_from_collection(value);
            g_log << Logger::Info << "[cassandrabackend] got records for " << request.domain << endl;
        }

        break;
    }

    if (m_requests.empty())
    {
        g_log << Logger::Info << "[cassandrabackend] no more data possible " << endl;
        return false;
    }

    auto& request = m_requests.front();

    assert(request.record);

    while (cass_iterator_next(request.record))
    {

        const CassValue* value = cass_iterator_get_value(request.record);
        assert(value);

        CassIteratorPtr it = cass_iterator_from_tuple(value);

        if (!it)
        {
            break;
        }

        std::string type;
        std::string name;
        std::string content;

        int ttl = 0;

        /// 1. Type
        cass_iterator_next(it);

        const char* data;
        size_t len;

        CassError err;

        err = cass_value_get_string(cass_iterator_get_value(it), &data, &len);

        if (err != CASS_OK)
        {
            g_log << Logger::Error << "[cassandrabackend] cannot get record type" << endl;
            return false;
        }

        type.assign(data, len);

        if (m_requestedType != QType::ANY && m_requestedType.getName() != type)
        {
            continue;
        }

        /// 2. Name
        cass_iterator_next(it);

        err = cass_value_get_string(cass_iterator_get_value(it), &data, &len);

        if (err != CASS_OK)
        {
            g_log << Logger::Error << "[cassandrabackend] cannot get name" << endl;
            break;
        }

        if (m_requestedDomain == request.domain && len != 0)
        {
            continue;
        }

        name.assign(data, len);

        ////  3. TTL
        cass_iterator_next(it);

        cass_int32_t out;
        err = cass_value_get_int32(cass_iterator_get_value(it), &out);

        if (err != CASS_OK)
        {
            g_log << Logger::Error << "[cassandrabackend] cannot get record ttl" << endl;
            break;
        }

        ttl = out;


        //// 4. Content
        cass_iterator_next(it);

        err = cass_value_get_string(cass_iterator_get_value(it), &data, &len);

        if (err != CASS_OK)
        {
            g_log << Logger::Error << "[cassandrabackend] cannot get record content" << endl;
            break;
        }

        content.assign(data, len);

        if (!name.empty())
        {
            name += '.';
        }

        name += request.domain;

        if (m_requestedDomain != request.domain && m_requestedDomain != name)
        {
            g_log << Logger::Error << "[cassandrabackend] not what we look for. Requested: " << m_requestedDomain << " name: " << name << endl;
            continue;
        }

        g_log << Logger::Error << "[cassandrabackend] returning " << name << " - " << type << " - " << content << endl;

        rr.qname = DNSName(name);
        rr.qtype = type;
        rr.ttl = ttl;
        rr.auth = 1; // we are always authorative
        rr.setContent(std::move(content));

        return true;
    }


    g_log << Logger::Error << "[cassandrabackend] request finished" << endl;

    m_requests.pop_front();

    if (m_requests.empty())
    {
        return false;
    }

    return true;
}

class CassandraBackendFactory : public BackendFactory
{
public:
    CassandraBackendFactory() : BackendFactory("cassandra") {}

    virtual void declareArguments(const string& suffix) override
    {
        g_log << Logger::Info << "[cassandrabackend] suffix" << suffix << endl;
        declare(suffix, "contact-points", "Cassandra cluster connection points", "127.0.0.1");
        declare(suffix, "keyspace", "Cassandra keyspace", "no-keyspace-selected");
    }

    virtual DNSBackend *make(const string& suffix) override
    {
        return new CassandraBackend(suffix);
    }
};

class Loader
{
public:
    Loader()
    {
        BackendMakers().report(new CassandraBackendFactory);
        g_log << Logger::Info << "[cassandrabackend] registered" << endl;
    }
};

static Loader loader;
