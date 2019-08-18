#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pdns/dnsbackend.hh"
#include "pdns/logger.hh"

#include "cassandrabackend.h"

CassandraBackend::CassandraBackend(const std::string& suffix)
{
    setArgPrefix("cassandra" + suffix);

    auto contactPoints  = getArg("contact-points");
    auto keyspace       = getArg("keyspace");
    auto table          = getArg("table");
    auto createTable    = mustDo("create-table");

    if (keyspace.empty())
    {
        throw PDNSException("[cassandrabackend] cassandra-keyspace must be specified");
    }

    m_cluster = cass_cluster_new();

    CassError err;

    err = cass_cluster_set_contact_points_n(m_cluster, contactPoints.c_str(), contactPoints.size());

    if (err != CASS_OK)
    {
        g_log << Logger::Error << "[cassandrabackend] cass_cluster_set_contact_points_n(): " << cass_error_desc(err) << endl;
        throw PDNSException("[cassandrabackend] cannot set cassandra cluster contact points");
    }

    m_session = cass_session_new();

    CassFuturePtr future  = cass_session_connect_keyspace_n(m_session, m_cluster, keyspace.data(), keyspace.size());

    checkCassFutureError(future, "cannot connect to keyspace '" + keyspace + "'", true);

    if (createTable)
    {
        std::string query {
            "CREATE TABLE IF NOT EXISTS " + table + " ("
                "domain text PRIMARY KEY,"
                "record list<frozen<tuple<ascii, text, int, text>>>"
            ")"
        };

        CassStatementPtr st = cass_statement_new_n(query.data(), query.size(), 0);

        future = cass_session_execute(m_session, st);

        checkCassFutureError(future, "cannot create table", true);
    }

    auto q = "SELECT record FROM " + table + " WHERE domain = ?";

    future = cass_session_prepare_n(m_session, q.data(), q.size());

    checkCassFutureError(future, "cannot prepare query", true);

    m_query = cass_future_get_prepared(future);
}

CassandraBackend::~CassandraBackend()
{
    g_log << Logger::Debug << "[cassandrabackend] closing session";

    CassFuturePtr f  = cass_session_close(m_session);
    cass_future_wait_timed(f, 10'000);
}

bool CassandraBackend::checkCassFutureError(CassFuturePtr& future, const std::string& msg, bool throwException)
{
    CassError err = cass_future_error_code(future);

    if (err == CASS_OK)
    {
        return true;
    }

    const char* data;
    size_t len;

    cass_future_error_message(future, &data, &len);

    std::string errMessage = "[cassandrabackend] " + msg + ": " + cass_error_desc(err) +  ": " + std::string(data, len);
    g_log << Logger::Error << errMessage  << endl;

    if (throwException)
    {
        throw PDNSException(errMessage);
    }

    return false;
}

bool CassandraBackend::list(const DNSName& target, int id, bool include_disabled)
{
    g_log << Logger::Debug << "[cassandrabackend] list " << target << endl;

    CassStatementPtr st = cass_prepared_bind(m_query);

    if (!st)
    {
        m_requests.clear();
        g_log << Logger::Error << "[cassandrabackend] cass_prepared_bind() error" << endl;
        throw PDNSException("[cassandrabackend] cass_prepared_bind() error");
    }

    std::string domainName = target.makeLowerCase().toStringRootDot();

    g_log << Logger::Debug << "[cassandrabackend] requesting all records for " << domainName << endl;

    cass_statement_bind_string_n(st, 0, domainName.c_str(), domainName.size());

    m_requests.push_back(Request{std::move(domainName), cass_session_execute(m_session, st)});
    m_requestedType = QType(QType::ANY);

    m_requestedName.clear(); // return everything we have in zone

    return true;
}

void CassandraBackend::lookup(const QType& type, const DNSName &qdomain, DNSPacket *p, int zoneId)
{
    g_log << Logger::Debug << "[cassandrabackend] lookup " << qdomain << " type: " << type.getName() << endl;

    DNSName domain(qdomain);

    domain.makeUsLowerCase();

    m_requestedName = domain;

    if (domain.isWildcard())
    {
        // we should never have "*.domain.name" domains in database
        // but actual domains can have "*" record(s)
        domain.chopOff();
    }

    do
    {

        CassStatementPtr st = cass_prepared_bind(m_query);

        if (!st)
        {
            m_requests.clear();
            g_log << Logger::Error << "[cassandrabackend] cass_prepared_bind() error" << endl;
            throw PDNSException("[cassandrabackend] cass_prepared_bind() error");
        }

        std::string domainName = domain.toStringRootDot();

        g_log << Logger::Debug << "[cassandrabackend] requesting " << domainName << endl;

        cass_statement_bind_string_n(st, 0, domainName.c_str(), domainName.size());

        m_requests.push_back(Request{std::move(domainName), cass_session_execute(m_session, st)});
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
            // in-flight request, wait and process

            if (!checkCassFutureError(request.future, "request error", false))
            {
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

            if (!value)
            {
                g_log << Logger::Info << "[cassandrabackend] cannot get column value" << endl;
                return false;
            }

            request.record = cass_iterator_from_collection(value);
            g_log << Logger::Info << "[cassandrabackend] got records for " << request.domain << endl;
        }

        assert(request.record);

        while (cass_iterator_next(request.record))
        {
            const CassValue* value = cass_iterator_get_value(request.record);
            assert(value);

            CassIteratorPtr it = cass_iterator_from_tuple(value);

            if (!it)
            {
                g_log << Logger::Error << "[cassandrabackend] looks like record value is not a tuple" << endl;
                continue;
            }

            std::string type;
            std::string name;
            std::string content;

            int ttl = 0;

            /// 1. Type
            cass_iterator_next(it);
            type = getString(it);

            if (m_requestedType != QType::ANY && m_requestedType.getName() != type)
            {
                continue;
            }

            /// 2. Name
            cass_iterator_next(it);
            name = getString(it);

            ////  3. TTL
            cass_iterator_next(it);
            ttl = getInt(it);


            //// 4. Content
            cass_iterator_next(it);
            content = getString(it);


            DNSName recordName(name);

            recordName += DNSName(request.domain);

            if (!m_requestedName.empty() && m_requestedName != recordName)
            {
                g_log << Logger::Debug << "[cassandrabackend] not what we look for. Requested: " << m_requestedName << " name: " << recordName << endl;
                continue;
            }

            g_log << Logger::Debug << "[cassandrabackend] returning " << recordName << " - " << type << " - " << content << " - " << ttl << endl;

            rr.qname = recordName;
            rr.qtype = type;
            rr.ttl = ttl;
            rr.auth = true; // we are always authorative

            rr.setContent(std::move(content));

            return true;
        }


        g_log << Logger::Debug << "[cassandrabackend] request finished" << endl;

        m_requests.pop_front();
    }

    return false;
}

std::string CassandraBackend::getString(const CassIteratorPtr& it)
{
    const char* data;
    size_t len;

    CassError err;

    err = cass_value_get_string(cass_iterator_get_value(it), &data, &len);

    if (err != CASS_OK)
    {
        throw PDNSException(std::string("[cassandrabackend] cannot get string value: ") + cass_error_desc(err));
    }

    return std::string(data, len);
}

int CassandraBackend::getInt(const CassIteratorPtr& it)
{
    cass_int32_t out;

    CassError err;

    err = cass_value_get_int32(cass_iterator_get_value(it), &out);

    if (err != CASS_OK)
    {
        throw PDNSException(std::string("[cassandrabackend] cannot get integer value: ") + cass_error_desc(err));
    }

    return out;
}

class CassandraBackendFactory : public BackendFactory
{
public:
    CassandraBackendFactory() : BackendFactory("cassandra") {}

    virtual void declareArguments(const string& suffix) override
    {
        g_log << Logger::Info << "[cassandrabackend] suffix" << suffix << endl;
        declare(suffix, "contact-points", "Cassandra cluster connection points", "127.0.0.1");
        declare(suffix, "keyspace", "Cassandra keyspace", "");
        declare(suffix, "table", "Cassandra table", "dns");
        declare(suffix, "create-table", "Create table if it doesn't exist", "no");
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
