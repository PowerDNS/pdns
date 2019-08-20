#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <boost/algorithm/string.hpp>

#include "pdns/dnsbackend.hh"
#include "pdns/logger.hh"

#include "cassandrabackend.h"

static const std::map<std::string, CassConsistency> s_consistencyMap =
{
    {"ONE",         CASS_CONSISTENCY_ONE},
    {"TWO",         CASS_CONSISTENCY_TWO},
    {"THREE",       CASS_CONSISTENCY_THREE},
    {"QUORUM",      CASS_CONSISTENCY_QUORUM},
    {"ALL",         CASS_CONSISTENCY_ALL},
    {"LOCAL_QUORUM",CASS_CONSISTENCY_LOCAL_QUORUM},
    {"EACH_QUORUM", CASS_CONSISTENCY_EACH_QUORUM},
    {"SERIAL",      CASS_CONSISTENCY_SERIAL},
    {"LOCAL_SERIAL",CASS_CONSISTENCY_LOCAL_SERIAL},
    {"LOCAL_ONE",   CASS_CONSISTENCY_LOCAL_ONE},
};

CassandraBackend::CassandraBackend(const std::string& suffix)
{
    setArgPrefix("cassandra" + suffix);

    auto contactPoints  = getArg("contact-points");
    auto keyspace       = getArg("keyspace");
    auto table          = getArg("table");
    auto createTable    = mustDo("create-table");
    auto localDC        = getArg("local-dc");
    auto consistency    = getArg("consistency");

    m_logMetricsInterval= getArgAsNum("log-metrics-interval");

    m_table = table;

    if (keyspace.empty())
    {
        throw PDNSException("[cassandrabackend] cassandra-keyspace must be specified");
    }

    m_cluster = cass_cluster_new();

    if (!localDC.empty())
    {
        checkError(cass_cluster_set_load_balance_dc_aware_n(m_cluster, localDC.data(), localDC.size(), 0, cass_false), "cannot set local DC name");
    }

    if (!consistency.empty())
    {
        boost::to_upper(consistency);

        auto it = s_consistencyMap.find(consistency);

        if (it == s_consistencyMap.end())
        {
            throw PDNSException("Invalid cassandra consistency map specified: " + consistency);
        }

        checkError(cass_cluster_set_consistency(m_cluster, it->second), "cannot set default consistency");
    }

    checkError(cass_cluster_set_contact_points_n(m_cluster, contactPoints.c_str(), contactPoints.size()), "cannot set cluster contact points");

    m_session = cass_session_new();

    CassFuturePtr future  = cass_session_connect_keyspace_n(m_session, m_cluster, keyspace.data(), keyspace.size());

    checkCassFutureError(future, "cannot connect to keyspace '" + keyspace + "'", true);

    if (createTable)
    {
        std::string query {
            "CREATE TABLE IF NOT EXISTS " + table + " ("
                "domain      text PRIMARY KEY,"
                "records     list<frozen<tuple<ascii, text, int, text, text>>>,"
                "keys        list<frozen<tuple<boolean, int, text, int>>>,"
                "metadata    map<ascii, text>"
            ");"
        };

        CassStatementPtr st = cass_statement_new_n(query.data(), query.size(), 0);

        future = cass_session_execute(m_session, st);

        checkCassFutureError(future, "cannot create table", true);
    }

    auto q = "SELECT records FROM " + table + " WHERE domain = ?";

    future = cass_session_prepare_n(m_session, q.data(), q.size());

    checkCassFutureError(future, "cannot prepare query", true);

    m_query = cass_future_get_prepared(future);
}

CassandraBackend::~CassandraBackend()
{
    g_log << Logger::Info << "[cassandrabackend] closing session" << endl;

    CassFuturePtr f  = cass_session_close(m_session);
    cass_future_wait_timed(f, 10'000);
}

bool CassandraBackend::checkCassFutureError(const CassFuturePtr& future, const std::string& msg, bool throwException)
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

bool CassandraBackend::checkError(const CassError err, const std::string& msg, bool throwException)
{
    if (err == CASS_OK)
    {
        return true;
    }

    std::string errMessage = "[cassandrabackend] " + msg + ": " + cass_error_desc(err);
    g_log << Logger::Error << errMessage  << endl;

    if (throwException)
    {
        throw PDNSException(errMessage);
    }

    return false;
}

void CassandraBackend::logMetrics()
{
    if (m_logMetricsInterval == 0)
    {
        return;
    }

    time_t t_now = time(nullptr);

    if (t_now - m_lastMetricsLog < m_logMetricsInterval)
    {
        return;
    }

    CassMetrics metrics;
    cass_session_get_metrics(m_session, &metrics);

    g_log << Logger::Notice << "[cassandrabackend] metrics"
            << ": min: "    << metrics.requests.min
            << ", max: "    << metrics.requests.max
            << ", mean: "   << metrics.requests.mean
            << ", 1m: "     << metrics.requests.one_minute_rate
            << ", 5m: "     << metrics.requests.five_minute_rate
            << ", 15m: "    << metrics.requests.fifteen_minute_rate
            << ", p95: "    << metrics.requests.percentile_95th
            << ", p98: "    << metrics.requests.percentile_98th
            << ", p99: "    << metrics.requests.percentile_99th
            << ", p999: "   << metrics.requests.percentile_999th
            << endl;

    m_lastMetricsLog = t_now;
}

bool CassandraBackend::list(const DNSName& target, int id, bool include_disabled)
{
    g_log << Logger::Debug << "[cassandrabackend] list " << target << endl;

    logMetrics();

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

    logMetrics();

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
    g_log << Logger::Debug << "[cassandrabackend] get" << endl;

    if (m_requests.empty())
    {
        g_log << Logger::Debug << "[cassandrabackend] no requests" << endl;
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
                g_log << Logger::Debug << "[cassandrabackend] empty response, no domain found for " << request.domain << endl;
                m_requests.pop_front();
                continue;
            }

            const CassValue* value = cass_row_get_column(row, 0);

            if (!value)
            {
                g_log << Logger::Debug << "[cassandrabackend] cannot get column value" << endl;
                return false;
            }

            request.record = cass_iterator_from_collection(value);
            g_log << Logger::Debug << "[cassandrabackend] got records for " << request.domain << endl;
        }

        while (request.record && cass_iterator_next(request.record))
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
            type = getString(cass_iterator_get_value(it));

            if (m_requestedType != QType::ANY && m_requestedType.getName() != type)
            {
                continue;
            }

            /// 2. Name
            cass_iterator_next(it);
            name = getString(cass_iterator_get_value(it));

            ////  3. TTL
            cass_iterator_next(it);
            ttl = getInt(cass_iterator_get_value(it));

            //// 4. Content
            cass_iterator_next(it);
            content = getString(cass_iterator_get_value(it));


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

void CassandraBackend::getAllDomains(vector<DomainInfo> *domains, bool include_disabled)
{
    g_log << Logger::Debug << "[cassandrabackend] getAllDomain()" << endl;

    CassStatementPtr st = cass_statement_new(("SELECT domain FROM " + m_table).c_str(), 0);

    CassFuturePtr f = cass_session_execute(m_session, st);

    checkCassFutureError(f, "cannot select all domains", true);

    CassIteratorPtr it = cass_iterator_from_result(cass_future_get_result(f));

    while (cass_iterator_next(it))
    {
        const CassValue* value = cass_row_get_column(cass_iterator_get_row(it), 0);
        auto domainName = getString(value);

        DomainInfo domain{};

        domain.zone = DNSName(domainName);
        domain.backend = this;

        domains->push_back(domain);
    }
}

#if HAVE_DNSBACKEND_DOMAIN_INFO_WITH_SERIAL
bool CassandraBackend::getDomainInfo(const DNSName &domain, DomainInfo &di, bool getSerial)
#else
bool CassandraBackend::getDomainInfo(const DNSName &domain, DomainInfo &di)
#endif
{
    g_log << Logger::Debug << "[cassandrabackend] getDomainInfo(\"" << domain << "\")" << endl;

    CassStatementPtr st = cass_statement_new(("SELECT domain FROM " + m_table + " WHERE domain = ?").c_str(), 1);

    cass_statement_bind_string(st, 0, domain.toStringRootDot().c_str());

    CassFuturePtr f = cass_session_execute(m_session, st);

    checkCassFutureError(f, "cannot get domain info", true);

    CassResultPtr result = cass_future_get_result(f);

    if (cass_result_first_row(result) == nullptr)
    {
        return false;
    }

    di.zone = domain;
    di.backend = this;

    return true;
}

std::string CassandraBackend::getString(const CassValue* value)
{
    const char* data;
    size_t len;

    checkError(cass_value_get_string(value, &data, &len), "cannot get string value");

    return std::string(data, len);
}

int CassandraBackend::getInt(const CassValue* value)
{
    cass_int32_t out;

    checkError(cass_value_get_int32(value, &out), "cannot get integer value");

    return out;
}

bool CassandraBackend::getBool(const CassValue* value)
{
    cass_bool_t out;

    checkError(cass_value_get_bool(value, &out), "cannot get boolean value");

    return out;
}
