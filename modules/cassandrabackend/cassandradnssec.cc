#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "cassandradnssec.h"

#include "pdns/dnsbackend.hh"
#include "pdns/logger.hh"


bool CassandraBackendDNSSec::activateDomainKey(const DNSName& name, unsigned int id)
{
    changeActivation(name, id, true);
    return true;
}

bool CassandraBackendDNSSec::deactivateDomainKey(const DNSName& name, unsigned int id)
{
    changeActivation(name, id, false);
    return true;
}

void CassandraBackendDNSSec::changeActivation(const DNSName& name, unsigned int id, bool active)
{
    std::vector<KeyData> keys;
    getDomainKeys(name, keys);

    int n = -1;
    KeyData* key = nullptr;

    for (int i = 0; i < (int)keys.size(); ++i)
    {
        if (keys[i].id == id)
        {
            key = &keys[i];
            n = i;
            break;
        }
    }

    if (n == -1)
    {
        return;
    }

    CassStatementPtr st = cass_statement_new(("UPDATE " + m_table + " SET keys[?] = ? WHERE domain = ?").c_str(), 3);

    CassTuplePtr tuple = cass_tuple_new(4);

    cass_tuple_set_bool     (tuple, 0, active ? cass_true : cass_false);
    cass_tuple_set_int32    (tuple, 1, key->flags);
    cass_tuple_set_string_n (tuple, 2, key->content.data(), key->content.size());
    cass_tuple_set_int32    (tuple, 3, key->id);

    cass_statement_bind_int32 (st, 0, n);
    cass_statement_bind_tuple (st, 1, tuple);
    cass_statement_bind_string(st, 2, name.toStringRootDot().c_str());

    CassFuturePtr f = cass_session_execute(m_session, st);
    checkCassFutureError(f, "cannot activate domain key", true);
}

bool CassandraBackendDNSSec::addDomainKey(const DNSName& name, const KeyData& key, int64_t& id)
{
    std::vector<KeyData> keys;
    getDomainKeys(name, keys);

    uint32_t newId = 0;
    for (const auto& key: keys)
    {
        if (key.id > newId)
        {
            newId = key.id;
        }
    }

    ++newId;

    g_log << Logger::Info << "[cassandrabackend] addDomainKey(\"" << name << "\", \"" + key.content + "\")" << endl;

    CassStatementPtr st = cass_statement_new(("UPDATE " + m_table + " SET keys = keys + ? WHERE domain = ?").c_str(), 2);

    CassCollectionPtr list = cass_collection_new(CASS_COLLECTION_TYPE_LIST, 1);

    CassTuplePtr tuple = cass_tuple_new(4);

    cass_tuple_set_bool     (tuple, 0, key.active ? cass_true : cass_false);
    cass_tuple_set_int32    (tuple, 1, key.flags);
    cass_tuple_set_string_n (tuple, 2, key.content.data(), key.content.size());
    cass_tuple_set_int32    (tuple, 3, newId);

    cass_collection_append_tuple(list, tuple);

    cass_statement_bind_collection  (st, 0, list);
    cass_statement_bind_string      (st, 1, name.toStringRootDot().c_str());

    checkCassFutureError(cass_session_execute(m_session, st), "cannot add DNSSEC key", true);

    return true;
}

bool CassandraBackendDNSSec::getDomainKeys(const DNSName& name, std::vector<KeyData>& keys)
{
    g_log << Logger::Info << "[cassandrabackend] getDomainKeys(\"" << name << "\")" << endl;

    CassStatementPtr st = cass_statement_new(("SELECT keys FROM " + m_table + " WHERE domain = ?").c_str(), 1);

    cass_statement_bind_string(st, 0, name.toStringRootDot().c_str());

    CassFuturePtr f = cass_session_execute(m_session, st);

    checkCassFutureError(f, "cannot add DNSSEC key", true);

    CassResultPtr result = cass_future_get_result(f);

    const CassRow* row = cass_result_first_row(result);

    if (!row)
    {
        return true;
    }

    CassIteratorPtr it = cass_iterator_from_collection(cass_row_get_column_by_name(row, "keys"));

    if (!it)
    {
        return true;
    }

    while (cass_iterator_next(it))
    {
        const CassValue* value = cass_iterator_get_value(it);

        CassIteratorPtr tupleIt = cass_iterator_from_tuple(value);

        KeyData data {};

        cass_iterator_next(tupleIt);
        data.active = getBool(cass_iterator_get_value(tupleIt));

        cass_iterator_next(tupleIt);
        data.flags = getInt(cass_iterator_get_value(tupleIt));

        cass_iterator_next(tupleIt);
        data.content = getString(cass_iterator_get_value(tupleIt));

        cass_iterator_next(tupleIt);
        data.id = getInt(cass_iterator_get_value(tupleIt));

        g_log << Logger::Info << "[cassandrabackend] loaded domain key : "
                            << data.active  << " - "
                            << data.flags   << " - "
                            << data.content << " - "
                            << data.id      << " - "
                            << endl;

        keys.push_back(std::move(data));
    }

    return true;
}

bool CassandraBackendDNSSec::removeDomainKey(const DNSName& name, unsigned int id)
{
    g_log << Logger::Info << "[cassandrabackend] getDomainKeys(\"" << name << "\")" << endl;

    std::vector<KeyData> keys;
    getDomainKeys(name, keys);

    int n = -1;

    for (int i = 0; i < (int)keys.size(); ++i)
    {
        if (keys[i].id == id)
        {
            n = i;
            break;
        }
    }

    if (n != -1)
    {
        CassStatementPtr st = cass_statement_new(("DELETE keys[?] FROM " + m_table + " WHERE domain = ?").c_str(), 2);

        cass_statement_bind_int32 (st, 0, n);
        cass_statement_bind_string(st, 1, name.toStringRootDot().c_str());

        CassFuturePtr f = cass_session_execute(m_session, st);
        checkCassFutureError(f, "cannot remove domain key", true);
    }

    return true;
}

bool CassandraBackendDNSSec::doesDNSSEC()
{
    return true;
}

bool CassandraBackendDNSSec::getBeforeAndAfterNamesAbsolute(uint32_t id, const DNSName& qname, DNSName& unhashed, DNSName& before, DNSName& after)
{
    return true;
}

bool CassandraBackendDNSSec::updateDNSSECOrderNameAndAuth(uint32_t domain_id, const DNSName& qname, const DNSName& ordername, bool auth, const uint16_t qtype)
{
    return true;
}
