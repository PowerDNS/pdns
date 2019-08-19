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
    checkCassFutureError(f, "cannot activate/deactivate domain key " + std::to_string(n) + " for " + name.toString(), true);
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
    CassStatementPtr st = cass_statement_new(("SELECT records FROM " + m_table + " WHERE domain = ?").c_str(), 1);
    cass_statement_bind_string(st, 0, m_currentDomain.toStringRootDot().c_str());

    CassFuturePtr f = cass_session_execute(m_session, st);

    if (!checkCassFutureError(f, "before/after: cannot get records for " + m_currentDomain.toStringRootDot(), false))
    {
        return false;
    }

    CassResultPtr res = cass_future_get_result(f);

    const CassRow* row = cass_result_first_row(res);

    if (!row)
    {
        return false;
    }

    CassIteratorPtr it = cass_iterator_from_collection(cass_row_get_column(row, 0));

    if (!it)
    {
        return false;
    }

    std::string orderName = qname.toStringNoDot();

    while (cass_iterator_next(it))
    {
        CassIteratorPtr tupleIt = cass_iterator_from_tuple(cass_iterator_get_value(it));

        if (!tupleIt)
        {
            g_log << Logger::Error << "[cassandrabackend] looks like record value is not a tuple" << endl;
            continue;
        }

        cass_iterator_next(tupleIt); // type
        cass_iterator_next(tupleIt); // name
        cass_iterator_next(tupleIt); // ttl
        cass_iterator_next(tupleIt); // record content

        cass_iterator_next(tupleIt); // ordering
        std::string ordering = getString(cass_iterator_get_value(tupleIt));

        if (before.empty() && ordering <= orderName)
        {
            before = DNSName(ordering);
        }

        if (after.empty() && ordering > orderName)
        {
            after = DNSName(ordering);
        }
    }

    if (before.empty())
    {
        before = DNSName("");
    }

    if (after.empty())
    {
        before = qname;
    }

    return true;
}

bool CassandraBackendDNSSec::updateDNSSECOrderNameAndAuth(uint32_t domain_id, const DNSName& qname, const DNSName& ordername, bool auth, const uint16_t qtype)
{
    DNSName relative(qname);

    std::string relativeName = relative.makeRelative(m_currentDomain).toStringNoDot();

    CassStatementPtr st = cass_statement_new(("SELECT records FROM " + m_table + " WHERE domain = ?").c_str(), 1);
    cass_statement_bind_string(st, 0, m_currentDomain.toStringRootDot().c_str());

    CassFuturePtr f = cass_session_execute(m_session, st);

    if (!checkCassFutureError(f, "cannot get records for " + m_currentDomain.toStringRootDot(), false))
    {
        return false;
    }

    CassResultPtr res = cass_future_get_result(f);

    const CassRow* row = cass_result_first_row(res);

    if (!row)
    {
        return false;
    }

    CassIteratorPtr it = cass_iterator_from_collection(cass_row_get_column(row, 0));

    if (!it)
    {
        return false;
    }

    int n = -1;
    QType requestedType(qtype);
    std::string ordering = ordername.toStringNoDot();

    while (cass_iterator_next(it))
    {
        ++n;

        CassIteratorPtr tupleIt = cass_iterator_from_tuple(cass_iterator_get_value(it));

        if (!tupleIt)
        {
            g_log << Logger::Error << "[cassandrabackend] looks like record value is not a tuple" << endl;
            continue;
        }

        cass_iterator_next(tupleIt); // type
        std::string type = getString(cass_iterator_get_value(tupleIt));

        if (requestedType != QType::ANY && requestedType.getName() != type)
        {
            continue;
        }

        cass_iterator_next(tupleIt); // name
        std::string name = getString(cass_iterator_get_value(tupleIt));

        if (name != relativeName)
        {
            continue;
        }

        cass_iterator_next(tupleIt); // ttl
        int ttl = getInt(cass_iterator_get_value(tupleIt));

        cass_iterator_next(tupleIt); // record content
        std::string content = getString(cass_iterator_get_value(tupleIt));

        CassStatementPtr st = cass_statement_new(("UPDATE " + m_table + " SET records[?] = ? WHERE domain = ?").c_str(), 3);

        CassTuplePtr tuple = cass_tuple_new(5);
        cass_tuple_set_string_n (tuple, 0, type.data(), type.size());
        cass_tuple_set_string_n (tuple, 1, name.data(), name.size());
        cass_tuple_set_int32    (tuple, 2, ttl);
        cass_tuple_set_string_n (tuple, 3, content.data(), content.size());
        cass_tuple_set_string_n (tuple, 4, ordering.data(), ordering.size());

        cass_statement_bind_int32   (st, 0, n);
        cass_statement_bind_tuple   (st, 1, tuple);
        cass_statement_bind_string  (st, 2, m_currentDomain.toStringRootDot().c_str());

        CassFuturePtr f = cass_session_execute(m_session, st);
        checkCassFutureError(f, "cannot update ordering information");
    }

    return true;
}

bool CassandraBackendDNSSec::getDomainMetadata(const DNSName& name, const std::string& kind, std::vector<std::string>& meta)
{
    std::string domainName = name.toStringRootDot();

    CassStatementPtr st = cass_statement_new(("SELECT metadata FROM " + m_table + " WHERE domain = ?").c_str(), 1);

    cass_statement_bind_string_n    (st, 0, domainName.data(), domainName.size());

    CassFuturePtr f = cass_session_execute(m_session, st);

    if (!checkCassFutureError(f, "cannot get metadata", false))
    {
        return false;
    }

    CassResultPtr res = cass_future_get_result(f);

    const CassRow* row = cass_result_first_row(res);

    if (!row)
    {
        return false;
    }

    CassIteratorPtr it = cass_iterator_from_map(cass_row_get_column(row, 0));

    if (!it)
    {
        return false;
    }

    while (cass_iterator_next(it))
    {
        std::string key = getString(cass_iterator_get_map_key(it));

        if (key != kind)
        {
            continue;
        }

        std::string value = getString(cass_iterator_get_map_value(it));
        meta.push_back(value);
        return true;
    }

    return false;
}

bool CassandraBackendDNSSec::setDomainMetadata(const DNSName& name, const std::string& kind, const std::vector<std::string>& meta)
{
    std::string domainName = name.toStringRootDot();

    CassStatementPtr st;

    if (meta.empty())
    {
        st = cass_statement_new(("DELETE metadata[?] FROM " + m_table + " WHERE domain = ?").c_str(), 2);

        cass_statement_bind_string_n(st, 0, kind.data(), kind.size());
        cass_statement_bind_string_n(st, 1, domainName.data(), domainName.size());
    }
    else
    {
        st = cass_statement_new(("UPDATE " + m_table + " SET metadata = metadata + ? WHERE domain = ?").c_str(), 2);

        CassCollectionPtr map = cass_collection_new(CASS_COLLECTION_TYPE_MAP, 1);

        cass_collection_append_string_n (map, kind.data(), kind.size());
        cass_collection_append_string_n (map, meta.front().data(), meta.front().size());

        cass_statement_bind_collection  (st, 0, map);
        cass_statement_bind_string_n    (st, 1, domainName.data(), domainName.size());
    }

    CassFuturePtr f = cass_session_execute(m_session, st);

    return checkCassFutureError(f, "cannot add metadata", false);
}

bool CassandraBackendDNSSec::getSOA(const DNSName& name, SOAData& soadata)
{
    // cassandra doesn't have partial key lookups
    // keep current domain to avoid domain_id usage in updateDNSSECOrderNameAndAuth90 and getBeforeAndAfterNamesAbsolute()

    m_currentDomain = name;
    return CassandraBackend::getSOA(name, soadata);
}
