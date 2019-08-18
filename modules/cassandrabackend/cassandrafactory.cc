#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pdns/dnsbackend.hh"
#include "pdns/logger.hh"

#include "cassandrabackend.h"
#include "cassandradnssec.h"

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
        g_log << Logger::Info << "[cassandrabackend] loading " << suffix << endl;
        return new CassandraBackendDNSSec(suffix);
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

