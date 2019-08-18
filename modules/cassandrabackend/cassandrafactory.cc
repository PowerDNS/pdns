#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "pdns/dnsbackend.hh"
#include "pdns/logger.hh"
#include "pdns/arguments.hh"

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
        declare(suffix, "local-dc", "Cassandra local data-center name for DC-aware routing policy", "");
        declare(suffix, "table", "Cassandra table", "dns");
        declare(suffix, "create-table", "Create table if it doesn't exist", "no");
        declare(suffix, "dnssec", "Perform DNSSEC operations", "no");
        declare(suffix, "consistency", "Default cassandra consistency level", "");
        declare(suffix, "log-metrics-interval", "Interval between logging cassndra metrics. Set 0 to disable", "0");
    }

    virtual DNSBackend *make(const string& suffix) override
    {
        if (arg().mustDo(suffix + getName() + "-dnssec"))
        {
            g_log << Logger::Info << "[cassandrabackend] loading dnssec " << suffix << endl;
            return new CassandraBackendDNSSec(suffix);
        }
        else
        {
            g_log << Logger::Info << "[cassandrabackend] loading simple " << suffix << endl;
            return new CassandraBackend(suffix);
        }
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

