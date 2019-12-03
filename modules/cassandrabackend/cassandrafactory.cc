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

        declare(suffix, "local-address", "Sets the local address to bind when connecting to the cluster, if desired.", "");

        // RR-policy
        declare(suffix, "round-robin", "The driver discovers all nodes in a cluster and cycles through them per request. All are considered ‘local’.", "no");

        // DC-aware policy
        declare(suffix, "local-dc", "Cassandra local data-center name for DC-aware routing policy", "");
        declare(suffix, "remote-dc-allow", "Allows remote hosts to be used if no local dc hosts are available and the consistency level is LOCAL_ONE or LOCAL_QUORUM", "yes");
        declare(suffix, "remote-dc-num-hosts", "The number of hosts used in each remote DC if no hosts are available in the local dc", "0");

        // Token-aware policy
        declare(suffix, "token-aware", "Configures the cluster to use token-aware request routing or not", "yes");
        declare(suffix, "token-aware-shuffle", "Configures token-aware routing to randomly shuffle replicas. This can reduce the effectiveness of server-side caching, but it can better distribute load over replicas for a given partition key.", "no");

        // Latency-aware policy
        declare(suffix, "latency-aware", "Configures the cluster to use latency-aware request routing or not.", "no");
        declare(suffix, "latency-aware-exclusion-threshold", "Controls how much worse the latency must be compared to the average latency of the best performing node before it penalized.", "2.0");
        declare(suffix, "latency-aware-scale", "Controls the weight given to older latencies when calculating the average latency of a node. A bigger scale will give more weight to older latency measurements.", "100");
        declare(suffix, "latency-aware-retry", "The amount of time a node is penalized by the policy before being given a second chance when the current average latency exceeds the calculated threshold (exclusion-threshold * best-average-latency).", "10000");
        declare(suffix, "latency-aware-update-rate", "The rate at which the best average latency is recomputed.", "100");
        declare(suffix, "latency-aware-min-measured", "The minimum number of measurements per-host required to be considered by the policy.", "50");

        declare(suffix, "hosts-whitelist", "This policy filters requests to all other policies, only allowing requests to the hosts contained in the whitelist. Any host not in the whitelist will be ignored and a connection will not be established. This policy is useful for ensuring that the driver will only connect to a predefined set of hosts. Examples: : \"127.0.0.1\" \"127.0.0.1,127.0.0.2\"", "");
        declare(suffix, "hosts-blacklist", "This policy filters requests to all other policies, only allowing requests to the hosts not contained in the blacklist. Any host in the blacklist will be ignored and a connection will not be established. This policy is useful for ensuring that the driver will not connect to a predefined set of hosts. Examples: : \"127.0.0.1\" \"127.0.0.1,127.0.0.2\"", "");

        declare(suffix, "dc-whitelist", "Same as hosts-whitelist, but whitelist all hosts of a dc. Examples: \"dc1\", \"dc1,dc2\"", "");
        declare(suffix, "dc-blacklist", "Same as hosts-blacklist, but blacklist all hosts of a dc. Examples: \"dc1\", \"dc1,dc2\"", "");

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

