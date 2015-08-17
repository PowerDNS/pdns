/*
 * cassandradbmanager.h
 *
 *  Created on: 11-May-2015
 *      Author: sumit_kumar
 */
#include "cassandra.h"
#include "backendutil.cc"
class cassandradbmanager
{
private:
    static bool instanceFlag;
    static cassandradbmanager *single;
    CassCluster* cluster = NULL;
    CassSession* session = NULL;
protected:
    cassandradbmanager();
    ~cassandradbmanager();
    const CassPrepared* prepare_hashquery(CassSession* session);
public:
    static std::string seed_nodes, username, password, keyspace;
    static int core_connections, max_connections, max_concurrent_creations, num_io_threads,protocol_version,queue_size_io,queue_size_event,
    reconnect_wait_time,concurrent_requests_threshold,connect_timeout,request_timeout,enable_load_balance_round_robin,enable_token_aware_routing,
    enable_latency_aware_routing,enable_tcp_nodelay,enable_tcp_keepalive;

    static cassandradbmanager* getInstance();
    void method();
    void executeQuery(const char* query, struct domainlookuprecords* result, const char* key, const char* dns_query_type);
    void executeQuery(const char* query, struct domainlookuprecords* result, const char* dns_query_type);
    string executeAxfrQuery(const char* query,const int domain_id);
};
