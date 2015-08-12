/*
 * CassandraBackend - a high performance LMDB based backend for PowerDNS written by
 * Mark Zealey, 2013
 *
 * This was originally going to be a backend using BerkeleyDB 5 for high
 * performance DNS over massive (millions of zones) databases. However,
 * BerkeleyDB had a number of issues to do with locking, contention and
 * corruption which made it unsuitable for use. Instead, we use LMDB to perform
 * very fast lookups.
 *
 * See the documentation for more details, and lmdb-example.pl for an example
 * script which generates a simple zone.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "pdns/utility.hh"
#include "pdns/dnsbackend.hh"
#include "pdns/dns.hh"
#include "pdns/dnspacket.hh"
#include "pdns/pdnsexception.hh"
#include "pdns/logger.hh"
#include <signal.h>
#include "pdns/arguments.hh"
#include "pdns/base32.hh"
#include "pdns/lock.hh"
#include <iostream>
#include "cassandradbmanager.h"

#if 0
#define DEBUGLOG(msg) L<<Logger::Error<<msg
#else
#define DEBUGLOG(msg) do {} while(0)
#endif

class CassandraBackend : public DNSBackend
{

private:
  backendrecord* backendRecords = NULL;
  int recordIndex = 0;
  int totalSize = 0;
  domainlookuprecords record;
  std::string soarecord = "ahu.fake.com ns1.fake.com 2008080300 1800 3600 604800 3600";
  std::string domain;
  std::string queryType;

  bool hasEnding (std::string const &fullString, std::string const &ending) {
      if (fullString.length() >= ending.length()) {
          return (0 == fullString.compare (fullString.length() - ending.length(), ending.length(), ending));
      } else {
          return false;
      }
  }
public:
  CassandraBackend(const string &suffix) {
	  L << Logger::Info << " Launching CassandraBackend instance " << endl;
	  setArgPrefix("cassandra"+suffix);
	 try {
		std::string seed_nodes = getArg("seed-nodes");
		std::string username = getArg("username");
		std::string password = getArg("password");
		std::string keyspace = getArg("keyspace");
		int core_connections = getArgAsNum("core-connections");
		int max_connections = getArgAsNum("max-connections");
		int max_concurrent_creations = getArgAsNum("max-concurrent-creations");
		int num_io_threads = getArgAsNum("num-io-threads");
		int protocol_version = getArgAsNum("protocol-version");
		int queue_size_io = getArgAsNum("queue-size-io");
		int queue_size_event = getArgAsNum("queue-size-event");
		int reconnect_wait_time = getArgAsNum("reconnect-wait-time");
		int concurrent_requests_threshold = getArgAsNum("concurrent-requests-threshold");
		int connect_timeout = getArgAsNum("connect-timeout");
		int request_timeout = getArgAsNum("request-timeout");
		int enable_load_balance_round_robin = getArgAsNum("enable-load-balance-round-robin");
		int enable_token_aware_routing = getArgAsNum("enable-token-aware-routing");
		int enable_latency_aware_routing = getArgAsNum("enable-latency-aware-routing");
		int enable_tcp_nodelay = getArgAsNum("enable-tcp-nodelay");
		int enable_tcp_keepalive = getArgAsNum("enable-tcp-keepalive");

		L << Logger::Info << " cassandra-seed-nodes " << seed_nodes << " cassandra-keyspace " << keyspace << endl;
		L << Logger::Info << " cassandra-username " << username << " cassandra-password " << password << endl;
		L << Logger::Info << " cassandra-core-connections " << core_connections << " cassandra-max_connections " << max_connections << endl;
		L << Logger::Info << "[cassandradbmanager] cassandra-protocol-version " << protocol_version << endl;
		L << Logger::Info << "[cassandradbmanager] cassandra-max-concurrent-creations " << max_concurrent_creations << endl;
		L << Logger::Info << "[cassandradbmanager] cassandra-queue-size-io " << queue_size_io << " cassandra-queue-size-event " << queue_size_event << endl;
		L << Logger::Info << "[cassandradbmanager] cassandra-reconnect-wait-time " << reconnect_wait_time << " cassandra-concurrent-requests-threshold " << concurrent_requests_threshold << endl;
		L << Logger::Info << "[cassandradbmanager] cassandra-connect-timeout " << connect_timeout << " cassandra-request-timeout " << request_timeout << endl;
		L << Logger::Info << "[cassandradbmanager] cassandra-enable-load-balance-round-robin " << enable_load_balance_round_robin << " cassandra-enable-token-aware-routing " << enable_token_aware_routing << endl;
		L << Logger::Info << "[cassandradbmanager] cassandra-enable-latency-aware-routing " << enable_latency_aware_routing << endl;
		L << Logger::Info << "[cassandradbmanager] cassandra-enable-tcp-nodelay " << enable_tcp_nodelay << " cassandra-enable-tcp-keepalive " << enable_tcp_keepalive << endl;
		cassandradbmanager::seed_nodes = seed_nodes;
		cassandradbmanager::username = username;
		cassandradbmanager::password = password;
		cassandradbmanager::keyspace = keyspace;
		cassandradbmanager::core_connections = core_connections;
		cassandradbmanager::max_connections = max_connections;
		cassandradbmanager::max_concurrent_creations = max_concurrent_creations;
		cassandradbmanager::num_io_threads = num_io_threads;
		cassandradbmanager::protocol_version = protocol_version;
		cassandradbmanager::queue_size_io = queue_size_io;
		cassandradbmanager::queue_size_event = queue_size_event;
		cassandradbmanager::reconnect_wait_time = reconnect_wait_time;
		cassandradbmanager::concurrent_requests_threshold = concurrent_requests_threshold;
		cassandradbmanager::connect_timeout = connect_timeout;
		cassandradbmanager::request_timeout = request_timeout;
		cassandradbmanager::enable_load_balance_round_robin = enable_load_balance_round_robin;
		cassandradbmanager::enable_token_aware_routing = enable_token_aware_routing;
		cassandradbmanager::enable_latency_aware_routing = enable_latency_aware_routing;
		cassandradbmanager::enable_tcp_nodelay = enable_tcp_nodelay;
		cassandradbmanager::enable_tcp_keepalive = enable_tcp_keepalive;

		L << Logger::Info << " Connecting to cassandra cluster " << endl;
		cassandradbmanager::getInstance();
		L << Logger::Info << " Connection to cassandra cluster successful " << endl;

	 } catch (const ArgException &A) {
		L << Logger::Error << "[CassandraBackend]" << " Fatal argument error: "<< A.reason << endl;
		throw;
	 } catch (...) {
		throw;
	 }

  }

  bool list(const string &target, int domain_id, bool include_disabled=false)
  {
    return false; // we don't support AXFR
  }

  bool getSOA(const string &name, SOAData &soadata, DNSPacket *p=0) {
	 domain = name;
	 L << Logger::Info << "[CassandraBackend] Recieved getSOA " <<domain<< " "<< endl;
	 if(domain.compare("pdns.com") == 0) {
		 soadata.db = this;
		 soadata.serial = 0;
		 soadata.refresh = 10;
		 soadata.retry = 10;
		 soadata.expire = 10;
		 soadata.default_ttl = 10;
		 soadata.domain_id = 10;
		 soadata.ttl = 10;
		 soadata.nameserver = "ns1.pdns.com";
		 soadata.hostmaster = "ahu.pdns.com";
		return true;
	 } else {
		return false;
	 }
  }

  void lookup(const QType &type, const string &qdomain, DNSPacket *p, int zoneId)
  {
    queryType = type.getName();
    domain = qdomain;
    recordIndex = 0;
    totalSize = 0;
    L << Logger::Info << "[CassandraBackend] Recieved query for "<<queryType<< " " <<domain<< " "<< endl;
    L << Logger::Info << "[CassandraBackend] Calling cassandradbmanger" << endl;
    	cassandradbmanager *sc1 = cassandradbmanager::getInstance();

    	std::string trailingsuffix = ".pdns.com";
    	std::string::size_type i = domain.find(trailingsuffix);
    	if (i != std::string::npos) {
    		//domain.erase(i, trailingsuffix.length());
    	}
    	const char* query = "SELECT domain, recordmap, creation_time FROM pdns.domain_lookup_records WHERE domain = ?";
    	L << Logger::Info << "[CassandraBackend] SELECT domain, recordmap, creation_time FROM pdns.domain_lookup_records WHERE domain = "<<domain<< endl;
    	sc1->executeQuery(query,&record,domain.c_str(),queryType.c_str());
    	backendRecords = backendutil::parse(&record);
    	this->totalSize = record.size;
  }

  bool get(DNSResourceRecord &rr)
  {
	  L << Logger::Info << " Read record Step 1 " << recordIndex << " " << totalSize << endl;
	  if(this->totalSize == 0 || recordIndex >= this->totalSize) {
		  L << Logger::Info << " No record False " << recordIndex << " "<< totalSize << endl;
		  recordIndex = 0;totalSize = 0;domain.clear();queryType.clear();backendRecords = NULL;//record.url_hash = NULL; record.url_rawdata = NULL;record.a_record.clear(); record.txt_record.clear();
		  return false;
	  }
	  backendrecord backendRecord = backendRecords[recordIndex];
	  L << Logger::Info << " Read record Step 2 " << endl;
      rr.qname=domain;                               // fill in details
      L << Logger::Info << " Read record Step 3 " << rr.qname << endl;
      rr.qtype=backendRecord.getType();                                            // A/TXT record
      L << Logger::Info << " Read record Step 4 " << rr.qtype.getName() << " | "<< endl;
      rr.ttl=86400;                                                 // 1 day
      L << Logger::Info << " Read record Step 5 " << rr.ttl << endl;
      rr.content=backendRecord.getRecord();
      L << Logger::Info << " Read record Step 6 " << rr.content << endl;
      if(recordIndex < this->totalSize) {
    	  L << Logger::Info << " Read record True " << recordIndex << " "<< totalSize << endl;
    	  L << Logger::Info << "--------------------------------------" << endl;
    	  recordIndex++;
    	  return true;
      } else {
    	  L << Logger::Info << " Read record False " << recordIndex << " "<< totalSize << endl;
    	  L << Logger::Info << "--------------------------------------" << endl;
    	  //recordIndex = 0;totalSize = 0;domain.clear();queryType.clear();backendRecords = NULL;
    	  recordIndex++;
    	  return false;
      }
  }

};

/*bool hasEnding (std::string const &fullString, std::string const &ending) {
    if (fullString.length() >= ending.length()) {
        return (0 == fullString.compare (fullString.length() - ending.length(), ending.length(), ending));
    } else {
        return false;
    }
}*/

/* SECOND PART */

class CassandraBackendFactory : public BackendFactory
{
public:
  CassandraBackendFactory() : BackendFactory("cassandra") {}

  void declareArguments(const string &suffix="")
  {
	declare(suffix,"seed-nodes","seed nodes","myseeds");
	declare(suffix,"username","user name","myusername");
	declare(suffix,"password","password","mypassword");
	declare(suffix,"keyspace","keyspace","mykeyspace");
	declare(suffix,"core-connections","core connections","40");
	declare(suffix,"max-connections","max connections","100");
	declare(suffix,"max-concurrent-creations","max concurrent creations","100");
	declare(suffix,"num-io-threads","num io threads","1");
	declare(suffix,"protocol-version","protocol version","2");
	declare(suffix,"queue-size-io","queue size io","4096");
	declare(suffix,"queue-size-event","queue size event","4096");
	declare(suffix,"reconnect-wait-time","reconnect wait time","2000");
	declare(suffix,"concurrent-requests-threshold","concurrent requests threshold","100");
	declare(suffix,"connect-timeout","connect timeout","5000");
	declare(suffix,"request-timeout","request timeout","12000");
	declare(suffix,"enable-load-balance-round-robin","enable load balance round robin","1");
	declare(suffix,"enable-token-aware-routing","enable token aware routing","0");
	declare(suffix,"enable-latency-aware-routing","enable latency aware routing","0");
	declare(suffix,"enable-tcp-nodelay","enable tcp nodelay","0");
	declare(suffix,"enable-tcp-keepalive","enable tcp keepalive","0");
  }

  DNSBackend *make(const string &suffix="")
  {
    return new CassandraBackend(suffix);
  }
};

/* THIRD PART */

class CassandraBackendLoader
{
public:
  CassandraBackendLoader()
  {
    BackendMakers().report(new CassandraBackendFactory);
    L << Logger::Info << "[cassandrabackendbackend] This is the cassandrabackend backend version  1" << endl;
  }
};

static CassandraBackendLoader cassandrabackendloader;
