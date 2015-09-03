/*
 * cassandradbmanager.cc
 *
 *  Created on: 11-May-2015
 *      Author: sumit_kumar
 */
#ifndef MY_SINGLETON
#define MY_SINGLETON
#include <iostream>
#include <stdio.h>
#include <string>
#include <stdlib.h>
#include <cassandra.h>
#include <map>
#include "cassandradbmanager.h"
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

bool cassandradbmanager::instanceFlag = false;
cassandradbmanager* cassandradbmanager::single = NULL;
std::string cassandradbmanager::seed_nodes = "127.0.0.1";
std::string cassandradbmanager::username = "cassandra";
std::string cassandradbmanager::password = "cassandra";
std::string cassandradbmanager::keyspace = "pdns";
int cassandradbmanager::port = 9042;
int cassandradbmanager::core_connections = 1;
int cassandradbmanager::max_connections = 1;
int cassandradbmanager::max_concurrent_creations = 1;
int cassandradbmanager::num_io_threads = 1;
int cassandradbmanager::protocol_version = 3;
int cassandradbmanager::queue_size_io = 4096;
int cassandradbmanager::queue_size_event = 4096;
int cassandradbmanager::reconnect_wait_time = 2000;
int cassandradbmanager::concurrent_requests_threshold = 100;
int cassandradbmanager::connect_timeout = 5000;
int cassandradbmanager::request_timeout = 12000;
int cassandradbmanager::enable_load_balance_round_robin = 1;
int cassandradbmanager::enable_token_aware_routing = 0;
int cassandradbmanager::enable_latency_aware_routing = 0;
int cassandradbmanager::enable_tcp_nodelay = 0;
int cassandradbmanager::enable_tcp_keepalive = 0;

cassandradbmanager::cassandradbmanager()
{
	CassFuture* connect_future = NULL;
	  cluster = cass_cluster_new();
	  session = cass_session_new();

	  if(::arg().mustDo("query-logging")) {
		  L << Logger::Debug << "[cassandradbmanager] cassandra-seed-nodes " << seed_nodes << " cassandra-port " << port << endl;
		  L << Logger::Debug << "[cassandradbmanager] cassandra-username " << username << " cassandra-password " << password << endl;
		  L << Logger::Debug << "[cassandradbmanager] cassandra-core-connections " << core_connections << " cassandra-max-connections " << max_connections << endl;
		  L << Logger::Debug << "[cassandradbmanager] cassandra-protocol-version " << protocol_version << " cassandra-num-io-threads " << num_io_threads<< endl;
		  L << Logger::Debug << "[cassandradbmanager] cassandra-max-concurrent-creations " << max_concurrent_creations << endl;
		  L << Logger::Debug << "[cassandradbmanager] cassandra-queue-size-io " << queue_size_io << " cassandra-queue-size-event " << queue_size_event << endl;
		  L << Logger::Debug << "[cassandradbmanager] cassandra-reconnect-wait-time " << reconnect_wait_time << " cassandra-concurrent-requests-threshold " << concurrent_requests_threshold << endl;
		  L << Logger::Debug << "[cassandradbmanager] cassandra-connect-timeout " << connect_timeout << " cassandra-request-timeout " << request_timeout << endl;
		  L << Logger::Debug << "[cassandradbmanager] cassandra-enable-load-balance-round-robin " << enable_load_balance_round_robin << " cassandra-enable-token-aware-routing " << enable_token_aware_routing << endl;
		  L << Logger::Debug << "[cassandradbmanager] cassandra-enable-latency-aware-routing " << enable_latency_aware_routing << endl;
		  L << Logger::Debug << "[cassandradbmanager] cassandra-enable-tcp-nodelay " << enable_tcp_nodelay << " cassandra-enable-tcp-keepalive " << enable_tcp_keepalive << endl;
	  }

	  cass_cluster_set_contact_points(cluster, seed_nodes.c_str());
	  cass_cluster_set_port(cluster, port);
	  cass_cluster_set_credentials(cluster,username.c_str(),password.c_str());
	  cass_cluster_set_num_threads_io(cluster,num_io_threads);
	  cass_cluster_set_protocol_version(cluster,protocol_version);
	  cass_cluster_set_queue_size_io(cluster,queue_size_io);
	  cass_cluster_set_queue_size_event(cluster,queue_size_event);
	  cass_cluster_set_reconnect_wait_time(cluster,reconnect_wait_time);
	  cass_cluster_set_core_connections_per_host(cluster,core_connections);
	  cass_cluster_set_max_connections_per_host(cluster,max_connections);
	  cass_cluster_set_max_concurrent_creation(cluster,max_concurrent_creations);
	  cass_cluster_set_max_concurrent_requests_threshold(cluster,concurrent_requests_threshold);
	  cass_cluster_set_connect_timeout(cluster,connect_timeout);
	  cass_cluster_set_request_timeout(cluster,request_timeout);
	  cass_log_set_level(CASS_LOG_DEBUG);
	  CassRetryPolicy* downgrading_policy = cass_retry_policy_downgrading_consistency_new();
	  cass_cluster_set_retry_policy(cluster, downgrading_policy);
	  if(enable_load_balance_round_robin == 1) {
		  cass_cluster_set_load_balance_round_robin(cluster);
	  }
	  if(enable_token_aware_routing == 1) {
		  cass_cluster_set_token_aware_routing(cluster,cass_true);
	  }
	  if(enable_latency_aware_routing == 1) {
		  cass_cluster_set_latency_aware_routing(cluster,cass_true);
	  }
	  if(enable_tcp_nodelay == 1) {
		  cass_cluster_set_tcp_nodelay(cluster,cass_false);
	  }
	  if(enable_tcp_keepalive == 1) {
		  cass_cluster_set_tcp_keepalive(cluster,cass_false,1);
	  }

	  /* Provide the cluster object as configuration to connect the session */
	  for (int retry_count = 0; retry_count < 10; ++retry_count) {
		  L << Logger::Info << "Connection count "<<retry_count<<endl;
		  connect_future = cass_session_connect_keyspace(session, cluster, keyspace.c_str());
		  if ((cass_future_error_code(connect_future)) == CASS_OK) {
			  instanceFlag = true;
			  break;
		  }
		  sleep(10);
	  }
	  if(instanceFlag == false) {
		  cass_cluster_free(cluster);
		  cass_session_free(session);
	  }
}

cassandradbmanager::~cassandradbmanager()
{
    instanceFlag = false;
    if(session != NULL) {
    	cass_session_free(session);
    }
    if(cluster != NULL) {
    	cass_cluster_free(cluster);
    }
}

cassandradbmanager* cassandradbmanager::getInstance()
{
    if(! instanceFlag)
    {
        single = new cassandradbmanager();
        instanceFlag = true;
        return single;
    }
    else
    {
        return single;
    }
}

string cassandradbmanager::executeAxfrQuery(const char* query,const int domain_id) {
	  if(::arg().mustDo("query-logging")) {
		  L << Logger::Info <<"[cassandradbmanager] Executing axfr query====== domain_id "<<domain_id<<endl;
		  L << Logger::Info <<query<<endl;
	  }
	  CassError rc = CASS_OK;
	  string param = "";
	  CassStatement* statement = NULL;
	  CassFuture* future = NULL;

	  statement = cass_statement_new(query, 1);

	  cass_statement_bind_int32(statement, 0, domain_id);

	  future = cass_session_execute(session, statement);
	  cass_future_wait(future);

	  rc = cass_future_error_code(future);

	  if (rc != CASS_OK) {
		//print_error(future);
	  } else {
		const CassResult* result = cass_future_get_result(future);
		CassIterator* iterator = cass_iterator_from_result(result);
		if (cass_iterator_next(iterator)) {
				  const CassRow* row = cass_iterator_get_row(iterator);
				  CassIterator* fields = cass_iterator_from_collection(cass_row_get_column_by_name(row, "domain"));
				  bool first = true;
				  const char* domain;char* domainTemp;
				  size_t domain_length;
				  while (fields != NULL && cass_iterator_next(fields)) {
					  cass_value_get_string(cass_iterator_get_value(fields), &domain, &domain_length);
					  if(::arg().mustDo("query-logging")) {
						  L << Logger::Debug <<"domain "<<domain<<" length "<<domain_length<<" param |"<<param<<"|"<<endl;
					  }
					  domainTemp = (char*)domain;
					  domainTemp[domain_length] = '\0';
					  if(::arg().mustDo("query-logging")) {
						  L << Logger::Debug <<"trimmed domain "<<domainTemp<<" length "<<domain_length<<" param |"<<param<<"|"<<endl;
					  }
					  if(!first) {
						  param.append(",");
					  }
					  param.append("'");param.append(domainTemp);param.append("'");
					  first = false;
				  }
				  cass_iterator_free(fields);
		}
		cass_result_free(result);
		cass_iterator_free(iterator);
	  }
	  cass_future_free(future);
	  cass_statement_free(statement);
	  return param;
}

void cassandradbmanager::executeQuery(const char* query, struct domainlookuprecords* result1, const char* key, const char* dns_query_type) {
	  if(::arg().mustDo("query-logging")) {
		  L << Logger::Info <<"[cassandradbmanager] Executing executeQuery====== key "<<key<< "dns_query_type" <<dns_query_type<<endl;
		  L << Logger::Info <<query<<endl;
	  }
	  CassError rc = CASS_OK;
	  CassStatement* statement = NULL;
	  CassFuture* future = NULL;

	  statement = cass_statement_new(query, 1);

	  cass_statement_bind_string(statement, 0, key);

	  future = cass_session_execute(session, statement);
	  cass_future_wait(future);

	  rc = cass_future_error_code(future);

	  if (rc != CASS_OK) {
	    //print_error(future);
	  } else {
	    const CassResult* result = cass_future_get_result(future);
	    CassIterator* iterator = cass_iterator_from_result(result);

	    if (cass_iterator_next(iterator)) {
	      const CassRow* row = cass_iterator_get_row(iterator);

	      size_t key_length;const char* key;
	      cass_value_get_string(cass_row_get_column_by_name(row, "domain"), &key, &key_length);
	      result1->domain = key;
	      if(::arg().mustDo("query-logging")) {
	    	  L << Logger::Info <<"[cassandradbmanager] Domain "<<result1->domain<< endl;
	      }
	      CassIterator* record_map_iterator = cass_iterator_from_map(cass_row_get_column_by_name(row, "recordmap"));
	      while (record_map_iterator != NULL && cass_iterator_next(record_map_iterator)) {
	    	  const char* dns_type;
	    	  size_t dns_type_length;
	    	  cass_value_get_string(cass_iterator_get_map_key(record_map_iterator), &dns_type, &dns_type_length);
	    	  if(std::strcmp(dns_type,dns_query_type)!=0 && std::strcmp("ANY",dns_query_type)!=0) {
	    		  continue;
	    	  }
			  CassIterator* fields = cass_iterator_from_user_type(cass_iterator_get_map_value(record_map_iterator));
			  while (fields != NULL && cass_iterator_next(fields)) {
				  const char* field_name;
				  size_t field_name_length;
				  const CassValue* field_value = NULL;
				  cass_iterator_get_user_type_field_name(fields, &field_name, &field_name_length);
				  field_value = cass_iterator_get_user_type_field_value(fields);

				  records record_obj;
				  if (!cass_value_is_null(field_value) && cass_value_type(field_value) == CASS_VALUE_TYPE_MAP) {
					  CassIterator* field_value_record = cass_iterator_from_map(field_value);
					  std::map<std::string, uint32_t> record_obj_map;
					  while (cass_iterator_next(field_value_record)) {
						  const char* dns_record;
						  size_t key_length;
						  cass_value_get_string(cass_iterator_get_map_key(field_value_record), &dns_record, &key_length);
						  cass_int32_t ttl;
						  cass_value_get_int32(cass_iterator_get_map_value(field_value_record), &ttl);
						  record_obj_map.insert(std::pair<std::string, std::uint32_t>(dns_record, ttl));
					  }
					  record_obj.recordMap = record_obj_map;
				  }
				  result1->recordTypeResultArrayMap.insert(std::pair<std::string, records>(dns_type, record_obj));
				  //result1->recordTypeResultArrayMap[dns_type] = record_obj;
			  }
			  cass_iterator_free(fields);
	      }
	      cass_iterator_free(record_map_iterator);
	      cass_bool_t disabled;
	      cass_value_get_bool(cass_row_get_column_by_name(row, "disabled"),&disabled);
	      result1->disabled = disabled;
	      cass_int64_t ts;
	      cass_value_get_int64(cass_row_get_column_by_name(row, "creation_time"), &ts);
	      result1->creation_time = ts;
	      char buff[20];
	      struct tm * timeinfo;
	      timeinfo = localtime (&(result1->creation_time));
	      strftime(buff, sizeof(buff), "%b %d %H:%M\n", timeinfo);

	    }

	    cass_result_free(result);
	    cass_iterator_free(iterator);
	  }

	  cass_future_free(future);
	  cass_statement_free(statement);

}

void cassandradbmanager::executeQuery(const char* query, struct domainlookuprecords* result1, const char* dns_query_type) {
	  if(::arg().mustDo("query-logging")) {
		  L << Logger::Info <<"[cassandradbmanager] Executing executeQuery====== dns_query_type" <<dns_query_type<<endl;
		  L << Logger::Info <<query<<endl;
	  }
	  CassError rc = CASS_OK;
	  CassStatement* statement = NULL;
	  CassFuture* future = NULL;

	  statement = cass_statement_new(query, 0);

	  future = cass_session_execute(session, statement);
	  cass_future_wait(future);

	  rc = cass_future_error_code(future);

	  if (rc != CASS_OK) {
	    //print_error(future);
	  } else {
	    const CassResult* result = cass_future_get_result(future);
	    CassIterator* iterator = cass_iterator_from_result(result);

	    while (cass_iterator_next(iterator)) {
	      const CassRow* row = cass_iterator_get_row(iterator);

	      size_t key_length;const char* key;
	      cass_value_get_string(cass_row_get_column_by_name(row, "domain"), &key, &key_length);
	      result1->domain = key;
	      if(::arg().mustDo("query-logging")) {
	    	  L << Logger::Info <<"[cassandradbmanager] Domain "<<result1->domain<< endl;
	      }
	      CassIterator* record_map_iterator = cass_iterator_from_map(cass_row_get_column_by_name(row, "recordmap"));
	      while (record_map_iterator != NULL && cass_iterator_next(record_map_iterator)) {
	    	  const char* dns_type;
	    	  size_t dns_type_length;
	    	  cass_value_get_string(cass_iterator_get_map_key(record_map_iterator), &dns_type, &dns_type_length);
	    	  if(std::strcmp(dns_type,dns_query_type)!=0 && std::strcmp("ANY",dns_query_type)!=0) {
	    		  continue;
	    	  }
			  CassIterator* fields = cass_iterator_from_user_type(cass_iterator_get_map_value(record_map_iterator));
			  while (fields != NULL && cass_iterator_next(fields)) {
				  const char* field_name;
				  size_t field_name_length;
				  const CassValue* field_value = NULL;
				  cass_iterator_get_user_type_field_name(fields, &field_name, &field_name_length);
				  field_value = cass_iterator_get_user_type_field_value(fields);

				  records record_obj;
				  if (!cass_value_is_null(field_value) && cass_value_type(field_value) == CASS_VALUE_TYPE_MAP) {
					  CassIterator* field_value_record = cass_iterator_from_map(field_value);
					  std::map<std::string, uint32_t> record_obj_map;
					  while (cass_iterator_next(field_value_record)) {
						  const char* dns_record;
						  size_t key_length;
						  cass_value_get_string(cass_iterator_get_map_key(field_value_record), &dns_record, &key_length);
						  cass_int32_t ttl;
						  cass_value_get_int32(cass_iterator_get_map_value(field_value_record), &ttl);
						  record_obj_map.insert(std::pair<std::string, std::uint32_t>(dns_record, ttl));
					  }
					  record_obj.recordMap = record_obj_map;
				  }
				  result1->recordTypeResultArrayMap.insert(std::pair<std::string, records>(dns_type, record_obj));
				  //result1->recordTypeResultArrayMap[dns_type] = record_obj;
			  }
			  cass_iterator_free(fields);
	      }
	      cass_iterator_free(record_map_iterator);
	      cass_bool_t disabled;
	      cass_value_get_bool(cass_row_get_column_by_name(row, "disabled"),&disabled);
	      result1->disabled = disabled;
	      cass_int64_t ts;
	      cass_value_get_int64(cass_row_get_column_by_name(row, "creation_time"), &ts);
	      result1->creation_time = ts;
	      char buff[20];
	      struct tm * timeinfo;
	      timeinfo = localtime (&(result1->creation_time));
	      strftime(buff, sizeof(buff), "%b %d %H:%M\n", timeinfo);

	    }

	    cass_result_free(result);
	    cass_iterator_free(iterator);
	  }

	  cass_future_free(future);
	  cass_statement_free(statement);

}

/*void print_error(CassFuture* future) {
  const char* message;
  size_t message_length;
  cass_future_error_message(future, &message, &message_length);
  fprintf(stderr, "Error: %.*s\n", (int)message_length, message);
}*/

int main()
{
    cassandradbmanager *sc1;
    sc1 = cassandradbmanager::getInstance();
    domainlookuprecords rec;
    sc1->executeQuery("SELECT domain, recordmap, creation_time FROM pdns.domain_lookup_records WHERE domain = ?",&rec,"cassandra.pdns.com","ANY");
    return 0;
}

#endif

