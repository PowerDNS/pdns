/*
 * cassandradbmanager.cc
 *
 *  Created on: 11-May-2015
 *      Author: sumit_kumar5
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

bool cassandradbmanager::instanceFlag = false;
cassandradbmanager* cassandradbmanager::single = NULL;
std::string cassandradbmanager::seed_nodes = "dummy_seednodes";
std::string cassandradbmanager::username = "dummy_username";
std::string cassandradbmanager::password = "dummy_password";
std::string cassandradbmanager::keyspace = "dummy_keyspace";
int cassandradbmanager::core_connections = 1;
int cassandradbmanager::max_connections = 1;
int cassandradbmanager::max_concurrent_creations = 1;
int cassandradbmanager::num_io_threads = 1;
int cassandradbmanager::protocol_version = 2;
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
const CassPrepared* preparedHashQuery = NULL;

cassandradbmanager::cassandradbmanager()
{
	CassFuture* connect_future = NULL;
	  cluster = cass_cluster_new();
	  session = cass_session_new();

	  std::cout << "[cassandradbmanager] cassandra-seed-nodes " << seed_nodes << " cassandra-num-io-threads " << num_io_threads << endl;
	  std::cout << "[cassandradbmanager] cassandra-username " << username << " cassandra-password " << password << endl;
	  std::cout << "[cassandradbmanager] cassandra-core-connections " << core_connections << " cassandra-max-connections " << max_connections << endl;
	  std::cout << "[cassandradbmanager] cassandra-protocol-version " << protocol_version << endl;
	  std::cout << "[cassandradbmanager] cassandra-max-concurrent-creations " << max_concurrent_creations << endl;
	  std::cout << "[cassandradbmanager] cassandra-queue-size-io " << queue_size_io << " cassandra-queue-size-event " << queue_size_event << endl;
	  std::cout << "[cassandradbmanager] cassandra-reconnect-wait-time " << reconnect_wait_time << " cassandra-concurrent-requests-threshold " << concurrent_requests_threshold << endl;
	  std::cout << "[cassandradbmanager] cassandra-connect-timeout " << connect_timeout << " cassandra-request-timeout " << request_timeout << endl;
	  std::cout << "[cassandradbmanager] cassandra-enable-load-balance-round-robin " << enable_load_balance_round_robin << " cassandra-enable-token-aware-routing " << enable_token_aware_routing << endl;
	  std::cout << "[cassandradbmanager] cassandra-enable-latency-aware-routing " << enable_latency_aware_routing << endl;
	  std::cout << "[cassandradbmanager] cassandra-enable-tcp-nodelay " << enable_tcp_nodelay << " cassandra-enable-tcp-keepalive " << enable_tcp_keepalive << endl;

	  /* Add contact points */
	  cass_cluster_set_contact_points(cluster, seed_nodes.c_str());
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
	  connect_future = cass_session_connect_keyspace(session, cluster, keyspace.c_str());

	  if ((cass_future_error_code(connect_future)) != CASS_OK) {
	      cass_cluster_free(cluster);
	      cass_session_free(session);
	      instanceFlag = false;
	   } else {
		   instanceFlag = true;
		   preparedHashQuery = this->prepare_hashquery(session);
	   }
}

cassandradbmanager::~cassandradbmanager()
{
    instanceFlag = false;
    cass_prepared_free(preparedHashQuery);
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

void cassandradbmanager::executeQuery(const char* query, struct domainlookuprecords* result1, const char* key, const char* dns_query_type) {
	printf("====Executing domain query======");
	//Query : SELECT domain, recordmap, creation_time FROM pdns.domain_lookup_records WHERE domain = ?
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
	      printf("\n%s\n",result1->domain);

	      //const CassDataType* udt_records = cass_schema_get_udt(schema, "pdns", "records");

	      ////////////////
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

				  printf("%.*s ", (int)field_name_length, field_name);

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
	      /////////////////////

	      cass_bool_t disabled;
	      cass_value_get_bool(cass_row_get_column_by_name(row, "disabled"),&disabled);
	      result1->disabled = disabled;
	      printf("disabled %d\n",result1->disabled);

	      cass_int64_t ts;
	      cass_value_get_int64(cass_row_get_column_by_name(row, "creation_time"), &ts);
	      result1->creation_time = ts;
	      char buff[20];
	      struct tm * timeinfo;
	      timeinfo = localtime (&(result1->creation_time));
	      strftime(buff, sizeof(buff), "%b %d %H:%M\n", timeinfo);
	      printf("%s",buff);

	    }

	    cass_result_free(result);
	    cass_iterator_free(iterator);
	  }

	  cass_future_free(future);
	  cass_statement_free(statement);

	  //return rc;

}

/*const CassPrepared* cassandradbmanager::prepare_hashquery(CassSession* session) {
  const char* query = "";
  CassFuture* prepare_future = cass_session_prepare(session, query);
  const CassPrepared* prepared = NULL;

  CassError rc = cass_future_error_code(prepare_future);
  printf("Prepare result: %s\n", cass_error_desc(rc));
  if (rc != CASS_OK) {
	 Handle error
	cass_future_free(prepare_future);
  } else {
    This could be stored for later use and can even used by multiple threads
    prepared = cass_future_get_prepared(prepare_future);
  }
  cass_future_free(prepare_future);

  return prepared;
}*/

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
    sc1->executeQuery("SELECT domain, recordmap, creation_time FROM pdns.domain_lookup_records WHERE domain = ?",&rec,"www.google.","ANY");
    return 0;
}

#endif

