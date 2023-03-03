/*
 * This file is part of PowerDNS or dnsdist.
 * Copyright -- PowerDNS.COM B.V. and its contributors
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * In addition, for the avoidance of any doubt, permission is granted to
 * link this program with OpenSSL and to (re)distribute the binaries
 * produced as the result of such linking.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* we don't use a guard (C++ pragma once or even #ifndef because this file (the .inc version)
   is passed to the Lua FFI wrapper which doesn't support it */

typedef struct dnsdist_ffi_dnsquestion_t dnsdist_ffi_dnsquestion_t;
typedef struct dnsdist_ffi_dnsresponse_t dnsdist_ffi_dnsresponse_t;
typedef struct dnsdist_ffi_servers_list_t dnsdist_ffi_servers_list_t;
typedef struct dnsdist_ffi_server_t dnsdist_ffi_server_t;

typedef struct dnsdist_ffi_ednsoption {
  uint16_t    optionCode;
  uint16_t    len;
  const void* data;
} dnsdist_ffi_ednsoption_t;

typedef struct dnsdist_ffi_http_header {
  const char* name;
  const char* value;
} dnsdist_ffi_http_header_t;

typedef struct dnsdist_ffi_tag {
  const char* name;
  const char* value;
} dnsdist_ffi_tag_t;

typedef struct dnsdist_ffi_raw_value {
  const char* value;
  uint16_t size;
} dnsdist_ffi_raw_value_t;

typedef enum {
 dnsdist_ffi_protocol_type_doudp = 0,
 dnsdist_ffi_protocol_type_dotcp = 1,
 dnsdist_ffi_protocol_type_dnscryptudp = 2,
 dnsdist_ffi_protocol_type_dnscrypttcp = 3,
 dnsdist_ffi_protocol_type_dot = 4,
 dnsdist_ffi_protocol_type_doh = 5,
} dnsdist_ffi_protocol_type;

void dnsdist_ffi_dnsquestion_get_localaddr(const dnsdist_ffi_dnsquestion_t* dq, const void** addr, size_t* addrSize) __attribute__ ((visibility ("default")));
uint16_t dnsdist_ffi_dnsquestion_get_local_port(const dnsdist_ffi_dnsquestion_t* dq) __attribute__ ((visibility ("default")));
void dnsdist_ffi_dnsquestion_get_remoteaddr(const dnsdist_ffi_dnsquestion_t* dq, const void** addr, size_t* addrSize) __attribute__ ((visibility ("default")));
void dnsdist_ffi_dnsquestion_get_masked_remoteaddr(dnsdist_ffi_dnsquestion_t* dq, const void** addr, size_t* addrSize, uint8_t bits) __attribute__ ((visibility ("default")));
uint16_t dnsdist_ffi_dnsquestion_get_remote_port(const dnsdist_ffi_dnsquestion_t* dq) __attribute__ ((visibility ("default")));
void dnsdist_ffi_dnsquestion_get_qname_raw(const dnsdist_ffi_dnsquestion_t* dq, const char** qname, size_t* qnameSize) __attribute__ ((visibility ("default")));
size_t dnsdist_ffi_dnsquestion_get_qname_hash(const dnsdist_ffi_dnsquestion_t* dq, size_t init) __attribute__ ((visibility ("default")));
uint16_t dnsdist_ffi_dnsquestion_get_qtype(const dnsdist_ffi_dnsquestion_t* dq) __attribute__ ((visibility ("default")));
uint16_t dnsdist_ffi_dnsquestion_get_qclass(const dnsdist_ffi_dnsquestion_t* dq) __attribute__ ((visibility ("default")));
uint16_t dnsdist_ffi_dnsquestion_get_id(const dnsdist_ffi_dnsquestion_t* dq) __attribute__ ((visibility ("default")));
int dnsdist_ffi_dnsquestion_get_rcode(const dnsdist_ffi_dnsquestion_t* dq) __attribute__ ((visibility ("default")));
void* dnsdist_ffi_dnsquestion_get_header(const dnsdist_ffi_dnsquestion_t* dq) __attribute__ ((visibility ("default")));
uint16_t dnsdist_ffi_dnsquestion_get_len(const dnsdist_ffi_dnsquestion_t* dq) __attribute__ ((visibility ("default")));
size_t dnsdist_ffi_dnsquestion_get_size(const dnsdist_ffi_dnsquestion_t* dq) __attribute__ ((visibility ("default")));
bool dnsdist_ffi_dnsquestion_set_size(dnsdist_ffi_dnsquestion_t* dq, size_t newSize) __attribute__ ((visibility ("default")));
uint8_t dnsdist_ffi_dnsquestion_get_opcode(const dnsdist_ffi_dnsquestion_t* dq) __attribute__ ((visibility ("default")));
bool dnsdist_ffi_dnsquestion_get_tcp(const dnsdist_ffi_dnsquestion_t* dq) __attribute__ ((visibility ("default")));
dnsdist_ffi_protocol_type dnsdist_ffi_dnsquestion_get_protocol(const dnsdist_ffi_dnsquestion_t* dq) __attribute__ ((visibility ("default")));
bool dnsdist_ffi_dnsquestion_get_skip_cache(const dnsdist_ffi_dnsquestion_t* dq) __attribute__ ((visibility ("default")));
bool dnsdist_ffi_dnsquestion_get_use_ecs(const dnsdist_ffi_dnsquestion_t* dq) __attribute__ ((visibility ("default")));
bool dnsdist_ffi_dnsquestion_get_add_xpf(const dnsdist_ffi_dnsquestion_t* dq) __attribute__ ((visibility ("default")));
bool dnsdist_ffi_dnsquestion_get_ecs_override(const dnsdist_ffi_dnsquestion_t* dq) __attribute__ ((visibility ("default")));
uint16_t dnsdist_ffi_dnsquestion_get_ecs_prefix_length(const dnsdist_ffi_dnsquestion_t* dq) __attribute__ ((visibility ("default")));
bool dnsdist_ffi_dnsquestion_is_temp_failure_ttl_set(const dnsdist_ffi_dnsquestion_t* dq) __attribute__ ((visibility ("default")));
uint32_t dnsdist_ffi_dnsquestion_get_temp_failure_ttl(const dnsdist_ffi_dnsquestion_t* dq) __attribute__ ((visibility ("default")));
bool dnsdist_ffi_dnsquestion_get_do(const dnsdist_ffi_dnsquestion_t* dq) __attribute__ ((visibility ("default")));
void dnsdist_ffi_dnsquestion_get_sni(const dnsdist_ffi_dnsquestion_t* dq, const char** sni, size_t* sniSize) __attribute__ ((visibility ("default")));
const char* dnsdist_ffi_dnsquestion_get_tag(const dnsdist_ffi_dnsquestion_t* dq, const char* label) __attribute__ ((visibility ("default")));
size_t dnsdist_ffi_dnsquestion_get_tag_raw(const dnsdist_ffi_dnsquestion_t* dq, const char* label, char* buffer, size_t bufferSize) __attribute__ ((visibility ("default")));
const char* dnsdist_ffi_dnsquestion_get_http_path(dnsdist_ffi_dnsquestion_t* dq) __attribute__ ((visibility ("default")));
const char* dnsdist_ffi_dnsquestion_get_http_query_string(dnsdist_ffi_dnsquestion_t* dq) __attribute__ ((visibility ("default")));
const char* dnsdist_ffi_dnsquestion_get_http_host(dnsdist_ffi_dnsquestion_t* dq) __attribute__ ((visibility ("default")));
const char* dnsdist_ffi_dnsquestion_get_http_scheme(dnsdist_ffi_dnsquestion_t* dq) __attribute__ ((visibility ("default")));
size_t dnsdist_ffi_dnsquestion_get_mac_addr(const dnsdist_ffi_dnsquestion_t* dq, void* buffer, size_t bufferSize) __attribute__ ((visibility ("default")));
uint64_t dnsdist_ffi_dnsquestion_get_elapsed_us(const dnsdist_ffi_dnsquestion_t* dq) __attribute__ ((visibility ("default")));

// returns the length of the resulting 'out' array. 'out' is not set if the length is 0
size_t dnsdist_ffi_dnsquestion_get_edns_options(dnsdist_ffi_dnsquestion_t* ref, const dnsdist_ffi_ednsoption_t** out) __attribute__ ((visibility ("default")));
size_t dnsdist_ffi_dnsquestion_get_http_headers(dnsdist_ffi_dnsquestion_t* ref, const dnsdist_ffi_http_header_t** out) __attribute__ ((visibility ("default")));
size_t dnsdist_ffi_dnsquestion_get_tag_array(dnsdist_ffi_dnsquestion_t* ref, const dnsdist_ffi_tag_t** out) __attribute__ ((visibility ("default")));

void dnsdist_ffi_dnsquestion_set_result(dnsdist_ffi_dnsquestion_t* dq, const char* str, size_t strSize) __attribute__ ((visibility ("default")));
void dnsdist_ffi_dnsquestion_set_rcode(dnsdist_ffi_dnsquestion_t* dq, int rcode) __attribute__ ((visibility ("default")));
void dnsdist_ffi_dnsquestion_set_len(dnsdist_ffi_dnsquestion_t* dq, uint16_t len) __attribute__ ((visibility ("default")));
void dnsdist_ffi_dnsquestion_set_skip_cache(dnsdist_ffi_dnsquestion_t* dq, bool skipCache) __attribute__ ((visibility ("default")));
void dnsdist_ffi_dnsquestion_set_use_ecs(dnsdist_ffi_dnsquestion_t* dq, bool useECS) __attribute__ ((visibility ("default")));
void dnsdist_ffi_dnsquestion_set_ecs_override(dnsdist_ffi_dnsquestion_t* dq, bool ecsOverride) __attribute__ ((visibility ("default")));
void dnsdist_ffi_dnsquestion_set_ecs_prefix_length(dnsdist_ffi_dnsquestion_t* dq, uint16_t ecsPrefixLength) __attribute__ ((visibility ("default")));
void dnsdist_ffi_dnsquestion_set_temp_failure_ttl(dnsdist_ffi_dnsquestion_t* dq, uint32_t tempFailureTTL) __attribute__ ((visibility ("default")));
void dnsdist_ffi_dnsquestion_unset_temp_failure_ttl(dnsdist_ffi_dnsquestion_t* dq) __attribute__ ((visibility ("default")));
void dnsdist_ffi_dnsquestion_set_tag(dnsdist_ffi_dnsquestion_t* dq, const char* label, const char* value) __attribute__ ((visibility ("default")));
void dnsdist_ffi_dnsquestion_set_tag_raw(dnsdist_ffi_dnsquestion_t* dq, const char* label, const char* value, size_t valueSize) __attribute__ ((visibility ("default")));

void dnsdist_ffi_dnsquestion_set_requestor_id(dnsdist_ffi_dnsquestion_t* dq, const char* value, size_t valueSize) __attribute__ ((visibility ("default")));
void dnsdist_ffi_dnsquestion_set_device_id(dnsdist_ffi_dnsquestion_t* dq, const char* value, size_t valueSize) __attribute__ ((visibility ("default")));
void dnsdist_ffi_dnsquestion_set_device_name(dnsdist_ffi_dnsquestion_t* dq, const char* value, size_t valueSize) __attribute__ ((visibility ("default")));

void dnsdist_ffi_dnsquestion_set_http_response(dnsdist_ffi_dnsquestion_t* dq, uint16_t statusCode, const char* body, size_t bodyLen, const char* contentType) __attribute__ ((visibility ("default")));

size_t dnsdist_ffi_dnsquestion_get_trailing_data(dnsdist_ffi_dnsquestion_t* dq, const char** out) __attribute__ ((visibility ("default")));

bool dnsdist_ffi_dnsquestion_set_trailing_data(dnsdist_ffi_dnsquestion_t* dq, const char* data, size_t dataLen) __attribute__ ((visibility ("default")));

void dnsdist_ffi_dnsquestion_send_trap(dnsdist_ffi_dnsquestion_t* dq, const char* reason, size_t reasonLen) __attribute__ ((visibility ("default")));

// the content of values should contain raw DNS record data ('\192\000\002\001' for A, '\034this text has a comma at the end,' for TXT, etc)
void dnsdist_ffi_dnsquestion_spoof_raw(dnsdist_ffi_dnsquestion_t* dq, const dnsdist_ffi_raw_value_t* values, size_t valuesCount) __attribute__ ((visibility ("default")));
// the content of values should contain raw IPv4 or IPv6 addresses in network byte-order
void dnsdist_ffi_dnsquestion_spoof_addrs(dnsdist_ffi_dnsquestion_t* dq, const dnsdist_ffi_raw_value_t* values, size_t valuesCount) __attribute__ ((visibility ("default")));
// spoof raw response. will just replace qid to match question
void dnsdist_ffi_dnsquestion_spoof_packet(dnsdist_ffi_dnsquestion_t* dq, const char* rawresponse, size_t len) __attribute__ ((visibility ("default")));

/* decrease the returned TTL but _after_ inserting the original response into the packet cache */
void dnsdist_ffi_dnsquestion_set_max_returned_ttl(dnsdist_ffi_dnsquestion_t* dq, uint32_t max) __attribute__ ((visibility ("default")));
bool dnsdist_ffi_dnsquestion_set_restartable(dnsdist_ffi_dnsquestion_t* dq) __attribute__ ((visibility ("default")));

typedef struct dnsdist_ffi_servers_list_t dnsdist_ffi_servers_list_t;
typedef struct dnsdist_ffi_server_t dnsdist_ffi_server_t;

size_t dnsdist_ffi_servers_list_get_count(const dnsdist_ffi_servers_list_t* list) __attribute__ ((visibility ("default")));
void dnsdist_ffi_servers_list_get_server(const dnsdist_ffi_servers_list_t* list, size_t idx, const dnsdist_ffi_server_t** out) __attribute__ ((visibility ("default")));
size_t dnsdist_ffi_servers_list_chashed(const dnsdist_ffi_servers_list_t* list, const dnsdist_ffi_dnsquestion_t* dq, size_t hash) __attribute__ ((visibility ("default")));
size_t dnsdist_ffi_servers_list_whashed(const dnsdist_ffi_servers_list_t* list, const dnsdist_ffi_dnsquestion_t* dq, size_t hash) __attribute__ ((visibility ("default")));

uint64_t dnsdist_ffi_server_get_outstanding(const dnsdist_ffi_server_t* server) __attribute__ ((visibility ("default")));
bool dnsdist_ffi_server_is_up(const dnsdist_ffi_server_t* server) __attribute__ ((visibility ("default")));
const char* dnsdist_ffi_server_get_name(const dnsdist_ffi_server_t* server) __attribute__ ((visibility ("default")));
const char* dnsdist_ffi_server_get_name_with_addr(const dnsdist_ffi_server_t* server) __attribute__ ((visibility ("default")));
int dnsdist_ffi_server_get_weight(const dnsdist_ffi_server_t* server) __attribute__ ((visibility ("default")));
int dnsdist_ffi_server_get_order(const dnsdist_ffi_server_t* server) __attribute__ ((visibility ("default")));
double dnsdist_ffi_server_get_latency(const dnsdist_ffi_server_t* server) __attribute__ ((visibility ("default")));

void dnsdist_ffi_dnsresponse_set_min_ttl(dnsdist_ffi_dnsresponse_t* dr, uint32_t min) __attribute__ ((visibility ("default")));
void dnsdist_ffi_dnsresponse_set_max_ttl(dnsdist_ffi_dnsresponse_t* dr, uint32_t max) __attribute__ ((visibility ("default")));
void dnsdist_ffi_dnsresponse_limit_ttl(dnsdist_ffi_dnsresponse_t* dr, uint32_t min, uint32_t max) __attribute__ ((visibility ("default")));
/* decrease the returned TTL but _after_ inserting the original response into the packet cache */
void dnsdist_ffi_dnsresponse_set_max_returned_ttl(dnsdist_ffi_dnsresponse_t* dr, uint32_t max) __attribute__ ((visibility ("default")));
void dnsdist_ffi_dnsresponse_clear_records_type(dnsdist_ffi_dnsresponse_t* dr, uint16_t qtype) __attribute__ ((visibility ("default")));
bool dnsdist_ffi_dnsresponse_rebase(dnsdist_ffi_dnsresponse_t* dr, const char* initialName, size_t initialNameSize) __attribute__ ((visibility ("default")));

bool dnsdist_ffi_dnsquestion_set_async(dnsdist_ffi_dnsquestion_t* dq, uint16_t asyncID, uint16_t queryID, uint32_t timeoutMs) __attribute__ ((visibility ("default")));
bool dnsdist_ffi_dnsresponse_set_async(dnsdist_ffi_dnsquestion_t* dq, uint16_t asyncID, uint16_t queryID, uint32_t timeoutMs) __attribute__ ((visibility ("default")));

bool dnsdist_ffi_resume_from_async(uint16_t asyncID, uint16_t queryID, const char* tag, size_t tagSize, const char* tagValue, size_t tagValueSize, bool useCache) __attribute__ ((visibility ("default")));
bool dnsdist_ffi_drop_from_async(uint16_t asyncID, uint16_t queryID) __attribute__ ((visibility ("default")));
bool dnsdist_ffi_set_answer_from_async(uint16_t asyncID, uint16_t queryID, const char* raw, size_t rawSize) __attribute__ ((visibility ("default")));
bool dnsdist_ffi_set_rcode_from_async(uint16_t asyncID, uint16_t queryID, uint8_t rcode, bool clearAnswers) __attribute__ ((visibility ("default")));
bool dnsdist_ffi_resume_from_async_with_alternate_name(uint16_t asyncID, uint16_t queryID, const char* alternateName, size_t alternateNameSize, const char* tag, size_t tagSize, const char* tagValue, size_t tagValueSize, const char* formerNameTagName, size_t formerNameTagSize) __attribute__ ((visibility ("default")));

typedef struct dnsdist_ffi_proxy_protocol_value {
  const char* value;
  uint16_t size;
  uint8_t type;
} dnsdist_ffi_proxy_protocol_value_t;

size_t dnsdist_ffi_generate_proxy_protocol_payload(size_t addrSize, const void* srcAddr, const void* dstAddr, uint16_t srcPort, uint16_t dstPort, bool tcp, size_t valuesCount, const dnsdist_ffi_proxy_protocol_value_t* values, void* out, size_t outSize) __attribute__ ((visibility ("default")));
size_t dnsdist_ffi_dnsquestion_generate_proxy_protocol_payload(const dnsdist_ffi_dnsquestion_t* dq, const size_t valuesCount, const dnsdist_ffi_proxy_protocol_value_t* values, void* out, const size_t outSize) __attribute__ ((visibility ("default")));

typedef struct dnsdist_ffi_domain_list_t dnsdist_ffi_domain_list_t;
typedef struct dnsdist_ffi_address_list_t dnsdist_ffi_address_list_t;

const char* dnsdist_ffi_address_list_get(const dnsdist_ffi_address_list_t* list, size_t idx) __attribute__ ((visibility ("default")));
void dnsdist_ffi_address_list_free(dnsdist_ffi_address_list_t*) __attribute__ ((visibility ("default")));

const char* dnsdist_ffi_domain_list_get(const dnsdist_ffi_domain_list_t* list, size_t idx) __attribute__ ((visibility ("default")));
void dnsdist_ffi_domain_list_free(dnsdist_ffi_domain_list_t*) __attribute__ ((visibility ("default")));

size_t dnsdist_ffi_packetcache_get_domain_list_by_addr(const char* poolName, const char* addr, dnsdist_ffi_domain_list_t** out) __attribute__ ((visibility ("default")));
size_t dnsdist_ffi_packetcache_get_address_list_by_domain(const char* poolName, const char* domain, dnsdist_ffi_address_list_t** out) __attribute__ ((visibility ("default")));

typedef struct dnsdist_ffi_ring_entry_list_t dnsdist_ffi_ring_entry_list_t;

bool dnsdist_ffi_ring_entry_is_response(const dnsdist_ffi_ring_entry_list_t* list, size_t idx) __attribute__ ((visibility ("default")));
const char* dnsdist_ffi_ring_entry_get_name(const dnsdist_ffi_ring_entry_list_t* list, size_t idx) __attribute__ ((visibility ("default")));
uint16_t dnsdist_ffi_ring_entry_get_type(const dnsdist_ffi_ring_entry_list_t* list, size_t idx) __attribute__ ((visibility ("default")));
const char* dnsdist_ffi_ring_entry_get_requestor(const dnsdist_ffi_ring_entry_list_t* list, size_t idx) __attribute__ ((visibility ("default")));
uint8_t dnsdist_ffi_ring_entry_get_protocol(const dnsdist_ffi_ring_entry_list_t* list, size_t idx) __attribute__ ((visibility ("default")));
uint16_t dnsdist_ffi_ring_entry_get_size(const dnsdist_ffi_ring_entry_list_t* list, size_t idx) __attribute__ ((visibility ("default")));
bool dnsdist_ffi_ring_entry_has_mac_address(const dnsdist_ffi_ring_entry_list_t* list, size_t idx) __attribute__ ((visibility ("default")));
const char* dnsdist_ffi_ring_entry_get_mac_address(const dnsdist_ffi_ring_entry_list_t* list, size_t idx) __attribute__ ((visibility ("default")));

void dnsdist_ffi_ring_entry_list_free(dnsdist_ffi_ring_entry_list_t*) __attribute__ ((visibility ("default")));

size_t dnsdist_ffi_ring_get_entries(dnsdist_ffi_ring_entry_list_t** out) __attribute__ ((visibility ("default")));
size_t dnsdist_ffi_ring_get_entries_by_addr(const char* addr, dnsdist_ffi_ring_entry_list_t** out) __attribute__ ((visibility ("default")));
size_t dnsdist_ffi_ring_get_entries_by_mac(const char* addr, dnsdist_ffi_ring_entry_list_t** out) __attribute__ ((visibility ("default")));

typedef struct dnsdist_ffi_network_endpoint_t dnsdist_ffi_network_endpoint_t;

bool dnsdist_ffi_network_endpoint_new(const char* path, size_t pathSize, dnsdist_ffi_network_endpoint_t** out) __attribute__ ((visibility ("default")));
bool dnsdist_ffi_network_endpoint_is_valid(const dnsdist_ffi_network_endpoint_t* endpoint) __attribute__ ((visibility ("default")));
bool dnsdist_ffi_network_endpoint_send(const dnsdist_ffi_network_endpoint_t* endpoint, const char* payload, size_t payloadSize) __attribute__ ((visibility ("default")));
void dnsdist_ffi_network_endpoint_free(dnsdist_ffi_network_endpoint_t* endpoint) __attribute__ ((visibility ("default")));

typedef struct dnsdist_ffi_dnspacket_t dnsdist_ffi_dnspacket_t;

bool dnsdist_ffi_dnspacket_parse(const char* packet, size_t packetSize, dnsdist_ffi_dnspacket_t** out) __attribute__ ((visibility ("default")));
void dnsdist_ffi_dnspacket_get_qname_raw(const dnsdist_ffi_dnspacket_t* packet, const char** qname, size_t* qnameSize) __attribute__ ((visibility ("default")));
uint16_t dnsdist_ffi_dnspacket_get_qtype(const dnsdist_ffi_dnspacket_t* packet) __attribute__ ((visibility ("default")));
uint16_t dnsdist_ffi_dnspacket_get_qclass(const dnsdist_ffi_dnspacket_t* packet) __attribute__ ((visibility ("default")));
uint16_t dnsdist_ffi_dnspacket_get_records_count_in_section(const dnsdist_ffi_dnspacket_t* packet, uint8_t section) __attribute__ ((visibility ("default")));
void dnsdist_ffi_dnspacket_get_record_name_raw(const dnsdist_ffi_dnspacket_t* packet, size_t idx, const char** name, size_t* nameSize) __attribute__ ((visibility ("default")));
uint16_t dnsdist_ffi_dnspacket_get_record_type(const dnsdist_ffi_dnspacket_t* packet, size_t idx) __attribute__ ((visibility ("default")));
uint16_t dnsdist_ffi_dnspacket_get_record_class(const dnsdist_ffi_dnspacket_t* packet, size_t idx) __attribute__ ((visibility ("default")));
uint32_t dnsdist_ffi_dnspacket_get_record_ttl(const dnsdist_ffi_dnspacket_t* packet, size_t idx) __attribute__ ((visibility ("default")));
uint16_t dnsdist_ffi_dnspacket_get_record_content_length(const dnsdist_ffi_dnspacket_t* packet, size_t idx) __attribute__ ((visibility ("default")));
uint16_t dnsdist_ffi_dnspacket_get_record_content_offset(const dnsdist_ffi_dnspacket_t* packet, size_t idx) __attribute__ ((visibility ("default")));
size_t dnsdist_ffi_dnspacket_get_name_at_offset_raw(const char* packet, size_t packetSize, size_t offset, char* name, size_t nameSize) __attribute__ ((visibility ("default")));
void dnsdist_ffi_dnspacket_free(dnsdist_ffi_dnspacket_t*) __attribute__ ((visibility ("default")));

void dnsdist_ffi_metric_inc(const char* metricName, size_t metricNameLen) __attribute__ ((visibility ("default")));
void dnsdist_ffi_metric_dec(const char* metricName, size_t metricNameLen) __attribute__ ((visibility ("default")));
void dnsdist_ffi_metric_set(const char* metricName, size_t metricNameLen, double value) __attribute__ ((visibility ("default")));
double dnsdist_ffi_metric_get(const char* metricName, size_t metricNameLen, bool isCounter) __attribute__ ((visibility ("default")));

typedef struct dnsdist_ffi_network_message_t dnsdist_ffi_network_message_t;

const char* dnsdist_ffi_network_message_get_payload(const dnsdist_ffi_network_message_t* msg) __attribute__ ((visibility ("default")));
size_t dnsdist_ffi_network_message_get_payload_size(const dnsdist_ffi_network_message_t* msg) __attribute__ ((visibility ("default")));
uint16_t dnsdist_ffi_network_message_get_endpoint_id(const dnsdist_ffi_network_message_t* msg) __attribute__ ((visibility ("default")));

