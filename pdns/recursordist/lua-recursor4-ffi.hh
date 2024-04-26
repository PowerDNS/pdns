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

extern "C"
{
  typedef struct pdns_ffi_param pdns_ffi_param_t;

  typedef struct pdns_ednsoption
  {
    uint16_t optionCode;
    uint16_t len;
    const void* data;
  } pdns_ednsoption_t;

  typedef struct pdns_proxyprotocol_value
  {
    uint8_t type;
    uint16_t len;
    const void* data;
  } pdns_proxyprotocol_value_t;

  typedef enum
  {
    pdns_record_place_answer = 1,
    pdns_record_place_authority = 2,
    pdns_record_place_additional = 3
  } pdns_record_place_t;

  // Must match DNSFilterEngine::PolicyKind
  typedef enum
  {
    pdns_policy_kind_noaction = 0,
    pdns_policy_kind_drop = 1,
    pdns_policy_kind_nxdomain = 2,
    pdns_policy_kind_nodata = 3,
    pdns_policy_kind_truncate = 4,
    pdns_policy_kind_custom = 5
  } pdns_policy_kind_t;

  typedef struct pdns_ffi_record
  {
    const char* name;
    size_t name_len;
    const char* content;
    size_t content_len;
    uint32_t ttl;
    pdns_record_place_t place;
    uint16_t type;
  } pdns_ffi_record_t;

  const char* pdns_ffi_param_get_qname(pdns_ffi_param_t* ref) __attribute__((visibility("default")));
  void pdns_ffi_param_get_qname_raw(pdns_ffi_param_t* ref, const char** qname, size_t* qnameSize) __attribute__((visibility("default")));
  uint16_t pdns_ffi_param_get_qtype(const pdns_ffi_param_t* ref) __attribute__((visibility("default")));
  const char* pdns_ffi_param_get_remote(pdns_ffi_param_t* ref) __attribute__((visibility("default")));
  void pdns_ffi_param_get_remote_raw(pdns_ffi_param_t* ref, const void** addr, size_t* addrSize) __attribute__((visibility("default")));
  uint16_t pdns_ffi_param_get_remote_port(const pdns_ffi_param_t* ref) __attribute__((visibility("default")));
  const char* pdns_ffi_param_get_local(pdns_ffi_param_t* ref) __attribute__((visibility("default")));
  void pdns_ffi_param_get_local_raw(pdns_ffi_param_t* ref, const void** addr, size_t* addrSize) __attribute__((visibility("default")));
  uint16_t pdns_ffi_param_get_local_port(const pdns_ffi_param_t* ref) __attribute__((visibility("default")));

  const char* pdns_ffi_param_get_interface_remote(pdns_ffi_param_t* ref) __attribute__((visibility("default")));
  void pdns_ffi_param_get_interface_remote_raw(pdns_ffi_param_t* ref, const void** addr, size_t* addrSize) __attribute__((visibility("default")));
  uint16_t pdns_ffi_param_get_interface_remote_port(const pdns_ffi_param_t* ref) __attribute__((visibility("default")));
  const char* pdns_ffi_param_get_interface_local(pdns_ffi_param_t* ref) __attribute__((visibility("default")));
  void pdns_ffi_param_get_interface_local_raw(pdns_ffi_param_t* ref, const void** addr, size_t* addrSize) __attribute__((visibility("default")));
  uint16_t pdns_ffi_param_get_interface_local_port(const pdns_ffi_param_t* ref) __attribute__((visibility("default")));

  const char* pdns_ffi_param_get_edns_cs(pdns_ffi_param_t* ref) __attribute__((visibility("default")));
  void pdns_ffi_param_get_edns_cs_raw(pdns_ffi_param_t* ref, const void** net, size_t* netSize) __attribute__((visibility("default")));
  uint8_t pdns_ffi_param_get_edns_cs_source_mask(const pdns_ffi_param_t* ref) __attribute__((visibility("default")));

  // returns the length of the resulting 'out' array. 'out' is not set if the length is 0
  size_t pdns_ffi_param_get_edns_options(pdns_ffi_param_t* ref, const pdns_ednsoption_t** out) __attribute__((visibility("default")));
  size_t pdns_ffi_param_get_edns_options_by_code(pdns_ffi_param_t* ref, uint16_t optionCode, const pdns_ednsoption_t** out) __attribute__((visibility("default")));

  // returns the length of the resulting 'out' array. 'out' is not set if the length is 0
  size_t pdns_ffi_param_get_proxy_protocol_values(pdns_ffi_param_t* ref, const pdns_proxyprotocol_value_t** out) __attribute__((visibility("default")));

  void pdns_ffi_param_set_tag(pdns_ffi_param_t* ref, unsigned int tag) __attribute__((visibility("default")));
  void pdns_ffi_param_add_policytag(pdns_ffi_param_t* ref, const char* name) __attribute__((visibility("default")));
  void pdns_ffi_param_set_requestorid(pdns_ffi_param_t* ref, const char* name) __attribute__((visibility("default")));
  void pdns_ffi_param_set_devicename(pdns_ffi_param_t* ref, const char* name) __attribute__((visibility("default")));
  void pdns_ffi_param_set_deviceid(pdns_ffi_param_t* ref, size_t len, const void* name) __attribute__((visibility("default")));
  void pdns_ffi_param_set_routingtag(pdns_ffi_param_t* ref, const char* name) __attribute__((visibility("default")));

  void pdns_ffi_param_set_variable(pdns_ffi_param_t* ref, bool variable) __attribute__((visibility("default")));
  void pdns_ffi_param_set_ttl_cap(pdns_ffi_param_t* ref, uint32_t ttl) __attribute__((visibility("default")));
  void pdns_ffi_param_set_log_query(pdns_ffi_param_t* ref, bool logQuery) __attribute__((visibility("default")));
  void pdns_ffi_param_set_log_response(pdns_ffi_param_t* ref, bool logResponse) __attribute__((visibility("default")));
  void pdns_ffi_param_set_rcode(pdns_ffi_param_t* ref, int rcode) __attribute__((visibility("default")));
  void pdns_ffi_param_set_follow_cname_records(pdns_ffi_param_t* ref, bool follow) __attribute__((visibility("default")));

  void pdns_ffi_param_set_extended_error_code(pdns_ffi_param_t* ref, uint16_t code) __attribute__((visibility("default")));
  void pdns_ffi_param_set_extended_error_extra(pdns_ffi_param_t* ref, size_t len, const char* extra) __attribute__((visibility("default")));

  /* returns true if the record was correctly added, false if something went wrong.
     Passing a NULL pointer to 'name' will result in the qname being used for the record owner name. */
  bool pdns_ffi_param_add_record(pdns_ffi_param_t* ref, const char* name, uint16_t type, uint32_t ttl, const char* content, size_t contentSize, pdns_record_place_t place) __attribute__((visibility("default")));

  void pdns_ffi_param_set_padding_disabled(pdns_ffi_param_t* ref, bool disabled) __attribute__((visibility("default")));
  void pdns_ffi_param_add_meta_single_string_kv(pdns_ffi_param_t* ref, const char* key, const char* val) __attribute__((visibility("default")));
  void pdns_ffi_param_add_meta_single_int64_kv(pdns_ffi_param_t* ref, const char* key, int64_t val) __attribute__((visibility("default")));

  typedef struct pdns_postresolve_ffi_handle pdns_postresolve_ffi_handle_t;

  const char* pdns_postresolve_ffi_handle_get_qname(pdns_postresolve_ffi_handle_t* ref) __attribute__((visibility("default")));
  void pdns_postresolve_ffi_handle_get_qname_raw(pdns_postresolve_ffi_handle_t* ref, const char** qname, size_t* qnameSize) __attribute__((visibility("default")));
  uint16_t pdns_postresolve_ffi_handle_get_qtype(const pdns_postresolve_ffi_handle_t* ref) __attribute__((visibility("default")));
  uint16_t pdns_postresolve_ffi_handle_get_rcode(const pdns_postresolve_ffi_handle_t* ref) __attribute__((visibility("default")));
  void pdns_postresolve_ffi_handle_set_rcode(const pdns_postresolve_ffi_handle_t* ref, uint16_t rcode) __attribute__((visibility("default")));
  pdns_policy_kind_t pdns_postresolve_ffi_handle_get_appliedpolicy_kind(const pdns_postresolve_ffi_handle_t* ref) __attribute__((visibility("default")));
  void pdns_postresolve_ffi_handle_set_appliedpolicy_kind(pdns_postresolve_ffi_handle_t* ref, pdns_policy_kind_t kind) __attribute__((visibility("default")));
  bool pdns_postresolve_ffi_handle_get_record(pdns_postresolve_ffi_handle_t* ref, unsigned int i, pdns_ffi_record_t* record, bool raw) __attribute__((visibility("default")));
  bool pdns_postresolve_ffi_handle_set_record(pdns_postresolve_ffi_handle_t* ref, unsigned int i, const char* content, size_t contentLen, bool raw) __attribute__((visibility("default")));
  void pdns_postresolve_ffi_handle_clear_records(pdns_postresolve_ffi_handle_t* ref) __attribute__((visibility("default")));
  bool pdns_postresolve_ffi_handle_add_record(pdns_postresolve_ffi_handle_t* ref, const char* name, uint16_t type, uint32_t ttl, const char* content, size_t contentLen, pdns_record_place_t place, bool raw) __attribute__((visibility("default")));
  const char* pdns_postresolve_ffi_handle_get_authip(pdns_postresolve_ffi_handle_t* ref) __attribute__((visibility("default")));
  void pdns_postresolve_ffi_handle_get_authip_raw(pdns_postresolve_ffi_handle_t* ref, const void** addr, size_t* addrSize) __attribute__((visibility("default")));
}
