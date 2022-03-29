Lua FFI API
===========

PowerDNS Recursor provides a set of functions available through the LUA FFI library that allow you to interact with handle passed to :func:`gettag_ffi` and :func:`postresolve_ffi`.

Functions for :func:`gettag_ffi`
--------------------------------

.. function:: pdns_ffi_param_get_qname(pdns_ffi_param_t* ref) -> const char*

   Get the query's qualified name

.. function:: pdns_ffi_param_get_qtype(const pdns_ffi_param_t* ref) -> uint16_t

   Get the query's type

.. function:: pdns_ffi_param_get_remote(pdns_ffi_param_t* ref) -> const char*

   Get the sender's IP address

.. function:: pdns_ffi_param_get_remote_port(const pdns_ffi_param_t* ref) -> uint16_t

   Get the sender's port

.. function:: pdns_ffi_param_get_local(pdns_ffi_param_t* ref) -> const char*

   Get the local IP address the query was received on

.. function:: pdns_ffi_param_get_local_port(const pdns_ffi_param_t* ref) -> uint16_t

   Get the local port the query was received on

.. function:: pdns_ffi_param_get_edns_cs(pdns_ffi_param_t* ref) -> const char*

   Get query's EDNS client subnet

.. function:: pdns_ffi_param_get_edns_cs_source_mask(const pdns_ffi_param_t* ref) -> uint8_t

   Get query's EDNS client subnet mask

.. function:: pdns_ffi_param_get_edns_options(pdns_ffi_param_t* ref, const pdns_ednsoption_t** out) -> size_t

   Get query's EDNS options. Returns the length of the resulting `out` array

.. function:: pdns_ffi_param_get_edns_options_by_code(pdns_ffi_param_t* ref, uint16_t optionCode, const pdns_ednsoption_t** out) -> size_t

   Get query's EDNS option for a given code. Returns the length of the resulting `out` array

.. function:: pdns_ffi_param_get_proxy_protocol_values(pdns_ffi_param_t* ref, const pdns_proxyprotocol_value_t** out) -> size_t

   Get query's proxy protocol values. Returns the length of the resulting `out` array

.. function:: pdns_ffi_param_get_edns_cs_raw(pdns_ffi_param_t* ref, const void** net, size_t* netSize) -> void

   Fill out `net` with query's EDNS client subnet

.. function:: pdns_ffi_param_get_remote_raw(pdns_ffi_param_t* ref, const void** addr, size_t* addrSize) -> void

   Fill out `addr` with sender's IP address

.. function:: pdns_ffi_param_get_qname_raw(pdns_ffi_param_t* ref, const char** qname, size_t* qnameSize) -> void

   Fill out `qname` with query's qualified name

.. function:: pdns_ffi_param_get_local_raw(pdns_ffi_param_t* ref, const void** addr, size_t* addrSize) -> void

   Fill out `addr` with local IP address the query was received on

.. function:: pdns_ffi_param_set_tag(pdns_ffi_param_t* ref, unsigned int tag) -> void

   Tag the query with the given number

.. function:: pdns_ffi_param_add_policytag(pdns_ffi_param_t* ref, const char* name) -> void

   Add the given tag to the query

.. function:: pdns_ffi_param_set_requestorid(pdns_ffi_param_t* ref, const char* name) -> void

   Set query's requestor ID

.. function:: pdns_ffi_param_set_devicename(pdns_ffi_param_t* ref, const char* name) -> void

   Set query's device name

.. function:: pdns_ffi_param_set_deviceid(pdns_ffi_param_t* ref, size_t len, const void* name) -> void

   Set query's device ID

.. function:: pdns_ffi_param_set_routingtag(pdns_ffi_param_t* ref, const char* name) -> void

   Set routing tag which is used as an extra name to identify records in the record cache, see :func:`gettag`

.. function:: pdns_ffi_param_set_variable(pdns_ffi_param_t* ref, bool variable) -> void

   Mark as variable and ensure it’s not inserted into the packetcache

.. function:: pdns_ffi_param_set_ttl_cap(pdns_ffi_param_t* ref, uint32_t ttl) -> void

   Cap the max TTL of the returned records

.. function:: pdns_ffi_param_set_log_query(pdns_ffi_param_t* ref, bool logQuery) -> void

   Turn on/off query logging

.. function:: pdns_ffi_param_set_log_response(pdns_ffi_param_t* ref, bool logResponse) -> void

   Turn on/off response logging

.. function:: pdns_ffi_param_set_rcode(pdns_ffi_param_t* ref, int rcode) -> void

   Set response RCode

.. function:: pdns_ffi_param_set_follow_cname_records(pdns_ffi_param_t* ref, bool follow) -> void

   Instruct the recursor to do a proper resolution in order to follow any CNAME records added

.. function:: pdns_ffi_param_set_extended_error_code(pdns_ffi_param_t* ref, uint16_t code) -> void

   Set extended DNS error info code

.. function:: pdns_ffi_param_set_extended_error_extra(pdns_ffi_param_t* ref, size_t len, const char* extra) -> void

   Set extended DNS error extra text

.. function:: pdns_ffi_param_set_padding_disabled(pdns_ffi_param_t* ref, bool disabled) -> void

   Disable padding

.. function:: pdns_ffi_param_add_record(pdns_ffi_param_t* ref, const char* name, uint16_t type, uint32_t ttl, const char* content, size_t contentSize, pdns_record_place_t place) -> bool

   Adds a record. Returns true if it was correctly added, false otherwise

.. function:: pdns_ffi_param_add_meta_single_string_kv(pdns_ffi_param_t* ref, const char* key, const char* val) -> void

   .. versionadded:: 4.6.0

   This function allows you to add an arbitrary string value for a given key in the ``meta`` field of the produced :doc:`protobuf <../lua-config/protobuf>` log message

.. function:: pdns_ffi_param_add_meta_single_int64_kv(pdns_ffi_param_t *ref, const char* key, int64_t val) -> void

   .. versionadded:: 4.6.0

   This function allows you to add an arbitrary int value for a given key in the ``meta`` field of the produced :doc:`protobuf <../lua-config/protobuf>` log message

Functions for :func:`postresolve_ffi`
-------------------------------------

.. versionadded:: 4.7.0

All functions below were added in version 4.7.0.

.. function::  pdns_postresolve_ffi_handle_get_qname(pdns_postresolve_ffi_handle_t* ref) -> const char*

    Get the name queried as a string.

.. function::  pdns_postresolve_ffi_handle_get_qname_raw(pdns_postresolve_ffi_handle_t* ref, const char** qname, size_t* qnameSize) -> void

    Get the name queried (and its size) in DNS wire format.

.. function::  pdns_postresolve_ffi_handle_get_qtype(const pdns_postresolve_ffi_handle_t* ref) -> uint16

    Get the qtype of the query.

.. function::  pdns_postresolve_ffi_handle_get_rcode(const pdns_postresolve_ffi_handle_t* ref) -> uint16

    Get the rcode returned by the resolving process.

.. function::  pdns_postresolve_ffi_handle_set_rcode(const pdns_postresolve_ffi_handle_t* ref, uint16_t rcode) -> void

    Set the rcode to be returned.

.. function::  pdns_postresolve_ffi_handle_get_appliedpolicy_kind(const pdns_postresolve_ffi_handle_t* ref) -> pdns_policy_kind_t

    Get the applied policy.

.. function::  pdns_postresolve_ffi_handle_set_appliedpolicy_kind(pdns_postresolve_ffi_handle_t* ref, pdns_policy_kind_t kind) -> void

    Set the applied policy.

.. function::  pdns_postresolve_ffi_handle_get_record(pdns_postresolve_ffi_handle_t* ref, unsigned int i, pdns_ffi_record_t* record, bool raw) -> bool

    Get a record indexed by i.
    Returns false if no record is available at index i.

.. function::  pdns_postresolve_ffi_handle_set_record(pdns_postresolve_ffi_handle_t* ref, unsigned int i, const char* content, size_t contentLen, bool raw) -> bool

    Set the record at index i.

.. function::  pdns_postresolve_ffi_handle_clear_records(pdns_postresolve_ffi_handle_t* ref) -> void

    Clear all records.

.. function::  pdns_postresolve_ffi_handle_add_record(pdns_postresolve_ffi_handle_t* ref, const char* name, uint16_t type, uint32_t ttl, const char* content, size_t contentLen, pdns_record_place_t place, bool raw) -> bool

    Add a record to the existing records.

.. function::  pdns_postresolve_ffi_handle_get_authip(pdns_postresolve_ffi_handle_t* ref) -> const char*

    Get a string representation of the IP address of the authoritative server that answered the query.
    The string might by empty if the address is not available.

.. function::  pdns_postresolve_ffi_handle_get_authip_raw(pdns_postresolve_ffi_handle_t* ref, const void** addr, size_t* addrSize) -> void

    Get the raw IP address (in network byte order) and size of the raw IP address of the authoritative server that answered the query.
    The string might be empty if the address is not available.
