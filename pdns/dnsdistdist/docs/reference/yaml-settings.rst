.. THIS IS A GENERATED FILE. DO NOT EDIT. See dnsdist-settings-documentation-generator.py

.. raw:: latex

    \setcounter{secnumdepth}{-1}

YAML configuration reference
============================

Since 2.0.0, :program:`dnsdist` supports the YAML configuration format in addition to the existing Lua one.

If the configuration file passed to :program:`dnsdist` via the ``-C`` command-line switch ends in ``.yml``, it is assumed to be in the new YAML format, and an attempt to load a Lua configuration file with the same name but the ``.lua`` will be done before loading the YAML configuration. If the names ends in ``.lua``, there will also be an attempt to find a file with the same name but ending in ``.yml``. Otherwise the existing Lua configuration format is assumed.

By default, when a YAML configuration file is used, any Lua configuration file used along the YAML configuration should only contain functions, and ideally even those should be defined either inline in the YAML file or in separate files included from the YAML configuration, for clarity. It is however possible to change this behaviour using the :func:`enableLuaConfiguration` directive to enable Lua configuration directives, but it is strongly advised not to use this directive unless absolutely necessary, and to prefer doing all the configuration in either Lua or YAML but to not mix them.
Note that Lua directives that can be used at runtime are always available via the :doc:`../guides/console`, regardless of whether they are enabled during configuration.

A YAML configuration file contains several sections, that are described below.

.. code-block:: yaml

.. _yaml-settings-GlobalConfiguration:

GlobalConfiguration
-------------------

- **acl**: Sequence of String ``(127.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 192.168.0.0/16, 172.16.0.0/12, ::1/128, fc00::/7, fe80::/10)`` - CIDR netmasks of the clients allowed to send DNS queries
- **backends**: Sequence of :ref:`BackendConfiguration <yaml-settings-BackendConfiguration>` - List of backends
- **binds**: Sequence of :ref:`BindConfiguration <yaml-settings-BindConfiguration>` - List of endpoints to accept queries on
- **cache_hit_response_rules**: Sequence of :ref:`ResponseRuleConfiguration <yaml-settings-ResponseRuleConfiguration>` - List of rules executed on a cache hit
- **cache_inserted_response_rules**: Sequence of :ref:`ResponseRuleConfiguration <yaml-settings-ResponseRuleConfiguration>` - List of rules executed after inserting a new response into the cache
- **cache_miss_rules**: Sequence of :ref:`QueryRuleConfiguration <yaml-settings-QueryRuleConfiguration>` - List of rules executed after a cache miss
- **cache_settings**: :ref:`CacheSettingsConfiguration <yaml-settings-CacheSettingsConfiguration>` - Caching-related settings
- **console**: :ref:`ConsoleConfiguration <yaml-settings-ConsoleConfiguration>` - Console-related settings
- **dynamic_rules**: Sequence of :ref:`DynamicRulesConfiguration <yaml-settings-DynamicRulesConfiguration>` - List of dynamic rules
- **dynamic_rules_settings**: :ref:`DynamicRulesSettingsConfiguration <yaml-settings-DynamicRulesSettingsConfiguration>` - Dynamic rules-related settings
- **ebpf**: :ref:`EbpfConfiguration <yaml-settings-EbpfConfiguration>` - EBPF settings
- **edns_client_subnet**: :ref:`EdnsClientSubnetConfiguration <yaml-settings-EdnsClientSubnetConfiguration>` - EDNS Client Subnet-related settings
- **general**: :ref:`GeneralConfiguration <yaml-settings-GeneralConfiguration>` - General settings
- **key_value_stores**: :ref:`KeyValueStoresConfiguration <yaml-settings-KeyValueStoresConfiguration>` - Key-Value stores
- **load_balancing_policies**: :ref:`LoadBalancingPoliciesConfiguration <yaml-settings-LoadBalancingPoliciesConfiguration>` - Load-balancing policies
- **logging**: :ref:`LoggingConfiguration <yaml-settings-LoggingConfiguration>` - Logging settings
- **metrics**: :ref:`MetricsConfiguration <yaml-settings-MetricsConfiguration>` - Metrics-related settings
- **packet_caches**: Sequence of :ref:`PacketCacheConfiguration <yaml-settings-PacketCacheConfiguration>` - Packet-cache definitions
- **pools**: Sequence of :ref:`PoolConfiguration <yaml-settings-PoolConfiguration>` - Pools of backends
- **proxy_protocol**: :ref:`ProxyProtocolConfiguration <yaml-settings-ProxyProtocolConfiguration>` - Proxy-protocol-related settings
- **query_count**: :ref:`QueryCountConfiguration <yaml-settings-QueryCountConfiguration>` - Queries counting-related settings
- **query_rules**: Sequence of :ref:`QueryRuleConfiguration <yaml-settings-QueryRuleConfiguration>` - List of rules executed when a query is received
- **remote_logging**: :ref:`RemoteLoggingConfiguration <yaml-settings-RemoteLoggingConfiguration>` - Remote logging-related settings
- **response_rules**: Sequence of :ref:`ResponseRuleConfiguration <yaml-settings-ResponseRuleConfiguration>` - List of rules executed when a response is received
- **ring_buffers**: :ref:`RingBuffersConfiguration <yaml-settings-RingBuffersConfiguration>` - In-memory ring buffer settings
- **security_polling**: :ref:`SecurityPollingConfiguration <yaml-settings-SecurityPollingConfiguration>` - Automatic checking of outdated version
- **selectors**: Sequence of :ref:`Selector <yaml-settings-Selector>` - List of selectors that can be reused in rules
- **self_answered_response_rules**: Sequence of :ref:`ResponseRuleConfiguration <yaml-settings-ResponseRuleConfiguration>` - List of rules executed when a response is generated by DNSdist itself
- **snmp**: :ref:`SnmpConfiguration <yaml-settings-SnmpConfiguration>` - SNMP-related settings
- **tuning**: :ref:`TuningConfiguration <yaml-settings-TuningConfiguration>` - Performance-related settings
- **webserver**: :ref:`WebserverConfiguration <yaml-settings-WebserverConfiguration>` - Internal web server configuration
- **xfr_response_rules**: Sequence of :ref:`ResponseRuleConfiguration <yaml-settings-ResponseRuleConfiguration>` - List of rules executed when a XFR response is received
- **xsk**: Sequence of :ref:`XskConfiguration <yaml-settings-XskConfiguration>` - List of AF_XDP / XSK objects
- **timeout_response_rules**: Sequence of :ref:`ResponseRuleConfiguration <yaml-settings-ResponseRuleConfiguration>` - List of rules executed when a timeout event triggered from timer expiration or network I/O error. Note that this rule is intent only for an action to restart a timed-out or network I/O failed query.



.. _yaml-settings-BackendConfiguration:

BackendConfiguration
--------------------

Generic settings for backends

- **address**: String - ``ip``:``port`` of the backend server (if unset, port defaults to 53 for Do53 backends, 853 for DoT and DoQ, and 443 for DoH and DoH3 ones
- **id**: String ``("")`` - Use a pre-defined UUID instead of a random one
- **name**: String ``("")`` - The name associated to this backend, for display purpose
- **protocol**: String - The DNS protocol to use to contact this backend. Supported values are: Do53, DoT, DoH
- **tls**: :ref:`OutgoingTlsConfiguration <yaml-settings-OutgoingTlsConfiguration>` - TLS-related settings for DoT and DoH backends
- **doh**: :ref:`OutgoingDohConfiguration <yaml-settings-OutgoingDohConfiguration>` - DoH-related settings for DoH backends
- **use_client_subnet**: Boolean ``(false)`` - Whether to add (or override, see :ref:`yaml-settings-EdnsClientSubnetConfiguration`) an EDNS Client Subnet to the DNS payload before forwarding it to the backend. Please see :doc:`../advanced/passing-source-address` for more information
- **use_proxy_protocol**: Boolean ``(false)`` - Add a proxy protocol header to the query, passing along the client's IP address and port along with the original destination address and port
- **queries_per_second**: Unsigned integer ``(0)`` - Limit the number of queries per second to ``number``, when using the ``firstAvailable`` policy
- **order**: Unsigned integer ``(1)`` - The order of this server, used by the `leastOutstanding` and `firstAvailable` policies
- **weight**: Unsigned integer ``(1)`` - The weight of this server, used by the `wrandom`, `whashed` and `chashed` policies, default: 1. Supported values are a minimum of 1, and a maximum of 2147483647
- **udp_timeout**: Unsigned integer ``(0)`` - The udp backend query timeout value in seconds, default: 0. Supported values are a minimum of 1, and a maximum of 255. Value greater than 0 will override global UDP timeout setting
- **pools**: Sequence of String ``("")`` - List of pools to place this backend into. By default a server is placed in the default ("") pool
- **tcp**: :ref:`OutgoingTcpConfiguration <yaml-settings-OutgoingTcpConfiguration>` - TCP-related settings for a backend
- **ip_bind_addr_no_port**: Boolean ``(true)`` - Whether to enable ``IP_BIND_ADDRESS_NO_PORT`` if available
- **health_checks**: :ref:`HealthCheckConfiguration <yaml-settings-HealthCheckConfiguration>` - Health-check settings
- **source**: String ``("")`` - The source address or interface to use for queries to this backend, by default this is left to the kernel's address selection.
  The following formats are supported:

  - address, e.g. ``""192.0.2.2""``
  - interface name, e.g. ``""eth0""``
  - address@interface, e.g. ``""192.0.2.2@eth0""``

- **sockets**: Unsigned integer ``(1)`` - Number of UDP sockets (and thus source ports) used toward the backend server, defaults to a single one. Note that for backends which are multithreaded, this setting will have an effect on the number of cores that will be used to process traffic from dnsdist. For example you may want to set ``sockets`` to a number somewhat greater than the number of worker threads configured in the backend, particularly if the Linux kernel is being used to distribute traffic to multiple threads listening on the same socket (via ``reuseport``). See also ``randomize_outgoing_sockets_to_backend`` in :ref:`yaml-settings-UdpTuningConfiguration`
- **disable_zero_scope**: Boolean ``(false)`` - Disable the EDNS Client Subnet :doc:`../advanced/zero-scope` feature, which does a cache lookup for an answer valid for all subnets (ECS scope of 0) before adding ECS information to the query and doing the regular lookup. Default is false. This requires the ``parse_ecs`` option of the corresponding cache to be set to true
- **reconnect_on_up**: Boolean ``(false)`` - Close and reopen the sockets when a server transits from Down to Up. This helps when an interface is missing when dnsdist is started
- **max_in_flight**: Unsigned integer ``(1)`` - Maximum number of in-flight queries. The default is 0, which disables out-of-order processing. It should only be enabled if the backend does support out-of-order processing. Out-of-order processing needs to be enabled on the frontend as well
- **tcp_only**: Boolean ``(false)`` - Always forward queries to that backend over TCP, never over UDP. Always enabled for TLS backends
- **auto_upgrade**: :ref:`OutgoingAutoUpgradeConfiguration <yaml-settings-OutgoingAutoUpgradeConfiguration>` - Auto-upgrade related settings
- **max_concurrent_tcp_connections**: Unsigned integer ``(0)`` - Maximum number of TCP connections to that backend. When that limit is reached, queries routed to that backend that cannot be forwarded over an existing connection will be dropped. Default is 0 which means no limit
- **proxy_protocol_advertise_tls**: Boolean ``(false)`` - Whether to set the SSL Proxy Protocol TLV in the proxy protocol payload sent to the backend if the query was received over an encrypted channel (DNSCrypt, DoQ, DoH or DoT). Requires ``use_proxy_protocol``
- **mac_address**: String ``("")`` - When the ``xsk`` option is set, this parameter can be used to specify the destination MAC address to use to reach the backend. If this options is not specified, dnsdist will try to get it from the IP of the backend by looking into the system's MAC address table, but it will fail if the corresponding MAC address is not present
- **cpus**: String ``("")`` - Set the CPU affinity for this thread, asking the scheduler to run it on a single CPU id, or a set of CPU ids. This parameter is only available if the OS provides the ``pthread_setaffinity_np()`` function
- **xsk**: String ``("")`` - The name of an XSK sockets map to attach to this frontend, if any
- **dscp**: Unsigned integer ``(0)`` - The DSCP marking value to be applied. Range 0-63. Default is 0 which means no action for DSCP marking


.. _yaml-settings-BindConfiguration:

BindConfiguration
-----------------

General settings for frontends

- **listen_address**: String - Address and port to listen to
- **reuseport**: Boolean ``(false)`` - Set the ``SO_REUSEPORT`` socket option, allowing several sockets to be listening on this address and port
- **protocol**: String ``(Do53)`` - The DNS protocol for this frontend. Supported values are: Do53, DoT, DoH, DoQ, DoH3, DNSCrypt
- **threads**: Unsigned integer ``(1)`` - Number of listening threads to create for this frontend. Note that each listening thread will have its own metrics, but identical DoT and DoH threads will share the same TLS Session Ticket Encryption Keys to improve session resumption rates. One side-effect is that rotating / altering the STEKs on all threads in a frontend group except the first one will be ignored, to prevent unwanted actions by existing code. :func:`reloadAllCertificates` properly handles frontend groups.
- **interface**: String ``("")`` - Set the network interface to use
- **cpus**: String ``("")`` - Set the CPU affinity for this listener thread, asking the scheduler to run it on a single CPU id, or a set of CPU ids. This parameter is only available if the OS provides the ``pthread_setaffinity_np()`` function
- **enable_proxy_protocol**: Boolean ``(false)`` - Whether to expect a proxy protocol v2 header in front of incoming queries coming from an address allowed by the ACL in :ref:`yaml-settings-ProxyProtocolConfiguration`. Default is ``true``, meaning that queries are expected to have a proxy protocol payload if they come from an address present in the proxy protocol ACL
- **tcp**: :ref:`IncomingTcpConfiguration <yaml-settings-IncomingTcpConfiguration>` - TCP-specific settings
- **tls**: :ref:`IncomingTlsConfiguration <yaml-settings-IncomingTlsConfiguration>` - TLS-specific settings
- **doh**: :ref:`IncomingDohConfiguration <yaml-settings-IncomingDohConfiguration>` - DNS over HTTPS-specific settings
- **doq**: :ref:`IncomingDoqConfiguration <yaml-settings-IncomingDoqConfiguration>` - DNS over QUIC-specific settings
- **quic**: :ref:`IncomingQuicConfiguration <yaml-settings-IncomingQuicConfiguration>` - QUIC-specific settings
- **dnscrypt**: :ref:`IncomingDnscryptConfiguration <yaml-settings-IncomingDnscryptConfiguration>` - DNSCrypt-specific settings
- **additional_addresses**: Sequence of String ``("")`` - List of additional addresses (with port) to listen on. Using this option instead of creating a new frontend for each address avoids the creation of new thread and Frontend objects, reducing the memory usage. The drawback is that there will be a single set of metrics for all addresses
- **xsk**: String ``("")`` - The name of an XSK sockets map to attach to this frontend, if any


.. _yaml-settings-CacheSettingsConfiguration:

CacheSettingsConfiguration
--------------------------

- **stale_entries_ttl**: Unsigned integer ``(0)``
- **cleaning_delay**: Unsigned integer ``(60)``
- **cleaning_percentage**: Unsigned integer ``(100)``


.. _yaml-settings-CarbonConfiguration:

CarbonConfiguration
-------------------

Carbon endpoint to send metrics to

- **address**: String - Indicates the IP address where the statistics should be sent
- **name**: String ``("")`` - An optional string specifying the hostname that should be used. If left empty, the system hostname is used
- **interval**: Unsigned integer ``(30)`` - An optional unsigned integer indicating the interval in seconds between exports
- **namespace**: String ``("")`` - An optional string specifying the namespace name that should be used
- **instance**: String ``("")`` - An optional string specifying the instance name that should be used


.. _yaml-settings-CdbKvStoreConfiguration:

CdbKvStoreConfiguration
-----------------------

CDB-based key-value store

- **name**: String - The name of this object
- **file_name**: String - The path to an existing CDB database
- **refresh_delay**: Unsigned integer - The delay in seconds between two checks of the database modification time. 0 means disabled


.. _yaml-settings-ConsoleConfiguration:

ConsoleConfiguration
--------------------

Console-related settings

- **listen_address**: String ``("")`` - IP address and port to listen on for console connections
- **key**: String ``("")`` - The shared secret used to secure connections between the console client and the server, generated via ``makeKey()``
- **acl**: Sequence of String ``(127.0.0.1, ::1)`` - List of network masks or IP addresses that are allowed to open a connection to the console server
- **maximum_output_size**: Unsigned integer ``(10000000)`` - Set the maximum size, in bytes, of a single console message
- **log_connections**: Boolean ``(true)`` - Whether to log the opening and closing of console connections
- **max_concurrent_connections**: Unsigned integer ``(0)`` - Set the maximum number of concurrent console connection


.. _yaml-settings-CustomLoadBalancingPolicyConfiguration:

CustomLoadBalancingPolicyConfiguration
--------------------------------------

Settings for a custom load-balancing policy

- **name**: String - The name of this load-balancing policy
- **function_name**: String ``("")`` - The name of a Lua function implementing the custom load-balancing policy. If ``ffi`` is false, this function takes a table of :class:`Server` objects and a :class:`DNSQuestion` representing the current query, and must return the index of the selected server in the supplied table. If ``ffi`` is true, this function takes a ``const dnsdist_ffi_servers_list_t*`` and a ``dnsdist_ffi_dnsquestion_t*``
- **function_code**: String ``("")`` - Same than ``function_name`` but contain actual Lua code returning a function instead of a name
- **function_file**: String ``("")`` - Same than ``function_name`` but contain the path to a file containing actual Lua code returning a function instead of a name
- **ffi**: Boolean ``(false)`` - Whether the function uses the faster but more complicated Lua FFI API
- **per_thread**: Boolean ``(false)`` - If set, the resulting policy will be executed in a lock-free per-thread context, instead of running in the global Lua context. Note that ``function_name`` cannot be used, since this needs the Lua code to create the function in a new Lua context instead of just a function


.. _yaml-settings-DnstapLoggerConfiguration:

DnstapLoggerConfiguration
-------------------------

Endpoint to send queries and/or responses data to, using the dnstap format

- **name**: String - Name of this endpoint
- **transport**: String - The dnstap transport to use. Supported values are: unix, tcp
- **address**: String - The address of the endpoint. If the transport is set to 'unix', the address should be local ``AF_UNIX`` socket path. Note that most platforms have a rather short limit on the length. Otherwise the address should be an IP:port
- **buffer_hint**: Unsigned integer ``(0)`` - The threshold number of bytes to accumulate in the output buffer before forcing a buffer flush. According to the libfstrm library, the minimum is 1024, the maximum is 65536, and the default is 8192
- **flush_timeout**: Unsigned integer ``(0)`` - The number of seconds to allow unflushed data to remain in the output buffer. According to the libfstrm library, the minimum is 1 second, the maximum is 600 seconds (10 minutes), and the default is 1 second
- **input_queue_size**: Unsigned integer ``(0)`` - The number of queue entries to allocate for each input queue. This value must be a power of 2. According to the fstrm library, the minimum is 2, the maximum is 16384, and the default is 512
- **output_queue_size**: Unsigned integer ``(0)`` - The number of queue entries to allocate for each output queue. According to the libfstrm library, the minimum is 2, the maximum is system-dependent and based on ``IOV_MAX``, and the default is 64
- **queue_notify_threshold**: Unsigned integer ``(0)`` - The number of outstanding queue entries to allow on an input queue before waking the I/O thread. According to the libfstrm library, the minimum is 1 and the default is 32
- **reopen_interval**: Unsigned integer ``(0)`` - The number of queue entries to allocate for each output queue. According to the libfstrm library, the minimum is 2, the maximum is system-dependent and based on IOV_MAX, and the default is 64
- **connection_count**: Unsigned integer ``(1)`` - Number of connections to open to the endpoint


.. _yaml-settings-DohTuningConfiguration:

DohTuningConfiguration
----------------------

- **outgoing_worker_threads**: Unsigned integer ``(10)``
- **outgoing_max_idle_time**: Unsigned integer ``(300)``
- **outgoing_cleanup_interval**: Unsigned integer ``(60)``
- **outgoing_max_idle_connection_per_backend**: Unsigned integer ``(10)``


.. _yaml-settings-DynamicRuleConfiguration:

DynamicRuleConfiguration
------------------------

Dynamic rule settings

- **type**: String - The type of this rule. Supported values are: query-rate, rcode-rate, rcode-ratio, qtype-rate, cache-miss-ratio, response-byte-rate
- **seconds**: Unsigned integer - Number of seconds the rule has been exceeded
- **action_duration**: Unsigned integer - How long the action is going to be enforced
- **comment**: String - Comment describing why the action why taken
- **rate**: Unsigned integer ``(0)`` - For ``query-rate``, ``rcode-rate``, ``qtype-rate`` and ``response-byte-rate``, the rate that should be exceeded
- **ratio**: Double ``(0.0)`` - For ``rcode-ratio``, ``qtype-ratio`` and ``cache-miss-ratio``, the ratio that should be exceeded
- **action**: String ``(drop)`` - The action that will be taken once the rate or ratio is exceeded. Supported values are: Drop, NoNop, NoRecurse, NXDomain, SetTag, Truncate, Refused
- **warning_rate**: Unsigned integer ``(0)`` - For ``query-rate``, ``rcode-rate``, ``qtype-rate`` and ``response-byte-rate``, the rate that should be exceeded for a warning to be logged, but no action enforced
- **warning_ratio**: Double ``(0.0)`` - For ``rcode-ratio`` and ``cache-miss-ratio``, the ratio that should be exceeded for a warning to be logged, but no action enforced
- **tag_name**: String ``("")``
- **tag_value**: String ``(0)`` - If ``action`` is set to ``SetTag``, the value that will be set
- **visitor_function_name**: String ``("")`` - For ``suffix-match`` and ``suffix-match-ffi``, the name of the Lua visitor function to call for each label of every domain seen in recent queries and responses
- **visitor_function_code**: String ``("")`` - For ``suffix-match`` and ``suffix-match-ffi``, the code of Lua visitor function for each label of every domain seen in recent queries and responses
- **visitor_function_file**: String ``("")`` - For ``suffix-match`` and ``suffix-match-ffi``, a path to a file containing the code of Lua visitor function for each label of every domain seen in recent queries and responses
- **rcode**: String ``("")`` - For ``rcode-rate`` and ``rcode-ratio``, the response code to match
- **qtype**: String ``("")`` - For ``qtype-rate``, the query type to match
- **minimum_number_of_responses**: Unsigned integer ``(0)`` - For ``cache-miss-ratio`` and ``rcode-ratio``, the minimum number of responses to have received for this rule to apply
- **minimum_global_cache_hit_ratio**: Double ``(0.0)`` - The minimum global cache-hit ratio (over all pools, so ``cache-hits`` / (``cache-hits`` + ``cache-misses``)) for a ``cache-miss-ratio`` rule to be applied


.. _yaml-settings-DynamicRulesConfiguration:

DynamicRulesConfiguration
-------------------------

Group of dynamic rules

- **name**: String - The name of this group of dynamic rules
- **mask_ipv4**: Unsigned integer ``(32)`` - Number of bits to keep for IPv4 addresses
- **mask_ipv6**: Unsigned integer ``(64)`` - Number of bits to keep for IPv6 addresses. In some scenarios it might make sense to block a whole /64 IPv6 range instead of a single address, for example
- **mask_port**: Unsigned integer ``(0)`` - Number of bits of the port number to consider over IPv4, for CGNAT deployments. Default is 0 meaning that the port is not taken into account. For example passing ``2`` here, which only makes sense if the IPv4 parameter is set to ``32``, will split a given IPv4 address into four port ranges: ``0-16383``, ``16384-32767``, ``32768-49151`` and ``49152-65535``
- **exclude_ranges**: Sequence of String ``("")`` - Exclude this list of ranges, meaning that no dynamic block will ever be inserted for clients in that range. Default to empty, meaning rules are applied to all ranges. When used in combination with ``include_ranges`` the more specific entry wins
- **include_ranges**: Sequence of String ``("")`` - Include this list of ranges, meaning that dynamic rules will be inserted for clients in that range. When used in combination with ``exclude_ranges`` the more specific entry wins
- **exclude_domains**: Sequence of String ``("")`` - Exclude this list of domains, meaning that no dynamic rules will ever be inserted for this domain via ``suffix-match`` or ``suffix-match-ffi`` rules. Default to empty, meaning rules are applied to all domains
- **rules**: Sequence of :ref:`DynamicRuleConfiguration <yaml-settings-DynamicRuleConfiguration>` - List of dynamic rules in this group


.. _yaml-settings-DynamicRulesSettingsConfiguration:

DynamicRulesSettingsConfiguration
---------------------------------

Dynamic rules-related settings

- **purge_interval**: Unsigned integer ``(60)`` - Set at which interval, in seconds, the expired dynamic blocks entries will be effectively removed from the tree. Entries are not applied anymore as soon as they expire, but they remain in the tree for a while for performance reasons. Removing them makes the addition of new entries faster and frees up the memory they use. Setting this value to 0 disables the purging mechanism, so entries will remain in the tree
- **default_action**: String ``(Drop)`` - Set which action is performed when a query is blocked. Supported values are: Drop, NoOp, NoRecurse, NXDomain, Refused, Truncate


.. _yaml-settings-EbpfConfiguration:

EbpfConfiguration
-----------------

``eBPF`` and ``XDP`` related settings

- **ipv4**: :ref:`EbpfMapConfiguration <yaml-settings-EbpfMapConfiguration>` - IPv4 map
- **ipv6**: :ref:`EbpfMapConfiguration <yaml-settings-EbpfMapConfiguration>` - IPv6 map
- **cidr_ipv4**: :ref:`EbpfMapConfiguration <yaml-settings-EbpfMapConfiguration>` - IPv4 subnets map
- **cidr_ipv6**: :ref:`EbpfMapConfiguration <yaml-settings-EbpfMapConfiguration>` - IPv6 subnets map
- **qnames**: :ref:`EbpfMapConfiguration <yaml-settings-EbpfMapConfiguration>` - DNS names map
- **external**: Boolean ``(false)`` - If set to true, :program:`dnsdist` does not load the internal ``eBPF`` program. This is useful for ``AF_XDP`` and ``XDP`` maps


.. _yaml-settings-EbpfMapConfiguration:

EbpfMapConfiguration
--------------------

An ``eBPF`` map that is used to share data with kernel-land ``AF_XDP``/``XSK``, ``socket filter`` or ``XDP`` programs. Maps can be pinned to a filesystem path, which makes their content persistent across restarts and allows external programs to read their content and to add new entries. :program:`dnsdist` will try to load maps that are pinned to a filesystem path on startups, inheriting any existing entries, and fall back to creating them if they do not exist yet. Note that the user :program`dnsdist` is running under must have the right privileges to read and write to the given file, and to go through all the directories in the path leading to that file. The pinned path must be on a filesystem of type ``BPF``, usually below ``/sys/fs/bpf/``

- **max_entries**: Unsigned integer ``(0)`` - Maximum number of entries in this map. 0 means no entry at all
- **pinned_path**: String ``("")`` - The filesystem path this map should be pinned to


.. _yaml-settings-EdnsClientSubnetConfiguration:

EdnsClientSubnetConfiguration
-----------------------------

EDNS Client Subnet-related settings

- **override_existing**: Boolean ``(false)`` - When ``useClientSubnet`` in :func:`newServer()` or ``use_client_subnet`` in :ref:`yaml-settings-BackendConfiguration` are set, and :program:`dnsdist` adds an EDNS Client Subnet Client option to the query, override an existing option already present in the query, if any. Please see Passing the source address to the backend for more information. Note that it’s not recommended to enable this option in front of an authoritative server responding with EDNS Client Subnet information as mismatching data (ECS scopes) can confuse clients and lead to SERVFAIL responses on downstream nameservers
- **source_prefix_v4**: Unsigned integer ``(32)`` - When ``useClientSubnet`` in :func:`newServer()` or ``use_client_subnet`` in :ref:`yaml-settings-BackendConfiguration` are set, and :program:`dnsdist` adds an EDNS Client Subnet Client option to the query, truncate the requestor's IPv4 address to this number of bits
- **source_prefix_v6**: Unsigned integer ``(56)`` - When ``useClientSubnet`` in :func:`newServer()` or ``use_client_subnet`` in :ref:`yaml-settings-BackendConfiguration` are set, and :program:`dnsdist` adds an EDNS Client Subnet Client option to the query, truncate the requestor's IPv6 address to this number of bits


.. _yaml-settings-GeneralConfiguration:

GeneralConfiguration
--------------------

General settings

- **edns_udp_payload_size_self_generated_answers**: Unsigned integer ``(1232)`` - Set the UDP payload size advertised via EDNS on self-generated responses. In accordance with :rfc:`RFC 6891 <6891#section-6.2.5>`, values lower than 512 will be treated as equal to 512
- **add_edns_to_self_generated_answers**: Boolean ``(true)`` - Whether to add EDNS to self-generated responses, provided that the initial query had EDNS
- **truncate_tc_answers**: Boolean ``(false)`` - Remove any left-over records in responses with the TC bit set, in accordance with :rfc:`RFC 6891 <6891#section-7>`
- **fixup_case**: Boolean ``(false)`` - If set, ensure that the case of the DNS qname in the response matches the one from the query
- **allow_empty_responses**: Boolean ``(false)`` - Set to true (defaults to false) to allow empty responses (qdcount=0) with a NoError or NXDomain rcode (default) from backends. dnsdist drops these responses by default because it can't match them against the initial query since they don't contain the qname, qtype and qclass, and therefore the risk of collision is much higher than with regular responses
- **drop_empty_queries**: Boolean ``(false)`` - Set to true (defaults to false) to drop empty queries (qdcount=0) right away, instead of answering with a NotImp rcode. dnsdist used to drop these queries by default because most rules and existing Lua code expects a query to have a qname, qtype and qclass. However :rfc:`7873` uses these queries to request a server cookie, and :rfc:`8906` as a conformance test, so answering these queries with NotImp is much better than not answering at all
- **capabilities_to_retain**: Sequence of String ``("")`` - Accept a Linux capability as a string, or a list of these, to retain after startup so that privileged operations can still be performed at runtime.
  Keeping ``CAP_SYS_ADMIN`` on kernel 5.8+ for example allows loading eBPF programs and altering eBPF maps at runtime even if the ``kernel.unprivileged_bpf_disabled`` sysctl is set.
  Note that this does not grant the capabilities to the process, doing so might be done by running it as root which we don't advise, or by adding capabilities via the systemd unit file, for example.
  Please also be aware that switching to a different user via ``--uid`` will still drop all capabilities."



.. _yaml-settings-HealthCheckConfiguration:

HealthCheckConfiguration
------------------------

Health-checks related settings for backends

- **mode**: String ``(auto)`` - The health-check mode to use: 'auto' which sends health-check queries every ``check_interval`` seconds, 'up' which considers that the backend is always available, 'down' that it is always not available, and 'lazy' which only sends health-check queries after a configurable amount of regular queries have failed (see :ref:`yaml-settings-LazyHealthCheckConfiguration` for more information). Default is 'auto'. See :ref:`Healthcheck` for a more detailed explanation. Supported values are: auto, down, lazy, up
- **qname**: String ``("")`` - The DNS name to use as QNAME in health-check queries
- **qclass**: String ``(IN)`` - The DNS class to use in health-check queries
- **qtype**: String ``(A)`` - The DNS type to use in health-check queries
- **function**: String ``("")`` - The name of an optional Lua function to call to dynamically set the QNAME, QTYPE and QCLASS to use in the health-check query (see :ref:`Healthcheck`)
- **lua**: String ``("")`` - The code of an optional Lua function to call to dynamically set the QNAME, QTYPE and QCLASS to use in the health-check query (see :ref:`Healthcheck`)
- **lua_file**: String ``("")`` - A path to a file containing the code of an optional Lua function to call to dynamically set the QNAME, QTYPE and QCLASS to use in the health-check query (see :ref:`Healthcheck`)
- **timeout**: Unsigned integer ``(1000)`` - The timeout (in milliseconds) of a health-check query, default: 1000 (1s)
- **set_cd**: Boolean ``(false)`` - Set the CD (Checking Disabled) flag in the health-check query
- **max_failures**: Unsigned integer ``(1)`` - Allow this many check failures before declaring the backend down
- **rise**: Unsigned integer ``(1)`` - Require ``number`` consecutive successful checks before declaring the backend up
- **interval**: Unsigned integer ``(1)`` - The time in seconds between health checks
- **must_resolve**: Boolean ``(false)`` - Set to true when the health check MUST return a RCODE different from NXDomain, ServFail and Refused. Default is false, meaning that every RCODE except ServFail is considered valid
- **use_tcp**: Boolean ``(false)`` - Whether to do healthcheck queries over TCP, instead of UDP. Always enabled for TCP-only, DNS over TLS and DNS over HTTPS backends
- **lazy**: :ref:`LazyHealthCheckConfiguration <yaml-settings-LazyHealthCheckConfiguration>` - Settings for lazy health-checks


.. _yaml-settings-HttpCustomResponseHeaderConfiguration:

HttpCustomResponseHeaderConfiguration
-------------------------------------

List of custom HTTP headers

- **key**: String - The key, or name, part of the header
- **value**: String - The value part of the header


.. _yaml-settings-HttpResponsesMapConfiguration:

HttpResponsesMapConfiguration
-----------------------------

An entry of an HTTP response map. Every query that matches the regular expression supplied in ``expression`` will be immediately answered with a HTTP response.
The status of the HTTP response will be the one supplied by ``status``, and the content set to the one supplied by ``content``, except if the status is a redirection (3xx) in which case the content is expected to be the URL to redirect to.


- **expression**: String - A regular expression to match the path against
- **status**: Unsigned integer - The HTTP code to answer with
- **content**: String - The content of the HTTP response, or a URL if the status is a redirection (3xx)
- **headers**: Sequence of :ref:`HttpCustomResponseHeaderConfiguration <yaml-settings-HttpCustomResponseHeaderConfiguration>` - The custom headers to set for the HTTP response, if any. The default is to use the value of the ``custom_response_headers`` parameter of the frontend


.. _yaml-settings-IncomingDnscryptCertificateKeyPairConfiguration:

IncomingDnscryptCertificateKeyPairConfiguration
-----------------------------------------------

Certificate and associated key for DNSCrypt frontends

- **certificate**: String - The path to a DNSCrypt certificate file
- **key**: String - The path to the private key file corresponding to the certificate, or a list of paths to such files, whose order should match the certFile(s) ones


.. _yaml-settings-IncomingDnscryptConfiguration:

IncomingDnscryptConfiguration
-----------------------------

Settings for DNSCrypt frontends

- **provider_name**: String ``("")`` - The DNSCrypt provider name for this frontend
- **certificates**: Sequence of :ref:`IncomingDnscryptCertificateKeyPairConfiguration <yaml-settings-IncomingDnscryptCertificateKeyPairConfiguration>` - List of certificates and associated keys


.. _yaml-settings-IncomingDohConfiguration:

IncomingDohConfiguration
------------------------

The DNS over HTTP(s) parameters of a frontend

- **provider**: String ``(nghttp2)``. Supported values are: nghttp2, h2o
- **paths**: Sequence of String ``(/dns-query)`` - The path part of a URL, or a list of paths, to accept queries on. Any query with a path matching exactly one of these will be treated as a DoH query (sub-paths can be accepted by setting the ``exact_path_matching`` setting to false)
- **idle_timeout**: Unsigned integer ``(30)`` - Set the idle timeout, in seconds
- **server_tokens**: String ``("")`` - The content of the Server: HTTP header returned by dnsdist. The default is ``h2o/dnsdist`` when ``h2o`` is used, ``nghttp2-<version>/dnsdist`` when ``nghttp2`` is
- **send_cache_control_headers**: Boolean ``(true)`` - Whether to parse the response to find the lowest TTL and set a HTTP Cache-Control header accordingly
- **keep_incoming_headers**: Boolean ``(false)`` - Whether to retain the incoming headers in memory, to be able to use :func:`HTTPHeaderRule` or :meth:`DNSQuestion.getHTTPHeaders`
- **trust_forwarded_for_header**: Boolean ``(false)`` - Whether to parse any existing X-Forwarded-For header in the HTTP query and use the right-most value as the client source address and port, for ACL checks, rules, logging and so on
- **early_acl_drop**: Boolean ``(true)`` - Whether to apply the ACL right when the connection is established, immediately dropping queries that are not allowed by the ACL (true), or later when a query is received, sending a HTTP 403 response when it is not allowed
- **exact_path_matching**: Boolean ``(true)`` - Whether to do exact path matching of the query path against the paths configured in ``paths`` (true) or to accepts sub-paths (false)
- **internal_pipe_buffer_size**: Unsigned integer ``(1048576)`` - Set the size in bytes of the internal buffer of the pipes used internally to pass queries and responses between threads. Requires support for ``F_SETPIPE_SZ`` which is present in Linux since 2.6.35. The actual size might be rounded up to a multiple of a page size. 0 means that the OS default size is used.
- **custom_response_headers**: Sequence of :ref:`HttpCustomResponseHeaderConfiguration <yaml-settings-HttpCustomResponseHeaderConfiguration>` - Set custom HTTP header(s) returned by dnsdist
- **responses_map**: Sequence of :ref:`HttpResponsesMapConfiguration <yaml-settings-HttpResponsesMapConfiguration>` - Set a list of HTTP response rules allowing to intercept HTTP queries very early, before the DNS payload has been processed, and send custom responses including error pages, redirects and static content


.. _yaml-settings-IncomingDoqConfiguration:

IncomingDoqConfiguration
------------------------

Settings for DNS over QUIC frontends

- **max_concurrent_queries_per_connection**: Unsigned integer ``(65535)`` - Maximum number of in-flight queries on a single connection


.. _yaml-settings-IncomingQuicConfiguration:

IncomingQuicConfiguration
-------------------------

QUIC settings for DNS over QUIC and DNS over HTTP/3 frontends

- **idle_timeout**: Unsigned integer ``(5)`` - Set the idle timeout, in seconds
- **congestion_control_algorithm**: String ``(reno)`` - The congestion control algorithm to be used. Supported values are: reno, cubic, bbr
- **internal_pipe_buffer_size**: Unsigned integer ``(1048576)`` - Set the size in bytes of the internal buffer of the pipes used internally to pass queries and responses between threads. Requires support for ``F_SETPIPE_SZ`` which is present in Linux since 2.6.35. The actual size might be rounded up to a multiple of a page size. 0 means that the OS default size is used


.. _yaml-settings-IncomingTcpConfiguration:

IncomingTcpConfiguration
------------------------

TCP-related settings for frontends

- **max_in_flight_queries**: Unsigned integer ``(0)`` - Maximum number of in-flight queries over a single TCP connection. The default is 0, which disables out-of-order processing
- **listen_queue_size**: Unsigned integer ``(0)`` - Set the size of the listen queue. Default is ``SOMAXCONN``
- **fast_open_queue_size**: Unsigned integer ``(0)`` - Set the TCP Fast Open queue size, enabling TCP Fast Open when available and the value is larger than 0
- **max_concurrent_connections**: Unsigned integer ``(0)`` - Maximum number of concurrent incoming TCP connections to this frontend. The default is 0 which means unlimited


.. _yaml-settings-IncomingTlsCertificateKeyPairConfiguration:

IncomingTlsCertificateKeyPairConfiguration
------------------------------------------

A pair of TLS certificate and key, with an optional associated password

- **certificate**: String - A path to a file containing the certificate, in ``PEM``, ``DER`` or ``PKCS12`` format
- **key**: String ``("")`` - A path to a file containing the key corresponding to the certificate, in ``PEM``, ``DER`` or ``PKCS12`` format
- **password**: String ``("")`` - Password protecting the PKCS12 file if appropriate


.. _yaml-settings-IncomingTlsConfiguration:

IncomingTlsConfiguration
------------------------

TLS parameters for frontends

- **provider**: String ``(OpenSSL)`` - . Supported values are: OpenSSL, GnuTLS
- **certificates**: Sequence of :ref:`IncomingTlsCertificateKeyPairConfiguration <yaml-settings-IncomingTlsCertificateKeyPairConfiguration>` - List of TLS certificates and their associated keys
- **ciphers**: String ``("")`` - The TLS ciphers to use, in OpenSSL format. Note that ``ciphers_tls_13`` should be used for TLS 1.3
- **ciphers_tls_13**: String ``("")`` - The TLS ciphers to use for TLS 1.3, in OpenSSL format
- **minimum_version**: String ``(tls1.0)`` - The minimum version of the TLS protocol to support. Supported values are: tls1.0, tls1.1, tls1.2, tls1.3
- **ticket_key_file**: String ``("")`` - The path to a file from where TLS tickets keys should be loaded, to support :rfc:`5077`. These keys should be rotated often and never written to persistent storage to preserve forward secrecy. The default is to generate a random key. dnsdist supports several tickets keys to be able to decrypt existing sessions after the rotation. See :doc:`../advanced/tls-sessions-management` for more information
- **tickets_keys_rotation_delay**: Unsigned integer ``(43200)`` - Set the delay before the TLS tickets key is rotated, in seconds. Default is 43200 (12h). A value of 0 disables the automatic rotation, which might be useful when ``ticket_key_file`` is used
- **number_of_tickets_keys**: Unsigned integer ``(5)`` - The maximum number of tickets keys to keep in memory at the same time. Only one key is marked as active and used to encrypt new tickets while the remaining ones can still be used to decrypt existing tickets after a rotation
- **prefer_server_ciphers**: Boolean ``(true)`` - Whether to prefer the order of ciphers set by the server instead of the one set by the client. Default is true, meaning that the order of the server is used. For OpenSSL >= 1.1.1, setting this option also enables the temporary re-prioritization of the ChaCha20-Poly1305 cipher if the client prioritizes it
- **session_timeout**: Unsigned integer ``(0)`` - Set the TLS session lifetime in seconds, this is used both for TLS ticket lifetime and for sessions kept in memory
- **session_tickets**: Boolean ``(true)`` - Whether session resumption via session tickets is enabled. Default is true, meaning tickets are enabled
- **number_of_stored_sessions**: Unsigned integer ``(20480)`` - The maximum number of sessions kept in memory at the same time. Default is 20480. Setting this value to 0 disables stored session entirely
- **ocsp_response_files**: Sequence of String ``("")`` - List of files containing OCSP responses, in the same order than the certificates and keys, that will be used to provide OCSP stapling responses
- **key_log_file**: String ``("")`` - Write the TLS keys in the specified file so that an external program can decrypt TLS exchanges, in the format described in https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format. Note that this feature requires OpenSSL >= 1.1.1
- **release_buffers**: Boolean ``(true)`` - Whether OpenSSL should release its I/O buffers when a connection goes idle, saving roughly 35 kB of memory per connection
- **enable_renegotiation**: Boolean ``(false)`` - Whether secure TLS renegotiation should be enabled. Disabled by default since it increases the attack surface and is seldom used for DNS
- **async_mode**: Boolean ``(false)`` - Whether to enable experimental asynchronous TLS I/O operations if the ``nghttp2`` library is used, ``OpenSSL`` is used as the TLS implementation and an asynchronous capable SSL engine (or provider) is loaded. See also :func:`loadTLSEngine` or :func:`loadTLSProvider` to load the engine (or provider)
- **ktls**: Boolean ``(false)`` - Whether to enable the experimental kernel TLS support on Linux, if both the kernel and the OpenSSL library support it
- **read_ahead**: Boolean ``(true)`` - When the TLS provider is set to OpenSSL, whether we tell the library to read as many input bytes as possible, which leads to better performance by reducing the number of syscalls
- **proxy_protocol_outside_tls**: Boolean ``(false)`` - When the use of incoming proxy protocol is enabled, whether the payload is prepended after the start of the TLS session (so inside, meaning it is protected by the TLS layer providing encryption and authentication) or not (outside, meaning it is in clear-text). Default is false which means inside. Note that most third-party software like HAproxy expect the proxy protocol payload to be outside, in clear-text
- **ignore_configuration_errors**: Boolean ``(false)`` - Ignore TLS configuration errors (such as invalid certificate path) and just issue a warning instead of aborting the whole process


.. _yaml-settings-KeyValueStoresConfiguration:

KeyValueStoresConfiguration
---------------------------

List of key-value stores that can be used with :ref:`yaml-settings-KeyValueStoreLookupAction` or :ref:`yaml-settings-KeyValueStoreLookupSelector`

- **lmdb**: Sequence of :ref:`LmdbKvStoreConfiguration <yaml-settings-LmdbKvStoreConfiguration>` - List of LMDB-based key-value stores
- **cdb**: Sequence of :ref:`CdbKvStoreConfiguration <yaml-settings-CdbKvStoreConfiguration>` - List of CDB-based key-value stores
- **lookup_keys**: :ref:`KvsLookupKeysConfiguration <yaml-settings-KvsLookupKeysConfiguration>` - List of lookup keys


.. _yaml-settings-KvsLookupKeyQnameConfiguration:

KvsLookupKeyQnameConfiguration
------------------------------

Lookup key that can be used with :ref:`yaml-settings-KeyValueStoreLookupAction` or :ref:`yaml-settings-KeyValueStoreLookupSelector`, will return the qname of the query in DNS wire format

- **name**: String - The name of this lookup key
- **wire_format**: Boolean ``(true)`` - Whether to do the lookup in wire format (default) or in plain text


.. _yaml-settings-KvsLookupKeySourceIpConfiguration:

KvsLookupKeySourceIpConfiguration
---------------------------------

Lookup key that can be used with :ref:`yaml-settings-KeyValueStoreLookupAction` or :ref:`yaml-settings-KeyValueStoreLookupSelector`, will return the source IP of the client in network byte-order

- **name**: String - The name of this lookup key
- **v4_mask**: Unsigned integer ``(32)`` - Mask applied to IPv4 addresses. Default is 32 (the whole address)
- **v6_mask**: Unsigned integer ``(128)`` - Mask applied to IPv6 addresses. Default is 128 (the whole address)
- **include_port**: Boolean ``(false)`` - Whether to append the port (in network byte-order) after the address


.. _yaml-settings-KvsLookupKeySuffixConfiguration:

KvsLookupKeySuffixConfiguration
-------------------------------

Lookup key that can be used with :ref:`yaml-settings-KeyValueStoreLookupAction` or :ref:`yaml-settings-KeyValueStoreLookupSelector`, will return a vector of keys based on the labels of the qname in DNS wire format or plain text. For example if the qname is sub.domain.powerdns.com. the following keys will be returned:

- ``\\3sub\\6domain\\8powerdns\\3com\\0``
- ``\\6domain\\8powerdns\\3com\\0``
- ``\\8powerdns\\3com\\0``
- ``\\3com\\0``
- ``\\0``

If ``min_labels`` is set to a value larger than ``0`` the lookup will only be done as long as there is at least ``min_labels`` labels remaining. Taking back our previous example, it means only the following keys will be returned if ``min_labels`` is set to ``2``:

- ``\\3sub\\6domain\\8powerdns\\3com\\0``
- ``\\6domain\\8powerdns\\3com\\0``
- ``\\8powerdns\\3com\\0``


- **name**: String - The name of this lookup key
- **minimum_labels**: Unsigned integer ``(0)`` - The minimum number of labels to do a lookup for. Default is 0 which means unlimited
- **wire_format**: Boolean ``(true)`` - Whether to do the lookup in wire format (default) or in plain text


.. _yaml-settings-KvsLookupKeyTagConfiguration:

KvsLookupKeyTagConfiguration
----------------------------

Lookup key that can be used with :ref:`yaml-settings-KeyValueStoreLookupAction` or :ref:`yaml-settings-KeyValueStoreLookupSelector`, will return the value of the corresponding tag for this query, if it exists

- **name**: String
- **tag**: String


.. _yaml-settings-KvsLookupKeysConfiguration:

KvsLookupKeysConfiguration
--------------------------

List of look keys that can be used with :ref:`yaml-settings-KeyValueStoreLookupAction` or :ref:`yaml-settings-KeyValueStoreLookupSelector`

- **source_ip_keys**: Sequence of :ref:`KvsLookupKeySourceIpConfiguration <yaml-settings-KvsLookupKeySourceIpConfiguration>`
- **qname_keys**: Sequence of :ref:`KvsLookupKeyQnameConfiguration <yaml-settings-KvsLookupKeyQnameConfiguration>`
- **suffix_keys**: Sequence of :ref:`KvsLookupKeySuffixConfiguration <yaml-settings-KvsLookupKeySuffixConfiguration>`
- **tag_keys**: Sequence of :ref:`KvsLookupKeyTagConfiguration <yaml-settings-KvsLookupKeyTagConfiguration>`


.. _yaml-settings-LazyHealthCheckConfiguration:

LazyHealthCheckConfiguration
----------------------------

Lazy health-check related settings for backends

- **interval**: Unsigned integer ``(30)`` - The interval, in seconds, between health-check queries in 'lazy' mode. Note that when ``use_exponential_back_off`` is set to true, the interval doubles between every queries. These queries are only sent when a threshold of failing regular queries has been reached, and until the backend is available again
- **min_sample_count**: Unsigned integer ``(1)`` - The minimum amount of regular queries that should have been recorded before the ``threshold`` threshold can be applied
- **mode**: String ``(TimeoutOrServFail)`` - The 'lazy' health-check mode: ``TimeoutOnly`` means that only timeout and I/O errors of regular queries will be considered for the ``threshold``, while ``TimeoutOrServFail`` will also consider ``Server Failure`` answers. Supported values are: TimeoutOnly, TimeoutOrServFail
- **sample_size**: Unsigned integer ``(100)`` - The maximum size of the sample of queries to record and consider for the ``threshold``. Default is 100, which means the result (failure or success) of the last 100 queries will be considered
- **threshold**: Unsigned integer ``(20)`` - The threshold, as a percentage, of queries that should fail for the 'lazy' health-check to be triggered. The default is 20 which means 20% of the last ``sample_size`` queries should fail for a health-check to be triggered
- **use_exponential_back_off**: Boolean ``(false)`` - Whether the 'lazy' health-check should use an exponential back-off instead of a fixed value, between health-check probes. The default is false which means that after a backend has been moved to the ``down`` state health-check probes are sent every ``interval`` seconds. When set to true, the delay between each probe starts at ``interval`` seconds and doubles between every probe, capped at ``max_back_off`` seconds
- **max_back_off**: Unsigned integer ``(3600)`` - This value, in seconds, caps the time between two health-check queries when ``use_exponential_back_off`` is set to true. The default is 3600 which means that at most one hour will pass between two health-check queries


.. _yaml-settings-LmdbKvStoreConfiguration:

LmdbKvStoreConfiguration
------------------------

LMDB-based key-value store

- **name**: String - The name of this object
- **file_name**: String - The path to an existing ``LMDB`` database created with ``MDB_NOSUBDIR``
- **database_name**: String - The name of the database to use
- **no_lock**: Boolean ``(false)`` - Whether to open the database with the ``MDB_NOLOCK`` flag


.. _yaml-settings-LoadBalancingPoliciesConfiguration:

LoadBalancingPoliciesConfiguration
----------------------------------

Setting for load-balancing policies

- **default_policy**: String ``(leastOutstanding)`` - Set the default server selection policy
- **servfail_on_no_server**: Boolean ``(false)`` - If set, return a ServFail when no servers are available, instead of the default behaviour of dropping the query
- **round_robin_servfail_on_no_server**: Boolean ``(false)`` - By default the roundrobin load-balancing policy will still try to select a backend even if all backends are currently down. Setting this to true will make the policy fail and return that no server is available instead
- **weighted_balancing_factor**: Double ``(0.0)`` - Set the maximum imbalance between the number of outstanding queries intended for a given server, based on its weight, and the actual number, when using the ``whashed`` or ``wrandom`` load-balancing policy. Default is 0, which disables the bounded-load algorithm
- **consistent_hashing_balancing_factor**: Double ``(0.0)`` - Set the maximum imbalance between the number of outstanding queries intended for a given server, based on its weight, and the actual number, when using the ``chashed`` consistent hashing load-balancing policy. Default is 0, which disables the bounded-load algorithm
- **custom_policies**: Sequence of :ref:`CustomLoadBalancingPolicyConfiguration <yaml-settings-CustomLoadBalancingPolicyConfiguration>` - Custom load-balancing policies implemented in Lua
- **hash_perturbation**: Unsigned integer ``(0)`` - Set the hash perturbation value to be used in the ``whashed`` policy instead of a random one, allowing to have consistent ``whashed`` results on different instances


.. _yaml-settings-LoggingConfiguration:

LoggingConfiguration
--------------------

Logging settings

- **verbose**: Boolean ``(false)`` - Set whether log messages issued at the verbose level should be logged
- **verbose_health_checks**: Boolean ``(false)`` - Set whether health check errors should be logged
- **verbose_log_destination**: String ``("")`` - Set a destination file to write the ‘verbose’ log messages to, instead of sending them to syslog and/or the standard output which is the default. Note that these messages will no longer be sent to syslog or the standard output once this option has been set. There is no rotation or file size limit. Only use this feature for debugging under active operator control
- **syslog_facility**: String ``("")`` - Set the syslog logging facility to the supplied value (values with or without the ``log_`` prefix are supported). Supported values are: local0, log_local0, local1, log_local1, local2, log_local2, local3, log_local3, local4, log_local4, local5, log_local5, local6, log_local6, local7, log_local7, kern, log_kern, user, log_user, mail, log_mail, daemon, log_daemon, auth, log_auth, syslog, log_syslog, lpr, log_lpr, news, log_news, uucp, log_uucp, cron, log_cron, authpriv, log_authpriv, ftp, log_ftp
- **structured**: :ref:`StructuredLoggingConfiguration <yaml-settings-StructuredLoggingConfiguration>`


.. _yaml-settings-MetricsConfiguration:

MetricsConfiguration
--------------------

Metrics-related settings

- **carbon**: Sequence of :ref:`CarbonConfiguration <yaml-settings-CarbonConfiguration>` - List of Carbon endpoints to send metrics to


.. _yaml-settings-OutgoingAutoUpgradeConfiguration:

OutgoingAutoUpgradeConfiguration
--------------------------------

Setting for the automatically upgraded backend to a more secure version of the DNS protocol

- **enabled**: Boolean ``(false)`` - Whether to use the 'Discovery of Designated Resolvers' mechanism to automatically upgrade a Do53 backend to DoT or DoH, depending on the priorities present in the SVCB record returned by the backend
- **interval**: Unsigned integer ``(3600)`` - If ``enabled`` is set, how often to check if an upgrade is available, in seconds
- **keep**: Boolean ``(false)`` - If ``enabled`` is set, whether to keep the existing Do53 backend around after an upgrade. Default is false which means the Do53 backend will be replaced by the upgraded one
- **pool**: String ``("")`` - If ``enabled`` is set, in which pool to place the newly upgraded backend. Default is empty which means the backend is placed in the default pool
- **doh_key**: Unsigned integer ``(7)`` - If ``enabled`` is set, the value to use for the SVC key corresponding to the DoH path. Default is 7
- **use_lazy_health_check**: Boolean ``(false)`` - Whether the auto-upgraded version of this backend should use the lazy health-checking mode. Default is false, which means it will use the regular health-checking mode


.. _yaml-settings-OutgoingDohConfiguration:

OutgoingDohConfiguration
------------------------

DNS over HTTPS specific settings for backends

- **path**: String ``(/dns-query)`` - The HTTP path to send queries to
- **add_x_forwarded_headers**: Boolean ``(false)`` - Whether to add X-Forwarded-For, X-Forwarded-Port and X-Forwarded-Proto headers to the backend


.. _yaml-settings-OutgoingTcpConfiguration:

OutgoingTcpConfiguration
------------------------

TCP-related settings for backends

- **retries**: Unsigned integer ``(5)`` - The number of TCP connection attempts to the backend, for a given query
- **connect_timeout**: Unsigned integer ``(5)`` - The timeout (in seconds) of a TCP connection attempt
- **send_timeout**: Unsigned integer ``(30)`` - The timeout (in seconds) of a TCP write attempt
- **receive_timeout**: Unsigned integer ``(30)`` - The timeout (in seconds) of a TCP read attempt
- **fast_open**: Boolean ``(false)`` - Whether to enable TCP Fast Open


.. _yaml-settings-OutgoingTlsConfiguration:

OutgoingTlsConfiguration
------------------------

TLS parameters for backends

- **provider**: String ``(OpenSSL)`` - . Supported values are: OpenSSL, GnuTLS
- **subject_name**: String ``("")`` - The subject name passed in the SNI value of the TLS handshake, and against which to validate the certificate presented by the backend. Default is empty. If set this value supersedes any ``subject_addr`` one
- **subject_address**: String ``("")`` - The subject IP address passed in the SNI value of the TLS handshake, and against which to validate the certificate presented by the backend
- **validate_certificate**: Boolean ``(true)`` - Whether the certificate presented by the backend should be validated against the CA store (see ``ca_store``)
- **ca_store**: String ``("")`` - Specifies the path to the CA certificate file, in PEM format, to use to check the certificate presented by the backend. Default is an empty string, which means to use the system CA store. Note that this directive is only used if ``validate_certificates`` is set
- **ciphers**: String ``("")`` - The TLS ciphers to use. The exact format depends on the provider used. When the OpenSSL provider is used, ciphers for TLS 1.3 must be specified via ``ciphers_tls_13``
- **ciphers_tls_13**: String ``("")`` - The ciphers to use for TLS 1.3, when the OpenSSL provider is used. When the GnuTLS provider is used, ``ciphers`` applies regardless of the TLS protocol and this setting is not used.
- **key_log_file**: String ``("")`` - Write the TLS keys in the specified file so that an external program can decrypt TLS exchanges, in the format described in https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format. Note that this feature requires OpenSSL >= 1.1.1
- **release_buffers**: Boolean ``(true)`` - Whether OpenSSL should release its I/O buffers when a connection goes idle, saving roughly 35 kB of memory per connection
- **enable_renegotiation**: Boolean ``(false)`` - Whether secure TLS renegotiation should be enabled. Disabled by default since it increases the attack surface and is seldom used for DNS
- **ktls**: Boolean ``(false)`` - Whether to enable the experimental kernel TLS support on Linux, if both the kernel and the OpenSSL library support it. Default is false. Currently both DoT and DoH backend support this option


.. _yaml-settings-PacketCacheConfiguration:

PacketCacheConfiguration
------------------------

Packet-cache settings

- **name**: String - The name of the packet cache object
- **size**: Unsigned integer - The maximum number of entries in this cache
- **deferrable_insert_lock**: Boolean ``(true)`` - Whether the cache should give up insertion if the lock is held by another thread, or simply wait to get the lock
- **dont_age**: Boolean ``(false)`` - Don’t reduce TTLs when serving from the cache. Use this when dnsdist fronts a cluster of authoritative servers
- **keep_stale_data**: Boolean ``(false)`` - Whether to suspend the removal of expired entries from the cache when there is no backend available in at least one of the pools using this cache
- **max_negative_ttl**: Unsigned integer ``(3600)`` - Cache a NXDomain or NoData answer from the backend for at most this amount of seconds, even if the TTL of the SOA record is higher
- **max_ttl**: Unsigned integer ``(86400)`` - Cap the TTL for records to his number
- **min_ttl**: Unsigned integer ``(0)`` - Don’t cache entries with a TTL lower than this
- **shards**: Unsigned integer ``(20)`` - Number of shards to divide the cache into, to reduce lock contention
- **parse_ecs**: Boolean ``(false)`` - Whether any EDNS Client Subnet option present in the query should be extracted and stored to be able to detect hash collisions involving queries with the same qname, qtype and qclass but a different incoming ECS value. Enabling this option adds a parsing cost and only makes sense if at least one backend might send different responses based on the ECS value, so it's disabled by default. Enabling this option is required for the :doc:`../advanced/zero-scope` option to work
- **stale_ttl**: Unsigned integer ``(60)`` - When the backend servers are not reachable, and global configuration setStaleCacheEntriesTTL is set appropriately, TTL that will be used when a stale cache entry is returned
- **temporary_failure_ttl**: Unsigned integer ``(60)`` - On a SERVFAIL or REFUSED from the backend, cache for this amount of seconds
- **truncated_ttl**: Unsigned integer ``(0)`` - On a truncated (TC=1, no records) response from the backend, cache for this amount of seconds. 0, the default, means that truncated answers are not cached
- **cookie_hashing**: Boolean ``(false)`` - If true, EDNS Cookie values will be hashed, resulting in separate entries for different cookies in the packet cache. This is required if the backend is sending answers with EDNS Cookies, otherwise a client might receive an answer with the wrong cookie
- **maximum_entry_size**: Unsigned integer ``(4096)`` - The maximum size, in bytes, of a DNS packet that can be inserted into the packet cache
- **options_to_skip**: Sequence of String ``("")`` - Extra list of EDNS option codes to skip when hashing the packet (if ``cookie_hashing`` above is false, EDNS cookie option number will be added to this list internally)


.. _yaml-settings-PoolConfiguration:

PoolConfiguration
-----------------

Settings for a pool of servers

- **name**: String - The name of this pool
- **packet_cache**: String ``("")`` - The name of a packet cache object, if any
- **policy**: String ``("")`` - The name of the load-balancing policy associated to this pool. If left empty, the global policy will be used


.. _yaml-settings-ProtoBufMetaConfiguration:

ProtoBufMetaConfiguration
-------------------------

Meta-data entry to be added to a Protocol Buffer message

- **key**: String - Name of the meta entry
- **value**: String - Value of the meta entry


.. _yaml-settings-ProtobufLoggerConfiguration:

ProtobufLoggerConfiguration
---------------------------

Endpoint to send queries and/or responses data to, using the native PowerDNS format

- **name**: String - Name of this endpoint
- **address**: String - An IP:PORT combination where the logger is listening
- **timeout**: Unsigned integer ``(2)`` - TCP connect timeout in seconds
- **max_queued_entries**: Unsigned integer ``(100)`` - Queue this many messages before dropping new ones (e.g. when the remote listener closes the connection)
- **reconnect_wait_time**: Unsigned integer ``(1)`` - Time in seconds between reconnection attempts
- **connection_count**: Unsigned integer ``(1)`` - Number of connections to open to the endpoint


.. _yaml-settings-ProxyProtocolConfiguration:

ProxyProtocolConfiguration
--------------------------

Proxy Protocol-related settings

- **acl**: Sequence of String ``("")`` - Set the list of netmasks from which a Proxy Protocol header will be required, over UDP, TCP and DNS over TLS. The default is empty. Note that a proxy protocol payload will be required from these clients, regular DNS queries will no longer be accepted if they are not preceded by a proxy protocol payload. Be also aware that, if ``apply_acl_to_proxied_clients`` is set (default is false), the general ACL will be applied to the source IP address as seen by dnsdist first, but also to the source IP address provided in the Proxy Protocol header.
- **maximum_payload_size**: Unsigned integer ``(512)`` - Set the maximum size of a Proxy Protocol payload that dnsdist is willing to accept, in bytes. The default is 512, which is more than enough except for very large TLV data. This setting can’t be set to a value lower than 16 since it would deny of Proxy Protocol headers
- **apply_acl_to_proxied_clients**: Boolean ``(false)`` - Whether the general ACL should be applied to the source IP address provided in the Proxy Protocol header, in addition to being applied to the source IP address as seen by dnsdist first


.. _yaml-settings-ProxyProtocolValueConfiguration:

ProxyProtocolValueConfiguration
-------------------------------

A proxy protocol Type-Length Value entry

- **key**: Unsigned integer - The type of the proxy protocol entry
- **value**: String - The value of the proxy protocol entry


.. _yaml-settings-QueryCountConfiguration:

QueryCountConfiguration
-----------------------

Per-record Carbon statistics of the amount of queries. See :doc:`../guides/carbon`

- **enabled**: Boolean ``(false)`` - Enable per-record Carbon statistics of the amount of queries
- **filter_function_name**: String ``("")`` - The name of a Lua function to filter which query should be accounted for, and how
- **filter_function_code**: String ``("")`` - The code of a Lua function to filter which query should be accounted for, and how
- **filter_function_file**: String ``("")`` - The path to a file containing the code of a Lua function to filter which query should be accounted for, and how


.. _yaml-settings-QueryRuleConfiguration:

QueryRuleConfiguration
----------------------

A rule that can applied on queries

- **name**: String ``("")`` - The name to assign to this rule
- **uuid**: String - The UUID to assign to this rule, if any
- **selector**: :ref:`Selector <yaml-settings-Selector>` - The selector to match queries against
- **action**: :ref:`Action <yaml-settings-Action>` - The action taken if the selector matches


.. _yaml-settings-RemoteLoggingConfiguration:

RemoteLoggingConfiguration
--------------------------

Queries and/or responses remote logging settings

- **protobuf_loggers**: Sequence of :ref:`ProtobufLoggerConfiguration <yaml-settings-ProtobufLoggerConfiguration>` - List of endpoints to send queries and/or responses data to, using the native PowerDNS format
- **dnstap_loggers**: Sequence of :ref:`DnstapLoggerConfiguration <yaml-settings-DnstapLoggerConfiguration>` - List of endpoints to send queries and/or responses data to, using the dnstap format


.. _yaml-settings-ResponseRuleConfiguration:

ResponseRuleConfiguration
-------------------------

A rule that can applied on responses

- **name**: String ``("")`` - The name to assign to this rule
- **uuid**: String ``("")`` - The UUID to assign to this rule, if any
- **selector**: :ref:`Selector <yaml-settings-Selector>` - The selector to match responses against
- **action**: :ref:`ResponseAction <yaml-settings-ResponseAction>` - The action taken if the selector matches


.. _yaml-settings-RingBuffersConfiguration:

RingBuffersConfiguration
------------------------

Settings for in-memory ring buffers, that are used for live traffic inspection and dynamic rules

- **size**: Unsigned integer ``(10000)`` - The maximum amount of queries to keep in the ringbuffer
- **shards**: Unsigned integer ``(10)`` - The number of shards to use to limit lock contention
- **lock_retries**: Unsigned integer ``(5)`` - Set the number of shards to attempt to lock without blocking before giving up and simply blocking while waiting for the next shard to be available. Default to 5 if there is more than one shard, 0 otherwise
- **record_queries**: Boolean ``(true)`` - Whether to record queries in the ring buffers
- **record_responses**: Boolean ``(true)`` - Whether to record responses in the ring buffers


.. _yaml-settings-SecurityPollingConfiguration:

SecurityPollingConfiguration
----------------------------

- **polling_interval**: Unsigned integer ``(3600)``
- **suffix**: String ``(secpoll.powerdns.com.)``


.. _yaml-settings-SnmpConfiguration:

SnmpConfiguration
-----------------

SNMP-related settings

- **enabled**: Boolean ``(false)`` - Enable SNMP support
- **traps_enabled**: Boolean ``(false)`` - Enable the sending of SNMP traps for specific events
- **daemon_socket**: String ``("")`` - A string specifying how to connect to the daemon agent. This is usually the path to a UNIX socket, but e.g. ``tcp:localhost:705`` can be used as well. By default, SNMP agent’s default socket is used


.. _yaml-settings-StructuredLoggingConfiguration:

StructuredLoggingConfiguration
------------------------------

Structured-like logging settings

- **enabled**: Boolean ``(false)`` - Set whether log messages should be in a structured-logging-like format. This is turned off by default.
  The resulting format looks like this (when timestamps are enabled via ``--log-timestamps`` and with ``level_prefix: prio`` and ``time_format: ISO8601``)::

      ts=\"2023-11-06T12:04:58+0100\" prio=\"Info\" msg=\"Added downstream server 127.0.0.1:53\"

  And with ``level_prefix: level`` and ``time_format: numeric``)::

      ts=\"1699268815.133\" level=\"Info\" msg=\"Added downstream server 127.0.0.1:53\"

- **level_prefix**: String ``(prio)`` - Set the key name for the log level. There is unfortunately no standard name for this key, so in some setups it might be useful to set this value to a different name to have consistency across products
- **time_format**: String ``(numeric)`` - Set the time format. Supported values are: ISO8601, numeric


.. _yaml-settings-TcpTuningConfiguration:

TcpTuningConfiguration
----------------------

- **worker_threads**: Unsigned integer ``(10)``
- **receive_timeout**: Unsigned integer ``(2)``
- **send_timeout**: Unsigned integer ``(2)``
- **max_queries_per_connection**: Unsigned integer ``(0)``
- **max_connection_duration**: Unsigned integer ``(0)``
- **max_queued_connections**: Unsigned integer ``(10000)``
- **internal_pipe_buffer_size**: Unsigned integer ``(1048576)``
- **outgoing_max_idle_time**: Unsigned integer ``(300)``
- **outgoing_cleanup_interval**: Unsigned integer ``(60)``
- **outgoing_max_idle_connection_per_backend**: Unsigned integer ``(10)``
- **max_connections_per_client**: Unsigned integer ``(0)``
- **fast_open_key**: String ``("")``
- **connections_overload_threshold**: Unsigned integer ``(90)`` - Set a threshold as a percentage to the maximum number of incoming TCP connections per frontend or per client. When this threshold is reached, new incoming TCP connections are restricted: only query per connection is allowed (no out-of-order processing, no idle time allowed), the receive timeout is reduced to 500 milliseconds and the total duration of the TCP connection is limited to 5 seconds
- **max_connection_rate_per_client**: Unsigned integer ``(0)`` - Set the maximum number of new TCP connections that a given client (see ``connections_mask_v4``, ``connections_mask_v6`` and ``connection_mask_v4_port`` to see how clients can be aggregated) can open, per second, over the last ``connection_rate_interval`` minutes. Clients exceeding this rate will not be able to open new TCP connections for ``ban_duration_for_exceeding_tcp_tls_rate`` seconds. See also ``max_tls_new_session_rate_per_client`` and ``max_tls_resumed_session_rate_per_client``
- **connection_rate_interval**: Unsigned integer ``(5)`` - Set the interval, in minutes, over which new TCP and TLS per client connection rates are computed (see ``max_connection_rate_per_client``, ``max_tls_new_session_rate_per_client`` and ``max_tls_resumed_session_rate_per_client``)
- **max_tls_new_session_rate_per_client**: Unsigned integer ``(0)`` - Set the maximum number of new TLS sessions, without resumption, that a given client (see ``connections_mask_v4``, ``connections_mask_v6`` and ``connection_mask_v4_port`` to see how clients can be aggregated) can open, per second, over the last ``connection_rate_interval`` minutes. Clients exceeding this rate will not be able to open new TCP connections for ``ban_duration_for_exceeding_tcp_tls_rate`` seconds. See also ``max_connection_rate_per_client`` and ```max_tls_resumed_session_rate_per_client`
- **max_tls_resumed_session_rate_per_client**: Unsigned integer ``(0)`` - Set the maximum number of resumed TLS sessions that a given client (see ``connections_mask_v4``, ``connections_mask_v6`` and ``connection_mask_v4_port`` to see how clients can be aggregated) can open, per second, over the last ``connection_rate_interval`` minutes. Clients exceeding this rate will not be able to open new TCP connections for ``ban_duration_for_exceeding_tcp_tls_rate`` seconds. See also ``max_connection_rate_per_client`` and ```max_tls_new_session_rate_per_client`
- **max_read_ios_per_query**: Unsigned integer ``(50)`` - Set the maximum number of read events needed to receive a new query on a TCP connection. Usually reading a DNS query over a TCP connection requires two read events, one to read the query size and one to read the query itself. For large queries, on congested networks, a few short reads might occur, increasing the number of read operations needed to read the full query, but if a large number of read events is needed the client might be misbehaving or even actively trying to hurt the server. When this limit is reached, the TCP connection will be terminated and the offending client IP (or range, see ``connections_mask_v4``, ``connections_mask_v6`` and ``connection_mask_v4_port`` to see how clients can be aggregated) will be prevented from opening a new TCP connection for up to ``ban_duration_for_exceeding_max_read_ios_per_query`` seconds
- **ban_duration_for_exceeding_max_read_ios_per_query**: Unsigned integer ``(60)`` - Set for how long, in seconds, a client (or range, see ``connections_mask_v4``, ``connections_mask_v6`` and ``connection_mask_v4_port`` to see how clients can be aggregated) will be prevented from opening a new TCP connection when it has exceeded ``max_read_ios_per_query`` over a TCP connection
- **ban_duration_for_exceeding_tcp_tls_rate**: Unsigned integer ``(10)`` - Set for how long, in seconds, a client (or range, see ``connections_mask_v4``, ``connections_mask_v6`` and ``connection_mask_v4_port`` to see how clients can be aggregated) will be prevented from opening a new TCP connection when it has exceeded ``max_connection_rate_per_client``, ``max_tls_new_session_rate_per_client`` or ``max_tls_resumed_session_rate_per_client``
- **connections_mask_v4**: Unsigned integer ``(32)`` - Mask to apply to IPv4 addresses when enforcing ``max_connection_rate_per_client``, ``max_tls_new_session_rate_per_client`` and ``max_tls_resumed_session_rate_per_client``. In some scenarios it might make sense to apply these settings to a /28 range rather than a single address, for example
- **connections_mask_v6**: Unsigned integer ``(128)`` - Mask to apply to IPv6 addresses when enforcing ``max_connection_rate_per_client``, ``max_tls_new_session_rate_per_client`` and ``max_tls_resumed_session_rate_per_client``. In some scenarios it might make sense to apply these settings to a whole /64 IPv6 range instead of a single address, for example
- **connections_mask_v4_port**: Unsigned integer ``(0)`` - Number of bits of port to consider when enforcing ``max_connection_rate_per_client``, ``max_tls_new_session_rate_per_client`` and ``max_tls_resumed_session_rate_per_client`` over IPv4, for CGNAT deployments. Default is 0 meaning that the port is not taken into account. For example passing ``2`` here, which only makes sense if ``connections_mask_v4`` is set to ``32``, will split a given IPv4 address into four port ranges: ``0-16383``, ``16384-32767``, ``32768-49151`` and ``49152-65535``


.. _yaml-settings-TlsEngineConfiguration:

TlsEngineConfiguration
----------------------

OpenSSL engine settings

- **name**: String - The engine name
- **default_string**: String ``("")`` - The default string to pass to the engine. The exact value depends on the engine but represents the algorithms to register with the engine, as a list of comma-separated keywords. For example 'RSA,EC,DSA,DH,PKEY,PKEY_CRYPTO,PKEY_ASN1'


.. _yaml-settings-TlsTuningConfiguration:

TlsTuningConfiguration
----------------------

- **outgoing_tickets_cache_cleanup_delay**: Unsigned integer ``(60)``
- **outgoing_tickets_cache_validity**: Unsigned integer ``(600)``
- **max_outgoing_tickets_per_backend**: Unsigned integer ``(20)``
- **providers**: Sequence of String ``("")`` - Load OpenSSL providers. Providers can be used to accelerate cryptographic operations, like for example Intel QAT. At the moment up to a maximum of 32 loaded providers are supported, and that support is experimental. Note that this feature is only available when building against OpenSSL version >= 3.0 and with the ``-–enable-tls-provider`` configure flag on. In other cases, ``engines`` should be used instead. Some providers might actually degrade performance unless the TLS asynchronous mode of OpenSSL is enabled. To enable it see the ``async_mode`` parameter of TLS frontends
- **engines**: Sequence of :ref:`TlsEngineConfiguration <yaml-settings-TlsEngineConfiguration>` - Load OpenSSL engines. Engines can be used to accelerate cryptographic operations, like for example Intel QAT. At the moment up to a maximum of 32 loaded engines are supported, and that support is experimental. Some engines might actually degrade performance unless the TLS asynchronous mode of OpenSSL is enabled. To enable it see the ``async_mode`` parameter of TLS frontends


.. _yaml-settings-TuningConfiguration:

TuningConfiguration
-------------------

Tuning settings

- **doh**: :ref:`DohTuningConfiguration <yaml-settings-DohTuningConfiguration>` - DoH-related tuning settings
- **tcp**: :ref:`TcpTuningConfiguration <yaml-settings-TcpTuningConfiguration>` - TCP-related tuning settings
- **tls**: :ref:`TlsTuningConfiguration <yaml-settings-TlsTuningConfiguration>` - TLS-related tuning settings
- **udp**: :ref:`UdpTuningConfiguration <yaml-settings-UdpTuningConfiguration>` - UDP-related tuning settings


.. _yaml-settings-UdpTuningConfiguration:

UdpTuningConfiguration
----------------------

- **messages_per_round**: Unsigned integer ``(1)``
- **send_buffer_size**: Unsigned integer ``(0)``
- **receive_buffer_size**: Unsigned integer ``(0)``
- **max_outstanding_per_backend**: Unsigned integer ``(65535)``
- **timeout**: Unsigned integer ``(2)``
- **randomize_outgoing_sockets_to_backend**: Boolean ``(false)``
- **randomize_ids_to_backend**: Boolean ``(false)``


.. _yaml-settings-WebserverConfiguration:

WebserverConfiguration
----------------------

- **listen_address**: String ``("")`` - IP address and port to listen on
- **password**: String ``("")`` - The password used to access the internal webserver. Since 1.7.0 the password should be hashed and salted via the ``hashPassword()`` command
- **api_key**: String ``("")`` - The API Key (set to an empty string do disable it). Since 1.7.0 the key should be hashed and salted via the ``hashPassword()`` command
- **acl**: Sequence of String ``(127.0.0.1, ::1)`` - List of network masks or IP addresses that are allowed to open a connection to the web server
- **api_requires_authentication**: Boolean ``(true)`` - Whether access to the API (/api endpoints) requires a valid API key
- **stats_require_authentication**: Boolean ``(true)`` - Whether access to the statistics (/metrics and /jsonstat endpoints) requires a valid password or API key
- **dashboard_requires_authentication**: Boolean ``(true)`` - Whether access to the internal dashboard requires a valid password
- **max_concurrent_connections**: Unsigned integer ``(100)`` - The maximum number of concurrent web connections, or 0 which means an unlimited number
- **hash_plaintext_credentials**: Boolean ``(false)`` - Whether passwords and API keys provided in plaintext should be hashed during startup, to prevent the plaintext versions from staying in memory. Doing so increases significantly the cost of verifying credentials
- **custom_headers**: Sequence of :ref:`HttpCustomResponseHeaderConfiguration <yaml-settings-HttpCustomResponseHeaderConfiguration>` - List of custom HTTP headers to set in our responses
- **api_configuration_directory**: String ``("")`` - A valid directory where the configuration files will be written by the API
- **api_read_write**: Boolean ``(false)`` - Allow modifications via the API. Optionally saving these changes to disk. Modifications done via the API will not be written to the configuration by default and will not persist after a reload


.. _yaml-settings-XskConfiguration:

XskConfiguration
----------------

An ``XSK`` / ``AF_XDP`` sockets map

- **name**: String - The name to give to this map
- **interface**: String - The network interface to which the sockets will be associated
- **queues**: Unsigned integer - The number of queues the network interface has (can be retrieved by looking at the ``Combined`` line in the output of ``sudo ethtool -l <interface name>``). It should match the number of threads of the frontend or backend associated to this map
- **frames**: Unsigned integer ``(65536)`` - The number of frames to allocate for this map
- **map_path**: String ``(/sys/fs/bpf/dnsdist/xskmap)``


