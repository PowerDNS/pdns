Built-in webserver
==================

To visually interact with dnsdist, try add :func:`webserver` to the configuration:

.. code-block:: lua

  webserver("127.0.0.1:8083", "supersecretpassword", "supersecretAPIkey")

Now point your browser at http://127.0.0.1:8083 and log in with any username, and that password. Enjoy!

Security of the Webserver
-------------------------

The built-in webserver serves its content from inside the binary, this means it will not and connot read from disk.

By default, our web server sends some security-related headers::

   X-Content-Type-Options: nosniff
   X-Frame-Options: deny
   X-Permitted-Cross-Domain-Policies: none
   X-XSS-Protection: 1; mode=block
   Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'

You can override those headers, or add custom headers by using the last parameter to :func:`webserver`.
For example, to remove the X-Frame-Options header and add a X-Custom one:

.. code-block:: lua

  webserver("127.0.0.1:8080", "supersecret", "apikey", {["X-Frame-Options"]= "", ["X-Custom"]="custom"}

Credentials can be changed over time using the :func:`setWebserverConfig` function.

dnsdist API
-----------

To access the API, the `apikey` must be set in the :func:`webserver` function.
Use the API, this key will need to be sent to dnsdist in the ``X-API-Key`` request header.
An HTTP 401 response is returned when a wrong or no API key is received.
A 404 response is generated is the requested endpoint does not exist.
And a 405 response is returned when the HTTP methos is not allowed.

URL Endpoints
~~~~~~~~~~~~~

.. http:get:: /jsonstat

  Get statistics from dnsdist in JSON format.
  The ``Accept`` request header is ignored.
  This endpoint accepts a ``command`` query for different statistics:

  * ``stats``: Get all :doc:`../statistics` as a JSON dict
  * ``dynblocklist``: Get all current :doc:`dynamic blocks <dynblocks>`, keyed by netmask
  * ``ebpfblocklist``: Idem, but for :doc:`eBPF <../advanced/ebpf>` blocks

  **Example request**:

   .. sourcecode:: http

      GET /jsonstat?command=stats HTTP/1.1
      Host: example.com
      Accept: application/json, text/javascript

  **Example response**:
   .. sourcecode:: http

      HTTP/1.1 200 OK
      Transfer-Encoding: chunked
      Connection: close
      Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'
      Content-Type: application/json
      X-Content-Type-Options: nosniff
      X-Frame-Options: deny
      X-Permitted-Cross-Domain-Policies: none
      X-Xss-Protection: 1; mode=block

      {"acl-drops": 0, "cache-hits": 0, "cache-misses": 0, "cpu-sys-msec": 633, "cpu-user-msec": 499, "downstream-send-errors": 0, "downstream-timeouts": 0, "dyn-block-nmg-size": 1, "dyn-blocked": 3, "empty-queries": 0, "fd-usage": 17, "latency-avg100": 7651.3982737482893, "latency-avg1000": 860.05142763680249, "latency-avg10000": 87.032142373878372, "latency-avg1000000": 0.87146026426551759, "latency-slow": 0, "latency0-1": 0, "latency1-10": 0, "latency10-50": 22, "latency100-1000": 1, "latency50-100": 0, "no-policy": 0, "noncompliant-queries": 0, "noncompliant-responses": 0, "over-capacity-drops": 0, "packetcache-hits": 0, "packetcache-misses": 0, "queries": 26, "rdqueries": 26, "real-memory-usage": 6078464, "responses": 23, "rule-drop": 0, "rule-nxdomain": 0, "rule-refused": 0, "self-answered": 0, "server-policy": "leastOutstanding", "servfail-responses": 0, "too-old-drops": 0, "trunc-failures": 0, "uptime": 412}

  **Example request**:

   .. sourcecode:: http

      GET /jsonstat?command=dynblocklist HTTP/1.1
      Host: example.com
      Accept: application/json, text/javascript

  **Example response**:
   .. sourcecode:: http

      HTTP/1.1 200 OK
      Transfer-Encoding: chunked
      Connection: close
      Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'
      Content-Type: application/json
      X-Content-Type-Options: nosniff
      X-Frame-Options: deny
      X-Permitted-Cross-Domain-Policies: none
      X-Xss-Protection: 1; mode=block

      {"127.0.0.1/32": {"blocks": 3, "reason": "Exceeded query rate", "seconds": 10}}

  :query command: one of ``stats``, ``dynblocklist`` or ``ebpfblocklist``

.. http:get:: /metrics

  Get statistics from dnsdist in `Prometheus <https://prometheus.io>`_ format.

  **Example request**:

   .. sourcecode:: http

      GET /metrics HTTP/1.1

  **Example response**:
   .. sourcecode:: http

      HTTP/1.1 200 OK
      Transfer-Encoding: chunked
      Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'
      Content-Type: text/plain
      X-Content-Type-Options: nosniff
      X-Frame-Options: deny
      X-Permitted-Cross-Domain-Policies: none
      X-Xss-Protection: 1; mode=block

      # HELP dnsdist_responses Number of responses received from backends
      # TYPE dnsdist_responses counter
      dnsdist_responses 0
      # HELP dnsdist_servfail_responses Number of SERVFAIL answers received from backends
      # TYPE dnsdist_servfail_responses counter
      dnsdist_servfail_responses 0
      # HELP dnsdist_queries Number of received queries
      # TYPE dnsdist_queries counter
      dnsdist_queries 0
      # HELP dnsdist_acl_drops Number of packets dropped because of the ACL
      # TYPE dnsdist_acl_drops counter
      dnsdist_acl_drops 0
      # HELP dnsdist_rule_drop Number of queries dropped because of a rule
      # TYPE dnsdist_rule_drop counter
      dnsdist_rule_drop 0
      # HELP dnsdist_rule_nxdomain Number of NXDomain answers returned because of a rule
      # TYPE dnsdist_rule_nxdomain counter
      dnsdist_rule_nxdomain 0
      # HELP dnsdist_rule_refused Number of Refused answers returned because of a rule
      # TYPE dnsdist_rule_refused counter
      dnsdist_rule_refused 0
      # HELP dnsdist_rule_servfail Number of SERVFAIL answers received because of a rule
      # TYPE dnsdist_rule_servfail counter
      dnsdist_rule_servfail 0
      # HELP dnsdist_self_answered Number of self-answered responses
      # TYPE dnsdist_self_answered counter
      dnsdist_self_answered 0
      # HELP dnsdist_downstream_timeouts Number of queries not answered in time by a backend
      # TYPE dnsdist_downstream_timeouts counter
      dnsdist_downstream_timeouts 0
      # HELP dnsdist_downstream_send_errors Number of errors when sending a query to a backend
      # TYPE dnsdist_downstream_send_errors counter
      dnsdist_downstream_send_errors 0
      # HELP dnsdist_trunc_failures Number of errors encountered while truncating an answer
      # TYPE dnsdist_trunc_failures counter
      dnsdist_trunc_failures 0
      # HELP dnsdist_no_policy Number of queries dropped because no server was available
      # TYPE dnsdist_no_policy counter
      dnsdist_no_policy 0
      # HELP dnsdist_latency0_1 Number of queries answered in less than 1ms
      # TYPE dnsdist_latency0_1 counter
      dnsdist_latency0_1 0
      # HELP dnsdist_latency1_10 Number of queries answered in 1-10 ms
      # TYPE dnsdist_latency1_10 counter
      dnsdist_latency1_10 0
      # HELP dnsdist_latency10_50 Number of queries answered in 10-50 ms
      # TYPE dnsdist_latency10_50 counter
      dnsdist_latency10_50 0
      # HELP dnsdist_latency50_100 Number of queries answered in 50-100 ms
      # TYPE dnsdist_latency50_100 counter
      dnsdist_latency50_100 0
      # HELP dnsdist_latency100_1000 Number of queries answered in 100-1000 ms
      # TYPE dnsdist_latency100_1000 counter
      dnsdist_latency100_1000 0
      # HELP dnsdist_latency_slow Number of queries answered in more than 1 second
      # TYPE dnsdist_latency_slow counter
      dnsdist_latency_slow 0
      # HELP dnsdist_latency_avg100 Average response latency in microseconds of the last 100 packets
      # TYPE dnsdist_latency_avg100 gauge
      dnsdist_latency_avg100 0
      # HELP dnsdist_latency_avg1000 Average response latency in microseconds of the last 1000 packets
      # TYPE dnsdist_latency_avg1000 gauge
      dnsdist_latency_avg1000 0
      # HELP dnsdist_latency_avg10000 Average response latency in microseconds of the last 10000 packets
      # TYPE dnsdist_latency_avg10000 gauge
      dnsdist_latency_avg10000 0
      # HELP dnsdist_latency_avg1000000 Average response latency in microseconds of the last 1000000 packets
      # TYPE dnsdist_latency_avg1000000 gauge
      dnsdist_latency_avg1000000 0
      # HELP dnsdist_uptime Uptime of the dnsdist process in seconds
      # TYPE dnsdist_uptime gauge
      dnsdist_uptime 39
      # HELP dnsdist_real_memory_usage Current memory usage in bytes
      # TYPE dnsdist_real_memory_usage gauge
      dnsdist_real_memory_usage 10276864
      # HELP dnsdist_noncompliant_queries Number of queries dropped as non-compliant
      # TYPE dnsdist_noncompliant_queries counter
      dnsdist_noncompliant_queries 0
      # HELP dnsdist_noncompliant_responses Number of answers from a backend dropped as non-compliant
      # TYPE dnsdist_noncompliant_responses counter
      dnsdist_noncompliant_responses 0
      # HELP dnsdist_rdqueries Number of received queries with the recursion desired bit set
      # TYPE dnsdist_rdqueries counter
      dnsdist_rdqueries 0
      # HELP dnsdist_empty_queries Number of empty queries received from clients
      # TYPE dnsdist_empty_queries counter
      dnsdist_empty_queries 0
      # HELP dnsdist_cache_hits Number of times an answer was retrieved from cache
      # TYPE dnsdist_cache_hits counter
      dnsdist_cache_hits 0
      # HELP dnsdist_cache_misses Number of times an answer not found in the cache
      # TYPE dnsdist_cache_misses counter
      dnsdist_cache_misses 0
      # HELP dnsdist_cpu_user_msec Milliseconds spent by dnsdist in the user state
      # TYPE dnsdist_cpu_user_msec counter
      dnsdist_cpu_user_msec 28
      # HELP dnsdist_cpu_sys_msec Milliseconds spent by dnsdist in the system state
      # TYPE dnsdist_cpu_sys_msec counter
      dnsdist_cpu_sys_msec 32
      # HELP dnsdist_fd_usage Number of currently used file descriptors
      # TYPE dnsdist_fd_usage gauge
      dnsdist_fd_usage 17
      # HELP dnsdist_dyn_blocked Number of queries dropped because of a dynamic block
      # TYPE dnsdist_dyn_blocked counter
      dnsdist_dyn_blocked 0
      # HELP dnsdist_dyn_block_nmg_size Number of dynamic blocks entries
      # TYPE dnsdist_dyn_block_nmg_size gauge
      dnsdist_dyn_block_nmg_size 0
      dnsdist_server_queries{server="1_1_1_1",address="1.1.1.1:53"} 0
      dnsdist_server_drops{server="1_1_1_1",address="1.1.1.1:53"} 0
      dnsdist_server_latency{server="1_1_1_1",address="1.1.1.1:53"} 0
      dnsdist_server_senderrors{server="1_1_1_1",address="1.1.1.1:53"} 0
      dnsdist_server_outstanding{server="1_1_1_1",address="1.1.1.1:53"} 0
      dnsdist_server_order{server="1_1_1_1",address="1.1.1.1:53"} 1
      dnsdist_server_weight{server="1_1_1_1",address="1.1.1.1:53"} 1
      dnsdist_server_queries{server="1_0_0_1",address="1.0.0.1:53"} 0
      dnsdist_server_drops{server="1_0_0_1",address="1.0.0.1:53"} 0
      dnsdist_server_latency{server="1_0_0_1",address="1.0.0.1:53"} 0
      dnsdist_server_senderrors{server="1_0_0_1",address="1.0.0.1:53"} 0
      dnsdist_server_outstanding{server="1_0_0_1",address="1.0.0.1:53"} 0
      dnsdist_server_order{server="1_0_0_1",address="1.0.0.1:53"} 1
      dnsdist_server_weight{server="1_0_0_1",address="1.0.0.1:53"} 2
      dnsdist_frontend_queries{frontend="127.0.0.1:1153",proto="udp"} 0
      dnsdist_frontend_queries{frontend="127.0.0.1:1153",proto="tcp"} 0
      dnsdist_pool_servers{pool="_default_"} 2
      dnsdist_pool_cache_size{pool="_default_"} 200000
      dnsdist_pool_cache_entries{pool="_default_"} 0
      dnsdist_pool_cache_hits{pool="_default_"} 0
      dnsdist_pool_cache_misses{pool="_default_"} 0
      dnsdist_pool_cache_deferred_inserts{pool="_default_"} 0
      dnsdist_pool_cache_deferred_lookups{pool="_default_"} 0
      dnsdist_pool_cache_lookup_collisions{pool="_default_"} 0
      dnsdist_pool_cache_insert_collisions{pool="_default_"} 0
      dnsdist_pool_cache_ttl_too_shorts{pool="_default_"} 0

  **Example prometheus configuration**:

   This is just the scrape job description, for details see the prometheus documentation.

   .. sourcecode:: yaml

      job_name: dnsdist
      scrape_interval: 10s
      scrape_timeout: 2s
      metrics_path: /metrics
      basic_auth:
        username: dontcare
        password: yoursecret

.. http:get:: /api/v1/servers/localhost

  Get a quick overview of several parameters.

  :>json string acl: A string of comma-separated netmasks currently allowed by the :ref:`ACL <ACL>`.
  :>json list cache-hit-response-rules: A list of :json:object:`ResponseRule` objects applied on cache hits
  :>json list self-answered-response-rules: A list of :json:object:`ResponseRule` objects applied on self-answered queries
  :>json string daemon_type: The type of daemon, always "dnsdist"
  :>json list frontends: A list of :json:object:`Frontend` objects
  :>json list pools: A list of :json:object:`Pool` objects
  :>json list response-rules: A list of :json:object:`ResponseRule` objects
  :>json list rules: A list of :json:object:`Rule` objects
  :>json list servers: A list of :json:object:`Server` objects
  :>json string version: The running version of dnsdist

.. http:get:: /api/v1/servers/localhost/statistics

  Returns a list of all statistics as :json:object:`StatisticItem`.

.. http:get:: /api/v1/servers/localhost/config

  Returns a list of :json:object:`ConfigSetting` objects.

.. http:get:: /api/v1/servers/localhost/config/allow-from

  Gets you the ``allow-from`` :json:object:`ConfigSetting`, who's value is a list of strings of all the netmasks in the :ref:`ACL <ACL>`.

  **Example request**:

   .. sourcecode:: http

      GET /api/v1/servers/localhost/config/allow-from HTTP/1.1
      X-API-Key: supersecretAPIkey

  **Example response**:
   .. sourcecode:: http

      HTTP/1.1 200 OK
      Connection: close
      Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'
      Content-Type: application/json
      Transfer-Encoding: chunked
      X-Content-Type-Options: nosniff
      X-Frame-Options: deny
      X-Permitted-Cross-Domain-Policies: none
      X-Xss-Protection: 1; mode=block

      {
          "name": "allow-from",
          "type": "ConfigSetting",
          "value": [
              "fc00::/7",
              "169.254.0.0/16",
              "100.64.0.0/10",
              "fe80::/10",
              "10.0.0.0/8",
              "127.0.0.0/8",
              "::1/128",
              "172.16.0.0/12",
              "192.168.0.0/16"
          ]
      }

.. http:put:: /api/v1/servers/localhost/config/allow-from

  Allows you to update the ``allow-from`` :ref:`ACL <ACL>` with a list of netmasks.

  Make sure you made the API writable using :func:`setAPIWritable`.

  **Example request**:

   .. sourcecode:: http

      PUT /api/v1/servers/localhost/config/allow-from HTTP/1.1
      Content-Length: 37
      Content-Type: application/json
      X-API-Key: supersecretAPIkey

      {
          "value": [
              "127.0.0.0/8",
              "::1/128"
          ]
      }

  **Example response**:
   .. sourcecode:: http

      HTTP/1.1 200 OK
      Connection: close
      Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'
      Content-Type: application/json
      Transfer-Encoding: chunked
      X-Content-Type-Options: nosniff
      X-Frame-Options: deny
      X-Permitted-Cross-Domain-Policies: none
      X-Xss-Protection: 1; mode=block

      {
          "name": "allow-from",
          "type": "ConfigSetting",
          "value": [
              "127.0.0.0/8",
              "::1/128"
          ]
      }

JSON Objects
~~~~~~~~~~~~

.. json:object:: ConfigSetting

  An object representing a global configuration element.
  The following configuration are returned:

  - ``acl`` The currently configured :ref:`ACLs <ACL>`
  - ``control-socket`` The currently configured :ref:`console address <Console>`
  - ``ecs-override``
  - ``ecs-source-prefix-v4`` The currently configured :func:`setECSSourcePrefixV4`
  - ``ecs-source-prefix-v6`` The currently configured :func:`setECSSourcePrefixV6`
  - ``fixup-case``
  - ``max-outstanding``
  - ``server-policy`` The currently set :doc:`serverselection`
  - ``stale-cache-entries-ttl``
  - ``tcp-recv-timeout``
  - ``tcp-send-timeout``
  - ``truncate-tc``
  - ``verbose``
  - ``verbose-health-checks`` The currently configured :func:`setVerboseHealthChecks`

  :property string name: The name of the setting
  :property string type: "ConfigSetting"
  :property string value: The value for this setting

.. json:object:: Frontend

  A description of a bind dnsdist is listening on.

  :property string address: IP and port that is listened on
  :property integer id: Internal identifier
  :property integer queries: The number of received queries on this bind
  :property boolean udp: true if this is a UDP bind
  :property boolean tcp: true if this is a TCP bind

.. json:object:: Pool

  A description of a pool of backend servers.

  :property integer id: Internal identifier
  :property integer cacheDeferredInserts: The number of times an entry could not be inserted in the associated cache, if any, because of a lock
  :property integer cacheDeferredLookups: The number of times an entry could not be looked up from the associated cache, if any, because of a lock
  :property integer cacheEntries: The current number of entries in the associated cache, if any
  :property integer cacheHits: The number of cache hits for the associated cache, if any
  :property integer cacheLookupCollisions: The number of times an entry retrieved from the cache based on the query hash did not match the actual query
  :property integer cacheInsertCollisions: The number of times an entry could not be inserted into the cache because a different entry with the same hash already existed
  :property integer cacheMisses: The number of cache misses for the associated cache, if any
  :property integer cacheSize: The maximum number of entries in the associated cache, if any
  :property integer cacheTTLTooShorts: The number of times an entry could not be inserted into the cache because its TTL was set below the minimum threshold
  :property string name: Name of the pool
  :property integer serversCount: Number of backends in this pool

.. json:object:: Rule

  This represents a policy that is applied to queries

  :property string action: The action taken when the rule matches (e.g. "to pool abuse")
  :property dict action-stats: A list of statistics whose content varies depending on the kind of rule
  :property integer id: The position of this rule
  :property integer matches: How many times this rule was hit
  :property string rule: The matchers for the packet (e.g. "qname==bad-domain1.example., bad-domain2.example.")
  :property string uuid: The UUID of this rule

.. json:object:: ResponseRule

  This represents a policy that is applied to responses

  :property string action: The action taken when the rule matches (e.g. "drop")
  :property integer id: The identifier (or order) of this rule
  :property integer matches: How many times this rule was hit
  :property string rule: The matchers for the packet (e.g. "qname==bad-domain1.example., bad-domain2.example.")

.. json:object:: Server

  This object represents a backend server.

  .. versionchanged:: 1.3.1
    The ``dropRate`` property was added

  :property string address: The remote IP and port
  :property integer id: Internal identifier
  :property integer latency: The current latency of this backend server
  :property string name: The name of this server
  :property integer order: Order number
  :property integer outstanding: Number of currently outstanding queries
  :property [string] pools: The pools this server belongs to
  :property integer qps: The current number of queries per second to this server
  :property integer qpsLimit: The configured maximum number of queries per second
  :property integer queries: Total number of queries sent to this backend
  :property integer reuseds: Number of queries for which a response was not received in time
  :property integer sendErrors: Number of network errors while sending a query to this server
  :property string state: The state of the server (e.g. "DOWN" or "up")
  :property integer weight: The weight assigned to this server
  :property float dropRate: The amount of packets dropped per second by this server

.. json:object:: StatisticItem

  This represents a statistics element.

  :property string name: The name of this statistic. See :doc:`../statistics`
  :property string type: "StatisticItem"
  :property integer value: The value for this item
