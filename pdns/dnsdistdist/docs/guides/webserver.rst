Built-in webserver
==================

To visually interact with dnsdist, try adding :func:`webserver` and :func:`setWebserverConfig` directives to the configuration:

.. code-block:: lua

  webserver("127.0.0.1:8083")
  setWebserverConfig({password="supersecretpassword", apiKey="supersecretAPIkey"})

Now point your browser at http://127.0.0.1:8083 and log in with any username, and that password. Enjoy!

Since 1.5.0, only connections from 127.0.0.1 and ::1 are allowed by default. To allow connections from 192.0.2.0/24 but not from 192.0.2.1, instead:

.. code-block:: lua

  setWebserverConfig({password="supersecretpassword", apiKey="supersecretAPIkey", acl="192.0.2.0/24, !192.0.2.1"})

The equivalent ``yaml`` configuration would be:

.. code-block:: yaml

  webserver:
    listen_address: "127.0.0.1:8083"
    password: "supersecretpassword"
    api_key: "supersecretAPIkey"
    acl:
      - "192.0.2.0/24"
      - "!192.0.2.1"


Security of the Webserver
-------------------------

The built-in webserver serves its content from inside the binary, this means it will not and cannot read from disk.

By default, our web server sends some security-related headers::

   X-Content-Type-Options: nosniff
   X-Frame-Options: deny
   X-Permitted-Cross-Domain-Policies: none
   X-XSS-Protection: 1; mode=block
   Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'

You can override those headers, or add custom headers by using the last parameter to :func:`setWebserverConfig`.
For example, to remove the X-Frame-Options header and add a X-Custom one:

.. code-block:: lua

  setWebserverConfig({password="supersecretpassword", apiKey="supersecretAPIkey", customHeaders={["X-Frame-Options"]= "", ["X-Custom"]="custom"} })

Credentials can be changed at run time using the :func:`setWebserverConfig` function.

dnsdist API
-----------

To access the API, the `apikey` must be set in the :func:`setWebserverConfig` function.
Use the API, this key will need to be sent to dnsdist in the ``X-API-Key`` request header.
An HTTP 401 response is returned when a wrong or no API key is received.
A 404 response is generated is the requested endpoint does not exist.
And a 405 response is returned when the HTTP method is not allowed.

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
      # HELP dnsdist_frontend_nxdomain Number of NXDomain answers sent to clients
      # TYPE dnsdist_frontend_nxdomain counter
      dnsdist_frontend_nxdomain 0
      # HELP dnsdist_frontend_servfail Number of SERVFAIL answers sent to clients
      # TYPE dnsdist_frontend_servfail counter
      dnsdist_frontend_servfail 0
      # HELP dnsdist_frontend_noerror Number of NoError answers sent to clients
      # TYPE dnsdist_frontend_noerror counter
      dnsdist_frontend_noerror 0
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
      # HELP dnsdist_rule_truncated Number of truncated answers returned because of a rule
      # TYPE dnsdist_rule_truncated counter
      dnsdist_rule_truncated 0
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
      # HELP dnsdist_latency_tcp_avg100 Average response latency, in microseconds, of the last 100 packets received over TCP
      # TYPE dnsdist_latency_tcp_avg100 gauge
      dnsdist_latency_tcp_avg100 0
      # HELP dnsdist_latency_tcp_avg1000 Average response latency, in microseconds, of the last 1000 packets received over TCP
      # TYPE dnsdist_latency_tcp_avg1000 gauge
      dnsdist_latency_tcp_avg1000 0
      # HELP dnsdist_latency_tcp_avg10000 Average response latency, in microseconds, of the last 10000 packets received over TCP
      # TYPE dnsdist_latency_tcp_avg10000 gauge
      dnsdist_latency_tcp_avg10000 0
      # HELP dnsdist_latency_tcp_avg1000000 Average response latency, in microseconds, of the last 1000000 packets received over TCP
      # TYPE dnsdist_latency_tcp_avg1000000 gauge
      dnsdist_latency_tcp_avg1000000 0
      # HELP dnsdist_latency_dot_avg100 Average response latency, in microseconds, of the last 100 packets received over DoT
      # TYPE dnsdist_latency_dot_avg100 gauge
      dnsdist_latency_dot_avg100 0
      # HELP dnsdist_latency_dot_avg1000 Average response latency, in microseconds, of the last 1000 packets received over DoT
      # TYPE dnsdist_latency_dot_avg1000 gauge
      dnsdist_latency_dot_avg1000 0
      # HELP dnsdist_latency_dot_avg10000 Average response latency, in microseconds, of the last 10000 packets received over DoT
      # TYPE dnsdist_latency_dot_avg10000 gauge
      dnsdist_latency_dot_avg10000 0
      # HELP dnsdist_latency_dot_avg1000000 Average response latency, in microseconds, of the last 1000000 packets received over DoT
      # TYPE dnsdist_latency_dot_avg1000000 gauge
      dnsdist_latency_dot_avg1000000 0
      # HELP dnsdist_latency_doh_avg100 Average response latency, in microseconds, of the last 100 packets received over DoH
      # TYPE dnsdist_latency_doh_avg100 gauge
      dnsdist_latency_doh_avg100 0
      # HELP dnsdist_latency_doh_avg1000 Average response latency, in microseconds, of the last 1000 packets received over DoH
      # TYPE dnsdist_latency_doh_avg1000 gauge
      dnsdist_latency_doh_avg1000 0
      # HELP dnsdist_latency_doh_avg10000 Average response latency, in microseconds, of the last 10000 packets received over DoH
      # TYPE dnsdist_latency_doh_avg10000 gauge
      dnsdist_latency_doh_avg10000 0
      # HELP dnsdist_latency_doh_avg1000000 Average response latency, in microseconds, of the last 1000000 packets received over DoH
      # TYPE dnsdist_latency_doh_avg1000000 gauge
      dnsdist_latency_doh_avg1000000 0
      # HELP dnsdist_uptime Uptime of the dnsdist process in seconds
      # TYPE dnsdist_uptime gauge
      dnsdist_uptime 19
      # HELP dnsdist_real_memory_usage Current memory usage in bytes
      # TYPE dnsdist_real_memory_usage gauge
      dnsdist_real_memory_usage 52269056
      # HELP dnsdist_udp_in_errors From /proc/net/snmp InErrors
      # TYPE dnsdist_udp_in_errors counter
      dnsdist_udp_in_errors 0
      # HELP dnsdist_udp_noport_errors From /proc/net/snmp NoPorts
      # TYPE dnsdist_udp_noport_errors counter
      dnsdist_udp_noport_errors 86
      # HELP dnsdist_udp_recvbuf_errors From /proc/net/snmp RcvbufErrors
      # TYPE dnsdist_udp_recvbuf_errors counter
      dnsdist_udp_recvbuf_errors 0
      # HELP dnsdist_udp_sndbuf_errors From /proc/net/snmp SndbufErrors
      # TYPE dnsdist_udp_sndbuf_errors counter
      dnsdist_udp_sndbuf_errors 0
      # HELP dnsdist_udp_in_csum_errors From /proc/net/snmp InCsumErrors
      # TYPE dnsdist_udp_in_csum_errors counter
      dnsdist_udp_in_csum_errors 0
      # HELP dnsdist_udp6_in_errors From /proc/net/snmp6 Udp6InErrors
      # TYPE dnsdist_udp6_in_errors counter
      dnsdist_udp6_in_errors 0
      # HELP dnsdist_udp6_recvbuf_errors From /proc/net/snmp6 Udp6RcvbufErrors
      # TYPE dnsdist_udp6_recvbuf_errors counter
      dnsdist_udp6_recvbuf_errors 0
      # HELP dnsdist_udp6_sndbuf_errors From /proc/net/snmp6 Udp6SndbufErrors
      # TYPE dnsdist_udp6_sndbuf_errors counter
      dnsdist_udp6_sndbuf_errors 0
      # HELP dnsdist_udp6_noport_errors From /proc/net/snmp6 Udp6NoPorts
      # TYPE dnsdist_udp6_noport_errors counter
      dnsdist_udp6_noport_errors 195
      # HELP dnsdist_udp6_in_csum_errors From /proc/net/snmp6 Udp6InCsumErrors
      # TYPE dnsdist_udp6_in_csum_errors counter
      dnsdist_udp6_in_csum_errors 0
      # HELP dnsdist_tcp_listen_overflows From /proc/net/netstat ListenOverflows
      # TYPE dnsdist_tcp_listen_overflows counter
      dnsdist_tcp_listen_overflows 0
      # HELP dnsdist_noncompliant_queries Number of queries dropped as non-compliant
      # TYPE dnsdist_noncompliant_queries counter
      dnsdist_noncompliant_queries 0
      # HELP dnsdist_noncompliant_responses Number of answers from a backend dropped as non-compliant
      # TYPE dnsdist_noncompliant_responses counter
      dnsdist_noncompliant_responses 0
      # HELP dnsdist_proxy_protocol_invalid Number of queries dropped because of an invalid Proxy Protocol header
      # TYPE dnsdist_proxy_protocol_invalid counter
      dnsdist_proxy_protocol_invalid 0
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
      # HELP dnsdist_cpu_iowait Time waiting for I/O to complete by the whole system, in units of USER_HZ
      # TYPE dnsdist_cpu_iowait counter
      dnsdist_cpu_iowait 0
      # HELP dnsdist_cpu_steal Stolen time, which is the time spent by the whole system in other operating systems when running in a virtualized environment, in units of USER_HZ
      # TYPE dnsdist_cpu_steal counter
      dnsdist_cpu_steal 0
      # HELP dnsdist_cpu_sys_msec Milliseconds spent by dnsdist in the system state
      # TYPE dnsdist_cpu_sys_msec counter
      dnsdist_cpu_sys_msec 38
      # HELP dnsdist_cpu_user_msec Milliseconds spent by dnsdist in the user state
      # TYPE dnsdist_cpu_user_msec counter
      dnsdist_cpu_user_msec 38
      # HELP dnsdist_fd_usage Number of currently used file descriptors
      # TYPE dnsdist_fd_usage gauge
      dnsdist_fd_usage 32
      # HELP dnsdist_dyn_blocked Number of queries dropped because of a dynamic block
      # TYPE dnsdist_dyn_blocked counter
      dnsdist_dyn_blocked 0
      # HELP dnsdist_dyn_block_nmg_size Number of dynamic blocks entries
      # TYPE dnsdist_dyn_block_nmg_size gauge
      dnsdist_dyn_block_nmg_size 0
      # HELP dnsdist_security_status Security status of this software. 0=unknown, 1=OK, 2=upgrade recommended, 3=upgrade mandatory
      # TYPE dnsdist_security_status gauge
      dnsdist_security_status 0
      # HELP dnsdist_doh_query_pipe_full Number of DoH queries dropped because the internal pipe used to distribute queries was full
      # TYPE dnsdist_doh_query_pipe_full counter
      dnsdist_doh_query_pipe_full 0
      # HELP dnsdist_doh_response_pipe_full Number of DoH responses dropped because the internal pipe used to distribute responses was full
      # TYPE dnsdist_doh_response_pipe_full counter
      dnsdist_doh_response_pipe_full 0
      # HELP dnsdist_outgoing_doh_query_pipe_full Number of outgoing DoH queries dropped because the internal pipe used to distribute queries was full
      # TYPE dnsdist_outgoing_doh_query_pipe_full counter
      dnsdist_outgoing_doh_query_pipe_full 0
      # HELP dnsdist_tcp_query_pipe_full Number of TCP queries dropped because the internal pipe used to distribute queries was full
      # TYPE dnsdist_tcp_query_pipe_full counter
      dnsdist_tcp_query_pipe_full 0
      # HELP dnsdist_tcp_cross_protocol_query_pipe_full Number of TCP cross-protocol queries dropped because the internal pipe used to distribute queries was full
      # TYPE dnsdist_tcp_cross_protocol_query_pipe_full counter
      dnsdist_tcp_cross_protocol_query_pipe_full 0
      # HELP dnsdist_tcp_cross_protocol_response_pipe_full Number of TCP cross-protocol responses dropped because the internal pipe used to distribute queries was full
      # TYPE dnsdist_tcp_cross_protocol_response_pipe_full counter
      dnsdist_tcp_cross_protocol_response_pipe_full 0
      # HELP dnsdist_latency Histogram of responses by latency (in milliseconds)
      # TYPE dnsdist_latency histogram
      dnsdist_latency_bucket{le="1"} 0
      dnsdist_latency_bucket{le="10"} 0
      dnsdist_latency_bucket{le="50"} 0
      dnsdist_latency_bucket{le="100"} 0
      dnsdist_latency_bucket{le="1000"} 0
      dnsdist_latency_bucket{le="+Inf"} 0
      dnsdist_latency_sum 0
      dnsdist_latency_count 0
      # HELP dnsdist_server_status Whether this backend is up (1) or down (0)
      # TYPE dnsdist_server_status gauge
      # HELP dnsdist_server_queries Amount of queries relayed to server
      # TYPE dnsdist_server_queries counter
      # HELP dnsdist_server_responses Amount of responses received from this server
      # TYPE dnsdist_server_responses counter
      # HELP dnsdist_server_noncompliantresponses Amount of non-compliant responses received from this server
      # TYPE dnsdist_server_noncompliantresponses counter
      # HELP dnsdist_server_drops Amount of queries not answered by server
      # TYPE dnsdist_server_drops counter
      # HELP dnsdist_server_latency Server's latency when answering questions in milliseconds
      # TYPE dnsdist_server_latency gauge
      # HELP dnsdist_server_senderrors Total number of OS send errors while relaying queries
      # TYPE dnsdist_server_senderrors counter
      # HELP dnsdist_server_outstanding Current number of queries that are waiting for a backend response
      # TYPE dnsdist_server_outstanding gauge
      # HELP dnsdist_server_order The order in which this server is picked
      # TYPE dnsdist_server_order gauge
      # HELP dnsdist_server_weight The weight within the order in which this server is picked
      # TYPE dnsdist_server_weight gauge
      # HELP dnsdist_server_tcpdiedsendingquery The number of TCP I/O errors while sending the query
      # TYPE dnsdist_server_tcpdiedsendingquery counter
      # HELP dnsdist_server_tcpdiedreadingresponse The number of TCP I/O errors while reading the response
      # TYPE dnsdist_server_tcpdiedreadingresponse counter
      # HELP dnsdist_server_tcpgaveup The number of TCP connections failing after too many attempts
      # TYPE dnsdist_server_tcpgaveup counter
      # HELP dnsdist_server_tcpconnecttimeouts The number of TCP connect timeouts
      # TYPE dnsdist_server_tcpconnecttimeouts counter
      # HELP dnsdist_server_tcpreadtimeouts The number of TCP read timeouts
      # TYPE dnsdist_server_tcpreadtimeouts counter
      # HELP dnsdist_server_tcpwritetimeouts The number of TCP write timeouts
      # TYPE dnsdist_server_tcpwritetimeouts counter
      # HELP dnsdist_server_tcpcurrentconnections The number of current TCP connections
      # TYPE dnsdist_server_tcpcurrentconnections gauge
      # HELP dnsdist_server_tcpmaxconcurrentconnections The maximum number of concurrent TCP connections
      # TYPE dnsdist_server_tcpmaxconcurrentconnections counter
      # HELP dnsdist_server_tcptoomanyconcurrentconnections Number of times we had to enforce the maximum number of concurrent TCP connections
      # TYPE dnsdist_server_tcptoomanyconcurrentconnections counter
      # HELP dnsdist_server_tcpnewconnections The number of established TCP connections in total
      # TYPE dnsdist_server_tcpnewconnections counter
      # HELP dnsdist_server_tcpreusedconnections The number of times a TCP connection has been reused
      # TYPE dnsdist_server_tcpreusedconnections counter
      # HELP dnsdist_server_tcpavgqueriesperconn The average number of queries per TCP connection
      # TYPE dnsdist_server_tcpavgqueriesperconn gauge
      # HELP dnsdist_server_tcpavgconnduration The average duration of a TCP connection (ms)
      # TYPE dnsdist_server_tcpavgconnduration gauge
      # HELP dnsdist_server_tlsresumptions The number of times a TLS session has been resumed
      # TYPE dnsdist_server_tlsresumptions counter
      # HELP dnsdist_server_tcplatency Server's latency when answering TCP questions in milliseconds
      # TYPE dnsdist_server_tcplatency gauge
      dnsdist_server_status{server="9_9_9_9:443",address="9.9.9.9:443"} 1
      dnsdist_server_queries{server="9_9_9_9:443",address="9.9.9.9:443"} 0
      dnsdist_server_responses{server="9_9_9_9:443",address="9.9.9.9:443"} 0
      dnsdist_server_noncompliantresponses{server="9_9_9_9:443",address="9.9.9.9:443"} 0
      dnsdist_server_drops{server="9_9_9_9:443",address="9.9.9.9:443"} 0
      dnsdist_server_latency{server="9_9_9_9:443",address="9.9.9.9:443"} 0
      dnsdist_server_tcplatency{server="9_9_9_9:443",address="9.9.9.9:443"} 0
      dnsdist_server_senderrors{server="9_9_9_9:443",address="9.9.9.9:443"} 0
      dnsdist_server_outstanding{server="9_9_9_9:443",address="9.9.9.9:443"} 0
      dnsdist_server_order{server="9_9_9_9:443",address="9.9.9.9:443"} 1
      dnsdist_server_weight{server="9_9_9_9:443",address="9.9.9.9:443"} 1
      dnsdist_server_tcpdiedsendingquery{server="9_9_9_9:443",address="9.9.9.9:443"} 0
      dnsdist_server_tcpdiedreadingresponse{server="9_9_9_9:443",address="9.9.9.9:443"} 0
      dnsdist_server_tcpgaveup{server="9_9_9_9:443",address="9.9.9.9:443"} 0
      dnsdist_server_tcpreadtimeouts{server="9_9_9_9:443",address="9.9.9.9:443"} 0
      dnsdist_server_tcpwritetimeouts{server="9_9_9_9:443",address="9.9.9.9:443"} 0
      dnsdist_server_tcpconnecttimeouts{server="9_9_9_9:443",address="9.9.9.9:443"} 0
      dnsdist_server_tcpcurrentconnections{server="9_9_9_9:443",address="9.9.9.9:443"} 0
      dnsdist_server_tcpmaxconcurrentconnections{server="9_9_9_9:443",address="9.9.9.9:443"} 1
      dnsdist_server_tcptoomanyconcurrentconnections{server="9_9_9_9:443",address="9.9.9.9:443"} 0
      dnsdist_server_tcpnewconnections{server="9_9_9_9:443",address="9.9.9.9:443"} 19
      dnsdist_server_tcpreusedconnections{server="9_9_9_9:443",address="9.9.9.9:443"} 0
      dnsdist_server_tcpavgqueriesperconn{server="9_9_9_9:443",address="9.9.9.9:443"} 0.173831
      dnsdist_server_tcpavgconnduration{server="9_9_9_9:443",address="9.9.9.9:443"} 3.92628
      dnsdist_server_tlsresumptions{server="9_9_9_9:443",address="9.9.9.9:443"} 18
      # HELP dnsdist_frontend_queries Amount of queries received by this frontend
      # TYPE dnsdist_frontend_queries counter
      # HELP dnsdist_frontend_noncompliantqueries Amount of non-compliant queries received by this frontend
      # TYPE dnsdist_frontend_noncompliantqueries counter
      # HELP dnsdist_frontend_responses Amount of responses sent by this frontend
      # TYPE dnsdist_frontend_responses counter
      # HELP dnsdist_frontend_tcpdiedreadingquery Amount of TCP connections terminated while reading the query from the client
      # TYPE dnsdist_frontend_tcpdiedreadingquery counter
      # HELP dnsdist_frontend_tcpdiedsendingresponse Amount of TCP connections terminated while sending a response to the client
      # TYPE dnsdist_frontend_tcpdiedsendingresponse counter
      # HELP dnsdist_frontend_tcpgaveup Amount of TCP connections terminated after too many attempts to get a connection to the backend
      # TYPE dnsdist_frontend_tcpgaveup counter
      # HELP dnsdist_frontend_tcpclienttimeouts Amount of TCP connections terminated by a timeout while reading from the client
      # TYPE dnsdist_frontend_tcpclienttimeouts counter
      # HELP dnsdist_frontend_tcpdownstreamtimeouts Amount of TCP connections terminated by a timeout while reading from the backend
      # TYPE dnsdist_frontend_tcpdownstreamtimeouts counter
      # HELP dnsdist_frontend_tcpcurrentconnections Amount of current incoming TCP connections from clients
      # TYPE dnsdist_frontend_tcpcurrentconnections gauge
      # HELP dnsdist_frontend_tcpmaxconcurrentconnections Maximum number of concurrent incoming TCP connections from clients
      # TYPE dnsdist_frontend_tcpmaxconcurrentconnections counter
      # HELP dnsdist_frontend_tcpavgqueriesperconnection The average number of queries per TCP connection
      # TYPE dnsdist_frontend_tcpavgqueriesperconnection gauge
      # HELP dnsdist_frontend_tcpavgconnectionduration The average duration of a TCP connection (ms)
      # TYPE dnsdist_frontend_tcpavgconnectionduration gauge
      # HELP dnsdist_frontend_tlsqueries Number of queries received by dnsdist over TLS, by TLS version
      # TYPE dnsdist_frontend_tlsqueries counter
      # HELP dnsdist_frontend_tlsnewsessions Amount of new TLS sessions negotiated
      # TYPE dnsdist_frontend_tlsnewsessions counter
      # HELP dnsdist_frontend_tlsresumptions Amount of TLS sessions resumed
      # TYPE dnsdist_frontend_tlsresumptions counter
      # HELP dnsdist_frontend_tlsunknownticketkeys Amount of attempts to resume TLS session from an unknown key (possibly expired)
      # TYPE dnsdist_frontend_tlsunknownticketkeys counter
      # HELP dnsdist_frontend_tlsinactiveticketkeys Amount of TLS sessions resumed from an inactive key
      # TYPE dnsdist_frontend_tlsinactiveticketkeys counter
      # HELP dnsdist_frontend_tlshandshakefailures Amount of TLS handshake failures
      # TYPE dnsdist_frontend_tlshandshakefailures counter
      dnsdist_frontend_queries{frontend="127.0.0.1:853",proto="TCP (DNS over TLS)",thread="0"} 0
      dnsdist_frontend_noncompliantqueries{frontend="127.0.0.1:853",proto="TCP (DNS over TLS)",thread="0"} 0
      dnsdist_frontend_responses{frontend="127.0.0.1:853",proto="TCP (DNS over TLS)",thread="0"} 0
      dnsdist_frontend_tcpdiedreadingquery{frontend="127.0.0.1:853",proto="TCP (DNS over TLS)",thread="0"} 0
      dnsdist_frontend_tcpdiedsendingresponse{frontend="127.0.0.1:853",proto="TCP (DNS over TLS)",thread="0"} 0
      dnsdist_frontend_tcpgaveup{frontend="127.0.0.1:853",proto="TCP (DNS over TLS)",thread="0"} 0
      dnsdist_frontend_tcpclienttimeouts{frontend="127.0.0.1:853",proto="TCP (DNS over TLS)",thread="0"} 0
      dnsdist_frontend_tcpdownstreamtimeouts{frontend="127.0.0.1:853",proto="TCP (DNS over TLS)",thread="0"} 0
      dnsdist_frontend_tcpcurrentconnections{frontend="127.0.0.1:853",proto="TCP (DNS over TLS)",thread="0"} 0
      dnsdist_frontend_tcpmaxconcurrentconnections{frontend="127.0.0.1:853",proto="TCP (DNS over TLS)",thread="0"} 0
      dnsdist_frontend_tcpavgqueriesperconnection{frontend="127.0.0.1:853",proto="TCP (DNS over TLS)",thread="0"} 0
      dnsdist_frontend_tcpavgconnectionduration{frontend="127.0.0.1:853",proto="TCP (DNS over TLS)",thread="0"} 0
      dnsdist_frontend_tlsnewsessions{frontend="127.0.0.1:853",proto="TCP (DNS over TLS)",thread="0"} 0
      dnsdist_frontend_tlsresumptions{frontend="127.0.0.1:853",proto="TCP (DNS over TLS)",thread="0"} 0
      dnsdist_frontend_tlsunknownticketkeys{frontend="127.0.0.1:853",proto="TCP (DNS over TLS)",thread="0"} 0
      dnsdist_frontend_tlsinactiveticketkeys{frontend="127.0.0.1:853",proto="TCP (DNS over TLS)",thread="0"} 0
      dnsdist_frontend_tlsqueries{frontend="127.0.0.1:853",proto="TCP (DNS over TLS)",thread="0",tls="tls10"} 0
      dnsdist_frontend_tlsqueries{frontend="127.0.0.1:853",proto="TCP (DNS over TLS)",thread="0",tls="tls11"} 0
      dnsdist_frontend_tlsqueries{frontend="127.0.0.1:853",proto="TCP (DNS over TLS)",thread="0",tls="tls12"} 0
      dnsdist_frontend_tlsqueries{frontend="127.0.0.1:853",proto="TCP (DNS over TLS)",thread="0",tls="tls13"} 0
      dnsdist_frontend_tlsqueries{frontend="127.0.0.1:853",proto="TCP (DNS over TLS)",thread="0",tls="unknown"} 0
      dnsdist_frontend_tlshandshakefailures{frontend="127.0.0.1:853",proto="TCP (DNS over TLS)",thread="0",error="dhKeyTooSmall"} 0
      dnsdist_frontend_tlshandshakefailures{frontend="127.0.0.1:853",proto="TCP (DNS over TLS)",thread="0",error="inappropriateFallBack"} 0
      dnsdist_frontend_tlshandshakefailures{frontend="127.0.0.1:853",proto="TCP (DNS over TLS)",thread="0",error="noSharedCipher"} 0
      dnsdist_frontend_tlshandshakefailures{frontend="127.0.0.1:853",proto="TCP (DNS over TLS)",thread="0",error="unknownCipherType"} 0
      dnsdist_frontend_tlshandshakefailures{frontend="127.0.0.1:853",proto="TCP (DNS over TLS)",thread="0",error="unknownKeyExchangeType"} 0
      dnsdist_frontend_tlshandshakefailures{frontend="127.0.0.1:853",proto="TCP (DNS over TLS)",thread="0",error="unknownProtocol"} 0
      dnsdist_frontend_tlshandshakefailures{frontend="127.0.0.1:853",proto="TCP (DNS over TLS)",thread="0",error="unsupportedEC"} 0
      dnsdist_frontend_tlshandshakefailures{frontend="127.0.0.1:853",proto="TCP (DNS over TLS)",thread="0",error="unsupportedProtocol"} 0
      dnsdist_frontend_queries{frontend="[::1]:443",proto="TCP (DNS over HTTPS)",thread="0"} 0
      dnsdist_frontend_noncompliantqueries{frontend="[::1]:443",proto="TCP (DNS over HTTPS)",thread="0"} 0
      dnsdist_frontend_responses{frontend="[::1]:443",proto="TCP (DNS over HTTPS)",thread="0"} 0
      dnsdist_frontend_tcpdiedreadingquery{frontend="[::1]:443",proto="TCP (DNS over HTTPS)",thread="0"} 0
      dnsdist_frontend_tcpdiedsendingresponse{frontend="[::1]:443",proto="TCP (DNS over HTTPS)",thread="0"} 0
      dnsdist_frontend_tcpgaveup{frontend="[::1]:443",proto="TCP (DNS over HTTPS)",thread="0"} 0
      dnsdist_frontend_tcpclienttimeouts{frontend="[::1]:443",proto="TCP (DNS over HTTPS)",thread="0"} 0
      dnsdist_frontend_tcpdownstreamtimeouts{frontend="[::1]:443",proto="TCP (DNS over HTTPS)",thread="0"} 0
      dnsdist_frontend_tcpcurrentconnections{frontend="[::1]:443",proto="TCP (DNS over HTTPS)",thread="0"} 0
      dnsdist_frontend_tcpmaxconcurrentconnections{frontend="[::1]:443",proto="TCP (DNS over HTTPS)",thread="0"} 0
      dnsdist_frontend_tcpavgqueriesperconnection{frontend="[::1]:443",proto="TCP (DNS over HTTPS)",thread="0"} 0
      dnsdist_frontend_tcpavgconnectionduration{frontend="[::1]:443",proto="TCP (DNS over HTTPS)",thread="0"} 0
      dnsdist_frontend_tlsnewsessions{frontend="[::1]:443",proto="TCP (DNS over HTTPS)",thread="0"} 0
      dnsdist_frontend_tlsresumptions{frontend="[::1]:443",proto="TCP (DNS over HTTPS)",thread="0"} 0
      dnsdist_frontend_tlsunknownticketkeys{frontend="[::1]:443",proto="TCP (DNS over HTTPS)",thread="0"} 0
      dnsdist_frontend_tlsinactiveticketkeys{frontend="[::1]:443",proto="TCP (DNS over HTTPS)",thread="0"} 0
      dnsdist_frontend_tlsqueries{frontend="[::1]:443",proto="TCP (DNS over HTTPS)",thread="0",tls="tls10"} 0
      dnsdist_frontend_tlsqueries{frontend="[::1]:443",proto="TCP (DNS over HTTPS)",thread="0",tls="tls11"} 0
      dnsdist_frontend_tlsqueries{frontend="[::1]:443",proto="TCP (DNS over HTTPS)",thread="0",tls="tls12"} 0
      dnsdist_frontend_tlsqueries{frontend="[::1]:443",proto="TCP (DNS over HTTPS)",thread="0",tls="tls13"} 0
      dnsdist_frontend_tlsqueries{frontend="[::1]:443",proto="TCP (DNS over HTTPS)",thread="0",tls="unknown"} 0
      dnsdist_frontend_tlshandshakefailures{frontend="[::1]:443",proto="TCP (DNS over HTTPS)",thread="0",error="dhKeyTooSmall"} 0
      dnsdist_frontend_tlshandshakefailures{frontend="[::1]:443",proto="TCP (DNS over HTTPS)",thread="0",error="inappropriateFallBack"} 0
      dnsdist_frontend_tlshandshakefailures{frontend="[::1]:443",proto="TCP (DNS over HTTPS)",thread="0",error="noSharedCipher"} 0
      dnsdist_frontend_tlshandshakefailures{frontend="[::1]:443",proto="TCP (DNS over HTTPS)",thread="0",error="unknownCipherType"} 0
      dnsdist_frontend_tlshandshakefailures{frontend="[::1]:443",proto="TCP (DNS over HTTPS)",thread="0",error="unknownKeyExchangeType"} 0
      dnsdist_frontend_tlshandshakefailures{frontend="[::1]:443",proto="TCP (DNS over HTTPS)",thread="0",error="unknownProtocol"} 0
      dnsdist_frontend_tlshandshakefailures{frontend="[::1]:443",proto="TCP (DNS over HTTPS)",thread="0",error="unsupportedEC"} 0
      dnsdist_frontend_tlshandshakefailures{frontend="[::1]:443",proto="TCP (DNS over HTTPS)",thread="0",error="unsupportedProtocol"} 0
      dnsdist_frontend_queries{frontend="127.0.0.1:53",proto="UDP",thread="0"} 0
      dnsdist_frontend_noncompliantqueries{frontend="127.0.0.1:53",proto="UDP",thread="0"} 0
      dnsdist_frontend_responses{frontend="127.0.0.1:53",proto="UDP",thread="0"} 0
      dnsdist_frontend_queries{frontend="127.0.0.1:53",proto="TCP",thread="0"} 0
      dnsdist_frontend_noncompliantqueries{frontend="127.0.0.1:53",proto="TCP",thread="0"} 0
      dnsdist_frontend_responses{frontend="127.0.0.1:53",proto="TCP",thread="0"} 0
      dnsdist_frontend_tcpdiedreadingquery{frontend="127.0.0.1:53",proto="TCP",thread="0"} 0
      dnsdist_frontend_tcpdiedsendingresponse{frontend="127.0.0.1:53",proto="TCP",thread="0"} 0
      dnsdist_frontend_tcpgaveup{frontend="127.0.0.1:53",proto="TCP",thread="0"} 0
      dnsdist_frontend_tcpclienttimeouts{frontend="127.0.0.1:53",proto="TCP",thread="0"} 0
      dnsdist_frontend_tcpdownstreamtimeouts{frontend="127.0.0.1:53",proto="TCP",thread="0"} 0
      dnsdist_frontend_tcpcurrentconnections{frontend="127.0.0.1:53",proto="TCP",thread="0"} 0
      dnsdist_frontend_tcpmaxconcurrentconnections{frontend="127.0.0.1:53",proto="TCP",thread="0"} 0
      dnsdist_frontend_tcpavgqueriesperconnection{frontend="127.0.0.1:53",proto="TCP",thread="0"} 0
      dnsdist_frontend_tcpavgconnectionduration{frontend="127.0.0.1:53",proto="TCP",thread="0"} 0
      # HELP dnsdist_frontend_http_connects Number of DoH TCP connections established to this frontend
      # TYPE dnsdist_frontend_http_connects counter
      # HELP dnsdist_frontend_doh_http_method_queries Number of DoH queries received by dnsdist, by HTTP method
      # TYPE dnsdist_frontend_doh_http_method_queries counter
      # HELP dnsdist_frontend_doh_http_version_queries Number of DoH queries received by dnsdist, by HTTP version
      # TYPE dnsdist_frontend_doh_http_version_queries counter
      # HELP dnsdist_frontend_doh_bad_requests Number of requests that could not be converted to a DNS query
      # TYPE dnsdist_frontend_doh_bad_requests counter
      # HELP dnsdist_frontend_doh_responses Number of responses sent, by type
      # TYPE dnsdist_frontend_doh_responses counter
      # HELP dnsdist_frontend_doh_version_status_responses Number of requests that could not be converted to a DNS query
      # TYPE dnsdist_frontend_doh_version_status_responses counter
      dnsdist_frontend_http_connects{frontend="[::1]:443",thread="0"} 0
      dnsdist_frontend_doh_http_method_queries{method="get",frontend="[::1]:443",thread="0"} 0
      dnsdist_frontend_doh_http_method_queries{method="post",frontend="[::1]:443",thread="0"} 0
      dnsdist_frontend_doh_http_version_queries{version="1",frontend="[::1]:443",thread="0"} 0
      dnsdist_frontend_doh_http_version_queries{version="2",frontend="[::1]:443",thread="0"} 0
      dnsdist_frontend_doh_bad_requests{frontend="[::1]:443",thread="0"} 0
      dnsdist_frontend_doh_responses{type="error",frontend="[::1]:443",thread="0"} 0
      dnsdist_frontend_doh_responses{type="redirect",frontend="[::1]:443",thread="0"} 0
      dnsdist_frontend_doh_responses{type="valid",frontend="[::1]:443",thread="0"} 0
      dnsdist_frontend_doh_version_status_responses{httpversion="1",status="200",frontend="[::1]:443",thread="0"} 0
      dnsdist_frontend_doh_version_status_responses{httpversion="1",status="400",frontend="[::1]:443",thread="0"} 0
      dnsdist_frontend_doh_version_status_responses{httpversion="1",status="403",frontend="[::1]:443",thread="0"} 0
      dnsdist_frontend_doh_version_status_responses{httpversion="1",status="500",frontend="[::1]:443",thread="0"} 0
      dnsdist_frontend_doh_version_status_responses{httpversion="1",status="502",frontend="[::1]:443",thread="0"} 0
      dnsdist_frontend_doh_version_status_responses{httpversion="1",status="other",frontend="[::1]:443",thread="0"} 0
      dnsdist_frontend_doh_version_status_responses{httpversion="2",status="200",frontend="[::1]:443",thread="0"} 0
      dnsdist_frontend_doh_version_status_responses{httpversion="2",status="400",frontend="[::1]:443",thread="0"} 0
      dnsdist_frontend_doh_version_status_responses{httpversion="2",status="403",frontend="[::1]:443",thread="0"} 0
      dnsdist_frontend_doh_version_status_responses{httpversion="2",status="500",frontend="[::1]:443",thread="0"} 0
      dnsdist_frontend_doh_version_status_responses{httpversion="2",status="502",frontend="[::1]:443",thread="0"} 0
      dnsdist_frontend_doh_version_status_responses{httpversion="2",status="other",frontend="[::1]:443",thread="0"} 0
      # HELP dnsdist_pool_servers Number of servers in that pool
      # TYPE dnsdist_pool_servers gauge
      # HELP dnsdist_pool_active_servers Number of available servers in that pool
      # TYPE dnsdist_pool_active_servers gauge
      # HELP dnsdist_pool_cache_size Maximum number of entries that this cache can hold
      # TYPE dnsdist_pool_cache_size gauge
      # HELP dnsdist_pool_cache_entries Number of entries currently present in that cache
      # TYPE dnsdist_pool_cache_entries gauge
      # HELP dnsdist_pool_cache_hits Number of hits from that cache
      # TYPE dnsdist_pool_cache_hits counter
      # HELP dnsdist_pool_cache_misses Number of misses from that cache
      # TYPE dnsdist_pool_cache_misses counter
      # HELP dnsdist_pool_cache_deferred_inserts Number of insertions into that cache skipped because it was already locked
      # TYPE dnsdist_pool_cache_deferred_inserts counter
      # HELP dnsdist_pool_cache_deferred_lookups Number of lookups into that cache skipped because it was already locked
      # TYPE dnsdist_pool_cache_deferred_lookups counter
      # HELP dnsdist_pool_cache_lookup_collisions Number of lookups into that cache that triggered a collision (same hash but different entry)
      # TYPE dnsdist_pool_cache_lookup_collisions counter
      # HELP dnsdist_pool_cache_insert_collisions Number of insertions into that cache that triggered a collision (same hash but different entry)
      # TYPE dnsdist_pool_cache_insert_collisions counter
      # HELP dnsdist_pool_cache_ttl_too_shorts Number of insertions into that cache skipped because the TTL of the answer was not long enough
      # TYPE dnsdist_pool_cache_ttl_too_shorts counter
      # HELP dnsdist_pool_cache_cleanup_count_total Number of times the cache has been scanned to remove expired entries, if any
      # TYPE dnsdist_pool_cache_cleanup_count_total counter
      dnsdist_pool_servers{pool="_default_"} 1
      dnsdist_pool_active_servers{pool="_default_"} 1
      dnsdist_pool_cache_size{pool="_default_"} 100
      dnsdist_pool_cache_entries{pool="_default_"} 0
      dnsdist_pool_cache_hits{pool="_default_"} 0
      dnsdist_pool_cache_misses{pool="_default_"} 0
      dnsdist_pool_cache_deferred_inserts{pool="_default_"} 0
      dnsdist_pool_cache_deferred_lookups{pool="_default_"} 0
      dnsdist_pool_cache_lookup_collisions{pool="_default_"} 0
      dnsdist_pool_cache_insert_collisions{pool="_default_"} 0
      dnsdist_pool_cache_ttl_too_shorts{pool="_default_"} 0
      dnsdist_pool_cache_cleanup_count_total{pool="_default_"} 0
      # HELP dnsdist_rule_hits Number of hits of that rule
      # TYPE dnsdist_rule_hits counter
      # HELP dnsdist_dynblocks_nmg_top_offenders_hits_per_second Number of hits per second blocked by Dynamic Blocks (netmasks) for the top offenders, averaged over the last 60s
      # TYPE dnsdist_dynblocks_nmg_top_offenders_hits_per_second gauge
      # HELP dnsdist_dynblocks_smt_top_offenders_hits_per_second Number of this per second blocked by Dynamic Blocks (suffixes) for the top offenders, averaged over the last 60s
      # TYPE dnsdist_dynblocks_smt_top_offenders_hits_per_second gauge
      # HELP dnsdist_info Info from dnsdist, value is always 1
      # TYPE dnsdist_info gauge
      dnsdist_info{version="1.7.3"} 1

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

.. http:delete:: /api/v1/cache?pool=<pool-name>&name=<dns-name>[&type=<dns-type>][&suffix=]

  .. versionadded:: 1.8.0

  Allows removing entries from a cache. The pool to which the cache is associated should be specified in the ``pool`` parameter, and the name to remove in the ``name`` parameter.
  By default only entries matching the exact name will be removed, but it is possible to remove all entries below that name by passing the ``suffix`` parameter set to any value.
  By default entries for all types for the name are removed, but it is possible to only remove entries for a specific type by passing the ``type`` parameter set to the requested type. Supported values are DNS type names as a strings (``AAAA``), or numerical values (as either ``#64`` or ``TYPE64``).

  **Example request**:

   .. sourcecode:: http

      DELETE /api/v1/cache?pool=&name=free.fr HTTP/1.1
      Accept: */*
      Accept-Encoding: gzip, deflate
      Connection: keep-alive
      Content-Length: 0
      Host: localhost:8080
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
          "count": "1",
          "status": "purged"
      }

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
  Changes to the ACL are directly applied, no restart is required.

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

.. http:get:: /api/v1/servers/localhost/pool?name=pool-name

  .. versionadded:: 1.6.1

  Get a quick overview of the pool named "pool-name".

  :>json list: A list of metrics related to that pool
  :>json list servers: A list of :json:object:`Server` objects present in that pool

.. http:get:: /api/v1/servers/localhost/rings?maxQueries=NUM&maxResponses=NUM

  .. versionadded:: 1.9.0

  Get the most recent queries and responses from the in-memory ring buffers. Returns up to ``maxQueries``
  query entries if set, up to ``maxResponses`` responses if set, and the whole content of the ring buffers otherwise.

  :>json list queries: The list of the most recent queries, as :json:object:`RingEntry` objects
  :>json list responses: The list of the most recent responses, as :json:object:`RingEntry` objects

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

.. json:object:: DoHFrontend

  A description of a DoH bind dnsdist is listening on.

  :property integer bad-requests: Number of requests that could not be converted to a DNS query
  :property integer error-responses: Number of HTTP responses sent with a non-200 code
  :property integer get-queries: Number of DoH queries received via the GET HTTP method
  :property integer http-connects: Number of DoH TCP connections established to this frontend
  :property integer http1-queries: Number of DoH queries received over HTTP/1 (or connection attempts with a HTTP/1.1 ALPN when the nghttp2 provider is used)
  :property integer http1-x00-responses: Number of DoH responses sent, over HTTP/1, per response code (200, 400, 403, 500, 502)
  :property integer http1-other-responses: Number of DoH responses sent, over HTTP/1, with another response code
  :property integer http2-queries: Number of DoH queries received over HTTP/2
  :property integer http2-x00-responses: Number of DoH responses sent, over HTTP/2, per response code (200, 400, 403, 500, 502)
  :property integer http1-other-responses: Number of DoH responses sent, over HTTP/2, with another response code
  :property integer post-queries: Number of DoH queries received via the POST HTTP method
  :property integer redirect-responses: Number of HTTP redirect responses sent
  :property integer valid-responses: Number of valid DoH (2xx) responses sent

.. json:object:: Frontend

  A description of a bind dnsdist is listening on.

  :property string address: IP and port that is listened on
  :property integer id: Internal identifier
  :property integer nonCompliantQueries: Amount of non-compliant queries received by this frontend
  :property integer queries: The number of received queries on this bind
  :property integer responses: Amount of responses sent by this frontend
  :property boolean tcp: true if this is a TCP bind
  :property integer tcpAvgConnectionDuration: The average duration of a TCP connection (ms)
  :property integer tcpAvgQueriesPerConnection: The average number of queries per TCP connection
  :property integer tcpClientTimeouts: Amount of TCP connections terminated by a timeout while reading from the client
  :property integer tcpCurrentConnections: Amount of current incoming TCP connections from clients
  :property integer tcpDiedReadingQuery: Amount of TCP connections terminated while reading the query from the client
  :property integer tcpDiedSendingResponse: Amount of TCP connections terminated while sending a response to the client
  :property integer tcpDownstreamTimeouts: Amount of TCP connections terminated by a timeout while reading from the backend
  :property integer tcpGaveUp: Amount of TCP connections terminated after too many attempts to get a connection to the backend
  :property integer tcpMaxConcurrentConnections: Maximum number of concurrent incoming TCP connections from clients
  :property integer tls10Queries: Number of queries received by dnsdist over TLS 1.0
  :property integer tls11Queries: Number of queries received by dnsdist over TLS 1.1
  :property integer tls12Queries: Number of queries received by dnsdist over TLS 1.2
  :property integer tls13Queries: Number of queries received by dnsdist over TLS 1.3
  :property integer tlsHandshakeFailuresDHKeyTooSmall: Amount of TLS connections where the client has negotiated a not strong enough diffie-hellman key during the TLS handshake
  :property integer tlsHandshakeFailuresInappropriateFallBack: Amount of TLS connections where the client tried to negotiate an invalid, too old, TLS version
  :property integer tlsHandshakeFailuresNoSharedCipher: Amount of TLS connections were no cipher shared by both the client and the server could been found during the TLS handshake
  :property integer tlsHandshakeFailuresUnknownCipher: Amount of TLS connections where the client has tried to negotiate an unknown TLS cipher
  :property integer tlsHandshakeFailuresUnknownKeyExchangeType: Amount of TLS connections where the client has tried to negotiate an unknown TLS key-exchange mechanism
  :property integer tlsHandshakeFailuresUnknownProtocol: Amount of TLS connections where the client has tried to negotiate an unknown TLS version
  :property integer tlsHandshakeFailuresUnsupportedEC: Amount of TLS connections where the client has tried to negotiate an unsupported elliptic curve
  :property integer tlsHandshakeFailuresUnsupportedProtocol: Amount of TLS connections where the client has tried to negotiate a unsupported TLS version
  :property integer tlsInactiveTicketKey: Amount of TLS sessions resumed from an inactive key
  :property integer tlsNewSessions: Amount of new TLS sessions negotiated
  :property integer tlsResumptions: Amount of TLS sessions resumed
  :property integer tlsUnknownQueries: Number of queries received by dnsdist over an unknown TLS version
  :property integer tlsUnknownTicketKey: Amount of attempts to resume TLS session from an unknown key (possibly expired)

  :property string type: UDP, TCP, DoT or DoH
  :property boolean udp: true if this is a UDP bind

.. json:object:: Pool

  A description of a pool of backend servers.

  :property integer id: Internal identifier
  :property integer cacheCleanupCount: Number of times that cache was scanned for expired entries, or just to remove entries because it is full
  :property integer cacheDeferredInserts: The number of times an entry could not be inserted in the associated cache, if any, because of a lock
  :property integer cacheDeferredLookups: The number of times an entry could not be looked up from the associated cache, if any, because of a lock
  :property integer cacheEntries: The current number of entries in the associated cache, if any
  :property integer cacheHits: The number of cache hits for the associated cache, if any
  :property integer cacheInsertCollisions: The number of times an entry could not be inserted into the cache because a different entry with the same hash already existed
  :property integer cacheLookupCollisions: The number of times an entry retrieved from the cache based on the query hash did not match the actual query
  :property integer cacheMisses: The number of cache misses for the associated cache, if any
  :property integer cacheSize: The maximum number of entries in the associated cache, if any
  :property integer cacheTTLTooShorts: The number of times an entry could not be inserted into the cache because its TTL was set below the minimum threshold
  :property string name: Name of the pool
  :property integer serversCount: Number of backends in this pool

.. json:object:: Rule

  This represents a policy that is applied to queries

  :property string action: The action taken when the rule matches (e.g. "to pool abuse")
  :property dict action-stats: A list of statistics whose content varies depending on the kind of rule
  :property integer creationOrder: The order in which a rule has been created, mostly used for automated tools
  :property integer id: The position of this rule
  :property integer matches: How many times this rule was hit
  :property string name: The name assigned to this rule by the administrator, if any
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

  :property string address: The remote IP and port
  :property integer id: Internal identifier
  :property integer latency: The current latency of this backend server for UDP queries, in milliseconds
  :property string name: The name of this server
  :property integer: nonCompliantResponses: Amount of non-compliant responses
  :property integer order: Order number
  :property integer outstanding: Number of currently outstanding queries
  :property [string] pools: The pools this server belongs to
  :property string protocol: The protocol used by this server (Do53, DoT, DoH)
  :property integer qps: The current number of queries per second to this server
  :property integer qpsLimit: The configured maximum number of queries per second
  :property integer queries: Total number of queries sent to this backend
  :property integer responses: Amount of responses received from this server
  :property integer reuseds: Number of queries for which a response was not received in time
  :property integer sendErrors: Number of network errors while sending a query to this server
  :property string state: The state of the server (e.g. "DOWN" or "up")
  :property integer tcpAvgConnectionDuration: The average duration of a TCP connection (ms)
  :property integer tcpAvgQueriesPerConnection: The average number of queries per TCP connection
  :property integer tcpConnectTimeouts: The number of TCP connect timeouts
  :property integer tcpCurrentConnections: The number of current TCP connections
  :property integer tcpDiedReadingResponse: The number of TCP I/O errors while reading the response
  :property integer tcpDiedSendingQuery: The number of TCP I/O errors while sending the query
  :property integer tcpGaveUp: The number of TCP connections failing after too many attempts
  :property integer tcpLatency: Server's latency when answering TCP questions in milliseconds
  :property integer tcpMaxConcurrentConnections: The maximum number of concurrent TCP connections
  :property integer tcpNewConnections: The number of established TCP connections in total
  :property integer tcpReadTimeouts: The number of TCP read timeouts
  :property integer tcpReusedConnections: The number of times a TCP connection has been reused
  :property integer tcpTooManyConcurrentConnections: Number of times we had to enforce the maximum number of concurrent TCP connections
  :property integer tcpWriteTimeouts: The number of TCP write timeouts
  :property integer tlsResumptions: The number of times a TLS session has been resumed
  :property integer weight: The weight assigned to this server
  :property float dropRate: The amount of packets dropped (timing out) per second by this server
  :property integer healthCheckFailures: Number of health check attempts that failed (total)
  :property integer healthCheckFailureParsing: Number of health check attempts that failed because the payload could not be parsed
  :property integer healthCheckFailureTimeout: Number of health check attempts that failed because the response was not received in time
  :property integer healthCheckFailureNetwork: Number of health check attempts that failed because of a network error
  :property integer healthCheckFailureMismatch: Number of health check attempts that failed because the ID, qname, qtype or qclass did not match
  :property integer healthCheckFailureInvalid: Number of health check attempts that failed because the DNS response was not valid

.. json:object:: StatisticItem

  This represents a statistics element.

  :property string name: The name of this statistic. See :doc:`../statistics`
  :property string type: "StatisticItem"
  :property integer value: The value for this item

.. json:object:: RingEntry

  This represents an entry in the in-memory ring buffers.

  :property float age: How long ago was the query or response received, in seconds
  :property integer id: The DNS ID
  :property string name: The requested domain name
  :property string requestor: The client IP and port
  :property integer size: The size of the query or response
  :property integer qtype: The requested DNS type
  :property string protocol: The DNS protocol the query or response was received over
  :property boolean rd: The RD flag
  :property string mac: The MAC address of the device sending the query
  :property float latency: The time it took for the response to be sent back to the client, in microseconds
  :property int rcode: The response code
  :property boolean tc: The TC flag
  :property boolean aa: The AA flag
  :property integer answers: The number of records in the answer section of the response
  :property string backend: The IP and port of the backend that returned the response, or "Cache" if it was a cache-hit
