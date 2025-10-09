Built-in Webserver and HTTP API
===============================

The PowerDNS Authoritative Server features a built-in webserver that exposes a JSON/REST API.
This API allows for controlling several functions, reading statistics and modifying zone content, metadata and DNSSEC key material.

Webserver
---------

To launch the internal webserver, add a :ref:`setting-webserver` to the configuration file.
This will instruct PowerDNS to start a webserver on localhost at port 8081, without password protection.
By default the webserver listens on localhost, meaning only local users (on the same host) will be able to access the webserver. Since the default ACL before 4.1.0 allows access from everywhere if :ref:`setting-webserver-address` is set to a different value, we strongly advise the use of password protection.
The webserver lists a lot of potentially sensitive information about the PowerDNS process, including frequent queries, frequently failing queries, lists of remote hosts sending queries, hosts sending corrupt queries etc.
The webserver does not allow remote management of the daemon, but allows control over the size of the queries and response rings that may be used to monitor activities.
The following webserver related configuration items are available:

* :ref:`setting-webserver`: If set to anything but 'no', a webserver is launched.
* :ref:`setting-webserver-address`: IP address (or UNIX domain socket path, from version 5.0.0 onward) to bind the webserver to. Defaults to 127.0.0.1, which implies that only the local computer is able to connect to the nameserver! To allow remote hosts to connect, change to 0.0.0.0 or the physical IP address of your nameserver.
* :ref:`setting-webserver-password`: If set, viewers will have to enter this password in order to gain access to the statistics, in addition to entering the configured API key on the index page.
* :ref:`setting-webserver-port`: Port to bind the webserver to (not relevant if :ref:`setting-webserver-address` is set to a UNIX domain socket).
* :ref:`setting-webserver-allow-from`: Netmasks that are allowed to connect to the webserver (not relevant if :ref:`setting-webserver-address` is set to a UNIX domain socket).
* :ref:`setting-webserver-max-bodysize`: Maximum request/response body size in megabytes
* :ref:`setting-webserver-connection-timeout`: Request/response timeout in seconds


Metrics Endpoint
----------------

.. versionadded:: 4.4.0

The webserver exposes a metrics-endpoint that follows the `prometheus exposition-format <https://github.com/prometheus/docs/blob/master/content/docs/instrumenting/exposition_formats.md>`_ on path ``/metrics``.

The metrics listed are equivalent to the variables section on the index-page of the webserver (prefixed with ``pdns_auth_`` and replacing dashes with underscores).

A simple ``GET`` request will return a response similar to the following:

.. http:get:: /metrics

::

  HTTP/1.1 200 OK
  Connection: close
  Content-Length: 12044
  Content-Type: text/plain
  Server: PowerDNS/0.0.19015.0.master.ge719aae4e8

  # HELP pdns_auth_corrupt_packets Number of corrupt packets received
  # TYPE pdns_auth_corrupt_packets counter
  pdns_auth_corrupt_packets 0
  # HELP pdns_auth_deferred_cache_inserts Amount of cache inserts that were deferred because of maintenance
  # TYPE pdns_auth_deferred_cache_inserts counter
  pdns_auth_deferred_cache_inserts 0
  # HELP pdns_auth_deferred_cache_lookup Amount of cache lookups that were deferred because of maintenance
  # TYPE pdns_auth_deferred_cache_lookup counter
  pdns_auth_deferred_cache_lookup 0
  # HELP pdns_auth_deferred_packetcache_inserts Amount of packet cache inserts that were deferred because of maintenance
  # TYPE pdns_auth_deferred_packetcache_inserts counter
  pdns_auth_deferred_packetcache_inserts 0
  # HELP pdns_auth_deferred_packetcache_lookup Amount of packet cache lookups that were deferred because of maintenance
  # TYPE pdns_auth_deferred_packetcache_lookup counter
  pdns_auth_deferred_packetcache_lookup 0
  # HELP pdns_auth_dnsupdate_answers DNS update packets successfully answered.
  # TYPE pdns_auth_dnsupdate_answers counter
  pdns_auth_dnsupdate_answers 0
  # HELP pdns_auth_dnsupdate_changes DNS update changes to records in total.
  # TYPE pdns_auth_dnsupdate_changes counter
  pdns_auth_dnsupdate_changes 0
  # HELP pdns_auth_dnsupdate_queries DNS update packets received.
  # TYPE pdns_auth_dnsupdate_queries counter
  pdns_auth_dnsupdate_queries 0
  # HELP pdns_auth_dnsupdate_refused DNS update packets that are refused.
  # TYPE pdns_auth_dnsupdate_refused counter
  pdns_auth_dnsupdate_refused 0
  # HELP pdns_auth_incoming_notifications NOTIFY packets received.
  # TYPE pdns_auth_incoming_notifications counter
  pdns_auth_incoming_notifications 0
  # HELP pdns_auth_overload_drops Queries dropped because backends overloaded
  # TYPE pdns_auth_overload_drops counter
  pdns_auth_overload_drops 0
  # HELP pdns_auth_packetcache_hit Number of hits on the packet cache
  # TYPE pdns_auth_packetcache_hit counter
  pdns_auth_packetcache_hit 0
  # HELP pdns_auth_packetcache_miss Number of misses on the packet cache
  # TYPE pdns_auth_packetcache_miss counter
  pdns_auth_packetcache_miss 0
  # HELP pdns_auth_packetcache_size Number of entries in the packet cache
  # TYPE pdns_auth_packetcache_size gauge
  pdns_auth_packetcache_size 0
  # HELP pdns_auth_query_cache_hit Number of hits on the query cache
  # TYPE pdns_auth_query_cache_hit counter
  pdns_auth_query_cache_hit 0
  # HELP pdns_auth_query_cache_miss Number of misses on the query cache
  # TYPE pdns_auth_query_cache_miss counter
  pdns_auth_query_cache_miss 0
  # HELP pdns_auth_query_cache_size Number of entries in the query cache
  # TYPE pdns_auth_query_cache_size gauge
  pdns_auth_query_cache_size 0
  # HELP pdns_auth_rd_queries Number of recursion desired questions
  # TYPE pdns_auth_rd_queries counter
  pdns_auth_rd_queries 0
  # HELP pdns_auth_recursing_answers Number of recursive answers sent out
  # TYPE pdns_auth_recursing_answers counter
  pdns_auth_recursing_answers 0
  # HELP pdns_auth_recursing_questions Number of questions sent to recursor
  # TYPE pdns_auth_recursing_questions counter
  pdns_auth_recursing_questions 0
  # HELP pdns_auth_recursion_unanswered Number of packets unanswered by configured recursor
  # TYPE pdns_auth_recursion_unanswered counter
  pdns_auth_recursion_unanswered 0
  # HELP pdns_auth_security_status Security status based on regular polling
  # TYPE pdns_auth_security_status gauge
  pdns_auth_security_status 0
  # HELP pdns_auth_servfail_packets Number of times a server-failed packet was sent out
  # TYPE pdns_auth_servfail_packets counter
  pdns_auth_servfail_packets 0
  # HELP pdns_auth_signatures Number of DNSSEC signatures made
  # TYPE pdns_auth_signatures counter
  pdns_auth_signatures 0
  # HELP pdns_auth_tcp_answers Number of answers sent out over TCP
  # TYPE pdns_auth_tcp_answers counter
  pdns_auth_tcp_answers 0
  # HELP pdns_auth_tcp_answers_bytes Total size of answers sent out over TCP
  # TYPE pdns_auth_tcp_answers_bytes counter
  pdns_auth_tcp_answers_bytes 0
  # HELP pdns_auth_tcp_queries Number of TCP queries received
  # TYPE pdns_auth_tcp_queries counter
  pdns_auth_tcp_queries 0
  # HELP pdns_auth_tcp4_answers Number of IPv4 answers sent out over TCP
  # TYPE pdns_auth_tcp4_answers counter
  pdns_auth_tcp4_answers 0
  # HELP pdns_auth_tcp4_answers_bytes Total size of answers sent out over TCPv4
  # TYPE pdns_auth_tcp4_answers_bytes counter
  pdns_auth_tcp4_answers_bytes 0
  # HELP pdns_auth_tcp4_queries Number of IPv4 TCP queries received
  # TYPE pdns_auth_tcp4_queries counter
  pdns_auth_tcp4_queries 0
  # HELP pdns_auth_tcp6_answers Number of IPv6 answers sent out over TCP
  # TYPE pdns_auth_tcp6_answers counter
  pdns_auth_tcp6_answers 0
  # HELP pdns_auth_tcp6_answers_bytes Total size of answers sent out over TCPv6
  # TYPE pdns_auth_tcp6_answers_bytes counter
  pdns_auth_tcp6_answers_bytes 0
  # HELP pdns_auth_tcp6_queries Number of IPv6 TCP queries received
  # TYPE pdns_auth_tcp6_queries counter
  pdns_auth_tcp6_queries 0
  # HELP pdns_auth_timedout_packets Number of packets which weren't answered within timeout set
  # TYPE pdns_auth_timedout_packets counter
  pdns_auth_timedout_packets 0
  # HELP pdns_auth_udp_answers Number of answers sent out over UDP
  # TYPE pdns_auth_udp_answers counter
  pdns_auth_udp_answers 0
  # HELP pdns_auth_udp_answers_bytes Total size of answers sent out over UDP
  # TYPE pdns_auth_udp_answers_bytes counter
  pdns_auth_udp_answers_bytes 0
  # HELP pdns_auth_udp_do_queries Number of UDP queries received with DO bit
  # TYPE pdns_auth_udp_do_queries counter
  pdns_auth_udp_do_queries 0
  # HELP pdns_auth_udp_queries Number of UDP queries received
  # TYPE pdns_auth_udp_queries counter
  pdns_auth_udp_queries 0
  # HELP pdns_auth_udp4_answers Number of IPv4 answers sent out over UDP
  # TYPE pdns_auth_udp4_answers counter
  pdns_auth_udp4_answers 0
  # HELP pdns_auth_udp4_answers_bytes Total size of answers sent out over UDPv4
  # TYPE pdns_auth_udp4_answers_bytes counter
  pdns_auth_udp4_answers_bytes 0
  # HELP pdns_auth_udp4_queries Number of IPv4 UDP queries received
  # TYPE pdns_auth_udp4_queries counter
  pdns_auth_udp4_queries 0
  # HELP pdns_auth_udp6_answers Number of IPv6 answers sent out over UDP
  # TYPE pdns_auth_udp6_answers counter
  pdns_auth_udp6_answers 0
  # HELP pdns_auth_udp6_answers_bytes Total size of answers sent out over UDPv6
  # TYPE pdns_auth_udp6_answers_bytes counter
  pdns_auth_udp6_answers_bytes 0
  # HELP pdns_auth_udp6_queries Number of IPv6 UDP queries received
  # TYPE pdns_auth_udp6_queries counter
  pdns_auth_udp6_queries 0
  # HELP pdns_auth_cpu_iowait Time spent waiting for I/O to complete by the whole system, in units of USER_HZ
  # TYPE pdns_auth_cpu_iowait counter
  pdns_auth_cpu_iowait 2739
  # HELP pdns_auth_cpu_steal Stolen time, which is the time spent by the whole system in other operating systems when running in a virtualized environment, in units of USER_HZ
  # TYPE pdns_auth_cpu_steal counter
  pdns_auth_cpu_steal 0
  # HELP pdns_auth_fd_usage Number of open filedescriptors
  # TYPE pdns_auth_fd_usage gauge
  pdns_auth_fd_usage 26
  # HELP pdns_auth_key_cache_size Number of entries in the key cache
  # TYPE pdns_auth_key_cache_size gauge
  pdns_auth_key_cache_size 0
  # HELP pdns_auth_latency Average number of microseconds needed to answer a question
  # TYPE pdns_auth_latency gauge
  pdns_auth_latency 0
  # HELP pdns_auth_meta_cache_size Number of entries in the metadata cache
  # TYPE pdns_auth_meta_cache_size gauge
  pdns_auth_meta_cache_size 0
  # HELP pdns_auth_open_tcp_connections Number of currently open TCP connections
  # TYPE pdns_auth_open_tcp_connections gauge
  pdns_auth_open_tcp_connections 0
  # HELP pdns_auth_qsize_q Number of questions waiting for database attention
  # TYPE pdns_auth_qsize_q gauge
  pdns_auth_qsize_q 0
  # HELP pdns_auth_real_memory_usage Actual unique use of memory in bytes (approx)
  # TYPE pdns_auth_real_memory_usage gauge
  pdns_auth_real_memory_usage 133189632
  # HELP pdns_auth_ring_logmessages_capacity Maximum number of entries in the logmessages ring
  # TYPE pdns_auth_ring_logmessages_capacity gauge
  pdns_auth_ring_logmessages_capacity 10000
  # HELP pdns_auth_ring_logmessages_size Number of entries in the logmessages ring
  # TYPE pdns_auth_ring_logmessages_size gauge
  pdns_auth_ring_logmessages_size 7
  # HELP pdns_auth_ring_noerror_queries_capacity Maximum number of entries in the noerror-queries ring
  # TYPE pdns_auth_ring_noerror_queries_capacity gauge
  pdns_auth_ring_noerror_queries_capacity 10000
  # HELP pdns_auth_ring_noerror_queries_size Number of entries in the noerror-queries ring
  # TYPE pdns_auth_ring_noerror_queries_size gauge
  pdns_auth_ring_noerror_queries_size 0
  # HELP pdns_auth_ring_nxdomain_queries_capacity Maximum number of entries in the nxdomain-queries ring
  # TYPE pdns_auth_ring_nxdomain_queries_capacity gauge
  pdns_auth_ring_nxdomain_queries_capacity 10000
  # HELP pdns_auth_ring_nxdomain_queries_size Number of entries in the nxdomain-queries ring
  # TYPE pdns_auth_ring_nxdomain_queries_size gauge
  pdns_auth_ring_nxdomain_queries_size 0
  # HELP pdns_auth_ring_queries_capacity Maximum number of entries in the queries ring
  # TYPE pdns_auth_ring_queries_capacity gauge
  pdns_auth_ring_queries_capacity 10000
  # HELP pdns_auth_ring_queries_size Number of entries in the queries ring
  # TYPE pdns_auth_ring_queries_size gauge
  pdns_auth_ring_queries_size 0
  # HELP pdns_auth_ring_remotes_capacity Maximum number of entries in the remotes ring
  # TYPE pdns_auth_ring_remotes_capacity gauge
  pdns_auth_ring_remotes_capacity 10000
  # HELP pdns_auth_ring_remotes_corrupt_capacity Maximum number of entries in the remotes-corrupt ring
  # TYPE pdns_auth_ring_remotes_corrupt_capacity gauge
  pdns_auth_ring_remotes_corrupt_capacity 10000
  # HELP pdns_auth_ring_remotes_corrupt_size Number of entries in the remotes-corrupt ring
  # TYPE pdns_auth_ring_remotes_corrupt_size gauge
  pdns_auth_ring_remotes_corrupt_size 0
  # HELP pdns_auth_ring_remotes_size Number of entries in the remotes ring
  # TYPE pdns_auth_ring_remotes_size gauge
  pdns_auth_ring_remotes_size 0
  # HELP pdns_auth_ring_remotes_unauth_capacity Maximum number of entries in the remotes-unauth ring
  # TYPE pdns_auth_ring_remotes_unauth_capacity gauge
  pdns_auth_ring_remotes_unauth_capacity 10000
  # HELP pdns_auth_ring_remotes_unauth_size Number of entries in the remotes-unauth ring
  # TYPE pdns_auth_ring_remotes_unauth_size gauge
  pdns_auth_ring_remotes_unauth_size 0
  # HELP pdns_auth_ring_servfail_queries_capacity Maximum number of entries in the servfail-queries ring
  # TYPE pdns_auth_ring_servfail_queries_capacity gauge
  pdns_auth_ring_servfail_queries_capacity 10000
  # HELP pdns_auth_ring_servfail_queries_size Number of entries in the servfail-queries ring
  # TYPE pdns_auth_ring_servfail_queries_size gauge
  pdns_auth_ring_servfail_queries_size 0
  # HELP pdns_auth_ring_unauth_queries_capacity Maximum number of entries in the unauth-queries ring
  # TYPE pdns_auth_ring_unauth_queries_capacity gauge
  pdns_auth_ring_unauth_queries_capacity 10000
  # HELP pdns_auth_ring_unauth_queries_size Number of entries in the unauth-queries ring
  # TYPE pdns_auth_ring_unauth_queries_size gauge
  pdns_auth_ring_unauth_queries_size 0
  # HELP pdns_auth_signature_cache_size Number of entries in the signature cache
  # TYPE pdns_auth_signature_cache_size gauge
  pdns_auth_signature_cache_size 0
  # HELP pdns_auth_sys_msec Number of msec spent in system time
  # TYPE pdns_auth_sys_msec counter
  pdns_auth_sys_msec 56
  # HELP pdns_auth_udp_in_errors UDP 'in' errors
  # TYPE pdns_auth_udp_in_errors counter
  pdns_auth_udp_in_errors 151
  # HELP pdns_auth_udp_noport_errors UDP 'noport' errors
  # TYPE pdns_auth_udp_noport_errors counter
  pdns_auth_udp_noport_errors 9
  # HELP pdns_auth_udp_recvbuf_errors UDP 'recvbuf' errors
  # TYPE pdns_auth_udp_recvbuf_errors counter
  pdns_auth_udp_recvbuf_errors 0
  # HELP pdns_auth_udp_sndbuf_errors UDP 'sndbuf' errors
  # TYPE pdns_auth_udp_sndbuf_errors counter
  pdns_auth_udp_sndbuf_errors 9
  # HELP pdns_auth_uptime Uptime of process in seconds
  # TYPE pdns_auth_uptime counter
  pdns_auth_uptime 672
  # HELP pdns_auth_user_msec Number of msec spent in user time
  # TYPE pdns_auth_user_msec counter
  pdns_auth_user_msec 48


Prometheus can then be configured to scrape metrics from this endpoint using a simple job description like the following::

  scrape_configs:
    - job_name: 'pdns_auth'
      scrape_interval: 1m
      static_configs:
        - targets: ['pdns_auth_host:pdns_auth_ws_port'] 

Further details can be gathered from the `prometheus docs <https://prometheus.io/docs/prometheus/latest/configuration/configuration/#scrape_config>`_.


Enabling the API
----------------

To enable the API, the webserver and the HTTP API need to be enabled.
Add these lines to ``pdns.conf``::

  api=yes
  api-key=changeme

And restart, the following examples should start working::

  curl -v -H 'X-API-Key: changeme' http://127.0.0.1:8081/api/v1/servers/localhost | jq .
  curl -v -H 'X-API-Key: changeme' http://127.0.0.1:8081/api/v1/servers/localhost/zones | jq .

Working with the API
--------------------

This chapter describes the PowerDNS Authoritative API.
When creating an API wrapper (for instance when fronting multiple API's), it is recommended to stick to this API specification.
The API is described in the `OpenAPI format <https://www.openapis.org/>`_, also known as "Swagger", and this description is `available <https://raw.githubusercontent.com/PowerDNS/pdns/master/docs/http-api/swagger/authoritative-api-swagger.yaml>`_. It can also be obtained from a running server if the administrator of that server has enabled the API; it
is available at the  `/api/docs` endpoint in both YAML and JSON formats (the 'Accept' header can be used to indicate the
desired format).

Authentication
~~~~~~~~~~~~~~

The PowerDNS daemons accept a static API Key, configured with the :ref:`setting-api-key` option, which has to be sent in the ``X-API-Key`` header.

Errors
~~~~~~

Response code ``4xx`` or ``5xx``, depending on the situation.

-  Invalid JSON body from client: ``400 Bad Request``
-  Input validation failed: ``422 Unprocessable Entity``
-  JSON body from client is not a hash: ``400 Bad Request``

Error responses have a JSON body of this format:

.. openapi:: swagger/authoritative-api-swagger.yaml
  :definitions: Error

Data format
~~~~~~~~~~~

The API accepts and emits :rfc:`JSON <7159>`.
The ``Accept:`` header determines the output format.
An unknown value or ``*/*`` will cause a ``400 Bad Request``.

All text is encoded in UTF-8 and HTTP headers will reflect this.

Data types:

-  empty fields: ``null`` but present
-  Regex: implementation defined
-  Dates: ISO 8601

Endpoints and Objects in the API
--------------------------------

The API has the basepath ``/api/v1`` and all URLs in this documentation are relative to this basepath.

The API exposes several endpoints and objects:

.. toctree::
  :maxdepth: 1

  server
  zone
  views
  networks
  cryptokey
  metadata
  tsigkey
  autoprimaries
  search
  statistics
  cache
