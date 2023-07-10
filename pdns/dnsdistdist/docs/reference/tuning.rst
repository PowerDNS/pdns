Tuning related functions
========================

.. function:: setDoHDownstreamCleanupInterval(interval)

  .. versionadded:: 1.7.0

  Set how often, in seconds, the outgoing DoH connections to backends of a given worker thread are scanned to expunge the ones that are no longer usable. The default is 60 so once per minute and per worker thread.

  :param int interval: The interval in seconds.

.. function:: setDoHDownstreamMaxIdleTime(max)

  .. versionadded:: 1.7.0

  Set how long, in seconds, an outgoing DoH connection to a backend might stay idle before being closed. The default is 300 so 5 minutes.

  :param int max: The maximum time in seconds.

.. function:: setMaxIdleDoHConnectionsPerDownstream(max)

  .. versionadded:: 1.7.0

  Set the maximum number of inactive DoH connections to a backend cached by each DoH worker thread. These connections can be reused when a new query comes in, instead of having to establish a new connection. dnsdist regularly checks whether the other end has closed any cached connection, closing them in that case.

  :param int max: The maximum number of inactive connections to keep. Default is 10, so 10 connections per backend and per DoH worker thread.

.. function:: setMaxCachedTCPConnectionsPerDownstream(max)

  .. versionadded:: 1.6.0

  Set the maximum number of inactive TCP connections to a backend cached by each TCP worker thread. These connections can be reused when a new query comes in, instead of having to establish a new connection. dnsdist regularly checks whether the other end has closed any cached connection, closing them in that case.

  :param int max: The maximum number of inactive connections to keep. Default is 10, so 10 connections per backend and per TCP worker thread.

.. function:: setMaxTCPClientThreads(num)

  .. versionchanged:: 1.6.0
    Before 1.6.0 the default value was 10.
  .. versionchanged:: 1.7.0
    The default value has been set back to 10.

  Set the maximum of TCP client threads, handling TCP connections. Before 1.4.0 a TCP thread could only handle a single incoming TCP connection at a time, while after 1.4.0 it can handle a larger number of them simultaneously.

  Note that before 1.6.0 the TCP worker threads were created at runtime, adding a new thread when the existing ones seemed to struggle with the load, until the maximum number of threads had been reached. Starting with 1.6.0 the configured number of worker threads are immediately created at startup.

  In 1.6.0 the default value was at least 10 TCP workers, but could be more if there is more than 10 TCP listeners (added via :func:`addDNSCryptBind`, :func:`addLocal`, or :func:`addTLSLocal`). In that last case there would have been as many TCP workers as TCP listeners. This led to issues in setups with a large number of TCP listeners and was therefore reverted back to 10 in 1.7.0.

  :param int num: The number of TCP worker threads.

.. function:: setMaxTCPConnectionDuration(num)

  Set the maximum duration of an incoming TCP connection, in seconds. 0 (the default) means unlimited

  :param int num:

.. function:: setMaxTCPConnectionsPerClient(num)

  Set the maximum number of TCP connections per client. 0 (the default) means unlimited

  :param int num:

.. function:: setMaxTCPQueriesPerConnection(num)

  Set the maximum number of queries in an incoming TCP connection. 0 (the default) means unlimited

  :param int num:

.. function:: setMaxTCPQueuedConnections(num)

  .. versionchanged:: 1.6.0
    Before 1.6.0 the default value was 1000 on all systems.

  Set the maximum number of TCP connections queued (waiting to be picked up by a client thread), defaults to 1000 (10000 on Linux since 1.6.0). 0 means unlimited

  :param int num:

.. function:: setMaxUDPOutstanding(num)

  .. versionchanged:: 1.4.0
    Before 1.4.0 the default value was 10240

  Set the maximum number of outstanding UDP queries to a given backend server. This can only be set at configuration time and defaults to 65535 (10240 before 1.4.0)

  :param int num:

.. function:: setCacheCleaningDelay(num)

  Set the interval in seconds between two runs of the cache cleaning algorithm, removing expired entries. Default is every 60s

  :param int num:

.. function:: setCacheCleaningPercentage(num)

  Set the percentage of the cache that the cache cleaning algorithm will try to free by removing expired entries. By default (100), all expired entries are removed

  :param int num:

.. function:: setOutgoingDoHWorkerThreads(num)

  .. versionadded:: 1.7.0

  Set the number of worker threads to use for outgoing DoH. That number defaults to 0 but is automatically raised to 1 when DoH is enabled on at least one backend.

.. function:: setStaleCacheEntriesTTL(num)

  Allows using cache entries expired for at most n seconds when no backend available to answer for a query

  :param int num:

.. function:: setTCPDownstreamCleanupInterval(interval)

  .. versionadded:: 1.6.0

  Set how often, in seconds, the outgoing TCP connections to backends of a given worker thread are scanned to expunge the ones that are no longer usable. The default is 60 so once per minute and per worker thread.

  :param int interval: The interval in seconds.

.. function:: setDoHDownstreamMaxIdleTime(max)

  .. versionadded:: 1.7.0

  Set how long, in seconds, an outgoing DoH connection to a backend might stay idle before being closed. The default is 300 so 5 minutes.

  :param int max: The maximum time in seconds.


.. function:: setRandomizedIdsOverUDP(val)

  .. versionadded:: 1.8.0

  Setting this parameter to true (default is false) will randomize the IDs in outgoing UDP queries, at a small performance cost, ignoring the :func:`setMaxUDPOutstanding`
  value. This is only useful if the path between dnsdist and the backend is not trusted and the 'TCP-only', DNS over TLS or DNS over HTTPS transports cannot be used.
  See also :func:`setRandomizedOutgoingSockets`.
  The default is to use a linearly increasing counter from 0 to 65535, wrapping back to 0 when necessary.

.. function:: setRandomizedOutgoingSockets(val)

  .. versionadded:: 1.8.0

  Setting this parameter to true (default is false) will randomize the outgoing socket used when forwarding a query to a backend.
  The default is to use a round-robin mechanism to select the outgoing socket.
  This requires configuring the backend to use more than one outgoing socket via the ``sockets`` parameter of :func:`newServer`
  to be of any use, and only makes sense if the path between dnsdist and the backend is not trusted and the 'TCP-only', DNS over
  TLS or DNS over HTTPS transports cannot be used.
  See also :func:`setRandomizedIdsOverUDP`.

.. function:: setTCPInternalPipeBufferSize(size)

  .. versionadded:: 1.6.0

  Set the size in bytes of the internal buffer of the pipes used internally to distribute connections to TCP (and DoT) workers threads. Requires support for ``F_SETPIPE_SZ`` which is present in Linux since 2.6.35. The actual size might be rounded up to a multiple of a page size. 0 means that the OS default size is used. The default value is 0, except on Linux where it is 1048576 since 1.6.0.

  :param int size: The size in bytes.

.. function:: setTCPUseSinglePipe(val)

  .. deprecated:: 1.6.0

  Whether the incoming TCP connections should be put into a single queue instead of using per-thread queues. Defaults to false. That option was useful before 1.4.0 when a single TCP connection could block a TCP worker thread, but should not be used in recent versions where the per-thread queues model avoids waking up all idle workers when a new connection arrives. This option will be removed in 1.7.0.

  :param bool val:

.. function:: setTCPRecvTimeout(num)

  Set the read timeout on TCP connections from the client, in seconds

  :param int num:

.. function:: setTCPSendTimeout(num)

  Set the write timeout on TCP connections from the client, in seconds

  :param int num:

.. function:: setUDPMultipleMessagesVectorSize(num)

  Set the maximum number of UDP queries messages to accept in a single ``recvmmsg()`` call. Only available if the underlying OS
  support ``recvmmsg()`` with the ``MSG_WAITFORONE`` option. Defaults to 1, which means only query at a time is accepted, using
  ``recvmsg()`` instead of ``recvmmsg()``.

  :param int num: maximum number of UDP queries to accept

.. function:: setUDPSocketBufferSizes(recv, send)

  .. versionadded:: 1.7.0

  Set the size of the receive (``SO_RCVBUF``) and send (``SO_SNDBUF``) buffers for incoming UDP sockets. On Linux the default
  values correspond to ``net.core.rmem_default`` and ``net.core.wmem_default`` , and the maximum values are restricted
  by ``net.core.rmem_max`` and ``net.core.wmem_max``.

  :param int recv: ``SO_RCVBUF`` value. Default is 0, meaning the system value will be kept.
  :param int send: ``SO_SNDBUF`` value. Default is 0, meaning the system value will be kept.

.. function:: setUDPTimeout(num)

  Set the maximum time dnsdist will wait for a response from a backend over UDP, in seconds. Defaults to 2

  :param int num:
