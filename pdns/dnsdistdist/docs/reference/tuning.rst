Tuning related functions
========================

.. function:: setMaxTCPClientThreads(num)

  Set the maximum of TCP client threads, handling TCP connections. Before 1.4.0 a TCP thread could only handle a single incoming TCP connection at a time, while after 1.4.0 it can handle a larger number of them simultaneously.

  :param int num:

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

  Set the maximum number of TCP connections queued (waiting to be picked up by a client thread), defaults to 1000. 0 means unlimited

  :param int num:

.. function:: setMaxUDPOutstanding(num)
  .. versionchanged:: 1.4.0
    Before 1.4.0 the default value was 10240

  Set the maximum number of outstanding UDP queries to a given backend server. This can only be set at configuration time and defaults to 65535 (10240 before 1.4.0)

  :param int num:

.. function:: setCacheCleaningDelay(num)

  Set the interval in seconds between two runs of the cache cleaning algorithm, removing expired entries

  :param int num:

.. function:: setCacheCleaningPercentage(num)

  Set the percentage of the cache that the cache cleaning algorithm will try to free by removing expired entries. By default (100), all expired entries are removed

  :param int num:

.. function:: setStaleCacheEntriesTTL(num)

  Allows using cache entries expired for at most n seconds when no backend available to answer for a query

  :param int num:

.. function:: setTCPUseSinglePipe(val)

  Whether the incoming TCP connections should be put into a single queue instead of using per-thread queues. Defaults to false

  :param bool val:

.. function:: setTCPRecvTimeout(num)

  Set the read timeout on TCP connections from the client, in seconds

  :param int num:

.. function:: setTCPSendTimeout(num)

  Set the write timeout on TCP connections from the client, in seconds

  :param int num:

.. function:: setUDPMultipleMessagesVectorSize(num)

  .. versionadded:: 1.3.0

  Set the maximum number of UDP queries messages to accept in a single ``recvmmsg()`` call. Only available if the underlying OS
  support ``recvmmsg()`` with the ``MSG_WAITFORONE`` option. Defaults to 1, which means only query at a time is accepted, using
  ``recvmsg()`` instead of ``recvmmsg()``.

  :param int num: maximum number of UDP queries to accept

.. function:: setUDPTimeout(num)

  Set the maximum time dnsdist will wait for a response from a backend over UDP, in seconds. Defaults to 2

  :param int num:
