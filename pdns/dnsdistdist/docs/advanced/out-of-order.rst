Out-of-order
------------

As of 1.6.0, dnsdist supports accepting and processing queries out-of-order as long as the
``maxInFlight`` parameter has been set on the frontend, via :func:`addLocal` and/or :func:`addTLSLocal`.
Note that it is always enabled on DoH frontends.
As many as ``maxInFlight`` queries will then be read from a TCP connection, processed and forwarded
to a backend simultaneously. If there is more queries pending, they will be processed once a response
has been sent for one of the already processed queries.

Backends are assumed not to support out-of-order by default, so only one query at a time will be sent over
a TCP connection to a backend, meaning that up to ``maxInFlight`` connections to a backend might be needed
to be able to process all accepted queries.
Setting ``maxInFlight`` to a value greater than zero on :func:`newServer` changes that, and up to ``maxInFlight``
queries can be sent to a backend simultaneously over the same TCP connection. This of course requires the
backend to actually process incoming queries out-of-order; otherwise, the latency will be considerably increased,
leading to timeouts and degraded service.

As of 1.6.0, only queries from the same incoming client connection will be sent to a server over a single
outgoing TCP connections. This will likely change in 1.7.0, once we have had time to check that it has no
adverse effects.

Backends for which Proxy Protocol support has been enabled will never be able to reuse the same outgoing TCP
connections for different clients, given that the payload indicating the source IP of the client, as seen by
dnsdist, is sent once at the beginning of the TCP connection. For the same reason, it might not even be possible
to reuse a TCP connection for the same client if any Type-Length-Value data has been sent over that connection.
