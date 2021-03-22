Performance Tuning
==================

First, a few words about :program:`dnsdist` architecture:

 * Each local bind has its own thread listening for incoming UDP queries
 * and its own thread listening for incoming TCP connections, dispatching them right away to a pool of threads
 * Each backend has its own thread listening for UDP responses, including the ones triggered by DoH queries, if any
 * A maintenance thread calls the maintenance() Lua function every second if any, and is responsible for cleaning the cache
 * A health check thread checks the backends availability
 * A control thread handles console connections
 * A carbon thread exports statistics to carbon servers if needed
 * One or more webserver threads handle queries to the internal webserver

TCP and DNS over TLS
--------------------

The maximum number of threads in the TCP / DNS over TLS pool is controlled by the :func:`setMaxTCPClientThreads` directive, and defaults to 10.
This number can be increased to handle a large number of simultaneous TCP / DNS over TLS connections.
If all the TCP threads are busy, new TCP connections are queued while they wait to be picked up.
Before 1.4.0, a TCP thread could only handle a single incoming connection at a time. Starting with 1.4.0 the handling of TCP connections is now event-based, so a single TCP worker can handle a large number of TCP incoming connections simultaneously.
Note that before 1.6.0 the TCP worker threads were created at runtime, adding a new thread when the existing ones seemed to struggle with the load, until the maximum number of threads had been reached. Starting with 1.6.0 the configured number of worker threads are immediately created at startup.

The maximum number of queued connections can be configured with :func:`setMaxTCPQueuedConnections` and defaults to 1000 (10000 on Linux since 1.6.0). Note that the size of the internal pipe used to distribute queries might need to be increased as well, using :func:`setTCPInternalPipeBufferSize`.
Any value larger than 0 will cause new connections to be dropped if there are already too many queued.
By default, every TCP worker thread has its own queue, and the incoming TCP connections are dispatched to TCP workers on a round-robin basis.
This might cause issues if some connections are taking a very long time, since incoming ones will be waiting until the TCP worker they have been assigned to has finished handling its current query, while other TCP workers might be available.

The experimental :func:`setTCPUseSinglePipe` directive can be used so that all the incoming TCP connections are put into a single queue and handled by the first TCP worker available. This used to be useful before 1.4.0 because a single connection could block a TCP worker, but the "one pipe per TCP worker" is preferable now that workers can handle multiple connections to prevent waking up all idle workers when a new connection arrives.

Rules and Lua
-------------

Most of the query processing is done in C++ for maximum performance, but some operations are executed in Lua for maximum flexibility:

 * Rules added by :func:`LuaAction`, :func:`LuaResponseAction`, :func:`LuaFFIAction` or :func:`LuaFFIResponseAction`
 * Server selection policies defined via :func:`setServerPolicyLua`, :func:`setServerPolicyLuaFFI`, :func:`setServerPolicyLuaFFIPerThread` or :func:`newServerPolicy`

While Lua is fast, its use should be restricted to the strict necessary in order to achieve maximum performance, it might be worth considering using LuaJIT instead of Lua.
When Lua inspection is needed, the best course of action is to restrict the queries sent to Lua inspection by using :func:`addLuaAction` with a selector.

UDP and DNS over HTTPS
-----------------------

:program:`dnsdist` design choices mean that the processing of UDP and DNS over HTTPS queries is done by only one thread per local bind.
This is great to keep lock contention to a low level, but might not be optimal for setups using a lot of processing power, caused for example by a large number of complicated rules.
To be able to use more CPU cores for UDP queries processing, it is possible to use the ``reusePort`` parameter of the :func:`addLocal` and :func:`setLocal` directives to be able to add several identical local binds to dnsdist::

  addLocal("192.0.2.1:53", {reusePort=true})
  addLocal("192.0.2.1:53", {reusePort=true})
  addLocal("192.0.2.1:53", {reusePort=true})
  addLocal("192.0.2.1:53", {reusePort=true})

:program:`dnsdist` will then add four identical local binds as if they were different IPs or ports, start four threads to handle incoming queries and let the kernel load balance those randomly to the threads, thus using four CPU cores for rules processing.
Note that this require ``SO_REUSEPORT`` support in the underlying operating system (added for example in Linux 3.9).
Please also be aware that doing so will increase lock contention and might not therefore scale linearly, as discussed below.

Another possibility is to use the reuseport option to run several dnsdist processes in parallel on the same host, thus avoiding the lock contention issue at the cost of having to deal with the fact that the different processes will not share informations, like statistics or DDoS offenders.

The UDP threads handling the responses from the backends do not use a lot of CPU, but if needed it is also possible to add the same backend several times to the dnsdist configuration to distribute the load over several responder threads::

  newServer({address="192.0.2.127:53", name="Backend1"})
  newServer({address="192.0.2.127:53", name="Backend2"})
  newServer({address="192.0.2.127:53", name="Backend3"})
  newServer({address="192.0.2.127:53", name="Backend4"})

For DNS over HTTPS, every :func:`addDOHLocal` directive adds a new thread dealing with incoming connections, so it might be useful to add more than one directive, as indicated above.

When dealing with a large traffic load, it might happen that the internal pipe used to pass queries between the threads handling the incoming connections and the one getting a response from the backend become full too quickly, degrading performance and causing timeouts. This can be prevented by increasing the size of the internal pipe buffer, via the `internalPipeBufferSize` option of :func:`addDOHLocal`. Setting a value of `1048576` is known to yield good results on Linux.

When dispatching UDP queries to backend servers, dnsdist keeps track of at most **n** outstanding queries for each backend.
This number **n** can be tuned by the :func:`setMaxUDPOutstanding` directive, defaulting to 65535 which is the maximum value.

.. versionchanged:: 1.4.0
  The default was 10240 before 1.4.0

Large installations running dnsdist before 1.4.0 are advised to increase the default value at the cost of a slightly increased memory usage.

Lock contention and sharding
----------------------------

Adding more threads makes it possible to use more CPU cores to deal with the load, but at the cost of possibly increasing lock contention between threads. This is especially true for Lua-intensive setups, because Lua processing in dnsdist is serialized by a unique lock for all threads.
For other components, like the packet cache and the in-memory ring buffers, it is possible to reduce the amount of contention by using sharding. Sharding divides the memory into several pieces, every one of these having its own separate lock, reducing the amount of times two threads or more will need to access the same data.
Sharding was disabled by default before 1.6.0 and could be enabled via the `numberOfShards` option to :func:`newPacketCache` and :func:`setRingBuffersSize`. It might still make sense to increment the number of shards when dealing with a lot of threads.
