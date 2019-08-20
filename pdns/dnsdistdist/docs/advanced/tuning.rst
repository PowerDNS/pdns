Performance Tuning
==================

First, a few words about :program:`dnsdist` architecture:

 * Each local bind has its own thread listening for incoming UDP queries
 * and its own thread listening for incoming TCP connections, dispatching them right away to a pool of threads
 * Each backend has its own thread listening for UDP responses
 * A maintenance thread calls the maintenance() Lua function every second if any, and is responsible for cleaning the cache
 * A health check thread checks the backends availability
 * A control thread handles console connections
 * A carbon thread exports statistics to carbon servers if needed
 * One or more webserver threads handle queries to the internal webserver

The maximum number of threads in the TCP pool is controlled by the :func:`setMaxTCPClientThreads` directive, and defaults to 10.
This number can be increased to handle a large number of simultaneous TCP connections.
If all the TCP threads are busy, new TCP connections are queued while they wait to be picked up.
Before 1.4.0, a TCP thread could only handle a single incoming connection at a time. Starting with 1.4.0 the handling of TCP connections is now event-based, so a single TCP worker can handle a large number of TCP incoming connections simultaneously.

The maximum number of queued connections can be configured with :func:`setMaxTCPQueuedConnections` and defaults to 1000.
Any value larger than 0 will cause new connections to be dropped if there are already too many queued.
By default, every TCP worker thread has its own queue, and the incoming TCP connections are dispatched to TCP workers on a round-robin basis.
This might cause issues if some connections are taking a very long time, since incoming ones will be waiting until the TCP worker they have been assigned to has finished handling its current query, while other TCP workers might be available.

The experimental :func:`setTCPUseSinglePipe` directive can be used so that all the incoming TCP connections are put into a single queue and handled by the first TCP worker available.

When dispatching UDP queries to backend servers, dnsdist keeps track of at most **n** outstanding queries for each backend.
This number **n** can be tuned by the :func:`setMaxUDPOutstanding` directive, defaulting to 10240 (65535 since 1.4.0), with a maximum value of 65535.
Large installations are advised to increase the default value at the cost of a slightly increased memory usage.

Most of the query processing is done in C++ for maximum performance, but some operations are executed in Lua for maximum flexibility:

 * Rules added by :func:`addLuaAction`
 * Server selection policies defined via :func:`setServerPolicyLua` or :func:`newServerPolicy`

While Lua is fast, its use should be restricted to the strict necessary in order to achieve maximum performance, it might be worth considering using LuaJIT instead of Lua.
When Lua inspection is needed, the best course of action is to restrict the queries sent to Lua inspection by using :func:`addLuaAction` with a selector.

:program:`dnsdist` design choices mean that the processing of UDP queries is done by only one thread per local bind.
This is great to keep lock contention to a low level, but might not be optimal for setups using a lot of processing power, caused for example by a large number of complicated rules.
To be able to use more CPU cores for UDP queries processing, it is possible to use the ``reusePort`` parameter of the :func:`addLocal` and :func:`setLocal` directives to be able to add several identical local binds to dnsdist::

  addLocal("192.0.2.1:53", {reusePort=true})
  addLocal("192.0.2.1:53", {reusePort=true})
  addLocal("192.0.2.1:53", {reusePort=true})
  addLocal("192.0.2.1:53", {reusePort=true})

:program:`dnsdist` will then add four identical local binds as if they were different IPs or ports, start four threads to handle incoming queries and let the kernel load balance those randomly to the threads, thus using four CPU cores for rules processing.
Note that this require ``SO_REUSEPORT`` support in the underlying operating system (added for example in Linux 3.9).
Please also be aware that doing so will increase lock contention and might not therefore scale linearly.
This is especially true for Lua-intensive setups, because Lua processing in dnsdist is serialized by an unique lock for all threads.

Another possibility is to use the reuseport option to run several dnsdist processes in parallel on the same host, thus avoiding the lock contention issue at the cost of having to deal with the fact that the different processes will not share informations, like statistics or DDoS offenders.

The UDP threads handling the responses from the backends do not use a lot of CPU, but if needed it is also possible to add the same backend several times to the dnsdist configuration to distribute the load over several responder threads::

  newServer({address="192.0.2.127:53", name="Backend1"})
  newServer({address="192.0.2.127:53", name="Backend2"})
  newServer({address="192.0.2.127:53", name="Backend3"})
  newServer({address="192.0.2.127:53", name="Backend4"})
