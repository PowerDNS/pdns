.. highlight:: lua

Configuration Reference
=======================

This page lists all configuration options for dnsdist.

.. note::

  When an IPv6 IP:PORT combination is needed, the bracketed syntax from :rfc:`RFC 3986 <3986#section-3.2.2>` should be used.
  e.g. "[2001:DB8:14::C0FF:FEE]:5300".

Functions and Types
-------------------

Within dnsdist several core object types exist:

* :class:`Server`: generated with :func:`newServer`, represents a downstream server
* :class:`ComboAddress`: represents an IP address and port
* :class:`DNSName`: represents a domain name
* :class:`NetmaskGroup`: represents a group of netmasks
* :class:`QPSLimiter`: implements a QPS-based filter
* :class:`SuffixMatchNode`: represents a group of domain suffixes for rapid testing of membership
* :class:`DNSHeader`: represents the header of a DNS packet
* :class:`ClientState`: sometimes also called Bind or Frontend, represents the addresses and ports dnsdist is listening on

The existence of most of these objects can mostly be ignored, unless you plan to write your own hooks and policies, but it helps to understand an expressions like:

.. code-block:: lua

  getServer(0).order=12         -- set order of server 0 to 12
  getServer(0):addPool("abuse") -- add this server to the abuse pool

The ``.`` means ``order`` is a data member, while the ``:`` means ``addPool`` is a member function.

Global configuration
--------------------

.. function:: includeDirectory(path)

  Include configuration files from ``path``.

  :param str path: The directory to load the configuration from

Listen Sockets
~~~~~~~~~~~~~~

.. function:: addLocal(address[, options])

  .. versionadded:: 1.2.0

  Add to the list of listen addresses.

  :param str address: The IP Address with an optional port to listen on.
                      The default port is 53.
  :param table options: A table with key: value pairs with listen options.

  Options:

  * ``doTCP=true``: bool - Also bind on TCP on ``address``.
  * ``reusePort=false``: bool - Set the ``SO_REUSEPORT`` socket option.
  * ``tcpFastOpenSize=0``: int - Set the TCP Fast Open queue size, enabling TCP Fast Open when available and the value is larger than 0.
  * ``interface=""``: str - Set the network interface to use.
  * ``cpus={}``: table - Set the CPU affinity for this listener thread, asking the scheduler to run it on a single CPU id, or a set of CPU ids. This parameter is only available if the OS provides the pthread_setaffinity_np() function.

  .. code-block:: lua

    addLocal('0.0.0.0:5300', { doTCP=true, reusePort=true })

  This will bind to both UDP and TCP on port 5300 with SO_REUSEPORT enabled.

.. function:: addLocal(address[[[,do_tcp], so_reuseport], tcp_fast_open_qsize])

  .. deprecated:: 1.2.0

  Add to the list of addresses listened on.

  :param str address: The IP Address with an optional port to listen on.
                      The default port is 53.
  :param bool do_tcp: Also bind a TCP port on ``address``, defaults to true.
  :param bool so_reuseport: Use ``SO_REUSEPORT`` if it is available, defaults to false
  :param int tcp_fast_open_qsize: The size of the TCP Fast Open queue. Set to a number
                                  higher than 0 to enable TCP Fast Open when available.
                                  Default is 0.

.. function:: setLocal(address[, options])

  .. versionadded:: 1.2.0

  Remove the list of listen addresses and add a new one.

  :param str address: The IP Address with an optional port to listen on.
                      The default port is 53.
  :param table options: A table with key: value pairs with listen options.

  The options that can be set are the same as :func:`addLocal`.

.. function:: setLocal(address[[[,do_tcp], so_reuseport], tcp_fast_open_qsize])

  .. deprecated:: 1.2.0

  Remove the list of listen addresses and add a new one.

  :param str address: The IP Address with an optional port to listen on.
                      The default port is 53.
  :param bool do_tcp: Also bind a TCP port on ``address``, defaults to true.
  :param bool so_reuseport: Use ``SO_REUSEPORT`` if it is available, defaults to false
  :param int tcp_fast_open_qsize: The size of the TCP Fast Open queue. Set to a number
                                  higher than 0 to enable TCP Fast Open when available.
                                  Default is 0.

Control Socket, Console and Webserver
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. function:: controlSocket(address)

  Bind to ``addr`` and listen for a connection for the console

  :param str address: An IP address with optional port. By default, the port is 5199.

.. function:: makeKey()

  Generate and print an encryption key.

.. function:: setConsoleConnectionsLogging(enabled)

  .. versionadded:: 1.2.0

  Whether to log the opening and closing of console connections.

  :param bool enabled: Default to true.

.. function:: setKey(key)

  Use ``key`` as shared secret between the client and the server

  :param str key: An encoded key, as generated by :func:`makeKey`

.. function:: testCrypto()

  Test the crypto code, will report errors when something is not ok.

Webserver
~~~~~~~~~

.. function:: webServer(listen_address, password[, apikey[, custom_headers]])

  Launch the :doc:`../guides/webserver` with statistics and the API.

  :param str listen_address: The IP address and Port to listen on
  :param str password: The password required to access the webserver
  :param str apikey: The key required to access the API
  :param {[str]=str,...} custom_headers: Allows setting custom headers and removing the defaults

.. function:: setAPIWritable(allow [,dir])

  Allow modifications via the API.
  Optionally saving these changes to disk.
  Modifications done via the API will not be written to the configuration by default and will not persist after a reload

  :param bool allow: Set to true to allow modification through the API
  :param str dir: A valid directory where the configuration files will be written by the API.

Access Control Lists
~~~~~~~~~~~~~~~~~~~~

.. function:: addACL(netmask)

  Add a netmask to the existing ACL

  :param str netmask: A CIDR netmask, e.g. ``"192.0.2.0/24"``. Without a subnetmask, only the specific address is allowed.

.. function:: setACL(netmasks)

  Remove the existing ACL and add the netmasks from the table.

  :param {str} netmasks: A table of CIDR netmask, e.g. ``{"192.0.2.0/24", "2001:DB8:14::/56"}``. Without a subnetmask, only the specific address is allowed.

EDNS Client Subnet
~~~~~~~~~~~~~~~~~~

.. function:: setECSSourcePrefixV4(prefix)

  When ``useClientSubnet`` in :func:`newServer` is set and dnsdist adds an EDNS Client Subnet Client option to the query, truncate the requestors IPv4 address to ``prefix`` bits

  :param int prefix: The prefix length

.. function:: setECSSourcePrefixV6(prefix)

  When ``useClientSubnet`` in :func:`newServer` is set and dnsdist adds an EDNS Client Subnet Client option to the query, truncate the requestor's IPv6 address to  bits

  :param int prefix: The prefix length

Ringbuffers
~~~~~~~~~~~

.. function:: setRingBuffersSize(num)

  Set the capacity of the ringbuffers used for live traffic inspection to ``num``

  :param int num: The maximum amount of queries to keep in the ringbuffer. Defaults to 10000

Servers
-------

.. function:: newServer(server_string)
              newServer(server_table)

  Add a new backend server. Call this function with either a string::

    newServer(
      "IP:PORT" -- IP and PORT of the backend server
    )

  or a table::

    newServer({
      address="IP:PORT",     -- IP and PORT of the backend server (mandatory)
      qps=NUM,               -- Limit the number of queries per second to NUM, when using the `firstAvailable` policy
      order=NUM,             -- The order of this server, used by the `leastOustanding` and `firstAvailable` policies
      weight=NUM,            -- The weight of this server, used by the `wrandom` and `whashed` policies
      pool=STRING|{STRING},  -- The pools this server belongs to (unset or empty string means default pool) as a string or table of strings
      retries=NUM,           -- The number of TCP connection attempts to the backend, for a given query
      tcpConnectTimeout=NUM, -- The timeout (in seconds) of a TCP connection attempt
      tcpSendTimeout=NUM,    -- The timeout (in seconds) of a TCP write attempt
      tcpRecvTimeout=NUM,    -- The timeout (in seconds) of a TCP read attempt
      tcpFastOpen=BOOL,      -- Whether to enable TCP Fast Open
      ipBindAddrNoPort=BOOL, -- Whether to enable IP_BIND_ADDRESS_NO_PORT if available, default: true
      name=STRING,           -- The name associated to this backend, for display purpose
      checkName=STRING,      -- Use STRING as QNAME in the health-check query, default: "a.root-servers.net."
      checkType=STRING,      -- Use STRING as QTYPE in the health-check query, default: "A"
      setCD=BOOL,            -- Set the CD (Checking Disabled) flag in the health-check query, default: false
      maxCheckFailures=NUM,  -- Allow NUM check failures before declaring the backend down, default: false
      mustResolve=BOOL,      -- Set to true when the health check MUST return a NOERROR RCODE and an answer
      useClientSubnet=BOOL,  -- Add the client's IP address in the EDNS Client Subnet option when forwarding the query to this backend
      source=STRING          -- The source address or interface to use for queries to this backend, by default this is left to the kernel's address selection
                             -- The following formats are supported:
                             --   "address", e.g. "192.0.2.2"
                             --   "interface name", e.g. "eth0"
                             --   "address@interface", e.g. "192.0.2.2@eth0"
    })

  :param str server_string: A simple IP:PORT string.
  :param table server_table: A table with at least a 'name' key

.. function:: getServer(index) -> Server

  Get a :class:`Server`

  :param int index: The number of the server (as seen in :func:`showServers`).
  :returns:  The :class:`Server` object or nil

.. function:: getServers()

  Returns a table with all defined servers.

.. function:: rmServer(index)
              rmServer(server)

  Remove a backend server.

  :param int index: The number of the server (as seen in :func:`showServers`).
  :param Server server: A :class:`Server` object as returned by e.g. :func:`getServer`.

Server Functions
~~~~~~~~~~~~~~~~
A server object returned by :func:`getServer` can be manipulated with these functions.

.. class:: Server

  This object represents a backend server. It has several methods.

.. classmethod:: Server:addPool(pool)

  Add this server to a pool.

  :param str pool: The pool to add the server to

.. classmethod:: Server:getName() -> string

  Get the name of this server.

  :returns: The name of the server, or an empty string if it does not have one

.. classmethod:: Server:getNameWithAddr() -> string

  Get the name plus IP address and port of the server

  :returns: A string containing the server name if any plus the server address and port

.. classmethod:: Server:getOutstanding() -> int

  Get the number of outstanding queries for this server.

  :returns: The number of outstanding queries

.. classmethod:: Server:isUp() -> bool

  Returns the up status of the server

  :returns: true when the server is up, false otherwise

.. classmethod:: Server:rmPool(pool)

  Removes the server from the named pool

  :param str pool: The pool to remove the server from

.. classmethod:: Server:setAuto([status])

.. versionchanged:: 1.3.0
    ``status`` optional parameter added.

  Set the server in the default auto state.
  This will enable health check queries that will set the server ``up`` and ``down`` appropriately.

  :param bool status: Set the initial status of the server to ``up`` (true) or ``down`` (false) instead of using the last known status

.. classmethod:: Server:setQPS(limit)

  Limit the queries per second for this server.

  :param int limit: The maximum number of queries per second

.. classmethod:: Server:setDown()

  Set the server in an ``DOWN`` state.
  The server will not receive queries and the health checks are disabled

.. classmethod:: Server:setUp()

  Set the server in an ``UP`` state.
  This server will still receive queries and health checks are disabled

Attributes
~~~~~~~~~~

.. attribute:: Server.name

  The name of the server

.. attribute:: Server.upStatus

  Whether or not this server is up or down

.. attribute:: Server.order

  The order of the server

.. attribute:: Server.weight

  The weight of the server

Pools
-----

:class:`Server`\ s can be part of any number of pools.
Pools are automatically created when a server is added to a pool (with :func:`newServer`), or can be manually created with :func:`addPool`.

.. function:: addPool(name) -> ServerPool

  Returns a :class:`ServerPool`.

  :param string name: The name of the pool to create

.. function:: getPool(name) -> ServerPool

  Returns a :class:`ServerPool` or nil.

  :param string name: The name of the pool

.. function:: rmPool(name)

   Remove the pool named `name`.

  :param string name: The name of the pool to remove

.. function:: getPoolServers(name) -> [ Server ]

  Returns a list of :class:`Server`\ s or nil.

  :param string name: The name of the pool

.. class:: ServerPool

  This represents the pool where zero or more servers are part of.

.. classmethod:: ServerPool:getCache() -> PacketCache

  Returns the :class:`PacketCache` for this pool or nil.

.. classmethod:: ServerPool:setCache(cache)

  Adds ``cache`` as the pool's cache.

  :param PacketCache cache: The new cache to add to the pool

.. classmethod:: ServerPool:unsetCache()

  Removes the cache from this pool.

PacketCache
~~~~~~~~~~~

A Pool can have a packet cache to answer queries directly in stead of going to the backend.
See :doc:`../guides/cache` for a how to.

.. function:: newPacketCache(maxEntries[, maxTTL=86400[, minTTL=0[, temporaryFailureTTL=60[, staleTTL=60[, dontAge=false[, numberOfShards=1[, deferrableInsertLock=true]]]]]]]) -> PacketCache

  .. versionchanged:: 1.2.0
    ``numberOfShard`` and ``deferrableInsertLock`` parameters added.

  Creates a new :class:`PacketCache` with the settings specified.

  :param int maxEntries: The maximum number of entries in this cache
  :param int maxTTL: Cap the TTL for records to his number
  :param int minTTL: Don't cache entries with a TTL lower than this
  :param int temporaryFailureTTL: On a SERVFAIL or REFUSED from the backend, cache for this amount of seconds
  :param int staleTTL: When the backend servers are not reachable, send responses if the cache entry is expired at most this amount of seconds
  :param bool dontAge: Don't reduce TTLs when serving from the cache. Use this when :program:`dnsdist` fronts a cluster of authoritative servers
  :param int numberOfShards: Number of shards to divide the cache into, to reduce lock contention
  :param bool deferrableInsertLock: Whether the cache should give up insertion if the lock is held by another thread, or simply wait to get the lock

.. class:: PacketCache

  Represents a cache that can be part of :class:`ServerPool`.

.. classmethod:: PacketCache:expunge(n)

  Remove entries from the cache, leaving at most ``n`` entries

  :param int n: Number of entries to keep

.. classmethod:: PacketCache:expungeByName(name [, qtype=dnsdist.ANY[, suffixMatch=false]])

  .. versionchanged:: 1.2.0
    ``suffixMatch`` parameter added.

  Remove entries matching ``name`` and type from the cache.

  :param DNSName name: The name to expunge
  :param int qtype: The type to expunge
  :param bool suffixMatch: When set to true, remove al entries under ``name``

.. classmethod:: PacketCache:isFull() -> bool

  Return true if the cache has reached the maximum number of entries.

.. classmethod:: PacketCache:printStats()

  Print the cache stats (hits, misses, deferred lookups and deferred inserts).

.. classmethod:: PacketCache:purgeExpired(n)

  Remove expired entries from the cache until there is at most ``n`` entries remaining in the cache.

  :param int n: Number of entries to keep

.. classmethod:: PacketCache:toString() -> string

  Return the number of entries in the Packet Cache, and the maximum number of entries

Client State
------------

Also called frontend or bind, the Client State object returned by :func:`getBind` and listed with :func:`showBinds` represents an address and port dnsdist is listening on.

.. function:: getBind(index) -> ClientState

  Return a ClientState object.

  :param int index: The object index

ClientState functions
~~~~~~~~~~~~~~~~~~~~~

.. class:: ClientState

  This object represents an address and port dnsdist is listening on. When ``reuseport`` is in use, several ClientState objects can be present for the same address and port.

.. classmethod:: Server:addPool(pool)

  Add this server to a pool.

  :param str pool: The pool to add the server to

.. classmethod:: ClientState:attachFilter(filter)

   Attach a BPF filter to this frontend.

   :param BPFFilter filter: The filter to attach to this frontend

.. classmethod:: ClientState:detachFilter()

   Remove the BPF filter associated to this frontend, if any.

.. classmethod:: ClientState:toString() -> string

  Return the address and port this frontend is listening on.

  :returns: The address and port this frontend is listening on

Attributes
~~~~~~~~~~

.. attribute:: ClientState.muted

  If set to true, queries received on this frontend will be normally processed and sent to a backend if needed, but no response will be ever be sent to the client over UDP. TCP queries are processed normally and responses sent to the client.

Status, Statistics and More
---------------------------

.. function:: dumpStats()

  Print all statistics dnsdist gathers

.. function:: grepq(selector[, num])
              grepq(selectors[, num])

  Prints the last ``num`` queries matching ``selector`` or ``selectors``.

  The selector can be:

  * a netmask (e.g. '192.0.2.0/24')
  * a DNS name (e.g. 'dnsdist.org')
  * a response time (e.g. '100ms')

  :param str selector: Select queries based on this property.
  :param {str} selectors: A lua table of selectors. Only queries matching all selectors are shown
  :param int num: Show a maximum of ``num`` recent queries, default is 10.

.. function:: showACL()

  Print a list of all allowed netmasks.

.. function:: showBinds()

  Print a list of all the current addresses and ports dnsdist is listening on, also called ``frontends``

.. function:: showResponseLatency()

  Show a plot of the response time latency distribution

.. function:: showServers()

  This function shows all backend servers currently configured and some statistics.
  These statics have the following fields:

  * ``#`` - The number of the server, can be used as the argument for :func:`getServer`
  * ``Address`` - The IP address and port of the server
  * ``State`` - The current state of the server
  * ``Qps`` - Current number of queries per second
  * ``Qlim`` - Configured maximum number of queries per second
  * ``Ord`` - The order number of the server
  * ``Wt`` - The weight of the server
  * ``Queries`` - Total amount of queries sent to this server
  * ``Drops`` - Number of queries that were dropped by this server
  * ``Drate`` - Number of queries dropped per second by this server
  * ``Lat`` - The latency of this server in milliseconds
  * ``Pools`` - The pools this server belongs to

.. function:: showTCPStats()

  Show some statistics regarding TCP

.. function:: showVersion()

  Print the version of dnsdist

.. function:: topBandwidth([num])

  Print the top ``num`` clients that consume the most bandwidth.

  :param int num: Number to show, defaults to 10.

.. function:: topClients([num])

  Print the top ``num`` clients sending the most queries over length of ringbuffer

  :param int num: Number to show, defaults to 10.

.. function:: topQueries([num[, labels]])

  Print the ``num`` most popular QNAMEs from queries.
  Optionally grouped by the rightmost ``labels`` DNS labels.

  :param int num: Number to show, defaults to 10
  :param int label: Number of labels to cut down to

.. function:: topResponses([num[, rcode[, labels]]])

  Print the ``num`` most seen responses with an RCODE of ``rcode``.
  Optionally grouped by the rightmost ``labels`` DNS labels.

  :param int num: Number to show, defaults to 10
  :param int rcode: :ref:`Response code <DNSRCode>`, defaults to 0 (No Error)
  :param int label: Number of labels to cut down to

.. function:: topSlow([num[, limit[, labels]]])

  Print the ``num`` slowest queries that are slower than ``limit`` milliseconds.
  Optionally grouped by the rightmost ``labels`` DNS labels.

  :param int num: Number to show, defaults to 10
  :param int limit: Show queries slower than this amount of milliseconds, defaults to 2000
  :param int label: Number of labels to cut down to

.. _dynblocksref:

Dynamic Blocks
--------------

.. function:: addDynBlocks(addresses, message[, seconds=10[, action]])

  .. versionchanged:: 1.2.0
    ``action`` parameter added.

  Block a set of addresses with ``message`` for (optionally) a number of seconds.
  The default number of seconds to block for is 10.

  :param addresses: set of Addresses as returned by an exceed function
  :param string message: The message to show next to the blocks
  :param int seconds: The number of seconds this block to expire
  :param int action: The action to take when the dynamic block matches, see :ref:`here <DNSAction>`. (default to the one set with :func:`setDynBlocksAction`)

.. function:: clearDynBlocks()

  Remove all current dynamic blocks.

.. function:: showDynBlocks()

  List all dynamic blocks in effect.

.. function:: setDynBlocksAction(action)

  Set which action is performed when a query is blocked.
  Only DNSAction.Drop (the default), DNSAction.Refused and DNSAction.Truncate are supported.

.. function:: addBPFFilterDynBlocks(addresses, filter[, seconds])

  Block the set of addresses using the supplied BPF Filter, for seconds seconds (10 by default)

  :param addresses: A set of addresses as returned by the exceed functions.
  :param filter: and EBPF filter
  :param int seconds: Number of seconds to block for

.. _exceedfuncs:

Getting addresses that exceeded parameters
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. function:: exceedServFails(rate, seconds)

  Get set of addresses that exceed ``rate`` servfails/s over ``seconds`` seconds

  :param int rate: Number of Servfails per second to exceed
  :param int seconds: Number of seconds the rate has been exceeded

.. function:: exceedNXDOMAINs(rate, seconds)

  get set of addresses that exceed ``rate`` NXDOMAIN/s over ``seconds`` seconds

  :param int rate: Number of NXDOMAIN per second to exceed
  :param int seconds: Number of seconds the rate has been exceeded

.. function:: exceedRespByterate(rate, seconds)

  get set of addresses that exceeded ``rate`` bytes/s answers over ``seconds`` seconds

  :param int rate: Number of bytes per second to exceed
  :param int seconds: Number of seconds the rate has been exceeded

.. function:: exceedQRate(rate, seconds)

  Get set of address that exceed ``rate`` queries/s over ``seconds`` seconds

  :param int rate: Number of queries per second to exceed
  :param int seconds: Number of seconds the rate has been exceeded

.. function:: exceedQTypeRate(type, rate, seconds)

  Get set of address that exceed ``rate`` queries/s for queries of QType ``type`` over ``seconds`` seconds

  :param int type: QType
  :param int rate: Number of QType queries per second to exceed
  :param int seconds: Number of seconds the rate has been exceeded

Other functions
---------------

.. function:: maintenance()

  If this function exists, it is called every second to so regular tasks.
  This can be used for e.g. :doc:`Dynamic Blocks <../guides/dynblocks>`.
