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

.. function:: addTLSLocal(address, certFile, keyFile[, options])

  .. versionadded:: 1.3.0

  Listen on the specified address and TCP port for incoming DNS over TLS connections, presenting the specified X.509 certificate.

  :param str address: The IP Address with an optional port to listen on.
                      The default port is 853.
  :param str certFile: The path to a X.509 certificate file in PEM format.
  :param str keyFile: The path to the private key file corresponding to the certificate.
  :param table options: A table with key: value pairs with listen options.

  Options:

  * ``doTCP=true``: bool - Also bind on TCP on ``address``.
  * ``reusePort=false``: bool - Set the ``SO_REUSEPORT`` socket option.
  * ``tcpFastOpenSize=0``: int - Set the TCP Fast Open queue size, enabling TCP Fast Open when available and the value is larger than 0.
  * ``interface=""``: str - Set the network interface to use.
  * ``cpus={}``: table - Set the CPU affinity for this listener thread, asking the scheduler to run it on a single CPU id, or a set of CPU ids. This parameter is only available if the OS provides the pthread_setaffinity_np() function.
  * ``provider``: str - The TLS library to use between GnuTLS and OpenSSL, if they were available and enabled at compilation time.
  * ``ciphers``: str - The TLS ciphers to use. The exact format depends on the provider used.
  * ``numberOfTicketsKeys``: int - The maximum number of tickets keys to keep in memory at the same time, if the provider supports it (GnuTLS doesn't, OpenSSL does). Only one key is marked as active and used to encrypt new tickets while the remaining ones can still be used to decrypt existing tickets after a rotation. Default to 5.
  * ``ticketKeyFile``: str - The path to a file from where TLS tickets keys should be loaded, to support RFC 5077. These keys should be rotated often and never written to persistent storage to preserve forward secrecy. The default is to generate a random key. The OpenSSL provider supports several tickets keys to be able to decrypt existing sessions after the rotation, while the GnuTLS provider only supports one key.
  * ``ticketsKeysRotationDelay``: int - Set the delay before the TLS tickets key is rotated, in seconds. Default is 43200 (12h).

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

.. function:: addConsoleACL(netmask)

  .. versionadded:: 1.3.0

  Add a netmask to the existing console ACL, allowing remote clients to connect to the console. Please make sure that encryption
  has been enabled with :func:`setKey` before doing so. The default is to only allow 127.0.0.1/8 and ::1/128.

  :param str netmask: A CIDR netmask, e.g. ``"192.0.2.0/24"``. Without a subnetmask, only the specific address is allowed.

.. function:: controlSocket(address)

  Bind to ``addr`` and listen for a connection for the console. Since 1.3.0 only connections from local users are allowed
  by default, :func:`addConsoleACL` and :func:`setConsoleACL` can be used to enable remote connections. Please make sure
  that encryption has been enabled with :func:`setKey` before doing so.

  :param str address: An IP address with optional port. By default, the port is 5199.

.. function:: inClientStartup()

  Returns true while the console client is parsing the configuration.

.. function:: makeKey()

  Generate and print an encryption key.

.. function:: setConsoleConnectionsLogging(enabled)

  .. versionadded:: 1.2.0

  Whether to log the opening and closing of console connections.

  :param bool enabled: Default to true.

.. function:: setKey(key)

  Use ``key`` as shared secret between the client and the server

  :param str key: An encoded key, as generated by :func:`makeKey`

.. function:: setConsoleACL(netmasks)

  .. versionadded:: 1.3.0

  Remove the existing console ACL and add the netmasks from the table, allowing remote clients to connect to the console. Please make sure that encryption
  has been enabled with :func:`setKey` before doing so.

  :param {str} netmasks: A table of CIDR netmask, e.g. ``{"192.0.2.0/24", "2001:DB8:14::/56"}``. Without a subnetmask, only the specific address is allowed.

.. function:: showConsoleACL()

  Print a list of all netmasks allowed to connect to the console.

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

  Add a netmask to the existing ACL controlling which clients can send UDP and TCP queries. See :ref:`ACL` for more information.

  :param str netmask: A CIDR netmask, e.g. ``"192.0.2.0/24"``. Without a subnetmask, only the specific address is allowed.

.. function:: setACL(netmasks)

  Remove the existing ACL and add the netmasks from the table of those allowed to send UDP and TCP queries. See :ref:`ACL` for more information.

  :param {str} netmasks: A table of CIDR netmask, e.g. ``{"192.0.2.0/24", "2001:DB8:14::/56"}``. Without a subnetmask, only the specific address is allowed.

.. function:: showACL()

  Print a list of all netmasks allowed to send queries over UDP and TCP. See :ref:`ACL` for more information.

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
      checkClass=NUM,        -- Use NUM as QCLASS in the health-check query, default: DNSClass.IN
      checkName=STRING,      -- Use STRING as QNAME in the health-check query, default: "a.root-servers.net."
      checkType=STRING,      -- Use STRING as QTYPE in the health-check query, default: "A"
      setCD=BOOL,            -- Set the CD (Checking Disabled) flag in the health-check query, default: false
      maxCheckFailures=NUM,  -- Allow NUM check failures before declaring the backend down, default: 1
      mustResolve=BOOL,      -- Set to true when the health check MUST return a NOERROR RCODE and an answer
      useClientSubnet=BOOL,  -- Add the client's IP address in the EDNS Client Subnet option when forwarding the query to this backend
      source=STRING,         -- The source address or interface to use for queries to this backend, by default this is left to the kernel's address selection
                             -- The following formats are supported:
                             --   "address", e.g. "192.0.2.2"
                             --   "interface name", e.g. "eth0"
                             --   "address@interface", e.g. "192.0.2.2@eth0"
      addXPF=NUM,            -- Add the client's IP address and port to the query, along with the original destination address and port,
                             -- using the experimental XPF record from `draft-bellis-dnsop-xpf <https://datatracker.ietf.org/doc/draft-bellis-dnsop-xpf/>`_ and the specified option code. Default is disabled (0)
      sockets=NUM            -- Number of sockets (and thus source ports) used toward the backend server, defaults to a single one
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

  .. method:: Server:addPool(pool)

    Add this server to a pool.

    :param str pool: The pool to add the server to

  .. method:: Server:getName() -> string

    Get the name of this server.

    :returns: The name of the server, or an empty string if it does not have one

  .. method:: Server:getNameWithAddr() -> string

    Get the name plus IP address and port of the server

    :returns: A string containing the server name if any plus the server address and port

  .. method:: Server:getOutstanding() -> int

    Get the number of outstanding queries for this server.

    :returns: The number of outstanding queries

  .. method:: Server:isUp() -> bool

    Returns the up status of the server

    :returns: true when the server is up, false otherwise

  .. method:: Server:rmPool(pool)

    Removes the server from the named pool

    :param str pool: The pool to remove the server from

  .. method:: Server:setAuto([status])

    .. versionchanged:: 1.3.0
        ``status`` optional parameter added.

    Set the server in the default auto state.
    This will enable health check queries that will set the server ``up`` and ``down`` appropriately.

    :param bool status: Set the initial status of the server to ``up`` (true) or ``down`` (false) instead of using the last known status

  .. method:: Server:setQPS(limit)

    Limit the queries per second for this server.

    :param int limit: The maximum number of queries per second

  .. method:: Server:setDown()

    Set the server in an ``DOWN`` state.
    The server will not receive queries and the health checks are disabled

  .. method:: Server:setUp()

    Set the server in an ``UP`` state.
    This server will still receive queries and health checks are disabled

  Apart from the functions, a :class:`Server` object has these attributes:

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

  .. method:: ServerPool:getCache() -> PacketCache

    Returns the :class:`PacketCache` for this pool or nil.

  .. method:: ServerPool:getECS()

    .. versionadded:: 1.3.0

    Whether dnsdist will add EDNS Client Subnet information to the query before looking up into the cache,
    when all servers from this pool are down. For more information see :meth:`ServerPool:setECS`.

  .. method:: ServerPool:setCache(cache)

    Adds ``cache`` as the pool's cache.

    :param PacketCache cache: The new cache to add to the pool

  .. method:: ServerPool:unsetCache()

    Removes the cache from this pool.

  .. method:: ServerPool:setECS()

    .. versionadded:: 1.3.0

    Set to true if dnsdist should add EDNS Client Subnet information to the query before looking up into the cache,
    when all servers from this pool are down. If at least one server is up, the preference of the
    selected server is used, this parameter is only useful if all the backends in this pool are down
    and have EDNS Client Subnet enabled, since the queries in the cache will have been inserted with
    ECS information. Default is false.

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

  .. method:: PacketCache:expunge(n)

    Remove entries from the cache, leaving at most ``n`` entries

    :param int n: Number of entries to keep

  .. method:: PacketCache:expungeByName(name [, qtype=dnsdist.ANY[, suffixMatch=false]])

    .. versionchanged:: 1.2.0
      ``suffixMatch`` parameter added.

    Remove entries matching ``name`` and type from the cache.

    :param DNSName name: The name to expunge
    :param int qtype: The type to expunge
    :param bool suffixMatch: When set to true, remove al entries under ``name``

  .. method:: PacketCache:isFull() -> bool

    Return true if the cache has reached the maximum number of entries.

  .. method:: PacketCache:printStats()

    Print the cache stats (hits, misses, deferred lookups and deferred inserts).

  .. method:: PacketCache:purgeExpired(n)

    Remove expired entries from the cache until there is at most ``n`` entries remaining in the cache.

    :param int n: Number of entries to keep

  .. method:: PacketCache:toString() -> string

    Return the number of entries in the Packet Cache, and the maximum number of entries

Client State
------------

Also called frontend or bind, the Client State object returned by :func:`getBind` and listed with :func:`showBinds` represents an address and port dnsdist is listening on.

.. function:: getBind(index) -> ClientState

  Return a :class:`ClientState` object.

  :param int index: The object index

ClientState functions
~~~~~~~~~~~~~~~~~~~~~

.. class:: ClientState

  This object represents an address and port dnsdist is listening on. When ``reuseport`` is in use, several ClientState objects can be present for the same address and port.

  .. method:: ClientState:attachFilter(filter)

     Attach a BPF filter to this frontend.

     :param BPFFilter filter: The filter to attach to this frontend

  .. method:: ClientState:detachFilter()

     Remove the BPF filter associated to this frontend, if any.

  .. method:: ClientState:toString() -> string

    Return the address and port this frontend is listening on.

    :returns: The address and port this frontend is listening on

  .. attribute:: ClientState.muted

    If set to true, queries received on this frontend will be normally processed and sent to a backend if needed, but no response will be ever be sent to the client over UDP. TCP queries are processed normally and responses sent to the client.

Status, Statistics and More
---------------------------

.. function:: dumpStats()

  Print all statistics dnsdist gathers

.. function:: getTLSContext(idx)

  .. versionadded:: 1.3.0

  Return the TLSContext object for the context of index ``idx``.

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

.. function:: showTLSContexts()

  .. versionadded:: 1.3.0

  Print the list of all availables DNS over TLS contexts.

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

DynBlockRulesGroup
~~~~~~~~~~~~~~~~~~

Instead of using several `exceed*()` lines, dnsdist 1.3.0 introduced a new `DynBlockRulesGroup` object
which can be used to group dynamic block rules.

See :doc:`../guides/dynblocks` for more information about the case where using a `DynBlockRulesGroup` might be
faster than the existing rules.

.. function:: dynBlockRulesGroup() -> DynBlockRulesGroup

  .. versionaddeded:: 1.3.0

  Creates a new :class:`DynBlockRulesGroup` object.

.. class:: DynBlockRulesGroup

  Represents a group of dynamic block rules.

  .. method:: DynBlockRulesGroup:setQueryRate(rate, seconds, reason, blockingTime [, action])

    Adds a query rate-limiting rule, equivalent to:
    ```
    addDynBlocks(exceedQRate(rate, seconds), reason, blockingTime, action)
    ```

    :param int rate: Number of queries per second to exceed
    :param int seconds: Number of seconds the rate has been exceeded
    :param string reason: The message to show next to the blocks
    :param int blockingTime: The number of seconds this block to expire
    :param int action: The action to take when the dynamic block matches, see :ref:`here <DNSAction>`. (default to the one set with :func:`setDynBlocksAction`)

  .. method:: DynBlockRulesGroup:setRCodeRate(rcode, rate, seconds, reason, blockingTime [, action])

    Adds a rate-limiting rule for responses of code ``rcode``, equivalent to:
    ```
    addDynBlocks(exceedServfails(rcode, rate, seconds), reason, blockingTime, action)
    ```

    :param int rcode: The response code
    :param int rate: Number of responses per second to exceed
    :param int seconds: Number of seconds the rate has been exceeded
    :param string reason: The message to show next to the blocks
    :param int blockingTime: The number of seconds this block to expire
    :param int action: The action to take when the dynamic block matches, see :ref:`here <DNSAction>`. (default to the one set with :func:`setDynBlocksAction`)

  .. method:: DynBlockRulesGroup:setQTypeRate(qtype, rate, seconds, reason, blockingTime [, action])

    Adds a rate-limiting rule for queries of type ``qtype``, equivalent to:
    ```
    addDynBlocks(exceedQTypeRate(type, rate, seconds), reason, blockingTime, action)
    ```

    :param int qtype: The qtype
    :param int rate: Number of queries per second to exceed
    :param int seconds: Number of seconds the rate has been exceeded
    :param string reason: The message to show next to the blocks
    :param int blockingTime: The number of seconds this block to expire
    :param int action: The action to take when the dynamic block matches, see :ref:`here <DNSAction>`. (default to the one set with :func:`setDynBlocksAction`)

  .. method:: DynBlockRulesGroup:setRespByteRate(rate, seconds, reason, blockingTime [, action])

    Adds a bandwidth rate-limiting rule for responses, equivalent to:
    ```
    addDynBlocks(exceedRespByterate(rate, seconds), reason, blockingTime, action)
    ```

    :param int rate: Number of bytes per second to exceed
    :param int seconds: Number of seconds the rate has been exceeded
    :param string reason: The message to show next to the blocks
    :param int blockingTime: The number of seconds this block to expire
    :param int action: The action to take when the dynamic block matches, see :ref:`here <DNSAction>`. (default to the one set with :func:`setDynBlocksAction`)

  .. method:: DynBlockRulesGroup:apply()

    Walk the in-memory query and response ring buffers and apply the configured rate-limiting rules, adding dynamic blocks when the limits have been exceeded.

Other functions
---------------

.. function:: maintenance()

  If this function exists, it is called every second to so regular tasks.
  This can be used for e.g. :doc:`Dynamic Blocks <../guides/dynblocks>`.

TLSContext
~~~~~~~~~~

.. class:: TLSContext

  .. versionadded:: 1.3.0

  This object represents an address and port dnsdist is listening on for DNS over TLS queries.

  .. method:: TLSContext:rotateTicketsKey()

     Replace the current TLS tickets key by a new random one.

  .. method:: TLSContext:loadTicketsKeys(ticketsKeysFile)

     Load new tickets keys from the selected file, replacing the existing ones. These keys should be rotated often and never written to persistent storage to preserve forward secrecy. The default is to generate a random key. The OpenSSL provider supports several tickets keys to be able to decrypt existing sessions after the rotation, while the GnuTLS provider only supports one key.

    :param str ticketsKeysFile: The path to a file from where TLS tickets keys should be loaded.
