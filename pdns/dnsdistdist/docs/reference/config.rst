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
* :class:`Netmask`: represents a netmask
* :class:`NetmaskGroup`: represents a group of netmasks
* :class:`QPSLimiter`: implements a QPS-based filter
* :class:`SuffixMatchNode`: represents a group of domain suffixes for rapid testing of membership
* :class:`DNSHeader`: represents the header of a DNS packet, see :ref:`DNSHeader`
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

  :param str path: The directory to load configuration files from. Each file must end in ``.conf``.

.. function:: reloadAllCertificates()

  .. versionadded:: 1.4.0

  Reload all DNSCrypt and TLS certificates, along with their associated keys.

.. function:: setSyslogFacility(facility)

  .. versionadded:: 1.4.0

  .. versionchanged:: 1.6.0
    ``facility`` can now be a string.

  Set the syslog logging facility to ``facility``.

  :param int or str facility: The new facility as a numeric value (raw value as defined in syslog.h), or as a case-insensitive string ("LOCAL0", or "daemon", for example). Defaults to LOG_DAEMON.

Listen Sockets
~~~~~~~~~~~~~~

.. function:: addLocal(address[, options])

  .. versionchanged:: 1.4.0
    Removed ``doTCP`` from the options. A listen socket on TCP is always created.

  .. versionchanged:: 1.5.0
    Added ``tcpListenQueueSize`` parameter.

  .. versionchanged:: 1.6.0
    Added ``maxInFlight`` and ``maxConcurrentTCPConnections`` parameters.

  Add to the list of listen addresses.

  :param str address: The IP Address with an optional port to listen on.
                      The default port is 53.
  :param table options: A table with key: value pairs with listen options.

  Options:

  * ``doTCP=true``: bool - Also bind on TCP on ``address``. Removed in 1.4.0.
  * ``reusePort=false``: bool - Set the ``SO_REUSEPORT`` socket option.
  * ``tcpFastOpenQueueSize=0``: int - Set the TCP Fast Open queue size, enabling TCP Fast Open when available and the value is larger than 0.
  * ``interface=""``: str - Set the network interface to use.
  * ``cpus={}``: table - Set the CPU affinity for this listener thread, asking the scheduler to run it on a single CPU id, or a set of CPU ids. This parameter is only available if the OS provides the pthread_setaffinity_np() function.
  * ``tcpListenQueueSize=SOMAXCONN``: int - Set the size of the listen queue. Default is ``SOMAXCONN``.
  * ``maxInFlight=0``: int - Maximum number of in-flight queries. The default is 0, which disables out-of-order processing.
  * ``maxConcurrentTCPConnections=0``: int - Maximum number of concurrent incoming TCP connections. The default is 0 which means unlimited.

  .. code-block:: lua

    addLocal('0.0.0.0:5300', { reusePort=true })

  This will bind to both UDP and TCP on port 5300 with SO_REUSEPORT enabled.

.. function:: addDOHLocal(address, [certFile(s) [, keyFile(s) [, urls [, options]]]])

  .. versionadded:: 1.4.0

  .. versionchanged:: 1.5.0
    ``internalPipeBufferSize``, ``sendCacheControlHeaders``, ``sessionTimeout``, ``trustForwardedForHeader`` options added.
    ``url`` now defaults to ``/dns-query`` instead of ``/``, and does exact matching instead of accepting sub-paths. Added ``tcpListenQueueSize`` parameter.

  .. versionchanged:: 1.6.0
    ``enableRenegotiation``, ``exactPathMatching``, ``maxConcurrentTCPConnections`` and ``releaseBuffers`` options added.
    ``internalPipeBufferSize`` now defaults to 1048576 on Linux.

  Listen on the specified address and TCP port for incoming DNS over HTTPS connections, presenting the specified X.509 certificate.
  If no certificate (or key) files are specified, listen for incoming DNS over HTTP connections instead.

  :param str address: The IP Address with an optional port to listen on.
                      The default port is 443.
  :param str certFile(s): The path to a X.509 certificate file in PEM format, or a list of paths to such files.
  :param str keyFile(s): The path to the private key file corresponding to the certificate, or a list of paths to such files, whose order should match the certFile(s) ones.
  :param str-or-list urls: The path part of a URL, or a list of paths, to accept queries on. Any query with a path matching exactly one of these will be treated as a DoH query (sub-paths can be accepted by setting the ``exactPathMatching`` to false). The default is /dns-query.
  :param table options: A table with key: value pairs with listen options.

  Options:

  * ``reusePort=false``: bool - Set the ``SO_REUSEPORT`` socket option.
  * ``tcpFastOpenQueueSize=0``: int - Set the TCP Fast Open queue size, enabling TCP Fast Open when available and the value is larger than 0.
  * ``interface=""``: str - Set the network interface to use.
  * ``cpus={}``: table - Set the CPU affinity for this listener thread, asking the scheduler to run it on a single CPU id, or a set of CPU ids. This parameter is only available if the OS provides the pthread_setaffinity_np() function.
  * ``idleTimeout=30``: int - Set the idle timeout, in seconds.
  * ``ciphers``: str - The TLS ciphers to use, in OpenSSL format. Ciphers for TLS 1.3 must be specified via ``ciphersTLS13``.
  * ``ciphersTLS13``: str - The TLS ciphers to use for TLS 1.3, in OpenSSL format.
  * ``serverTokens``: str - The content of the Server: HTTP header returned by dnsdist. The default is "h2o/dnsdist".
  * ``customResponseHeaders={}``: table - Set custom HTTP header(s) returned by dnsdist.
  * ``ocspResponses``: list - List of files containing OCSP responses, in the same order than the certificates and keys, that will be used to provide OCSP stapling responses.
  * ``minTLSVersion``: str - Minimum version of the TLS protocol to support. Possible values are 'tls1.0', 'tls1.1', 'tls1.2' and 'tls1.3'. Default is to require at least TLS 1.0.
  * ``numberOfTicketsKeys``: int - The maximum number of tickets keys to keep in memory at the same time. Only one key is marked as active and used to encrypt new tickets while the remaining ones can still be used to decrypt existing tickets after a rotation. Default to 5.
  * ``ticketKeyFile``: str - The path to a file from where TLS tickets keys should be loaded, to support :rfc:`5077`. These keys should be rotated often and never written to persistent storage to preserve forward secrecy. The default is to generate a random key. dnsdist supports several tickets keys to be able to decrypt existing sessions after the rotation. See :doc:`../advanced/tls-sessions-management` for more information.
  * ``ticketsKeysRotationDelay``: int - Set the delay before the TLS tickets key is rotated, in seconds. Default is 43200 (12h).
  * ``sessionTimeout``: int - Set the TLS session lifetime in seconds, this is used both for TLS ticket lifetime and for sessions kept in memory.
  * ``sessionTickets``: bool - Whether session resumption via session tickets is enabled. Default is true, meaning tickets are enabled.
  * ``numberOfStoredSessions``: int - The maximum number of sessions kept in memory at the same time. Default is 20480. Setting this value to 0 disables stored session entirely.
  * ``preferServerCiphers``: bool - Whether to prefer the order of ciphers set by the server instead of the one set by the client. Default is true, meaning that the order of the server is used. For OpenSSL >= 1.1.1, setting this option also enables the temporary re-prioritization of the ChaCha20-Poly1305 cipher if the client prioritizes it.
  * ``keyLogFile``: str - Write the TLS keys in the specified file so that an external program can decrypt TLS exchanges, in the format described in https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format. Note that this feature requires OpenSSL >= 1.1.1.
  * ``sendCacheControlHeaders``: bool - Whether to parse the response to find the lowest TTL and set a HTTP Cache-Control header accordingly. Default is true.
  * ``trustForwardedForHeader``: bool - Whether to parse any existing X-Forwarded-For header in the HTTP query and use the right-most value as the client source address and port, for ACL checks, rules, logging and so on. Default is false.
  * ``tcpListenQueueSize=SOMAXCONN``: int - Set the size of the listen queue. Default is ``SOMAXCONN``.
  * ``internalPipeBufferSize=0``: int - Set the size in bytes of the internal buffer of the pipes used internally to pass queries and responses between threads. Requires support for ``F_SETPIPE_SZ`` which is present in Linux since 2.6.35. The actual size might be rounded up to a multiple of a page size. 0 means that the OS default size is used. The default value is 0, except on Linux where it is 1048576 since 1.6.0.
  * ``exactPathMatching=true``: bool - Whether to do exact path matching of the query path against the paths configured in ``urls`` (true, the default since 1.5.0) or to accepts sub-paths (false, and was the default before 1.5.0).
  * ``maxConcurrentTCPConnections=0``: int - Maximum number of concurrent incoming TCP connections. The default is 0 which means unlimited.
  * ``releaseBuffers=true``: bool - Whether OpenSSL should release its I/O buffers when a connection goes idle, saving roughly 35 kB of memory per connection.
  * ``enableRenegotiation=false``: bool - Whether secure TLS renegotiation should be enabled. Disabled by default since it increases the attack surface and is seldom used for DNS.

.. function:: addTLSLocal(address, certFile(s), keyFile(s) [, options])

  .. versionchanged:: 1.4.0
    ``ciphersTLS13``, ``minTLSVersion``, ``ocspResponses``, ``preferServerCiphers``, ``keyLogFile`` options added.
  .. versionchanged:: 1.5.0
    ``sessionTimeout`` and ``tcpListenQueueSize`` options added.
  .. versionchanged:: 1.6.0
    ``enableRenegotiation``, ``maxConcurrentTCPConnections``, ``maxInFlight`` and ``releaseBuffers`` options added.

  Listen on the specified address and TCP port for incoming DNS over TLS connections, presenting the specified X.509 certificate.

  :param str address: The IP Address with an optional port to listen on.
                      The default port is 853.
  :param str certFile(s): The path to a X.509 certificate file in PEM format, or a list of paths to such files.
  :param str keyFile(s): The path to the private key file corresponding to the certificate, or a list of paths to such files, whose order should match the certFile(s) ones.
  :param table options: A table with key: value pairs with listen options.

  Options:

  * ``reusePort=false``: bool - Set the ``SO_REUSEPORT`` socket option.
  * ``tcpFastOpenQueueSize=0``: int - Set the TCP Fast Open queue size, enabling TCP Fast Open when available and the value is larger than 0.
  * ``interface=""``: str - Set the network interface to use.
  * ``cpus={}``: table - Set the CPU affinity for this listener thread, asking the scheduler to run it on a single CPU id, or a set of CPU ids. This parameter is only available if the OS provides the pthread_setaffinity_np() function.
  * ``provider``: str - The TLS library to use between GnuTLS and OpenSSL, if they were available and enabled at compilation time. Default is to use OpenSSL when available.
  * ``ciphers``: str - The TLS ciphers to use. The exact format depends on the provider used. When the OpenSSL provider is used, ciphers for TLS 1.3 must be specified via ``ciphersTLS13``.
  * ``ciphersTLS13``: str - The ciphers to use for TLS 1.3, when the OpenSSL provider is used. When the GnuTLS provider is used, ``ciphers`` applies regardless of the TLS protocol and this setting is not used.
  * ``numberOfTicketsKeys``: int - The maximum number of tickets keys to keep in memory at the same time, if the provider supports it (GnuTLS doesn't, OpenSSL does). Only one key is marked as active and used to encrypt new tickets while the remaining ones can still be used to decrypt existing tickets after a rotation. Default to 5.
  * ``ticketKeyFile``: str - The path to a file from where TLS tickets keys should be loaded, to support :rfc:`5077`. These keys should be rotated often and never written to persistent storage to preserve forward secrecy. The default is to generate a random key. The OpenSSL provider supports several tickets keys to be able to decrypt existing sessions after the rotation, while the GnuTLS provider only supports one key. See :doc:`../advanced/tls-sessions-management` for more information.
  * ``ticketsKeysRotationDelay``: int - Set the delay before the TLS tickets key is rotated, in seconds. Default is 43200 (12h).
  * ``sessionTimeout``: int - Set the TLS session lifetime in seconds, this is used both for TLS ticket lifetime and for sessions kept in memory.
  * ``sessionTickets``: bool - Whether session resumption via session tickets is enabled. Default is true, meaning tickets are enabled.
  * ``numberOfStoredSessions``: int - The maximum number of sessions kept in memory at the same time. At this time this is only supported by the OpenSSL provider, as stored sessions are not supported with the GnuTLS one. Default is 20480. Setting this value to 0 disables stored session entirely.
  * ``ocspResponses``: list - List of files containing OCSP responses, in the same order than the certificates and keys, that will be used to provide OCSP stapling responses.
  * ``minTLSVersion``: str - Minimum version of the TLS protocol to support. Possible values are 'tls1.0', 'tls1.1', 'tls1.2' and 'tls1.3'. Default is to require at least TLS 1.0. Note that this value is ignored when the GnuTLS provider is in use, and the ``ciphers`` option should be set accordingly instead. For example, 'NORMAL:!VERS-TLS1.0:!VERS-TLS1.1' will disable TLS 1.0 and 1.1.
  * ``preferServerCiphers``: bool - Whether to prefer the order of ciphers set by the server instead of the one set by the client. Default is true, meaning that the order of the server is used. For OpenSSL >= 1.1.1, setting this option also enables the temporary re-prioritization of the ChaCha20-Poly1305 cipher if the client prioritizes it.
  * ``keyLogFile``: str - Write the TLS keys in the specified file so that an external program can decrypt TLS exchanges, in the format described in https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format. Note that this feature requires OpenSSL >= 1.1.1.
  * ``tcpListenQueueSize=SOMAXCONN``: int - Set the size of the listen queue. Default is ``SOMAXCONN``.
  * ``maxInFlight=0``: int - Maximum number of in-flight queries. The default is 0, which disables out-of-order processing.
  * ``maxConcurrentTCPConnections=0``: int - Maximum number of concurrent incoming TCP connections. The default is 0 which means unlimited.
  * ``releaseBuffers=true``: bool - Whether OpenSSL should release its I/O buffers when a connection goes idle, saving roughly 35 kB of memory per connection.
  * ``enableRenegotiation=false``: bool - Whether secure TLS renegotiation should be enabled (OpenSSL only, the GnuTLS provider does not support it). Disabled by default since it increases the attack surface and is seldom used for DNS.

.. function:: setLocal(address[, options])

  Remove the list of listen addresses and add a new one.

  :param str address: The IP Address with an optional port to listen on.
                      The default port is 53.
  :param table options: A table with key: value pairs with listen options.

  The options that can be set are the same as :func:`addLocal`.

Control Socket, Console and Webserver
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. function:: addConsoleACL(netmask)

  Add a netmask to the existing console ACL, allowing remote clients to connect to the console. Please make sure that encryption
  has been enabled with :func:`setKey` before doing so. The default is to only allow 127.0.0.1/8 and ::1/128.

  :param str netmask: A CIDR netmask, e.g. ``"192.0.2.0/24"``. Without a subnetmask, only the specific address is allowed.

.. function:: clearConsoleHistory()

  .. versionadded:: 1.6.0

  Clear the internal (in-memory) buffers of console commands. These buffers are used to provide the :func:`delta` command and
  console completion and history, and can end up being quite large when a lot of commands are issued via the console, consuming
  a noticeable amount of memory.

.. function:: controlSocket(address)

  Bind to ``addr`` and listen for a connection for the console. Since 1.3.0 only connections from local users are allowed
  by default, :func:`addConsoleACL` and :func:`setConsoleACL` can be used to enable remote connections. Please make sure
  that encryption has been enabled with :func:`setKey` before doing so. Enabling encryption is also strongly advised for
  local connections, since not enabling it allows any local user to connect to the console.

  :param str address: An IP address with optional port. By default, the port is 5199.

.. function:: delta()

  Issuing `delta` on the console will print the changes to the configuration that have been made since startup.

.. function:: inClientStartup()

  Returns true while the console client is parsing the configuration.

.. function:: inConfigCheck()

  .. versionadded:: 1.5.0

  Returns true while the configuration is being checked, ie when run with ``--check-config``.

.. function:: makeKey()

  Generate and print an encryption key.

.. function:: setConsoleConnectionsLogging(enabled)

  Whether to log the opening and closing of console connections.

  :param bool enabled: Default to true.

.. function:: setConsoleMaximumConcurrentConnections(max)

  .. versionadded:: 1.6.0

  Set the maximum number of concurrent console connections.

  :param int max: The maximum number of concurrent console connections, or 0 which means an unlimited number. Defaults to 100

.. function:: setKey(key)

  Use ``key`` as shared secret between the client and the server

  :param str key: An encoded key, as generated by :func:`makeKey`

.. function:: setConsoleACL(netmasks)

  Remove the existing console ACL and add the netmasks from the table, allowing remote clients to connect to the console. Please make sure that encryption
  has been enabled with :func:`setKey` before doing so.

  :param {str} netmasks: A table of CIDR netmask, e.g. ``{"192.0.2.0/24", "2001:DB8:14::/56"}``. Without a subnetmask, only the specific address is allowed.

.. function:: showConsoleACL()

  Print a list of all netmasks allowed to connect to the console.

.. function:: testCrypto()

  Test the crypto code, will report errors when something is not ok.

.. function:: setConsoleOutputMaxMsgSize(size)

  Set the maximum size in bytes of a single console message, default set to 10 MB.

  :param int size: The new maximum size.

Webserver configuration
~~~~~~~~~~~~~~~~~~~~~~~

.. function:: hashPassword(password [, workFactor])

  .. versionadded:: 1.7.0

  Hash the supplied password using a random salt, and returns a string that can be used with :func:`setWebserverConfig`.

  :param string - password: The password to hash
  :param int - workFactor: The work factor to use for the hash function (currently scrypt), as a power of two. Default is 1024.

.. function:: webserver(listen_address [, password[, apikey[, custom_headers[, acl]]]])

  .. versionchanged:: 1.5.0
    ``acl`` optional parameter added.

  .. versionchanged:: 1.6.0
    The ``password`` parameter is now optional.
    The use of optional parameters is now deprecated. Please use :func:`setWebserverConfig` instead.

  Launch the :doc:`../guides/webserver` with statistics and the API. Note that the parameters are global, so the parameter from the last ``webserver`` will override any existing ones. For this reason
  the use of :func:`setWebserverConfig` is advised instead of specifying optional parameters here.

  :param str listen_address: The IP address and Port to listen on
  :param str password: The password required to access the webserver
  :param str apikey: The key required to access the API
  :param {[str]=str,...} custom_headers: Allows setting custom headers and removing the defaults
  :param str acl: List of netmasks, as a string, that are allowed to open a connection to the web server. Defaults to "127.0.0.1, ::1". It accepts the same syntax that :func:`NetmaskGroup:addMask` does

.. function:: setAPIWritable(allow [,dir])

  Allow modifications via the API.
  Optionally saving these changes to disk.
  Modifications done via the API will not be written to the configuration by default and will not persist after a reload

  :param bool allow: Set to true to allow modification through the API
  :param str dir: A valid directory where the configuration files will be written by the API.

.. function:: setWebserverConfig(options)

  .. versionchanged:: 1.5.0
    ``acl`` optional parameter added.

  .. versionchanged:: 1.6.0
    ``statsRequireAuthentication``, ``maxConcurrentConnections`` optional parameters added.

  .. versionchanged:: 1.7.0
    The optional ``password`` and ``apiKey`` parameters now accept hashed passwords.
    The optional ``hashPlaintextCredentials`` parameter has been added.

  Setup webserver configuration. See :func:`webserver`.

  :param table options: A table with key: value pairs with webserver options.

  Options:

  * ``password=newPassword``: string - Set the password used to access the internal webserver. Since 1.7.0 the password should be hashed and salted via the :func:`hashPassword` command.
  * ``apiKey=newKey``: string - Changes the API Key (set to an empty string do disable it). Since 1.7.0 the key should be hashed and salted via the :func:`hashPassword` command.
  * ``custom_headers={[str]=str,...}``: map of string - Allows setting custom headers and removing the defaults.
  * ``acl=newACL``: string - List of IP addresses, as a string, that are allowed to open a connection to the web server. Defaults to "127.0.0.1, ::1".
  * ``statsRequireAuthentication``: bool - Whether access to the statistics (/metrics and /jsonstat endpoints) require a valid password or API key. Defaults to true.
  * ``maxConcurrentConnections``: int - The maximum number of concurrent web connections, or 0 which means an unlimited number. Defaults to 100.
  * ``hashPlaintextCredentials``: bool - Whether passwords and API keys provided in plaintext should be hashed during startup, to prevent the plaintext versions from staying in memory. Doing so increases significantly the cost of verifying credentials. Defaults to false.

.. function:: registerWebHandler(path, handler)

  .. versionadded: 1.6.0

  Register a function named ``handler`` that will be called for every query sent to the exact ``path`` path. The function will receive a :class:`WebRequest` object
  and a :class:`WebResponse` object, representing respectively the HTTP request received and the HTTP response to send.
  For example a handler registered for '/foo' will receive these queries:

  - ``GET /foo``
  - ``POST /foo``
  - ``GET /foo?param=1``

  But not queries for /foobar or /foo/bar.

  A sample handler function could be:

  .. code-block:: lua

    function customHTTPHandler(req, resp)
      local get = req.getvars
      local headers = req.headers

      if req.path ~= '/foo' or req.version ~= 11 or req.method ~= 'GET' or get['param'] ~= '42' or headers['custom'] ~= 'foobar' then
        resp.status = 500
        return
      end

      resp.status = 200
      resp.body = 'It works!'
      resp.headers = { ['Foo']='Bar'}
    end

    registerWebHandler('/foo', customHTTPHandler)

  :param str path: Path to register the handler for.
  :param function handler: The Lua function to register.

Access Control Lists
~~~~~~~~~~~~~~~~~~~~

.. function:: addACL(netmask)

  Add a netmask to the existing ACL controlling which clients can send UDP, TCP, DNS over TLS and DNS over HTTPS queries. See :ref:`ACL` for more information.

  :param str netmask: A CIDR netmask, e.g. ``"192.0.2.0/24"``. Without a subnetmask, only the specific address is allowed.

.. function:: rmACL(netmask)

  Remove a network from the existing ACL controlling which clients can send UDP, TCP, DNS over TLS and DNS over HTTPS queries. See :ref:`ACL` for more information.
  This function only removes previously added entries, it does not remove subnets of entries.

  :param str netmask: A CIDR netmask, e.g. ``"192.0.2.0/24"``. Without a subnetmask, only the specific address is allowed.

  .. code-block:: lua

    addACL("192.0.2.0/24") -- for example add subnet to the ACL
    rmACL("192.0.2.10")    -- does NOT work, the ACL is unchanged
    rmACL("192.0.2.0/24")  -- does work, the exact match is removed from the ACL

.. function:: setACL(netmasks)

  Remove the existing ACL and add the netmasks from the table of those allowed to send UDP, TCP, DNS over TLS and DNS over HTTPS queries. See :ref:`ACL` for more information.

  :param {str} netmasks: A table of CIDR netmask, e.g. ``{"192.0.2.0/24", "2001:DB8:14::/56"}``. Without a subnetmask, only the specific address is allowed.

.. function:: setACLFromFile(fname)

  .. versionadded:: 1.6.0

  Reset the ACL to the list of netmasks from the given file. See :ref:`ACL` for more information.

  :param str fname: The path to a file containing a list of netmasks. Empty lines or lines starting with "#" are ignored.

.. function:: setProxyProtocolACL(netmasks)

  .. versionadded:: 1.6.0

  Set the list of netmasks from which a Proxy Protocol header will be accepted, over UDP, TCP and DNS over TLS. The default is empty. Note that, if :func:`setProxyProtocolApplyACLToProxiedClients` is set (default is false), the general ACL will be applied to the source IP address as seen by dnsdist first, but also to the source IP address provided in the Proxy Protocol header.

  :param {str} netmasks: A table of CIDR netmask, e.g. ``{"192.0.2.0/24", "2001:DB8:14::/56"}``. Without a subnetmask, only the specific address is allowed.

.. function:: setProxyProtocolApplyACL(apply)

  .. versionadded:: 1.6.0

  Whether the general ACL should be applied to the source IP address provided in the Proxy Protocol header, in addition to being applied to the source IP address as seen by dnsdist first.

  :param bool apply: Whether it should be applied or not (default is false).

.. function:: showACL()

  Print a list of all netmasks allowed to send queries over UDP, TCP, DNS over TLS and DNS over HTTPS. See :ref:`ACL` for more information.

EDNS Client Subnet
~~~~~~~~~~~~~~~~~~

.. function:: setECSOverride(bool)

  When ``useClientSubnet`` in :func:`newServer` is set and dnsdist adds an EDNS Client Subnet Client option to the query, override an existing option already present in the query, if any.
  Note that it's not recommended to enable ``setECSOverride`` in front of an authoritative server responding with EDNS Client Subnet information as mismatching data (ECS scopes) can confuse clients and lead to SERVFAIL responses on downstream nameservers.

  :param bool: Whether to override an existing EDNS Client Subnet option present in the query. Defaults to false

.. function:: setECSSourcePrefixV4(prefix)

  When ``useClientSubnet`` in :func:`newServer` is set and dnsdist adds an EDNS Client Subnet Client option to the query, truncate the requestors IPv4 address to ``prefix`` bits

  :param int prefix: The prefix length

.. function:: setECSSourcePrefixV6(prefix)

  When ``useClientSubnet`` in :func:`newServer` is set and dnsdist adds an EDNS Client Subnet Client option to the query, truncate the requestor's IPv6 address to  bits

  :param int prefix: The prefix length

Ringbuffers
~~~~~~~~~~~

.. function:: setRingBuffersLockRetries(num)

  Set the number of shards to attempt to lock without blocking before giving up and simply blocking while waiting for the next shard to be available

  :param int num: The maximum number of attempts. Defaults to 5 if there is more than one shard, 0 otherwise.

.. function:: setRingBuffersSize(num [, numberOfShards])

  .. versionchanged:: 1.6.0
    ``numberOfShards`` defaults to 10.

  Set the capacity of the ringbuffers used for live traffic inspection to ``num``, and the number of shards to ``numberOfShards`` if specified.
  Increasing the number of entries comes at both a memory cost (around 250 MB for 1 million entries) and a CPU processing cost, so we strongly advise not going over 1 million entries.

  :param int num: The maximum amount of queries to keep in the ringbuffer. Defaults to 10000
  :param int numberOfShards: the number of shards to use to limit lock contention. Default is 10, used to be 1 before 1.6.0

Servers
-------

.. function:: newServer(server_string)
              newServer(server_table)

  .. versionchanged:: 1.4.0
    Added ``checkInterval``, ``checkTimeout`` and ``rise`` to server_table.

  .. versionchanged:: 1.5.0
    Added ``useProxyProtocol`` to server_table.

  .. versionchanged:: 1.6.0
    Added ``maxInFlight`` to server_table.

  .. versionchanged:: 1.7.0
    Added ``addXForwardedHeaders``, ``caStore``, ``checkTCP``, ``ciphers``, ``ciphers13``, ``dohPath``, ``enableRenegotiation``, ``releaseBuffers``, ``subjectName``, ``tcpOnly``, ``tls`` and ``validateCertificates`` to server_table.

  Add a new backend server. Call this function with either a string::

    newServer(
      "IP:PORT" -- IP and PORT of the backend server
    )

  or a table::

    newServer({
      address="IP:PORT",        -- IP and PORT of the backend server (mandatory)
      id=STRING,                -- Use a pre-defined UUID instead of a random one
      qps=NUM,                  -- Limit the number of queries per second to NUM, when using the `firstAvailable` policy
      order=NUM,                -- The order of this server, used by the `leastOutstanding` and `firstAvailable` policies
      weight=NUM,               -- The weight of this server, used by the `wrandom`, `whashed` and `chashed` policies, default: 1
                                -- Supported values are a minimum of 1, and a maximum of 2147483647.
      pool=STRING|{STRING},     -- The pools this server belongs to (unset or empty string means default pool) as a string or table of strings
      retries=NUM,              -- The number of TCP connection attempts to the backend, for a given query
      tcpConnectTimeout=NUM,    -- The timeout (in seconds) of a TCP connection attempt
      tcpSendTimeout=NUM,       -- The timeout (in seconds) of a TCP write attempt
      tcpRecvTimeout=NUM,       -- The timeout (in seconds) of a TCP read attempt
      tcpFastOpen=BOOL,         -- Whether to enable TCP Fast Open
      ipBindAddrNoPort=BOOL,    -- Whether to enable IP_BIND_ADDRESS_NO_PORT if available, default: true
      name=STRING,              -- The name associated to this backend, for display purpose
      checkClass=NUM,           -- Use NUM as QCLASS in the health-check query, default: DNSClass.IN
      checkName=STRING,         -- Use STRING as QNAME in the health-check query, default: "a.root-servers.net."
      checkType=STRING,         -- Use STRING as QTYPE in the health-check query, default: "A"
      checkFunction=FUNCTION,   -- Use this function to dynamically set the QNAME, QTYPE and QCLASS to use in the health-check query (see :ref:`Healthcheck`)
      checkTimeout=NUM,         -- The timeout (in milliseconds) of a health-check query, default: 1000 (1s)
      setCD=BOOL,               -- Set the CD (Checking Disabled) flag in the health-check query, default: false
      maxCheckFailures=NUM,     -- Allow NUM check failures before declaring the backend down, default: 1
      checkInterval=NUM         -- The time in seconds between health checks
      mustResolve=BOOL,         -- Set to true when the health check MUST return a RCODE different from NXDomain, ServFail and Refused. Default is false, meaning that every RCODE except ServFail is considered valid
      useClientSubnet=BOOL,     -- Add the client's IP address in the EDNS Client Subnet option when forwarding the query to this backend
      source=STRING,            -- The source address or interface to use for queries to this backend, by default this is left to the kernel's address selection
                                -- The following formats are supported:
                                --   "address", e.g. "192.0.2.2"
                                --   "interface name", e.g. "eth0"
                                --   "address@interface", e.g. "192.0.2.2@eth0"
      addXPF=NUM,               -- Add the client's IP address and port to the query, along with the original destination address and port,
                                -- using the experimental XPF record from `draft-bellis-dnsop-xpf <https://datatracker.ietf.org/doc/draft-bellis-dnsop-xpf/>`_ and the specified option code. Default is disabled (0)
      sockets=NUM,              -- Number of sockets (and thus source ports) used toward the backend server, defaults to a single one. Note that for backends which are multithreaded, this setting will have an effect on the number of cores that will be used to process traffic from dnsdist. For example you may want to set 'sockets' to a number somewhat higher than the number of worker threads configured in the backend, particularly if the Linux kernel is being used to distribute traffic to multiple threads listening on the same socket (via `reuseport`).
      disableZeroScope=BOOL,    -- Disable the EDNS Client Subnet 'zero scope' feature, which does a cache lookup for an answer valid for all subnets (ECS scope of 0) before adding ECS information to the query and doing the regular lookup. This requires the ``parseECS`` option of the corresponding cache to be set to true
      rise=NUM,                 -- Require NUM consecutive successful checks before declaring the backend up, default: 1
      useProxyProtocol=BOOL,    -- Add a proxy protocol header to the query, passing along the client's IP address and port along with the original destination address and port. Default is disabled.
      reconnectOnUp=BOOL,       -- Close and reopen the sockets when a server transits from Down to Up. This helps when an interface is missing when dnsdist is started. Default is disabled.
      maxInFlight=NUM,          -- Maximum number of in-flight queries. The default is 0, which disables out-of-order processing. It should only be enabled if the backend does support out-of-order processing. As of 1.6.0, out-of-order processing needs to be enabled on the frontend as well, via :func:`addLocal` and/or :func:`addTLSLocal`. Note that out-of-order is always enabled on DoH frontends.
      tcpOnly=BOOL,             -- Always forward queries to that backend over TCP, never over UDP. Always enabled for TLS backends. Default is false.
      checkTCP=BOOL,            -- Whether to do healthcheck queries over TCP, instead of UDP. Always enabled for DNS over TLS backend. Default is false.
      tls=STRING,               -- Enable DNS over TLS communications for this backend, or DNS over HTTPS if ``dohPath`` is set, using the TLS provider ("openssl" or "gnutls") passed in parameter. Default is an empty string, which means this backend is used for plain UDP and TCP.
      caStore=STRING,           -- Specifies the path to the CA certificate file, in PEM format, to use to check the certificate presented by the backend. Default is an empty string, which means to use the system CA store. Note that this directive is only used if ``validateCertificates`` is set.
      ciphers=STRING,           -- The TLS ciphers to use. The exact format depends on the provider used. When the OpenSSL provider is used, ciphers for TLS 1.3 must be specified via ``ciphersTLS13``.
      ciphersTLS13=STRING,      -- The ciphers to use for TLS 1.3, when the OpenSSL provider is used. When the GnuTLS provider is used, ``ciphers`` applies regardless of the TLS protocol and this setting is not used.
      subjectName=STRING,       -- The subject name passed in the SNI value of the TLS handshake, and against which to validate the certificate presented by the backend. Default is empty.
      validateCertificates=BOOL,-- Whether the certificate presented by the backend should be validated against the CA store (see ``caStore``). Default is true.
      dohPath=STRING,           -- Enable DNS over HTTPS communication for this backend, using POST queries to the HTTP host supplied as ``subjectName`` and the HTTP path supplied in this parameter.
      addXForwardedHeaders=BOOL,-- Whether to add X-Forwarded-For, X-Forwarded-Port and X-Forwarded-Proto headers to a DNS over HTTPS backend.
      releaseBuffers=BOOL,      -- Whether OpenSSL should release its I/O buffers when a connection goes idle, saving roughly 35 kB of memory per connection. Default to true.
      enableRenegotiation=BOOL  -- Whether secure TLS renegotiation should be enabled. Disabled by default since it increases the attack surface and is seldom used for DNS.
    })

  :param str server_string: A simple IP:PORT string.
  :param table server_table: A table with at least a 'name' key

.. function:: getServer(index) -> Server

  .. versionchanged:: 1.5.0
    ``index`` might be an UUID.

  Get a :class:`Server`

  :param int or str index: The number of the server (as seen in :func:`showServers`) or its UUID as a string.
  :returns:  The :class:`Server` object or nil

.. function:: getServers()

  Returns a table with all defined servers.

.. function:: rmServer(index)
              rmServer(uuid)
              rmServer(server)

  .. versionchanged:: 1.5.0
    ``uuid`` selection added.

  Remove a backend server.

  :param int or str index: The number of the server (as seen in :func:`showServers`), its UUID as a string, or a server object.
  :param Server server: A :class:`Server` object as returned by e.g. :func:`getServer`.

Server Functions
~~~~~~~~~~~~~~~~
A server object returned by :func:`getServer` can be manipulated with these functions.

.. class:: Server

  This object represents a backend server. It has several methods.

  .. method:: Server:addPool(pool)

    Add this server to a pool.

    :param str pool: The pool to add the server to

  .. method:: Server:getLatency() -> double

    .. versionadded:: 1.6.0

    Return the average latency of this server over the last 128 UDP queries, in microseconds.

    :returns: The number of outstanding queries

  .. method:: Server:getName() -> string

    Get the name of this server.

    :returns: The name of the server, or an empty string if it does not have one

  .. method:: Server:getNameWithAddr() -> string

    Get the name plus IP address and port of the server

    :returns: A string containing the server name if any plus the server address and port

  .. method:: Server:getDrops() -> int

    .. versionadded:: 1.6.0

    Get the number of dropped queries for this server.

    :returns: The number of dropped queries

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
Pools are automatically created when a server is added to a pool (with :func:`newServer`), or can be manually created with :func:`getPool`.
Servers that are not assigned to a specific pool get assigned to the default pool that is always present, identified by the empty string ``''``.

.. function:: getPool(name) -> ServerPool

  Returns a :class:`ServerPool`. If the pool does not exist yet, it is created.

  :param string name: The name of the pool

.. function:: getPoolServers(name) -> [ Server ]

  Returns a list of :class:`Server`\ s or nil.

  :param string name: The name of the pool

.. function:: showPools()

   Display the name, associated cache, server policy and associated servers for every pool.

.. class:: ServerPool

  This represents the pool where zero or more servers are part of.

  .. method:: ServerPool:getCache() -> PacketCache

    Returns the :class:`PacketCache` for this pool or nil.

  .. method:: ServerPool:getECS()

    Whether dnsdist will add EDNS Client Subnet information to the query before looking up into the cache,
    when all servers from this pool are down. For more information see :meth:`ServerPool:setECS`.

  .. method:: ServerPool:setCache(cache)

    Adds ``cache`` as the pool's cache.

    :param PacketCache cache: The new cache to add to the pool

  .. method:: ServerPool:unsetCache()

    Removes the cache from this pool.

  .. method:: ServerPool:setECS()

    Set to true if dnsdist should add EDNS Client Subnet information to the query before looking up into the cache,
    when all servers from this pool are down. If at least one server is up, the preference of the
    selected server is used, this parameter is only useful if all the backends in this pool are down
    and have EDNS Client Subnet enabled, since the queries in the cache will have been inserted with
    ECS information. Default is false.

PacketCache
~~~~~~~~~~~

A Pool can have a packet cache to answer queries directly instead of going to the backend.
See :doc:`../guides/cache` for a how to.

.. function:: newPacketCache(maxEntries[, maxTTL=86400[, minTTL=0[, temporaryFailureTTL=60[, staleTTL=60[, dontAge=false[, numberOfShards=1[, deferrableInsertLock=true[, maxNegativeTTL=3600[, parseECS=false]]]]]]]) -> PacketCache

  .. deprecated:: 1.4.0

  Creates a new :class:`PacketCache` with the settings specified.

  :param int maxEntries: The maximum number of entries in this cache
  :param int maxTTL: Cap the TTL for records to his number
  :param int minTTL: Don't cache entries with a TTL lower than this
  :param int temporaryFailureTTL: On a SERVFAIL or REFUSED from the backend, cache for this amount of seconds
  :param int staleTTL: When the backend servers are not reachable, and global configuration ``setStaleCacheEntriesTTL`` is set appropriately, TTL that will be used when a stale cache entry is returned
  :param bool dontAge: Don't reduce TTLs when serving from the cache. Use this when :program:`dnsdist` fronts a cluster of authoritative servers
  :param int numberOfShards: Number of shards to divide the cache into, to reduce lock contention
  :param bool deferrableInsertLock: Whether the cache should give up insertion if the lock is held by another thread, or simply wait to get the lock
  :param int maxNegativeTTL: Cache a NXDomain or NoData answer from the backend for at most this amount of seconds, even if the TTL of the SOA record is higher
  :param bool parseECS: Whether any EDNS Client Subnet option present in the query should be extracted and stored to be able to detect hash collisions involving queries with the same qname, qtype and qclass but a different incoming ECS value. Enabling this option adds a parsing cost and only makes sense if at least one backend might send different responses based on the ECS value, so it's disabled by default

.. function:: newPacketCache(maxEntries, [options]) -> PacketCache

  .. versionadded:: 1.4.0

  .. versionchanged:: 1.6.0
    ``cookieHashing`` parameter added.
    ``numberOfShards`` now defaults to 20.

  .. versionchanged:: 1.7.0
    ``skipOptions`` parameter added.

  Creates a new :class:`PacketCache` with the settings specified.

  :param int maxEntries: The maximum number of entries in this cache

  Options:

  * ``deferrableInsertLock=true``: bool - Whether the cache should give up insertion if the lock is held by another thread, or simply wait to get the lock.
  * ``dontAge=false``: bool - Don't reduce TTLs when serving from the cache. Use this when :program:`dnsdist` fronts a cluster of authoritative servers.
  * ``keepStaleData=false``: bool - Whether to suspend the removal of expired entries from the cache when there is no backend available in at least one of the pools using this cache.
  * ``maxNegativeTTL=3600``: int - Cache a NXDomain or NoData answer from the backend for at most this amount of seconds, even if the TTL of the SOA record is higher.
  * ``maxTTL=86400``: int - Cap the TTL for records to his number.
  * ``minTTL=0``: int - Don't cache entries with a TTL lower than this.
  * ``numberOfShards=20``: int - Number of shards to divide the cache into, to reduce lock contention. Used to be 1 (no shards) before 1.6.0, and is now 20.
  * ``parseECS=false``: bool - Whether any EDNS Client Subnet option present in the query should be extracted and stored to be able to detect hash collisions involving queries with the same qname, qtype and qclass but a different incoming ECS value. Enabling this option adds a parsing cost and only makes sense if at least one backend might send different responses based on the ECS value, so it's disabled by default. Enabling this option is required for the 'zero scope' option to work
  * ``staleTTL=60``: int - When the backend servers are not reachable, and global configuration ``setStaleCacheEntriesTTL`` is set appropriately, TTL that will be used when a stale cache entry is returned.
  * ``temporaryFailureTTL=60``: int - On a SERVFAIL or REFUSED from the backend, cache for this amount of seconds..
  * ``cookieHashing=false``: bool - Whether EDNS Cookie values will be hashed, resulting in separate entries for different cookies in the packet cache. This is required if the backend is sending answers with EDNS Cookies, otherwise a client might receive an answer with the wrong cookie.
  * ``skipOptions={}``: Extra list of EDNS option codes to skip when hashing the packet (if ``cookieHashing`` above is false, EDNS cookie option number will already be added to this list).

.. class:: PacketCache

  Represents a cache that can be part of :class:`ServerPool`.

  .. method:: PacketCache:dump(fname)

    Dump a summary of the cache entries to a file.

    :param str fname: The path to a file where the cache summary should be dumped. Note that if the target file already exists, it will not be overwritten.

  .. method:: PacketCache:expunge(n)

    Remove entries from the cache, leaving at most ``n`` entries

    :param int n: Number of entries to keep

  .. method:: PacketCache:expungeByName(name [, qtype=DNSQType.ANY[, suffixMatch=false]])

    .. versionchanged:: 1.6.0
      ``name`` can now also be a string

    Remove entries matching ``name`` and type from the cache.

    :param DNSName name: The name to expunge
    :param int qtype: The type to expunge, can be a pre-defined :ref:`DNSQType`
    :param bool suffixMatch: When set to true, remove all entries under ``name``

  .. method:: PacketCache:getStats()

    .. versionadded:: 1.4.0

    Return the cache stats (number of entries, hits, misses, deferred lookups, deferred inserts, lookup collisions, insert collisions and TTL too shorts) as a Lua table.

  .. method:: PacketCache:isFull() -> bool

    Return true if the cache has reached the maximum number of entries.

  .. method:: PacketCache:printStats()

    Print the cache stats (number of entries, hits, misses, deferred lookups, deferred inserts, lookup collisions, insert collisions and TTL too shorts).

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

.. function:: getBindCount()

  .. versionadded:: 1.5.0

  Return the number of binds (Do53, DNSCrypt, DoH and DoT).

ClientState functions
~~~~~~~~~~~~~~~~~~~~~

.. class:: ClientState

  This object represents an address and port dnsdist is listening on. When ``reuseport`` is in use, several ClientState objects can be present for the same address and port.

  .. method:: ClientState:attachFilter(filter)

     Attach a BPF filter to this frontend.

     :param BPFFilter filter: The filter to attach to this frontend

  .. method:: ClientState:detachFilter()

     Remove the BPF filter associated to this frontend, if any.

  .. method:: ClientState:getEffectiveTLSProvider() -> string

    .. versionadded:: 1.7.0

    Return the name of the TLS provider actually used.

  .. method:: ClientState:getRequestedTLSProvider() -> string

    .. versionadded:: 1.7.0

    Return the name of the TLS provider requested in the configuration.

  .. method:: ClientState:getType() -> string

    .. versionadded:: 1.7.0

    Return the type of the frontend: UDP, UDP (DNSCrypt), TCP, TCP (DNSCrypt), TCP (DNS over TLS) or TCP (DNS over HTTPS).

  .. method:: ClientState:toString() -> string

    Return the address and port this frontend is listening on.

    :returns: The address and port this frontend is listening on

  .. attribute:: ClientState.muted

    If set to true, queries received on this frontend will be normally processed and sent to a backend if needed, but no response will be ever be sent to the client over UDP. TCP queries are processed normally and responses sent to the client.

Status, Statistics and More
---------------------------

.. function:: dumpStats()

  Print all statistics dnsdist gathers

.. function:: getDOHFrontend(idx)

  .. versionadded:: 1.4.0

  Return the DOHFrontend object for the DNS over HTTPS bind of index ``idx``.

.. function:: getDOHFrontendCount()

  .. versionadded:: 1.5.0

  Return the number of DOHFrontend binds.

.. function:: getTLSContext(idx)

  Return the TLSContext object for the context of index ``idx``.

.. function:: getTLSFrontend(idx)

  Return the TLSFrontend object for the TLS bind of index ``idx``.

.. function:: getTLSFrontendCount()

  .. versionadded:: 1.5.0

  Return the number of TLSFrontend binds.

.. function:: getTopCacheHitResponseRules([top])

  .. versionadded:: 1.6.0

  Return the cache-hit response rules that matched the most.

  :param int top: How many response rules to return.

.. function:: getTopResponseRules([top])

  .. versionadded:: 1.6.0

  Return the response rules that matched the most.

  :param int top: How many response rules to return.

.. function:: getTopRules([top])

  .. versionadded:: 1.6.0

  Return the rules that matched the most.

  :param int top: How many rules to return.

.. function:: getTopSelfAnsweredRules([top])

  .. versionadded:: 1.6.0

  Return the self-answered rules that matched the most.

  :param int top: How many rules to return.

.. function:: grepq(selector[, num])
              grepq(selectors[, num])

  Prints the last ``num`` queries and responses matching ``selector`` or ``selectors``.
  Queries and responses are accounted in separate ring buffers, and answers from the packet cache are not stored in the response ring buffer.
  Therefore, the ``num`` queries and ``num`` responses in the output may not always match up.

  The selector can be:

  * a netmask (e.g. '192.0.2.0/24')
  * a DNS name (e.g. 'dnsdist.org')
  * a response time (e.g. '100ms')

  :param str selector: Select queries based on this property.
  :param {str} selectors: A lua table of selectors. Only queries matching all selectors are shown
  :param int num: Show a maximum of ``num`` recent queries+responses, default is 10.

.. function:: setVerboseHealthChecks(verbose)

  Set whether health check errors should be logged. This is turned off by default.

  :param bool verbose: Set to true if you want to enable health check errors logging

.. function:: showBinds()

  Print a list of all the current addresses and ports dnsdist is listening on, also called ``frontends``

.. function:: showDOHFrontends()

  .. versionadded:: 1.4.0

  Print the list of all available DNS over HTTPS frontends.

.. function:: showDOHResponseCodes()

  .. versionadded:: 1.4.0

  Print the HTTP response codes statistics for all available DNS over HTTPS frontends.

.. function:: showResponseLatency()

  Show a plot of the response time latency distribution

.. function:: showServers([options])

  .. versionchanged:: 1.4.0
    ``options`` optional parameter added

  This function shows all backend servers currently configured and some statistics.
  These statics have the following fields:

  * ``#`` - The number of the server, can be used as the argument for :func:`getServer`
  * ``UUID`` - The UUID of the backend. Can be set with the ``id`` option of :func:`newServer`
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

  :param table options: A table with key: value pairs with display options.

  Options:

  * ``showUUIDs=false``: bool - Whether to display the UUIDs, defaults to false.

.. function:: showTCPStats()

  Show some statistics regarding TCP

.. function:: showTLSContexts()

  Print the list of all available DNS over TLS contexts.

.. function:: showTLSErrorCounters()

  .. versionadded:: 1.4.0

  Display metrics about TLS handshake failures.

.. function:: showVersion()

  Print the version of dnsdist

.. function:: topBandwidth([num])

  Print the top ``num`` clients that consume the most bandwidth.

  :param int num: Number to show, defaults to 10.

.. function:: topCacheHitResponseRules([top [, options]])

  .. versionadded:: 1.6.0

  This function shows the cache-hit response rules that matched the most.

  :param int top: How many rules to show.
  :param table options: A table with key: value pairs with display options.

  Options:

  * ``showUUIDs=false``: bool - Whether to display the UUIDs, defaults to false.

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

.. function:: topResponseRules([top [, options]])

  .. versionadded:: 1.6.0

  This function shows the response rules that matched the most.

  :param int top: How many rules to show.
  :param table options: A table with key: value pairs with display options.

  Options:

  * ``showUUIDs=false``: bool - Whether to display the UUIDs, defaults to false.

.. function:: topRules([top [, options]])

  .. versionadded:: 1.6.0

  This function shows the rules that matched the most.

  :param int top: How many rules to show.
  :param table options: A table with key: value pairs with display options.

  Options:

  * ``showUUIDs=false``: bool - Whether to display the UUIDs, defaults to false.

.. function:: topSelfAnsweredResponseRules([top [, options]])

  .. versionadded:: 1.6.0

  This function shows the self-answered response rules that matched the most.

  :param int top: How many rules to show.
  :param table options: A table with key: value pairs with display options.

  Options:

  * ``showUUIDs=false``: bool - Whether to display the UUIDs, defaults to false.

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

  Block a set of addresses with ``message`` for (optionally) a number of seconds.
  The default number of seconds to block for is 10.

  :param addresses: set of Addresses as returned by an exceed function
  :param string message: The message to show next to the blocks
  :param int seconds: The number of seconds this block to expire
  :param int action: The action to take when the dynamic block matches, see :ref:`DNSAction <DNSAction>`. (default to DNSAction.None, meaning the one set with :func:`setDynBlocksAction` is used)

  Please see the documentation for :func:`setDynBlocksAction` to confirm which actions are supported by the action paramater.

.. function:: clearDynBlocks()

  Remove all current dynamic blocks.

.. function:: showDynBlocks()

  List all dynamic blocks in effect.

.. function:: setDynBlocksAction(action)

  Set which action is performed when a query is blocked.
  Only DNSAction.Drop (the default), DNSAction.NoOp, DNSAction.NXDomain, DNSAction.Refused, DNSAction.Truncate and DNSAction.NoRecurse are supported.

.. function:: setDynBlocksPurgeInterval(sec)

  .. versionadded:: 1.6.0

  Set at which interval, in seconds, the expired dynamic blocks entries will be effectively removed from the tree. Entries are not applied anymore as
  soon as they expire, but they remain in the tree for a while for performance reasons. Removing them makes the addition of new entries faster and
  frees up the memory they use.
  Setting this value to 0 disable the purging mechanism, so entries will remain in the tree.

  :param int sec: The interval between two runs of the cleaning algorithm, in seconds. Default is 60 (1 minute), 0 means disabled.

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

  Creates a new :class:`DynBlockRulesGroup` object.

.. class:: DynBlockRulesGroup

  Represents a group of dynamic block rules.

  .. method:: DynBlockRulesGroup:setMasks(v4, v6, port)

    .. versionadded:: 1.7.0

    Set the number of bits to keep in the IP address when inserting a block. The default is 32 for IPv4 and 128 for IPv6, meaning
    that only the exact address is blocked, but in some scenarios it might make sense to block a whole /64 IPv6 range instead of a
    single address, for example.
    It is also possible to take the IPv4 UDP and TCP ports into account, for CGNAT deployments, by setting the number of bits of the port
    to consider. For example passing 2 as the last parameter, which only makes sense if the previous parameters are respectively 32
    and 128, will split a given IP address into four port ranges: 0-16383, 16384-32767, 32768-49151 and 49152-65535.

    :param int v4: Number of bits to keep for IPv4 addresses. Default is 32
    :param int v6: Number of bits to keep for IPv6 addresses. Default is 128
    :param int port: Number of bits of port to consider over IPv4. Default is 0 meaning that the port is not taken into account

  .. method:: DynBlockRulesGroup:setQueryRate(rate, seconds, reason, blockingTime [, action [, warningRate]])

    Adds a query rate-limiting rule, equivalent to:
    ```
    addDynBlocks(exceedQRate(rate, seconds), reason, blockingTime, action)
    ```

    :param int rate: Number of queries per second to exceed
    :param int seconds: Number of seconds the rate has been exceeded
    :param string reason: The message to show next to the blocks
    :param int blockingTime: The number of seconds this block to expire
    :param int action: The action to take when the dynamic block matches, see :ref:`DNSAction <DNSAction>`. (default to the one set with :func:`setDynBlocksAction`)
    :param int warningRate: If set to a non-zero value, the rate above which a warning message will be issued and a no-op block inserted

  .. method:: DynBlockRulesGroup:setRCodeRate(rcode, rate, seconds, reason, blockingTime [, action [, warningRate]])

    Adds a rate-limiting rule for responses of code ``rcode``, equivalent to:
    ```
    addDynBlocks(exceedServfails(rcode, rate, seconds), reason, blockingTime, action)
    ```

    :param int rcode: The response code
    :param int rate: Number of responses per second to exceed
    :param int seconds: Number of seconds the rate has been exceeded
    :param string reason: The message to show next to the blocks
    :param int blockingTime: The number of seconds this block to expire
    :param int action: The action to take when the dynamic block matches, see :ref:`DNSAction <DNSAction>`. (default to the one set with :func:`setDynBlocksAction`)
    :param int warningRate: If set to a non-zero value, the rate above which a warning message will be issued and a no-op block inserted

  .. method:: DynBlockRulesGroup:setRCodeRatio(rcode, ratio, seconds, reason, blockingTime, minimumNumberOfResponses [, action [, warningRate]])

    .. versionadded:: 1.5.0

    Adds a rate-limiting rule for the ratio of responses of code ``rcode`` over the total number of responses for a given client.

    :param int rcode: The response code
    :param int ratio: Ratio of responses per second of the given rcode over the total number of responses for this client to exceed
    :param int seconds: Number of seconds the ratio has been exceeded
    :param string reason: The message to show next to the blocks
    :param int blockingTime: The number of seconds this block to expire
    :param int minimumNumberOfResponses: How many total responses is required for this rule to apply
    :param int action: The action to take when the dynamic block matches, see :ref:`DNSAction <DNSAction>`. (default to the one set with :func:`setDynBlocksAction`)
    :param int warningRatio: If set to a non-zero value, the ratio above which a warning message will be issued and a no-op block inserted

  .. method:: DynBlockRulesGroup:setQTypeRate(qtype, rate, seconds, reason, blockingTime [, action [, warningRate]])

    Adds a rate-limiting rule for queries of type ``qtype``, equivalent to:
    ```
    addDynBlocks(exceedQTypeRate(type, rate, seconds), reason, blockingTime, action)
    ```

    :param int qtype: The qtype
    :param int rate: Number of queries per second to exceed
    :param int seconds: Number of seconds the rate has been exceeded
    :param string reason: The message to show next to the blocks
    :param int blockingTime: The number of seconds this block to expire
    :param int action: The action to take when the dynamic block matches, see :ref:`DNSAction <DNSAction>`. (default to the one set with :func:`setDynBlocksAction`)
    :param int warningRate: If set to a non-zero value, the rate above which a warning message will be issued and a no-op block inserted

  .. method:: DynBlockRulesGroup:setResponseByteRate(rate, seconds, reason, blockingTime [, action [, warningRate]])

    Adds a bandwidth rate-limiting rule for responses, equivalent to:
    ```
    addDynBlocks(exceedRespByterate(rate, seconds), reason, blockingTime, action)
    ```

    :param int rate: Number of bytes per second to exceed
    :param int seconds: Number of seconds the rate has been exceeded
    :param string reason: The message to show next to the blocks
    :param int blockingTime: The number of seconds this block to expire
    :param int action: The action to take when the dynamic block matches, see :ref:`DNSAction <DNSAction>`. (default to the one set with :func:`setDynBlocksAction`)
    :param int warningRate: If set to a non-zero value, the rate above which a warning message will be issued and a no-op block inserted

  .. method:: DynBlockRulesGroup:setSuffixMatchRule(seconds, reason, blockingTime, action , visitor)

    .. versionadded:: 1.4.0

    .. versionchanged:: 1.7.0
      This visitor function can now optionally return an additional string which will be set as the ``reason`` for the dynamic block.

    Set a Lua visitor function that will be called for each label of every domain seen in queries and responses. The function receives a `StatNode` object representing the stats of the parent, a second one with the stats of the current label and one with the stats of the current node plus all its children.
    Note that this function will not be called if a FFI version has been set using :meth:`DynBlockRulesGroup:setSuffixMatchRuleFFI`
    If the function returns true, the current label will be blocked according to the `seconds`, `reason`, `blockingTime` and `action` parameters. Since 1.7.0, the function can return an additional string, in addition to the boolean, which will be set as the ``reason`` for the dynamic block.
    Selected domains can be excluded from this processing using the :meth:`DynBlockRulesGroup:excludeDomains` method.

    This replaces the existing :func:`addDynBlockSMT` function.

    :param int seconds: Number of seconds the rate has been exceeded
    :param string reason: The message to show next to the blocks
    :param int blockingTime: The number of seconds this block to expire
    :param int action: The action to take when the dynamic block matches, see :ref:`DNSAction <DNSAction>`. (default to the one set with :func:`setDynBlocksAction`)
    :param function visitor: The Lua function to call.

  .. method:: DynBlockRulesGroup:setSuffixMatchRuleFFI(seconds, reason, blockingTime, action , visitor)

    .. versionadded:: 1.4.0

    Set a Lua FFI visitor function that will be called for each label of every domain seen in queries and responses. The function receives a `dnsdist_ffi_stat_node_t` object containing the stats of the parent, a second one with the stats of the current label and one with the stats of the current node plus all its children.
    If the function returns true, the current label will be blocked according to the `seconds`, `reason`, `blockingTime` and `action` parameters.
    Selected domains can be excluded from this processing using the :meth:`DynBlockRulesGroup:excludeDomains` method.

    :param int seconds: Number of seconds the rate has been exceeded
    :param string reason: The message to show next to the blocks
    :param int blockingTime: The number of seconds this block to expire
    :param int action: The action to take when the dynamic block matches, see :ref:`DNSAction <DNSAction>`. (default to the one set with :func:`setDynBlocksAction`)
    :param function visitor: The Lua FFI function to call.

  .. method:: DynBlockRulesGroup:apply()

    Walk the in-memory query and response ring buffers and apply the configured rate-limiting rules, adding dynamic blocks when the limits have been exceeded.

  .. method:: DynBlockRulesGroup:setQuiet(quiet)

    .. versionadded:: 1.4.0

    Set whether newly blocked clients or domains should be logged.

    :param bool quiet: True means that insertions will not be logged, false that they will. Default is false.

  .. method:: DynBlockRulesGroup:excludeDomains(domains)

    .. versionadded:: 1.4.0

    Exclude this domain, or list of domains, meaning that no dynamic block will ever be inserted for this domain via :meth:`DynBlockRulesGroup:setSuffixMatchRule` or :meth:`DynBlockRulesGroup:setSuffixMatchRuleFFI`. Default to empty, meaning rules are applied to all domains.

    :param str domain: A domain, or list of domains, as strings, like for example "powerdns.com"

  .. method:: DynBlockRulesGroup:excludeRange(netmasks)

    .. versionchanged:: 1.6.0
      This method now accepts a :class:`NetmaskGroup` object.

    Exclude this range, or list of ranges, meaning that no dynamic block will ever be inserted for clients in that range. Default to empty, meaning rules are applied to all ranges. When used in combination with :meth:`DynBlockRulesGroup:includeRange`, the more specific entry wins.

    :param list netmasks: A :class:`NetmaskGroup` object, or a netmask or list of netmasks as strings, like for example "192.0.2.1/24"

  .. method:: DynBlockRulesGroup:includeRange(netmasks)

    .. versionchanged:: 1.6.0
      This method now accepts a :class:`NetmaskGroup` object.

    Include this range, or list of ranges, meaning that rules will be applied to this range. When used in combination with :meth:`DynBlockRulesGroup:excludeRange`, the more specific entry wins.

    :param list netmasks: A :class:`NetmaskGroup` object, or a netmask or list of netmasks as strings, like for example "192.0.2.1/24"

  .. method:: DynBlockRulesGroup:toString()

    Return a string describing the rules and range exclusions of this DynBlockRulesGroup.

StatNode
~~~~~~~~

.. class:: StatNode

  Represent metrics about a given node, for the visitor functions used with :meth:`DynBlockRulesGroup:setSuffixMatchRule` and :meth:`DynBlockRulesGroup:setSuffixMatchRuleFFI`. Note that some nodes includes the metrics for their children as well as their own.

  .. attribute:: StatNode.bytes

    The number of bytes for all responses returned for that node.

  .. attribute:: StatNode.drops

    The number of drops for that node.

  .. attribute:: StatNode.fullname

    The complete name of that node, ie 'www.powerdns.com'.

  .. attribute:: StatNode.labelsCount

    The number of labels in that node, for example 3 for 'www.powerdns.com'.

  .. attribute:: StatNode.noerrors

    The number of No Error answers returned for that node.

  .. attribute:: StatNode.nxdomains

    The number of NXDomain answers returned for that node.

  .. attribute:: StatNode.queries

    The number of queries for that node.

  .. attribute:: StatNode.servfails

    The number of Server Failure answers returned for that node.

  .. method:: StatNode:numChildren

    The number of children of that node.

SuffixMatchNode
~~~~~~~~~~~~~~~

A SuffixMatchNode can be used to quickly check whether a given name belongs to a set or not. This is achieved
using an efficient tree structure based on DNS labels, making lookups cheap.
Be careful that Suffix Node matching will match for any sub-domain, regardless of the depth, under the name added to the set. For example,
if 'example.com.' is added to the set, 'www.example.com.' and 'sub.www.example.com.' will match as well.
If you are looking for exact name matching, your might want to consider using a :class:`DNSNameSet` instead.

.. function:: newSuffixMatchNode()

  Creates a new :class:`SuffixMatchNode`.

.. class:: SuffixMatchNode

  Represent a set of DNS suffixes for quick matching.

  .. method:: SuffixMatchNode:add(name)

    .. versionchanged:: 1.4.0
      This method now accepts strings, lists of DNSNames and lists of strings.

    Add a suffix to the current set.

    :param DNSName name: The suffix to add to the set.
    :param string name: The suffix to add to the set.
    :param table name: The suffixes to add to the set. Elements of the table should be of the same type, either DNSName or string.

  .. method:: SuffixMatchNode:remove(name)

    .. versionadded:: 1.5.0

    Remove a suffix from the current set.

    :param DNSName name: The suffix to remove from the set.
    :param string name: The suffix to remove from the set.
    :param table name: The suffixes to remove from the set. Elements of the table should be of the same type, either DNSName or string.

  .. method:: SuffixMatchNode:check(name) -> bool

    Return true if the given name is a sub-domain of one of those in the set, and false otherwise.

    :param DNSName name: The name to test against the set.

Outgoing TLS tickets cache management
-------------------------------------

Since 1.7, dnsdist supports securing the connection toward backends using DNS over TLS. For these connections, it keeps a cache of TLS tickets to be able to resume a TLS session quickly. By default that cache contains up to 20 TLS tickets per-backend, is cleaned up every every 60s, and TLS tickets expire if they have not been used after 600 seconds.
These values can be set at configuration time via:

.. function:: setOutgoingTLSSessionsCacheMaxTicketsPerBackend(num)

  .. versionadded: 1.7.0

  Set the maximum number of TLS tickets to keep, per-backend, to be able to quickly resume outgoing TLS connections to a backend. Keeping more tickets might provide a better TLS session resumption rate if there is a sudden peak of outgoing connections, at the cost of using a bit more memory.

  :param int num: The number of TLS tickets to keep, per-backend. The default is 20.

.. function:: setOutgoingTLSSessionsCacheCleanupDelay(delay)

  .. versionadded: 1.7.0

  Set the number of seconds between two scans of the TLS sessions cache, removing expired tickets and freeing up memory. Decreasing that value will lead to more scans, freeing up memory more quickly but using a bit more CPU doing so.

  :param int delay: The number of seconds between two scans of the cache. The default is 60.

.. function:: setOutgoingTLSSessionsCacheMaxTicketValidity(validity)

  .. versionadded: 1.7.0

  Set the number of seconds that a given TLS ticket can be kept inactive in the TLS sessions cache. After that delay the ticket will be removed during the next cleanup of the cache. Increasing that value might increase the TLS resumption rate if new connections are not often created, but it might also lead to trying to reuse a ticket that the server will consider too old and refuse.

  :param int validity: The number of seconds a ticket is considered valid. The default is 600, which matches the default lifetime of TLS tickets set by OpenSSL.

Other functions
---------------

.. function:: maintenance()

  If this function exists, it is called every second to do regular tasks.
  This can be used for e.g. :doc:`Dynamic Blocks <../guides/dynblocks>`.

.. function:: setAllowEmptyResponse()

  .. versionadded:: 1.4.0

  Set to true (defaults to false) to allow empty responses (qdcount=0) with a NoError or NXDomain rcode (default) from backends. dnsdist drops these responses by default because it can't match them against the initial query since they don't contain the qname, qtype and qclass, and therefore the risk of collision is much higher than with regular responses.

.. function:: setDropEmptyQueries(drop)

  .. versionadded:: 1.6.0

  Set to true (defaults to false) to drop empty queries (qdcount=0) right away, instead of answering with a NotImp rcode. dnsdist used to drop these queries by default because most rules and existing Lua code expects a query to have a qname, qtype and qclass. However :rfc:`7873` uses these queries to request a server cookie, and :rfc:`8906` as a conformance test, so answering these queries with NotImp is much better than not answering at all.

  :param bool drop: Whether to drop these queries (defaults to false)

.. function:: setProxyProtocolMaximumPayloadSize(size)

  .. versionadded:: 1.6.0

  Set the maximum size of a Proxy Protocol payload that dnsdist is willing to accept, in bytes. The default is 512, which is more than enough except for very large TLV data. This setting can't be set to a value lower than 16 since it would deny of Proxy Protocol headers.

  :param int size: The maximum size in bytes (default is 512)

.. function:: makeIPCipherKey(password) -> string

  .. versionadded:: 1.4.0

  Hashes the password to generate a 16-byte key that can be used to pseudonymize IP addresses with IP cipher.

.. function:: generateOCSPResponse(pathToServerCertificate, pathToCACertificate, pathToCAPrivateKey, outputFile, numberOfDaysOfValidity, numberOfMinutesOfValidity)

  .. versionadded:: 1.4.0

  When a local PKI is used to issue the certificate, or for testing purposes, :func:`generateOCSPResponse` can be used to generate an OCSP response file for a certificate, using the certificate and private key of the certification authority that signed that certificate.
  The resulting file can be directly used with the :func:`addDOHLocal` or the :func:`addTLSLocal` functions.

  :param string pathToServerCertificate: Path to a file containing the certificate used by the server.
  :param string pathToCACertificate: Path to a file containing the certificate of the certification authority that was used to sign the server certificate.
  :param string pathToCAPrivateKey: Path to a file containing the private key corresponding to the certification authority certificate.
  :param string outputFile: Path to a file where the resulting OCSP response will be written to.
  :param int numberOfDaysOfValidity: Number of days this OCSP response should be valid.
  :param int numberOfMinutesOfValidity: Number of minutes this OCSP response should be valid, in addition to the number of days.

DOHFrontend
~~~~~~~~~~~

.. class:: DOHFrontend

  .. versionadded:: 1.4.0

  This object represents an address and port dnsdist is listening on for DNS over HTTPS queries.

  .. method:: DOHFrontend:loadNewCertificatesAndKeys(certFile(s), keyFile(s))

     .. versionadded:: 1.6.1

     Create and switch to a new TLS context using the same options than were passed to the corresponding `addDOHLocal()` directive, but loading new certificates and keys from the selected files, replacing the existing ones.

     :param str certFile(s): The path to a X.509 certificate file in PEM format, or a list of paths to such files.
     :param str keyFile(s): The path to the private key file corresponding to the certificate, or a list of paths to such files, whose order should match the certFile(s) ones.

  .. method:: DOHFrontend:loadTicketsKeys(ticketsKeysFile)

     Load new tickets keys from the selected file, replacing the existing ones. These keys should be rotated often and never written to persistent storage to preserve forward secrecy. The default is to generate a random key. dnsdist supports several tickets keys to be able to decrypt existing sessions after the rotation.
     See :doc:`../advanced/tls-sessions-management` for more information.

    :param str ticketsKeysFile: The path to a file from where TLS tickets keys should be loaded.

  .. method:: DOHFrontend:reloadCertificates()

     Reload the current TLS certificate and key pairs.

  .. method:: DOHFrontend:rotateTicketsKey()

     Replace the current TLS tickets key by a new random one.

  .. method:: DOHFrontend:setResponsesMap(rules)

     Set a list of HTTP response rules allowing to intercept HTTP queries very early, before the DNS payload has been processed, and send custom responses including error pages, redirects and static content.

     :param list of DOHResponseMapEntry objects rules: A list of DOHResponseMapEntry objects, obtained with :func:`newDOHResponseMapEntry`.


.. function:: newDOHResponseMapEntry(regex, status, content [, headers]) -> DOHResponseMapEntry

  .. versionadded:: 1.4.0

  Return a DOHResponseMapEntry that can be used with :meth:`DOHFrontend:setResponsesMap`. Every query whose path is listed in the ``urls`` parameter to :func:`addDOHLocal` and matches the regular expression supplied in ``regex`` will be immediately answered with a HTTP response.
  The status of the HTTP response will be the one supplied by ``status``, and the content set to the one supplied by ``content``, except if the status is a redirection (3xx) in which case the content is expected to be the URL to redirect to.

  :param str regex: A regular expression to match the path against.
  :param int status: The HTTP code to answer with.
  :param str content: The content of the HTTP response, or a URL if the status is a redirection (3xx).
  :param table of headers: The custom headers to set for the HTTP response, if any. The default is to use the value of the ``customResponseHeaders`` parameter passed to :func:`addDOHLocal`.

TLSContext
~~~~~~~~~~

.. class:: TLSContext

  This object represents an address and port dnsdist is listening on for DNS over TLS queries.

  .. method:: TLSContext:loadTicketsKeys(ticketsKeysFile)

     Load new tickets keys from the selected file, replacing the existing ones. These keys should be rotated often and never written to persistent storage to preserve forward secrecy. The default is to generate a random key. The OpenSSL provider supports several tickets keys to be able to decrypt existing sessions after the rotation, while the GnuTLS provider only supports one key.
     See :doc:`../advanced/tls-sessions-management` for more information.

    :param str ticketsKeysFile: The path to a file from where TLS tickets keys should be loaded.

  .. method:: TLSContext:rotateTicketsKey()

     Replace the current TLS tickets key by a new random one.

TLSFrontend
~~~~~~~~~~~

.. class:: TLSFrontend

  This object represents the configuration of a listening frontend for DNS over TLS queries. To each frontend is associated a TLSContext.

  .. method:: TLSFrontend:loadNewCertificatesAndKeys(certFile(s), keyFile(s))

     Create and switch to a new TLS context using the same options than were passed to the corresponding `addTLSLocal()` directive, but loading new certificates and keys from the selected files, replacing the existing ones.

     :param str certFile(s): The path to a X.509 certificate file in PEM format, or a list of paths to such files.
     :param str keyFile(s): The path to the private key file corresponding to the certificate, or a list of paths to such files, whose order should match the certFile(s) ones.

  .. method:: TLSFrontend:loadTicketsKeys(ticketsKeysFile)

  .. versionadded:: 1.6.0

     Load new tickets keys from the selected file, replacing the existing ones. These keys should be rotated often and never written to persistent storage to preserve forward secrecy. The default is to generate a random key. The OpenSSL provider supports several tickets keys to be able to decrypt existing sessions after the rotation, while the GnuTLS provider only supports one key.
     See :doc:`../advanced/tls-sessions-management` for more information.

    :param str ticketsKeysFile: The path to a file from where TLS tickets keys should be loaded.

  .. method:: TLSFrontend:reloadCertificates()

  .. versionadded:: 1.6.0

     Reload the current TLS certificate and key pairs.

  .. method:: TLSFrontend:rotateTicketsKey()

  .. versionadded:: 1.6.0

     Replace the current TLS tickets key by a new random one.

EDNS on Self-generated answers
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

There are several mechanisms in dnsdist that turn an existing query into an answer right away,
without reaching out to the backend, including :func:`SpoofAction`, :func:`RCodeAction`, :func:`TCAction`
and returning a response from ``Lua``. Those responses should, according to :rfc:`6891`, contain an ``OPT``
record if the received request had one, which is the case by default and can be disabled using
:func:`setAddEDNSToSelfGeneratedResponses`.

We must, however, provide a responder's maximum payload size in this record, and we can't easily know the
maximum payload size of the actual backend so we need to provide one. The default value is 1232 since 1.6.0,
and can be overridden using :func:`setPayloadSizeOnSelfGeneratedAnswers`.

.. function:: setAddEDNSToSelfGeneratedResponses(add)

  Whether to add EDNS to self-generated responses, provided that the initial query had EDNS.

  :param bool add: Whether to add EDNS, default is true.

.. function:: setPayloadSizeOnSelfGeneratedAnswers(payloadSize)

  .. versionchanged:: 1.6.0
    Default value changed from 1500 to 1232.

  Set the UDP payload size advertised via EDNS on self-generated responses. In accordance with
  :rfc:`RFC 6891 <6891#section-6.2.5>`, values lower than 512 will be treated as equal to 512.

  :param int payloadSize: The responder's maximum UDP payload size, in bytes. Default is 1232 since 1.6.0, it was 1500 before.

Security Polling
~~~~~~~~~~~~~~~~

PowerDNS products can poll the security status of their respective versions. This polling, naturally,
happens over DNS. If the result is that a given version has a security problem, the software will
report this at level ‘Error’ during startup, and repeatedly during operations, every
:func:`setSecurityPollInterval` seconds.

By default, security polling happens on the domain ‘secpoll.powerdns.com’, but this can be changed with
the :func:`setSecurityPollSuffix` function. If this setting is made empty, no polling will take place.
Organizations wanting to host their own security zones can do so by changing this setting to a domain name
under their control.

To enable distributors of PowerDNS to signal that they have backported versions, the PACKAGEVERSION
compilation-time macro can be used to set a distributor suffix.

.. function:: setSecurityPollInterval(interval)

  Set the interval, in seconds, between two security polls.

  :param int interval: The interval, in seconds, between two polls. Default is 3600.

.. function:: setSecurityPollSuffix(suffix)

  Domain name from which to query security update notifications. Setting this to an empty string disables secpoll.

  :param string suffix: The suffix to use, default is 'secpoll.powerdns.com.'.
