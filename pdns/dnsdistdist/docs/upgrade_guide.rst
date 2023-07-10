Upgrade Guide
=============

1.7.x to 1.8.0
--------------

Responses to AXFR and IXFR queries are no longer cached.

Cache-hits are now counted as responses in our metrics.

The :func:`setMaxTCPConnectionsPerClient` limit is now properly applied to DNS over HTTPS connections, in addition to DNS over TCP and DNS over TLS ones.

The configuration check will now fail if the configuration file does not exist. For this reason we now create a default configuration file, based on the file previously called ``dnsdistconf.lua``, which contains commented-out examples of how to set up dnsdist.

Latency metrics have been broken down:

* per incoming protocol (Do53 UDP, Do53 TCP, DoT, DoH) for global latency metrics
* between UDP (Do53) and TCP (Do53 TCP, DoT, DoH) for backend latency metrics

1.7.0 to 1.7.1
--------------

In our Docker image, our binaries are no longer granted the ``net_bind_service`` capability, as this is unnecessary in many deployments.
For more information, see the section `"Privileged ports" in Docker-README <https://github.com/PowerDNS/pdns/blob/master/Docker-README.md#privileged-ports>`__.
(This note was in the 1.6.x to 1.7.0 upgrade guide before, but the change was not present in 1.7.0.)

1.6.x to 1.7.0
--------------

Truncated responses received over UDP for DoH clients will now be retried over TCP.

:func:`setTCPUseSinglePipe` has been removed.

Unless set via :func:`setMaxTCPClientThreads` the number of TCP workers now defaults to 10, instead of the number of TCP binds.

Plain-text API keys and passwords for web server authentication are now strongly discouraged. The :func:`hashPassword` method can be used to generate a hashed and salted version of passwords and API keys instead, so that the plain-text version can no longer be found in either the configuration file or the memory of the running process.

1.5.x to 1.6.0
--------------

The packet cache no longer hashes EDNS Cookies by default, which means that two queries that are identical except for the content of their cookie will now be served the same answer. This only works if the backend is not returning any answer containing EDNS Cookies, otherwise the wrong cookie might be returned to a client. To prevent this, the ``cookieHashing=true`` parameter might be passed to :func:`newPacketCache` so that cookies are hashed, resulting in separate entries in the packet cache.

All TCP worker threads are now created at startup, instead of being created on-demand. The existing behaviour was useful for very small setups but did not scale quickly to a large amount of TCP connections.
The new behaviour can cause a noticeable increase of TCP connections between dnsdist and its backends, as the TCP connections are not shared between TCP worker threads.
This is especially true for setups with a large number of frontends (:func:`addLocal`, :func:`addTLSLocal`, and :func:`addDNSCryptBind` directives), as 1.6.0 sets the number of TCP workers to the number of TCP-enabled binds (with a minimum of 10), unless that number has been set explicitly via :func:`setMaxTCPClientThreads`.

Several actions have been renamed so that almost all actions that allow further processing of rules start with 'Set', to prevent mistakes:

* ``DisableECSAction`` to :func:`SetDisableECSAction`
* ``DisableValidationAction`` to :func:`SetDisableValidationAction`
* ``ECSOverrideAction`` to :func:`SetECSOverrideAction`
* ``ECSPrefixLengthAction`` to :func:`SetECSPrefixLengthAction`
* ``MacAddrAction`` to :func:`SetMacAddrAction`
* ``NoRecurseAction`` to :func:`SetNoRecurseAction`
* ``SkipCacheAction`` to :func:`SetSkipCacheAction`
* ``TagAction`` to :func:`SetTagAction`
* ``TagResponseAction`` to :func:`SetTagResponseAction`
* ``TempFailureCacheTTLAction`` to :func:`SetAdditionalProxyProtocolValueAction`
* ``SetNegativeAndSOAAction`` to :func:`NegativeAndSOAAction`

Some ambiguous commands have also been renamed to prevent mistakes:

* `topCacheHitResponseRule` to :func:`mvCacheHitResponseRuleToTop`
* `topResponseRule` to :func:`mvResponseRuleToTop`
* `topRule` to :func:`mvRuleToTop`
* `topSelfAnsweredResponseRule` to :func:`mvSelfAnsweredResponseRuleToTop`

The use of additional parameters on the :func:`webserver` command has been deprecated in favor of using :func:`setWebserverConfig`.

Regular users should not be impacted by this change, but packagers should be aware that since 1.6.0 dnsdist now uses the C++17 standard instead of the C++11 one it was previously using.

1.4.x to 1.5.0
--------------

DOH endpoints specified in the fourth parameter of :func:`addDOHLocal` are now specified as exact paths instead of path prefixes. The default endpoint also switched from ``/`` to ``/dns-query``.
For example, ``addDOHLocal('2001:db8:1:f00::1', '/etc/ssl/certs/example.com.pem', '/etc/ssl/private/example.com.key', { "/dns-query" })`` will now only accept queries for ``/dns-query`` and no longer for ``/dns-query/foo/bar``.
This change also impacts the HTTP response rules set via :meth:`DOHFrontend:setResponsesMap`, since queries whose paths are not allowed will be discarded before the rules are evaluated.
If you want to accept DoH queries on ``/dns-query`` and redirect ``/rfc`` to the DoH RFC, you need to list ``/rfc`` in the list of paths:

.. code-block:: lua

  addDOHLocal('2001:db8:1:f00::1', '/etc/ssl/certs/example.com.pem', '/etc/ssl/private/example.com.key', { '/dns-query', '/rfc'})
  map = { newDOHResponseMapEntry("^/rfc$", 307, "https://www.rfc-editor.org/info/rfc8484") }
  dohFE = getDOHFrontend(0)
  dohFE:setResponsesMap(map)

The systemd service-file that is installed no longer uses the ``root`` user to start. It uses the user and group set with the ``--with-service-user`` and ``--with-service-group`` switches during
configuration, "dnsdist" by default.
This could mean that dnsdist can no longer read its own configuration, or other data. It is therefore recommended to recursively ``chown`` directories used  by dnsdist::

  chown -R root:dnsdist /etc/dnsdist

Packages provided on `the PowerDNS Repository <https://repo.powerdns.com>`__ will ``chown`` directories created by them accordingly in the post-installation steps.

This might not be sufficient if the dnsdist configuration refers to files outside of the /etc/dnsdist directory, like DoT or DoH certificates and private keys.
Many ACME clients used to get and renew certificates, like CertBot, set permissions assuming that services are started as root. For that particular case, making a copy of the necessary files in the /etc/dnsdist directory is advised, using for example CertBot's ``--deploy-hook`` feature to copy the files with the right permissions after a renewal.

The :func:`webserver` configuration now has an optional ACL parameter, that defaults to "127.0.0.1, ::1".

1.3.x to 1.4.0
--------------

:func:`addLuaAction` and :func:`addLuaResponseAction` have been removed. Instead, use :func:`addAction` with a :func:`LuaAction`, or :func:`addResponseAction` with a :func:`LuaResponseAction`.

:func:`newPacketCache` now takes an optional table as its second argument, instead of several optional parameters.

Lua's constants for DNS response codes and QTypes have been moved from the 'dnsdist' prefix to, respectively, the 'DNSQType' and 'DNSRCode' prefix.

To improve security, all ambient capabilities are now dropped after the startup phase, which might prevent launching the webserver on a privileged port at run-time, or impact some custom Lua code. In addition, systemd's sandboxing features are now determined at compile-time, resulting in more restrictions on recent distributions. See pull requests 7138 and 6634 for more information.

If you are compiling dnsdist, note that several ./configure options have been renamed to provide a more consistent experience. Features that depend on an external component have been prefixed with '--with-' while internal features use '--enable-'. This lead to the following changes:

- ``--enable-fstrm`` to ``--enable-dnstap``
- ``--enable-gnutls`` to ``--with-gnutls``
- ``--enable-libsodium`` to ``--with-libsodium``
- ``--enable-libssl`` to ``--with-libssl``
- ``--enable-re2`` to ``--with-re2``

1.3.2 to 1.3.3
--------------

When upgrading from a package before 1.3.3, on CentOS 6 and RHEL 6, dnsdist will be stopped instead of restarted.

1.2.x to 1.3.x
--------------

In version 1.3.0, these things have changed.

The :ref:`Console` has an ACL now, which is set to ``{"127.0.0.0/8", "::1/128"}`` by default.
Add the appropriate :func:`setConsoleACL` and :func:`addConsoleACL` statements to the configuration file.

The ``--daemon`` option is removed from the :program:`dnsdist` binary, meaning that :program:`dnsdist` will not fork to the background anymore.
Hence, it can only be run on the foreground or under a supervisor like systemd, supervisord and ``daemon(8)``.

Due to changes in the architecture of :program:`dnsdist`, several of the shortcut rules have been removed after deprecating them in 1.2.0.
All removed functions have their equivalent :func:`addAction` listed.
Please check the configuration for these statements (or use ``dnsdist --check-config``) and update where needed.
This removal affects these functions:

- :func:`addAnyTCRule`
- :func:`addDelay`
- :func:`addDisableValidationRule`
- :func:`addDomainBlock`
- :func:`addDomainCNAMESpoof`
- :func:`addDomainSpoof`
- :func:`addNoRecurseRule`
- :func:`addPoolRule`
- :func:`addQPSLimit`
- :func:`addQPSPoolRule`

1.1.0 to 1.2.0
--------------

In 1.2.0, several configuration options have been changed:

As the amount of possible settings for listen sockets is growing, all listen-related options must now be passed as a table as the second argument to both :func:`addLocal` and :func:`setLocal`.
See the function's reference for more information.

The ``BlockFilter`` function is removed, as :func:`addAction` combined with a :func:`DropAction` can do the same.
