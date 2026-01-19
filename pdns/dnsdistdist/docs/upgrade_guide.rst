Upgrade Guide
=============

2.0.x to 2.1.0
--------------

Custom load-balancing policies written in Lua now need to return the index in the servers array of the backend they intend to select, instead of returning a reference to the backend itself.

dnsdist no longer supports ``h2o`` for incoming DNS over HTTPS, as it is unfortunately no longer maintained in a way that is suitable for use as a library
(see https://github.com/h2o/h2o/issues/3230). This means that only ``nghttp2`` is supported from now on.
Note that ``nghttp2`` only supports HTTP/2, and not HTTP/1, while ``h2o`` supported both. This is not an issue for actual DNS over HTTPS clients that
support HTTP/2, but might be one in setups running dnsdist behind a reverse-proxy that does not support HTTP/2. See :doc:`guides/dns-over-https` for some work-around.

Structured logging is now enabled by default, and can be disabled via :func:`setStructuredLogging` or the ``--structured-logging`` command-line switch.

:program:`dnsdist` now looks by default for a configuration file named ``dnsdist.yml`` in the system configuration directory (determined by the ``SYSCONFDIR`` variable during compilation), instead of ``dnsdist.conf``.

1.9.x to 2.0.0
--------------

Since 2.0.0, a Python 3 interpreter with the ``YAML`` module is required to build :program:`dnsdist`.
:program:`dnsdist` 2.0.0 also supports a new, optional ``yaml`` :doc:`configuration format <reference/yaml-settings>`. To build with this feature enabled, a Rust development environment, including ``rustc`` and ``cargo`` is needed.

:func:`showTLSContexts` has been renamed to :func:`showTLSFrontends`.
:func:`getTLSContext` and the associated :class:`TLSContext` have been removed, please use :func:`getTLSFrontend` and the associated :class:`TLSFrontend` instead.

Our eBPF filtering code no longer treats the ``255``/``ANY`` qtype as a special value intended to block queries for all types, and will only block ``ANY`` queries instead. The reserved ``65535`` value now can be used to block queries for all qtypes.

XPF support has been removed.

:meth:`Server:setAuto` used to reset the health-check mode to ``active`` even if it had previously been set to ``lazy`` via :meth:`Server:setLazyAuto`. This is no longer the case, and :meth:`Server:setActiveAuto` should be used instead to set the health-check mode to ``Active``.

The ``options`` parameter of :func:`HTTPStatusAction` has been deprecated because it had unexpected side-effects, and should thus no longer be used.

In some cases, :program:`dnsdist` turns an incoming query into a response, setting the response code in the process. When doing so, it was not properly cleaning up records present in the answer, authority or additional sections, which could have been surprising to clients and wasted bandwidth. This has now been fixed. The cases in question are:

* :func:`RCodeAction`
* :func:`ERCodeAction`
* returning ``DNSAction.Nxdomain``, ``DNSAction.Refused`` or ``DNSAction.ServFail`` from ``Lua``
* using the ``DNSAction.Nxdomain``, ``DNSAction.Refused`` or ``DNSAction.ServFail`` dynamic block actions
* sending ``Server Failure`` when no downstream servers are usable
* receiving a zone transfer request over DoQ, DoH or DoH3

1.8.x to 1.9.0
--------------

dnsdist now supports a new library for dealing with incoming DNS over HTTPS queries: ``nghttp2``. The previously used library, ``h2o``, can still be used
but is now deprecated, disabled by default (see ``--with-h2o`` to enable it back) and will be removed in the future, as it is unfortunately no longer maintained in a way that is suitable for use as a library
(see https://github.com/h2o/h2o/issues/3230). See the ``library`` parameter on the :func:`addDOHLocal` directive for more information on how to select
the library used when dnsdist is built with support for both ``h2o`` and ``nghttp2``. The default is now ``nghttp2`` whenever possible.
Note that ``nghttp2`` only supports HTTP/2, and not HTTP/1, while ``h2o`` supported both. This is not an issue for actual DNS over HTTPS clients that
support HTTP/2, but might be one in setups running dnsdist behind a reverse-proxy that does not support HTTP/2. See :doc:`guides/dns-over-https` for some work-around.

SNMP support is no longer enabled by default during ``configure``, requiring ``--with-net-snmp`` to be built.

The use of :func:`makeRule` is now deprecated, please use :func:`NetmaskGroupRule` or :func:`QNameSuffixRule` instead.
Passing a string or list of strings instead of a :class:`DNSRule` to these functions is deprecated as well, :func:`NetmaskGroupRule` and :func:`QNameSuffixRule` should there again be used instead:

* :func:`addAction`
* :func:`addResponseAction`
* :func:`addCacheHitResponseAction`
* :func:`addCacheInsertedResponseAction`
* :func:`addSelfAnsweredResponseAction`

1.7.x to 1.8.0
--------------

Responses to AXFR and IXFR queries are no longer cached.

Cache-hits are now counted as responses in our metrics.

Cache hits are now inserted into the in-memory ring buffers, while before 1.8.0 only cache misses were inserted. This has a very noticeable impact on :doc:`guides/dynblocks` since cache hits now considered when computing the rcode rates and ratios, as well as the response bandwidth rate.

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

The packet cache no longer hashes EDNS Cookies by default, which means that two queries that are identical except for the content of their cookie will now be served the same answer. This only works if the backend is not returning any answer containing EDNS Cookies; otherwise, the wrong cookie might be returned to a client. To prevent this, the ``cookieHashing=true`` parameter might be passed to :func:`newPacketCache` so that cookies are hashed, resulting in separate entries in the packet cache.

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
