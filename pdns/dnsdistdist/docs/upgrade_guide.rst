Upgrade Guide
=============

1.4.0 to 1.5.x
--------------

DOH endpoints specified in the fourth parameter of :func:`addDOHLocal` are now specified as exact URLs instead of path prefixes. The default endpoint also switched from ``/`` to ``/dns-query``.
For example, ``addDOHLocal('2001:db8:1:f00::1', '/etc/ssl/certs/example.com.pem', '/etc/ssl/private/example.com.key', { "/dns-query" })`` will now only accept queries for ``/dns-query`` and no longer for ``/dns-query/foo/bar``.

The systemd service-file that is installed no longer uses the ``root`` user to start. It uses the user and group set with the ``--with-service-user`` and ``--with-service-group`` switches during
configuration, "dnsdist" by default.
This could mean that dnsdist can no longer read its own configuration, or other data. It is therefore recommended to recursively ``chown`` directories used  by dnsdist::

  chown -R root:dnsdist /etc/dnsdist

Packages provided on `the PowerDNS Repository <https://repo.powerdns.com>`__ will ``chown`` directories created by them accordingly in the post-installation steps.

This might not be sufficient if the dnsdist configuration refers to files outside of the /etc/dnsdist directory, like DoT or DoH certificates and private keys.
Many ACME clients used to get and renew certificates, like CertBot, set permissions assuming that services are started as root. For that particular case, making a copy of the necessary files in the /etc/dnsdist directory is advised, using for example CertBot's ``--deploy-hook`` feature to copy the files with the right permissions after a renewal.

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

The ``BlockFilter`` function is removed, as :func:`addRule` combined with a :func:`DropAction` can do the same.
