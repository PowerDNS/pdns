Upgrade Guide
=============

Before upgrading, it is advised to read the :doc:`changelog/index`.
When upgrading several versions, please read **all** notes applying to the upgrade.

4.8.0 to master
---------------

Metrics
^^^^^^^
The way metrics are collected has been changed to increase performance, especially when many thread are used.
This allows for solving a long standing issue that some statistics were not updated on packet cache hits.
This is now resolved, but has the consequence that some metrics (in particular response related ones) changed behaviour as they now also reflect packet cache hits, while they did not before.
This affects the results shown by ``rec_control get-qtypelist`` and the ``response-by-qtype``, ``response-sizes`` and ``response-by-rcode`` items returned by the ``/api/v1/servers/localhost/statistics`` API endpoint.
Additionally, most ``RCodes`` and ``QTypes`` that are marked ``Unassigned``, ``Reserved`` or ``Obsolete`` by IANA are not accounted, to reduce the memory consumed by these metrics.

New settings
~~~~~~~~~~~~
- The :ref:`setting-packetcache-negative-ttl` settings to control the TTL of negative (NxDomain or NoData) answers in the packet cache has been introduced.
- The :ref:`setting-stack-cache-size` setting to  control the number of allocated mthread stacks has been introduced.
- The :ref:`setting-packetcache-shards` settings to control the number of shards in the packet cache has been introduced.
- The :ref:`setting-aggressive-cache-min-nsec3-hit-ratio` setting to control which NSEC3 records are stored in the aggressive NSEC cache has been introduced.

Changed settings
~~~~~~~~~~~~~~~~
The first two settings below have effect on the way the recursor distributes queries over threads.
In some rare cases, this can have negative performance impact.
In those cases it might be needed to change these settings.
See :doc:`performance`.

- The :ref:`setting-pdns-distributes-queries` default has been changed to ``no``.
- The :ref:`setting-reuseport` default has been changed to ``yes``.

- The :ref:`setting-packetcache-ttl` default has been changed to 24 hours.

:program:`rec_control`
^^^^^^^^^^^^^^^^^^^^^^
The ``trace_regex`` subcommand has been changed to take a file argument.
Refer to :doc:`rec_control trace-regex <manpages/rec_control.1>` and :ref:`tracing` for details and example use.

4.8.1 to 4.8.2
--------------

Cache eviction policy
^^^^^^^^^^^^^^^^^^^^^
The cache eviction policy for the record and the negative caches has been improved to reduce imbalance between shards.
The maximum size of the negative cache is now 1/8th of the size of the record cache and its number of shards is 1/8th of the :ref:`setting-record-cache-shards` setting.
Previously the size was 1/10th of the record cache size and the number of shards was equal to the
number of shards of the record cache.
The ``rec_control dump-cache`` command now prints more information about shards.


4.7.0 to 4.8.0
--------------

Structured logging
^^^^^^^^^^^^^^^^^^
All logging (except query tracing) has been converted to structured logging.
Switch to old style logging by setting the :ref:`setting-structured-logging` setting to ``no``.
When using ``systemd``, structured logging information will be sent to ``journald`` using formatted text strings that list the key-value pairs and are human readable.
Switch to native key-value pair logging (more suitable for automated log processing) by setting :ref:`setting-structured-logging-backend` on the command line to ``systemd-journal``.

New settings
^^^^^^^^^^^^
- The :ref:`setting-max-ns-per-resolve` setting to limit the number of NS records processed to resolve a name has been introduced.
- The :ref:`setting-serve-stale-extensions` setting to control the new ``Serve Stale`` feature has been introduced.
- The :ref:`setting-record-cache-locked-ttl-perc` setting to control locking of record sets in the record cache has been introduced.
- The :ref:`setting-edns-padding-out` setting to control EDNS padding for outgoing DoT has been introduced.
- The :ref:`setting-structured-logging-backend` setting to control the type of structured logging to ``journald`` has been introduced.

:program:`pdns_recursor` changes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
THe ``--config`` command line option now implements the ``check``, ``default`` and ``diff`` keywords.

:program:`rec_control` changes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
The ``dump-throttle`` and ``dump-edns`` subcommands no longer produces a table per thread, as the corresponding tables are now shared by all threads.
Additionally, the ``dump-edns`` command  now only lists IPs that have a not OK status.
The ``dump-nsspeeds`` command has changed format to make it more readable and lists the last round trip time recorded for each address.
The ``get-proxymapping-stats`` and ``get-remotelogger-stats`` subcommands have been added.

4.7.2 to 4.7.3
--------------

New settings
^^^^^^^^^^^^
- The :ref:`setting-max-ns-per-resolve` setting to limit the number of NS records processed to resolve a name has been introduced.

4.6.2 to 4.7.0
---------------

Zone to Cache Changes
^^^^^^^^^^^^^^^^^^^^^
The :ref:`ztc` feature now validates ``ZONEMD`` records. This means that zones containing invalid ``ZONEMD`` records will
be rejected by default, while previously the ``ZONEMD`` records would be ignored. For more detail, refer to :ref:`ztc`.

Asynchronous retrieval of ``AAAA`` records for nameservers
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
If ``IPv6`` is enabled for outgoing queries using :ref:`setting-query-local-address`, the :program:`Recursor` will schedule an asynchronous task to resolve ``IPv6`` addresses of nameservers it did not otherwise learn.
These addresses will then be used (in addition to ``IPv4`` addresses) for future queries to authoritative nameservers.
This has the consequence that authoritative nameservers will be contacted over ``IPv6`` in more case than before.

New Lua Configuration Functions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
- The :func:`addAllowedAdditionalQType` ``Lua`` configuration function was added to make the :program:`Recursor` add additional records to answers for specific query types.
- The :func:`addProxyMapping` ``Lua`` configuration function was added to map source addresses to alternative addresses.

Post Resolve FFI Function
^^^^^^^^^^^^^^^^^^^^^^^^^
A new :func:`postresolve_ffi` Lua callback function has been introduced.

New settings
^^^^^^^^^^^^
- The :ref:`setting-save-parent-ns-set` setting has been introduced, enabling fallback cases if the parent ``NS`` set contains names not in the child ``NS`` set.
- The :ref:`setting-max-busy-dot-probes` settings has been introduced, enabling the :program:`Recursor` probe for ``DoT`` support of authoritative servers.
  This is an experimental function, use with care.

:program:`rec_control` changes
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
The ``dump-nsspeeds``, ``dump-failedservers`` and ``dump-non-resolving`` subcommands no longer produce a table per thread, as the corresponding tables are now shared by all threads.
They also use a better readable and sortable timestamp format.

4.6.3 to 4.6.4
--------------

New settings
^^^^^^^^^^^^
- The :ref:`setting-max-ns-per-resolve` setting to limit the number of NS records processed to resolve a name has been introduced.

4.6.1 to 4.6.2
--------------

Deprecated and changed settings
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
-  The :ref:`setting-hint-file` gained a special value ``no`` to indicate that no hint file should be processed. The hint processing code is also made less verbose.

4.5.x to 4.6.1
--------------

Offensive language
^^^^^^^^^^^^^^^^^^
Using the settings mentioned in :ref:`upgrade-offensive` now generates a warning. Please start using the new names.

File descriptor usage
^^^^^^^^^^^^^^^^^^^^^
The number of file descriptors used by the Recursor has increased because the Recursor now keeps idle outgoing TCP/DoT connections open for a while.
The extra file descriptors used in comparison to previous versions of the Recursor is :ref:`setting-tcp-out-max-idle-per-thread` times the number of worker threads (:ref:`setting-threads`).

New settings
^^^^^^^^^^^^
- The :ref:`setting-dot-to-auth-names` setting to list nameservers that should be contacted over DoT has been introduced.
- The :ref:`setting-dot-to-port-853` setting to specify that nameservers or forwarders using port 853 should be contacted over DoT has been introduced.
- The :ref:`setting-ignore-unknown-settings` setting has been introduced to make it easier to switch between recursor versions supporting different settings.
- The :ref:`setting-webserver-hash-plaintext-credentials` has been introduced to avoid keeping cleartext sensitive information in memory.
- The :ref:`setting-tcp-out-max-idle-ms`, :ref:`setting-tcp-out-max-idle-per-auth`, :ref:`setting-tcp-out-max-queries` and :ref:`setting-tcp-out-max-idle-per-thread` settings have been introduced to control the new TCP/DoT outgoing connections pooling. This mechanism keeps connections to authoritative servers or forwarders open for later re-use.
- The :ref:`setting-structured-logging` setting has been introduced to prefer structured logging (the default) when both an old style and a structured log messages is available.
- The :ref:`setting-max-include-depth` setting has been introduced to limit the number of nested ``$include`` directives while processing a zone file.
- The :ref:`setting-allow-notify-for`, :ref:`setting-allow-notify-for-file`, :ref:`setting-allow-notify-from` and :ref:`setting-allow-notify-from-file` settings have been introduced, allowing incoming notify queries to clear cache entries.

Deprecated and changed settings
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
-  The :ref:`setting-api-key` and :ref:`setting-webserver-password` settings now accept a hashed and salted version (if the support is available in the openssl library used).

Privileged port binding in Docker
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In our Docker image, our binaries are no longer granted the ``net_bind_service`` capability, as this is unnecessary in many deployments.
For more information, see the section `"Privileged ports" in Docker-README <https://github.com/PowerDNS/pdns/blob/master/Docker-README.md#privileged-ports>`__.

4.5.10 to 4.5.11
----------------

New settings
^^^^^^^^^^^^
- The :ref:`setting-max-ns-per-resolve` setting to limit the number of NS records processed to resolve a name has been introduced.

4.5.1 to 4.5.2
--------------

Deprecated and changed settings
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
- The :ref:`setting-nsec3-max-iterations` default value has been changed from 2500 to 150.

4.4.x to 4.5.1
--------------

.. _upgrade-offensive:

Offensive language
^^^^^^^^^^^^^^^^^^
Synonyms for various settings names containing ``master``, ``slave``,
``whitelist`` and ``blacklist`` have been introduced.

- For :ref:`setting-stats-api-blacklist` use :ref:`setting-stats-api-disabled-list`.
- For :ref:`setting-stats-carbon-blacklist` use :ref:`setting-stats-carbon-disabled-list`.
- For :ref:`setting-stats-rec-control-blacklist` use :ref:`setting-stats-rec-control-disabled-list`.
- For :ref:`setting-stats-snmp-blacklist` use :ref:`setting-stats-snmp-disabled-list`.
- For :ref:`setting-edns-subnet-whitelist` use :ref:`setting-edns-subnet-allow-list`.
- For :ref:`setting-new-domain-whitelist` use  :ref:`setting-new-domain-ignore-list`.
- For :ref:`setting-snmp-master-socket` use :ref:`setting-snmp-daemon-socket`.
- For the LUA config function :func:`rpzMaster` use :func:`rpzPrimary`.

Currently, the older setting names are also accepted and used.
The next release will start deprecating them.
Users are advised to start using the new names to avoid future
trouble.

Special domains
^^^^^^^^^^^^^^^
Queries for all names in the ``.localhost`` domain will answer in accordance with :rfc:`6761` section 6.3 point 4.
That means that they will be answered with ``127.0.0.1``, ``::1`` or a negative response.

:program:`rec_control` command writing to a file
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
For the commands that write to a file, the file to be dumped to is now opened by the :program:`rec_control` command itself using the credentials and the current working directory of the user running :program:`rec_control`.
A single minus *-* can be used as a filename to write the data to the standard output stream.
Previously the file was opened by the recursor, possibly in its chroot environment.

New settings
^^^^^^^^^^^^
- The :ref:`setting-extended-resolution-errors` setting has been added, enabling adding EDNS Extended Errors to responses.
- The :ref:`setting-refresh-on-ttl-perc` setting has been added, enabling an automatic cache-refresh mechanism.
- The :ref:`setting-ecs-ipv4-never-cache` and :ref:`setting-ecs-ipv6-never-cache` settings have been added, allowing an overrule of the existing decision whether to cache EDNS responses carrying subnet information.
- The :ref:`setting-aggressive-nsec-cache-size` setting has been added, enabling the functionality described in :rfc:`8198`.
- The :ref:`setting-x-dnssec-names` setting has been added, allowing DNSSEC metrics to be recorded in a different set of counter for given domains.
- The :ref:`setting-non-resolving-ns-max-fails` and :ref:`setting-non-resolving-ns-throttle-time` settings have been added, allowing the control of the cache of nameservers failing to resolve.
- The :ref:`setting-edns-padding-from` and :ref:`setting-edns-padding-mode` and :ref:`setting-edns-padding-tag` settings have been added, to control how padding is applied to answers sent to clients.
- The :ref:`setting-tcp-fast-open-connect` setting has been added, it enables TCP Fast Connect for outgoing connections. Please read :ref:`tcp-fast-open-support` before enabling this feature.

Deprecated and changed settings
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
- The :ref:`setting-minimum-ttl-override` and :ref:`setting-ecs-minimum-ttl-override` defaults have ben changed from 0 to 1.
- The :ref:`setting-spoof-nearmiss-max` default has been changed from 20 to 1.
- The :ref:`setting-dnssec` default has changed from ``process-no-validate`` to ``process``.
- The meaning of the :ref:`setting-max-packetcache-entries` has changed: previously there was one packet cache instance per worker thread.
  Since queries incoming over TCP are now also using the packet cache, there is now also one packet cache instance per distributor thread.
  Each cache instance has a size of :ref:`setting-max-packetcache-entries` divided by (:ref:`setting-threads` + :ref:`setting-distributor-threads`).

Removed settings
^^^^^^^^^^^^^^^^
- The :ref:`setting-query-local-address6` has been removed. It already was deprecated.

4.3.x to 4.4.0
--------------

Response Policy Zones (RPZ)
^^^^^^^^^^^^^^^^^^^^^^^^^^^

To conform better to the standard, RPZ processing has been modified.
This has consequences for the points in the resolving process where matches are checked and callbacks are called.
See :ref:`rpz` for details. Additionally a new type of callback has been introduced: :func:`policyEventFilter`.

Dropping queries from Lua callbacks
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
The method to drop a query from a Lua callback has been changed.
Previously, you could set `rcode` to `pdns.DROP`. See :ref:`hook-semantics` for the new method.

Parsing of unknown record types
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
The parsing (from zone files) of unknown records types (of the form
``\# <length> <hex data>``) has been made more strict. Previously, invalid formatted records could produce
inconsistent results.

Deprecated and changed settings
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
- The :ref:`setting-query-local-address` setting has been modified to be able to include both IPv4 and IPv6 addresses.
- The :ref:`setting-query-local-address6` settings is now deprecated.

New settings
^^^^^^^^^^^^
- The :ref:`setting-dns64-prefix` setting has been added, enabling common cases of DNS64 handling without having to write Lua code.
- The :ref:`setting-proxy-protocol-from` and :ref:`setting-proxy-protocol-maximum-size` settings have been added to allow for passing of Proxy Protocol Version 2 headers between a client and the recursor.
- The :ref:`setting-record-cache-shards` setting has been added, enabling the administrator to change the number of shards in the records cache. The value of the metric ``record-cache-contended`` divided by ``record-cache-acquired`` indicates if the record cache locks are contended. If so, increasing the number of shards can help reducing the contention.

4.2.x to 4.3.0
------------------------

Lua Netmask class methods changed
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
- Netmask class methods ``isIpv4`` and ``isIpv6`` have been deprecated in Lua, use :func:`Netmask.isIPv4` and :func:`Netmask.isIPv6` instead. In C++ API these methods have been removed.

``socket-dir`` changed
^^^^^^^^^^^^^^^^^^^^^^
The default :ref:`setting-socket-dir` has changed to include ``pdns-recursor`` in the path.
For non-chrooted setups, it is now whatever is passed to ``--with-socketdir`` during configure (``/var/run`` by default) plus ``pdns-recursor``.
The systemd unit-file is updated to reflect this change and systemd will automatically create the directory with the proper permissions.
The packaged sysV init-script also creates this directory.
For other operating systems, update your init-scripts accordingly.

Systemd service and permissions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
The systemd service-file that is installed no longer uses the ``root`` user to start.
It uses the user and group set with the ``--with-service-user`` and ``--with-service-group`` switches during
configuration, "pdns" on Debian and "pdns-recursor" on CentOS by default.
This could mean that PowerDNS Recursor cannot read its configuration, lua scripts, auth-zones or other data.
It is recommended to recursively ``chown`` directories used by PowerDNS Recursor::

  # For Debian-based systems
  chown -R root:pdns /etc/powerdns

  # For CentOS and RHEL based systems
  chown -R root:pdns-recursor /etc/pdns-recursor

Packages provided on `the PowerDNS Repository <https://repo.powerdns.com>`__ will ``chown`` directories created by them accordingly in the post-installation steps.

New settings
^^^^^^^^^^^^
- The :ref:`setting-allow-trust-anchor-query` setting has been added. This setting controls if negative trust anchors can be queried. The default is `no`.
- The :ref:`setting-max-concurrent-requests-per-tcp-connection` has been added. This setting controls how many requests are handled concurrently per incoming TCP connection. The default is 10.
- The :ref:`setting-max-generate-steps` setting has been added. This sets the maximum number of steps that will be performed when loading a BIND zone with the ``$GENERATE`` directive. The default is 0, which is unlimited.
- The :ref:`setting-nothing-below-nxdomain` setting has been added. This setting controls the way cached NXDOMAIN replies imply non-existence of a whole subtree. The default is `dnssec` which means that only DNSSEC validated NXDOMAINS results are used.
- The :ref:`setting-qname-minimization` setting has been added. This options controls if QName Minimization is used. The default is `yes`.
 
4.1.x to 4.2.0
--------------

Two new settings have been added:

- :ref:`setting-xpf-allow-from` can contain a list of IP addresses ranges from which `XPF (X-Proxied-For) <https://datatracker.ietf.org/doc/draft-bellis-dnsop-xpf/>`_ records will be trusted.
- :ref:`setting-xpf-rr-code` should list the number of the XPF record to use (in lieu of an assigned code).

4.0.x to 4.1.0
--------------

:ref:`setting-loglevel` defaulted to 4 but was always overridden to 6 during
the startup. The issue has been fixed and the default value set to 6 to keep the behavior
consistent.

The ``--with-libsodium`` configure flag has changed from 'no' to 'auto'.
This means that if libsodium and its development header are installed, it will be linked in.

4.0.3 to 4.0.4
--------------

One setting has been added to limit the risk of overflowing the stack:

-  :ref:`setting-max-recursion-depth`: defaults to 40 and was unlimited before

4.0.0 to 4.0.1
--------------

Two settings have changed defaults, these new defaults decrease CPU usage:

-  :ref:`setting-root-nx-trust` changed from "no" to "yes"
-  :ref:`setting-log-common-errors` changed from "yes" to "no"
