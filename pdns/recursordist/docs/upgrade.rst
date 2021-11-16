Upgrade Guide
=============

Before upgrading, it is advised to read the :doc:`changelog/index`.
When upgrading several versions, please read **all** notes applying to the upgrade.

4.5.x to 4.6.0 or master
------------------------

Offensive language
^^^^^^^^^^^^^^^^^^
Using the settings mentioned in :ref:`upgrade-offensive` now generates a warning. Please start using the new names.

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
Additionally, a single minus *-* can be used as a filename to write the data to the standard output stream.
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
