Authoritative Server Settings
=============================

All PowerDNS Authoritative Server settings are listed here, excluding
those that originate from backends, which are documented in the relevant
chapters. These settings can be set inside ``pdns.conf`` or on the
commandline when invoking the ``pdns`` binary.

You can use ``+=`` syntax to set some variables incrementally, but this
requires you to have at least one non-incremental setting for the
variable to act as base setting. This is mostly useful for
:ref:`setting-include-dir` directive.

For boolean settings, specifying the name of the setting without a value
means ``yes``.

.. _setting-8bit-dns:

``8bit-dns``
------------

-  Boolean
-  Default: no

.. versionadded:: 4.0.0

Allow 8 bit DNS queries.

.. _setting-allow-axfr-ips:

``allow-axfr-ips``
------------------

-  IP ranges, separated by commas
-  Default: 127.0.0.0/8,::1

If set, only these IP addresses or netmasks will be able to perform
AXFR.

.. _setting-allow-dnsupdate-from:

``allow-dnsupdate-from``
------------------------

-  IP ranges, separated by commas
-  Default: 127.0.0.0/8,::1

Allow DNS updates from these IP ranges. Set to empty string to honour ``ALLOW-DNSUPDATE-FROM`` in :ref:`metadata-allow-dnsupdate-from`.

.. _setting-allow-notify-from:

``allow-notify-from``
---------------------

-  IP ranges, separated by commas
-  Default: 0.0.0.0/0,::/0

Allow AXFR NOTIFY from these IP ranges. Setting this to an empty string
will drop all incoming notifies.

.. _setting-allow-recursion:

``allow-recursion``
-------------------

-  IP ranges, separated by commas
-  Default: 0.0.0.0/0

.. deprecated:: 4.1.0
  Recursion has been removed, see :doc:`guides/recursion`

By specifying ``allow-recursion``, recursion can be restricted to
netmasks specified. The default is to allow recursion from everywhere.
Example: ``allow-recursion=198.51.100.0/24, 10.0.0.0/8, 192.0.2.4``.

.. _setting-allow-unsigned-notify:

``allow-unsigned-notify``
-------------------------

-  Boolean
-  Default: yes

.. versionadded:: 4.0.0

Turning this off requires all notifications that are received to be
signed by valid TSIG signature for the zone.

.. _setting-allow-unsigned-supermaster:

``allow-unsigned-supermaster``
------------------------------

-  Boolean
-  Default: yes

.. versionadded:: 4.0.0

Turning this off requires all supermaster notifications to be signed by
valid TSIG signature. It will accept any existing key on slave.

.. _setting-also-notify:

``also-notify``
---------------

-  IP addresses, separated by commas

When notifying a domain, also notify these nameservers. Example:
``also-notify=192.0.2.1, 203.0.113.167``. The IP addresses listed in
``also-notify`` always receive a notification. Even if they do not match
the list in :ref:`setting-only-notify`.

.. _setting-any-to-tcp:

``any-to-tcp``
--------------

-  Boolean
-  Default: yes

.. versionchanged:: 4.0.1
  was 'no' before.

Answer questions for the ANY on UDP with a truncated packet that refers
the remote server to TCP. Useful for mitigating reflection attacks.

.. _setting-api:

``api``
-------

-  Boolean
-  Default: no

Enable/disable the :doc:`http-api/index`.

.. _setting-api-key:

``api-key``
-----------

-  String

.. versionadded:: 4.0.0

Static pre-shared authentication key for access to the REST API.

.. _setting-api-readonly:

``api-readonly``
----------------

-  Boolean
-  Default: no

.. versionadded:: 4.0.0
.. versionchanged:: 4.2.0
  This setting has been removed in 4.2.0.

Disallow data modification through the REST API when set.

.. _setting-axfr-fetch-timeout:

``axfr-fetch-timeout``
----------------------

- Integer
- Default: 10

.. versionadded:: 4.3.0

Maximum time in seconds for inbound AXFR to start or be idle after starting.

.. _setting-axfr-lower-serial:

``axfr-lower-serial``
---------------------

-  Boolean
-  Default: no

.. versionadded:: 4.0.4

Also AXFR a zone from a master with a lower serial.

.. _setting-cache-ttl:

``cache-ttl``
-------------

-  Integer
-  Default: 20

Seconds to store packets in the :ref:`packet-cache`. A value of 0 will disable the cache.

.. _setting-carbon-instance:

``carbon-instance``
-------------------

-  String
-  Default: auth

.. versionadded:: 4.2.0

Set the instance or third string of the metric key. Be careful not to include
any dots in this setting, unless you know what you are doing.
See :ref:`metricscarbon`

.. _setting-carbon-interval:

``carbon-interval``
-------------------

-  Integer
-  Default: 30

If sending carbon updates, this is the interval between them in seconds.
See :ref:`metricscarbon`.

.. _setting-carbon-namespace:

``carbon-namespace``
--------------------

-  String
-  Default: pdns

.. versionadded:: 4.2.0

Set the namespace or first string of the metric key. Be careful not to include
any dots in this setting, unless you know what you are doing.
See :ref:`metricscarbon`

.. _setting-carbon-ourname:

``carbon-ourname``
------------------

-  String
-  Default: the hostname of the server

If sending carbon updates, if set, this will override our hostname. Be
careful not to include any dots in this setting, unless you know what
you are doing. See :ref:`metricscarbon`

.. _setting-carbon-server:

``carbon-server``
-----------------

-  IP Address

Send all available metrics to this server via the carbon protocol, which
is used by graphite and metronome. It has to be an address (no
hostnames). Moreover you can specify more than one server using a comma delimited list, ex:
carbon-server=10.10.10.10,10.10.10.20.
You may specify an alternate port by appending :port, ex:
127.0.0.1:2004. See :ref:`metricscarbon`.

.. _setting-chroot:

``chroot``
----------

-  Path

If set, chroot to this directory for more security. See :doc:`security`.

Make sure that ``/dev/log`` is available from within the chroot. Logging
will silently fail over time otherwise (on logrotate).

When setting ``chroot``, all other paths in the config (except for
:ref:`setting-config-dir` and :ref:`setting-module-dir`)
set in the configuration are relative to the new root.

When running on a system where systemd manages services, ``chroot`` does
not work out of the box, as PowerDNS cannot use the ``NOTIFY_SOCKET``.
Either don't ``chroot`` on these systems or set the 'Type' of the this
service to 'simple' instead of 'notify' (refer to the systemd
documentation on how to modify unit-files)

.. _setting-config-dir:

``config-dir``
--------------

-  Path

Location of configuration directory (``pdns.conf``). Usually
``/etc/powerdns``, but this depends on ``SYSCONFDIR`` during
compile-time.

.. _setting-config-name:

``config-name``
---------------

-  String

Name of this virtual configuration - will rename the binary image. See
:doc:`guides/virtual-instances`.

.. _setting-control-console:

``control-console``
-------------------

Debugging switch - don't use.

.. _setting-daemon:

``daemon``
----------

-  Boolean
-  Default: no

Operate as a daemon.

.. _setting-default-api-rectify:

``default-api-rectify``
-----------------------
-  Boolean
-  Default: yes

.. versionadded:: 4.2.0

The value of :ref:`metadata-api-rectify` if it is not set on the zone.

.. note::
  Pre 4.2.0 the default was always no.

.. _setting-default-ksk-algorithms:
.. _setting-default-ksk-algorithm:

``default-ksk-algorithm``
-------------------------

-  String
-  Default: ecdsa256

.. versionchanged:: 4.1.0
  Renamed from ``default-ksk-algorithms``. No longer supports multiple algorithm names.

The algorithm that should be used for the KSK when running
:doc:`pdnsutil secure-zone <manpages/pdnsutil.1>` or using the :doc:`Zone API endpoint <http-api/cryptokey>`
to enable DNSSEC. Must be one of:

* rsasha1
* rsasha256
* rsasha512
* ecdsa256 (ECDSA P-256 with SHA256)
* ecdsa384 (ECDSA P-384 with SHA384)
* ed25519
* ed448

.. note::
  Actual supported algorithms depend on the crypto-libraries
  PowerDNS was compiled against. To check the supported DNSSEC algoritms
  in your build of PowerDNS, run ``pdnsutil list-algorithms``.

.. _setting-default-ksk-size:

``default-ksk-size``
--------------------

-  Integer
-  Default: whichever is default for `default-ksk-algorithm`_

The default keysize for the KSK generated with :doc:`pdnsutil secure-zone <dnssec/pdnsutil>`.
Only relevant for algorithms with non-fixed keysizes (like RSA).

.. _setting-default-soa-edit:

``default-soa-edit``
--------------------

-  String
-  Default: empty

Use this soa-edit value for all zones if no
:ref:`metadata-soa-edit` metadata value is set.

.. _setting-default-soa-edit-signed:

``default-soa-edit-signed``
---------------------------

-  String
-  Default: empty

Use this soa-edit value for all signed zones if no
:ref:`metadata-soa-edit` metadata value is set.
Overrides :ref:`setting-default-soa-edit`

.. _setting-default-soa-mail:

``default-soa-mail``
--------------------

-  String

.. deprecated:: 4.2.0
  This setting has been deprecated and will be removed in 4.3.0

Mail address to insert in the SOA record if none set in the backend.

.. _setting-default-soa-name:

``default-soa-name``
--------------------

-  String
-  Default: a.misconfigured.powerdns.server

.. deprecated:: 4.2.0
  This setting has been deprecated and will be removed in 4.3.0

Name to insert in the SOA record if none set in the backend.

.. _setting-default-ttl:

``default-ttl``
---------------

-  Integer
-  Default: 3600

TTL to use when none is provided.

.. _setting-default-zsk-algorithms:
.. _setting-default-zsk-algorithm:

``default-zsk-algorithm``
--------------------------

-  String
-  Default: (empty)

.. versionchanged:: 4.1.0
  Renamed from ``default-zsk-algorithms``. Does no longer support multiple algorithm names.

The algorithm that should be used for the ZSK when running
:doc:`pdnsutil secure-zone <manpages/pdnsutil.1>` or using the :doc:`Zone API endpoint <http-api/cryptokey>`
to enable DNSSEC. Must be one of:

* rsasha1
* rsasha256
* rsasha512
* ecdsa256 (ECDSA P-256 with SHA256)
* ecdsa384 (ECDSA P-384 with SHA384)
* ed25519
* ed448

.. note::
  Actual supported algorithms depend on the crypto-libraries
  PowerDNS was compiled against. To check the supported DNSSEC algoritms
  in your build of PowerDNS, run ``pdnsutil list-algorithms``.

.. _setting-default-zsk-size:

``default-zsk-size``
--------------------

-  Integer
-  Default: 0 (automatic default for `default-zsk-algorithm`_)

The default keysize for the ZSK generated with :doc:`pdnsutil secure-zone <dnssec/pdnsutil>`.
Only relevant for algorithms with non-fixed keysizes (like RSA).

.. _setting-direct-dnskey:

``direct-dnskey``
-----------------

-  Boolean
-  Default: no

Read additional DNSKEY, CDS and CDNSKEY records from the records table/your BIND zonefile. If not
set, DNSKEY, CDS and CDNSKEY records in the zonefiles are ignored.

.. _setting-disable-axfr:

``disable-axfr``
----------------

-  Boolean
-  Default: no

Do not allow zone transfers.

.. _setting-disable-axfr-rectify:

``disable-axfr-rectify``
------------------------

-  Boolean
-  Default: no

Disable the rectify step during an outgoing AXFR. Only required for
regression testing.

.. _setting-disable-syslog:

``disable-syslog``
------------------

-  Boolean
-  Default: no

Do not log to syslog, only to stdout. Use this setting when running
inside a supervisor that handles logging (like systemd).

.. warning::
  Do not use this setting in combination with :ref:`setting-daemon` as all
  logging will disappear.

.. _setting-disable-tcp:

``disable-tcp``
---------------

-  Boolean
-  Default: no

.. versionchanged:: 4.2.0
  This setting has been removed

Do not listen to TCP queries. Breaks RFC compliance.

.. _setting-distributor-threads:

``distributor-threads``
-----------------------

-  Integer
-  Default: 3

Number of Distributor (backend) threads to start per receiver thread.
See :doc:`performance`.

.. _setting-dname-processing:

``dname-processing``
--------------------

-  Boolean
-  Default: no

Synthesise CNAME records from DNAME records as required. This
approximately doubles query load. **Do not combine with DNSSEC!**

.. _setting-dnssec-key-cache-ttl:

``dnssec-key-cache-ttl``
------------------------

-  Integer
-  Default: 30

Seconds to cache DNSSEC keys from the database. A value of 0 disables
caching.

.. _setting-dnsupdate:

``dnsupdate``
-------------

-  Boolean
-  Default: no

Enable/Disable DNS update (RFC2136) support. See :doc:`dnsupdate` for more.

.. _setting-do-ipv6-additional-processing:

``do-ipv6-additional-processing``
---------------------------------

-  Boolean
-  Default: yes

Perform AAAA additional processing. This sends AAAA records in the
ADDITIONAL section when sending a referral.

.. _setting-domain-metadata-cache-ttl:

``domain-metadata-cache-ttl``
-----------------------------

-  Integer
-  Default: 60

Seconds to cache domain metadata from the database. A value of 0
disables caching.

.. _setting-edns-subnet-processing:

``edns-subnet-processing``
--------------------------

-  Boolean
-  Default: no

Enables EDNS subnet processing, for backends that support it.

.. _setting-enable-lua-records:

``enable-lua-records``
----------------------

-  One of ``no``, ``yes`` (or empty), or ``shared``, String
-  Default: no

.. versionadded:: 4.2.0

Globally enable the :doc:`LUA records <lua-records/index>` feature.

To use shared LUA states, set this to ``shared``, see :ref:`lua-records-shared-state`.

.. _setting-entropy-source:

``entropy-source``
------------------

-  Path
-  Default: /dev/urandom

Entropy source file to use.

.. _setting-expand-alias:

``expand-alias``
----------------

-  Boolean
-  Default: no

.. versionadded:: 4.1.0

If this is enabled, ALIAS records are expanded (synthesised to their
A/AAAA).

If this is disabled (the default), ALIAS records will not be expanded and
the server will will return NODATA for A/AAAA queries for such names.

.. note::
  :ref:`setting-resolver` must also be set for ALIAS expansion to work!

.. note::
  In PowerDNS Authoritative Server 4.0.x, this setting did not exist and
  ALIAS was always expanded.

.. _setting-forward-dnsupdate:

``forward-dnsupdate``
---------------------

-  Boolean
-  Default: no

Forward DNS updates sent to a slave to the master.

.. _setting-forward-notify:

``forward-notify``
------------------

-  IP addresses, separated by commas

IP addresses to forward received notifications to regardless of master
or slave settings.

.. note::
  The intended use is in anycast environments where it might be
  necessary for a proxy server to perform the AXFR. The usual checks are
  performed before any received notification is forwarded.

.. _setting-guardian:

``guardian``
------------

-  Boolean
-  Default: no

Run within a guardian process. See :ref:`running-guardian`.

.. _setting-include-dir:

``include-dir``
---------------

-  Path

Directory to scan for additional config files. All files that end with
.conf are loaded in order using ``POSIX`` as locale.

.. _setting-launch:

``launch``
----------

-  Backend names, separated by commas

Which backends to launch and order to query them in. Launches backends.
In its most simple form, supply all backends that need to be launched.
e.g.

.. code-block:: ini

    launch=bind,gmysql,remote

If you find that you need to query a backend multiple times with
different configuration, you can specify a name for later
instantiations. e.g.:

.. code-block:: ini

    launch=gmysql,gmysql:server2

In this case, there are 2 instances of the gmysql backend, one by the
normal name and the second one is called 'server2'. The backend
configuration item names change: e.g. ``gmysql-host`` is available to
configure the ``host`` setting of the first or main instance, and
``gmysql-server2-host`` for the second one.

Running multiple instances of the BIND backend is not allowed.

.. _setting-load-modules:

``load-modules``
----------------

-  Paths, separated by commas

If backends are available in nonstandard directories, specify their
location here. Multiple files can be loaded if separated by commas. Only
available in non-static distributions.

.. _setting-local-address:

``local-address``
-----------------

-  IPv4 Addresses, separated by commas or whitespace
-  Default: 0.0.0.0

Local IP address to which we bind. It is highly advised to bind to
specific interfaces and not use the default 'bind to any'. This causes
big problems if you have multiple IP addresses. Unix does not provide a
way of figuring out what IP address a packet was sent to when binding to
any.

.. _setting-local-address-nonexist-fail:

``local-address-nonexist-fail``
-------------------------------

-  Boolean
-  Default: no

Fail to start if one or more of the
:ref:`setting-local-address`'s do not exist on this server.

.. _setting-local-ipv6:

``local-ipv6``
--------------

-  IPv6 Addresses, separated by commas or whitespace
-  Default: '::'

Local IPv6 address to which we bind. It is highly advised to bind to
specific interfaces and not use the default 'bind to any'. This causes
big problems if you have multiple IP addresses.

.. _setting-local-ipv6-nonexist-fail:

``local-ipv6-nonexist-fail``
----------------------------

-  Boolean
-  Default: no

Fail to start if one or more of the :ref:`setting-local-ipv6`
addresses do not exist on this server.

.. _setting-local-port:

``local-port``
--------------

-  Integer
-  Default: 53

The port on which we listen. Only one port possible.

.. _setting-log-dns-details:

``log-dns-details``
-------------------

-  Boolean
-  Default: no

If set to 'no', informative-only DNS details will not even be sent to
syslog, improving performance.

.. _setting-log-dns-queries:

``log-dns-queries``
-------------------

-  Boolean
-  Default: no

Tell PowerDNS to log all incoming DNS queries. This will lead to a lot
of logging! Only enable for debugging! Set :ref:`setting-loglevel`
to at least 5 to see the logs.

.. _setting-log-timestamp:

``log-timestamp``
-----------------

- Bool
- Default: yes

.. versionadded:: 4.1.0

When printing log lines to stdout, prefix them with timestamps.
Disable this if the process supervisor timestamps these lines already.

.. note::
  The systemd unit file supplied with the source code already disables timestamp printing

.. _setting-logging-facility:

``logging-facility``
--------------------

If set to a digit, logging is performed under this LOCAL facility. See :ref:`logging-to-syslog`.
Do not pass names like 'local0'!

.. _setting-loglevel:

``loglevel``
------------

-  Integer
-  Default: 4

Amount of logging. Higher is more. Do not set below 3. Corresponds to "syslog" level values,
e.g. error = 3, warning = 4, notice = 5, info = 6

.. _setting-lua-axfr-script:

``lua-axfr-script``
-------------------

-  String
-  Default: empty

.. versionadded:: 4.1.0

Script to be used to edit incoming AXFRs, see :ref:`modes-of-operation-axfrfilter`

.. _setting-lua-prequery-script:

``lua-prequery-script``
-----------------------

-  Path

Lua script to run before answering a query. This is a feature used
internally for regression testing. The API of this functionality is not
guaranteed to be stable, and is in fact likely to change.

.. _setting-lua-records-exec-limit:

``lua-records-exec-limit``
-----------------------------

-  Integer
-  Default: 1000

Limit LUA records scripts to ``lua-records-exec-limit`` instructions.
Setting this to any value less than or equal to 0 will set no limit.

.. _setting-master:

``master``
----------

-  Boolean
-  Default: no

Turn on master support. See :ref:`master-operation`.

.. _setting-max-cache-entries:

``max-cache-entries``
---------------------

-  Integer
-  Default: 1000000

.. versionchanged:: 4.1.0
  The packet and query caches are distinct. Previously, this setting was used for
  both the packet and query caches. See :ref:`setting-max-packet-cache-entries` for
  the packet-cache setting.

Maximum number of entries in the query cache. 1 million (the default)
will generally suffice for most installations.

.. _setting-max-ent-entries:

``max-ent-entries``
-------------------

-  Integer
-  Default: 100000

Maximum number of empty non-terminals to add to a zone. This is a
protection measure to avoid database explosion due to long names.

.. _setting-max-nsec3-iterations:

``max-nsec3-iterations``
------------------------

-  Integer
-  Default: 500

Limit the number of NSEC3 hash iterations for zone configurations.
For more information see :ref:`dnssec-operational-nsec-modes-params`.

.. _setting-max-packet-cache-entries:

``max-packet-cache-entries``
----------------------------

-  Integer
-  Default: 1000000

.. versionadded:: 4.1.0

Maximum number of entries in the packet cache. 1 million (the default)
will generally suffice for most installations.

.. _setting-max-queue-length:

``max-queue-length``
--------------------

-  Integer
-  Default: 5000

If this many packets are waiting for database attention, consider the
situation hopeless and respawn.

.. _setting-max-signature-cache-entries:

``max-signature-cache-entries``
-------------------------------

-  Integer
-  Default: 2^31-1 (on most systems), 2^63-1 (on ILP64 systems)

Maximum number of signatures cache entries

.. _setting-max-tcp-connection-duration:

``max-tcp-connection-duration``
-------------------------------

-  Integer
-  Default: 0

Maximum time in seconds that a TCP DNS connection is allowed to stay
open. 0 means unlimited. Note that exchanges related to an AXFR or IXFR
are not affected by this setting.

.. _setting-max-tcp-connections:

``max-tcp-connections``
-----------------------

-  Integer
-  Default: 20

Allow this many incoming TCP DNS connections simultaneously.

.. _setting-max-tcp-connections-per-client:

``max-tcp-connections-per-client``
----------------------------------

-  Integer
-  Default: 0

Maximum number of simultaneous TCP connections per client. 0 means
unlimited.

.. _setting-max-tcp-transactions-per-conn:

``max-tcp-transactions-per-conn``
---------------------------------

-  Integer
-  Default: 0

Allow this many DNS queries in a single TCP transaction. 0 means
unlimited. Note that exchanges related to an AXFR or IXFR are not
affected by this setting.

.. _setting-module-dir:

``module-dir``
--------------

-  Path

Directory for modules. Default depends on ``PKGLIBDIR`` during
compile-time.

.. _setting-negquery-cache-ttl:

``negquery-cache-ttl``
----------------------

-  Integer
-  Default: 60

Seconds to store queries with no answer in the Query Cache. See :ref:`query-cache`.

.. _setting-no-config:

``no-config``
-------------

-  Boolean
-  Default: no

Do not attempt to read the configuration file. Useful for configuration
by parameters from the command line only.

.. _setting-no-shuffle:

``no-shuffle``
--------------

-  Boolean
-  Default: no

Do not attempt to shuffle query results, used for regression testing.

.. _setting-non-local-bind:

``non-local-bind``
------------------

-  Boolean
-  Default: no

Bind to addresses even if one or more of the
:ref:`setting-local-address`'s do not exist on this server.
Setting this option will enable the needed socket options to allow
binding to non-local addresses. This feature is intended to facilitate
ip-failover setups, but it may also mask configuration issues and for
this reason it is disabled by default.

.. _setting-only-notify:

``only-notify``
---------------

-  IP Ranges, separated by commas or whitespace
-  Default: 0.0.0.0/0, ::/0

For type=MASTER zones (or SLAVE zones with slave-renotify enabled)
PowerDNS automatically sends NOTIFYs to the name servers specified in
the NS records. By specifying networks/mask as whitelist, the targets
can be limited. The default is to notify the world. To completely
disable these NOTIFYs set ``only-notify`` to an empty value. Independent
of this setting, the IP addresses or netmasks configured with
:ref:`setting-also-notify` and ``ALSO-NOTIFY`` domain metadata
always receive AXFR NOTIFYs.

IP addresses and netmasks can be excluded by prefixing them with a ``!``.
To notify all IP addresses apart from the 192.168.0.0/24 subnet use the following::

  only-notify=0.0.0.0/0, ::/0, !192.168.0.0/24

.. note::
  Even if NOTIFYs are limited by a netmask, PowerDNS first has to
  resolve all the hostnames to check their IP addresses against the
  specified whitelist. The resolving may take considerable time,
  especially if those hostnames are slow to resolve. If you do not need to
  NOTIFY the slaves defined in the NS records (e.g. you are using another
  method to distribute the zone data to the slaves), then set
  :ref:`setting-only-notify` to an empty value and specify the notification targets
  explicitly using :ref:`setting-also-notify` and/or
  :ref:`metadata-also-notify` domain metadata to avoid this potential bottleneck.

.. note::
  If your slaves support an Internet Protocol version, which your master does not,
  then set ``only-notify`` to include only supported protocol version.
  Otherwise there will be error trying to resolve address.

  For example, slaves support both IPv4 and IPv6, but PowerDNS master have only IPv4,
  so allow only IPv4 with ``only-notify``:

  .. code-block:: ini

    only-notify=0.0.0.0/0

.. _setting-out-of-zone-additional-processing:

``out-of-zone-additional-processing``
-------------------------------------

-  Boolean
-  Default: yes

.. deprecated:: 4.2.0
  This setting has been removed.

Do out of zone additional processing. This means that if a malicious
user adds a '.com' zone to your server, it is not used for other domains
and will not contaminate answers. Do not enable this setting if you run
a public DNS service with untrusted users.

The docs had previously indicated that the default was "no", but the
default has been "yes" since 2005.

.. _setting-outgoing-axfr-expand-alias:

``outgoing-axfr-expand-alias``
------------------------------

-  Boolean
-  Default: no

If this is enabled, ALIAS records are expanded (synthesised to their
A/AAAA) during outgoing AXFR. This means slaves will not automatically
follow changes in those A/AAAA records unless you AXFR regularly!

If this is disabled (the default), ALIAS records are sent verbatim
during outgoing AXFR. Note that if your slaves do not support ALIAS,
they will return NODATA for A/AAAA queries for such names.

.. _setting-overload-queue-length:

``overload-queue-length``
-------------------------

-  Integer
-  Default: 0 (disabled)

If this many packets are waiting for database attention, answer any new
questions strictly from the packet cache.

.. _setting-prevent-self-notification:

``prevent-self-notification``
-----------------------------

-  Boolean
-  Default: yes

PowerDNS Authoritative Server attempts to not send out notifications to
itself in master mode. In very complicated situations we could guess
wrong and not notify a server that should be notified. In that case, set
prevent-self-notification to "no".

.. _setting-query-cache-ttl:

``query-cache-ttl``
-------------------

-  Integer
-  Default: 20

Seconds to store queries with an answer in the Query Cache. See :ref:`query-cache`.

.. _setting-query-local-address:

``query-local-address``
-----------------------

-  IPv4 Address
-  Default: 0.0.0.0

The IP address to use as a source address for sending queries. Useful if
you have multiple IPs and PowerDNS is not bound to the IP address your
operating system uses by default for outgoing packets.

.. _setting-query-local-address6:

``query-local-address6``
------------------------

-  IPv6 Address
-  Default: '::'

Source IP address for sending IPv6 queries.

.. _setting-query-logging:

``query-logging``
-----------------

-  Boolean
-  Default: no

Boolean, hints to a backend that it should log a textual representation
of queries it performs. Can be set at runtime.

.. _setting-queue-limit:

``queue-limit``
---------------

-  Integer
-  Default: 1500

Maximum number of milliseconds to queue a query. See :doc:`performance`.

.. _setting-receiver-threads:

``receiver-threads``
--------------------

-  Integer
-  Default: 1

Number of receiver (listening) threads to start. See :doc:`performance`.

.. _setting-recursive-cache-ttl:

``recursive-cache-ttl``
-----------------------

-  Integer
-  Default: 10

.. deprecated:: 4.1.0
  Recursion has been removed, see :doc:`guides/recursion`

Seconds to store recursive packets in the :ref:`packet-cache`.

.. _setting-recursor:

``recursor``
------------

-  IP Address

.. deprecated:: 4.1.0
  Recursion has been removed, see :doc:`guides/recursion`

If set, recursive queries will be handed to the recursor specified here.

.. _setting-resolver:

``resolver``
------------

-  IP Addresses with optional port, separated by commas

.. versionadded:: 4.1.0

Use these resolver addresses for ALIAS and the internal stub resolver.
If this is not set, ``/etc/resolv.conf`` is parsed for upstream
resolvers.

.. _setting-retrieval-threads:

``retrieval-threads``
---------------------

-  Integer
-  Default: 2

Number of AXFR slave threads to start.

.. _setting-reuseport:

``reuseport``
-------------

-  Boolean
-  Default: No

On Linux 3.9 and some BSD kernels the ``SO_REUSEPORT`` option allows
each receiver-thread to open a new socket on the same port which allows
for much higher performance on multi-core boxes. Setting this option
will enable use of ``SO_REUSEPORT`` when available and seamlessly fall
back to a single socket when it is not available. A side-effect is that
you can start multiple servers on the same IP/port combination which may
or may not be a good idea. You could use this to enable transparent
restarts, but it may also mask configuration issues and for this reason
it is disabled by default.

.. _setting-rng:

``rng``
-------

- String
- Default: auto

Specify which random number generator to use. Permissible choises are:

- auto - choose automatically
- sodium - Use libsodium ``randombytes_uniform``
- openssl - Use libcrypto ``RAND_bytes``
- getrandom - Use libc getrandom, falls back to urandom if it does not really work
- arc4random - Use BSD ``arc4random_uniform``
- urandom - Use ``/dev/urandom``
- kiss - Use simple settable deterministic RNG. **FOR TESTING PURPOSES ONLY!**

.. note::
  Not all choises are available on all systems.

.. _setting-security-poll-suffix:

``security-poll-suffix``
------------------------

-  String
-  Default: secpoll.powerdns.com.

Domain name from which to query security update notifications. Setting
this to an empty string disables secpoll.

.. _setting-send-signed-notify:

``send-signed-notify``
----------------------

-  Boolean
-  Default: yes

If yes, outgoing NOTIFYs will be signed if a TSIG key is configured for the zone.
If there are multiple TSIG keys configured for a domain, PowerDNS will use the
first one retrieved from the backend, which may not be the correct one for the
respective slave. Hence, in setups with multiple slaves with different TSIG keys
it may be required to send NOTIFYs unsigned.

.. _setting-server-id:

``server-id``
-------------

-  String
-  Default: The hostname of the server

This is the server ID that will be returned on an EDNS NSID query.

.. _setting-setgid:

``setgid``
----------

-  String

If set, change group id to this gid for more security. See :doc:`security`.

.. _setting-setuid:

``setuid``
----------

-  String

If set, change user id to this uid for more security. See :doc:`security`.

.. _setting-signing-threads:

``signing-threads``
-------------------

-  Integer
-  Default: 3

Tell PowerDNS how many threads to use for signing. It might help improve
signing speed by changing this number.

.. _setting-slave:

``slave``
---------

-  Boolean
-  Default: no

Turn on slave support. See :ref:`slave-operation`.

.. _setting-slave-cycle-interval:

``slave-cycle-interval``
------------------------

-  Integer
-  Default: 60

On a master, this is the amount of seconds between the master checking
the SOA serials in its database to determine to send out NOTIFYs to the
slaves. On slaves, this is the number of seconds between the slave
checking for updates to zones.

.. _setting-slave-renotify:

``slave-renotify``
------------------

-  Boolean
-  Default: no

This setting will make PowerDNS renotify the slaves after an AXFR is
*received* from a master. This is useful when using when running a
signing-slave.

See :ref:`metadata-slave-renotify` to set this per-zone.

.. _setting-soa-expire-default:

``soa-expire-default``
----------------------

-  Integer
-  Default: 604800

.. deprecated:: 4.2.0
  This setting has been deprecated and will be removed in 4.3.0

Default :ref:`types-soa` expire.

.. _setting-soa-minimum-ttl:

``soa-minimum-ttl``
-------------------

-  Integer
-  Default: 3600

.. deprecated:: 4.2.0
  This setting has been deprecated and will be removed in 4.3.0

Default :ref:`types-soa` minimum ttl.

.. _setting-soa-refresh-default:

``soa-refresh-default``
-----------------------

-  Integer
-  Default: 10800

.. deprecated:: 4.2.0
  This setting has been deprecated and will be removed in 4.3.0

Default :ref:`types-soa` refresh.

.. _setting-soa-retry-default:

``soa-retry-default``
---------------------

-  Integer
-  Default: 3600

.. deprecated:: 4.2.0
  This setting has been deprecated and will be removed in 4.3.0

Default :ref:`types-soa` retry.

.. _setting-socket-dir:

``socket-dir``
--------------

-  Path

Where the controlsocket will live. The default depends on
``LOCALSTATEDIR`` during compile-time (usually ``/var/run`` or
``/run``). See :ref:`control-socket`.

This path will also contain the pidfile for this instance of PowerDNS
called ``pdns.pid`` by default. See :ref:`setting-config-name`
and :doc:`Virtual Hosting <guides/virtual-instances>` how this can differ.

.. _setting-superslave:

``superslave``
---------------

-  Boolean
-  Default: no

.. versionadded:: 4.1.9
  In versions before 4.1.9, this setting did not exist and supermaster support
  was enabled by default.

.. versionchanged:: 4.2.0
  Before 4.2.0, the default was yes.

Turn on supermaster support. See :ref:`supermaster-operation`.

.. _setting-tcp-control-address:

``tcp-control-address``
-----------------------

-  IP Address

Address to bind to for TCP control.

.. _setting-tcp-control-port:

``tcp-control-port``
--------------------

-  Integer
-  Default: 53000

Port to bind to for TCP control.

.. _setting-tcp-control-range:

``tcp-control-range``
---------------------

-  IP Ranges, separated by commas or whitespace

Limit TCP control to a specific client range.

.. _setting-tcp-control-secret:

``tcp-control-secret``
----------------------

-  String

Password for TCP control.

.. _setting-tcp-fast-open:

``tcp-fast-open``
-----------------

-  Integer
-  Default: 0 (Disabled)

.. versionadded:: 4.1.0

Enable TCP Fast Open support, if available, on the listening sockets.
The numerical value supplied is used as the queue size, 0 meaning
disabled.

.. _setting-tcp-idle-timeout:

``tcp-idle-timeout``
--------------------

-  Integer
-  Default: 5

Maximum time in seconds that a TCP DNS connection is allowed to stay
open while being idle, meaning without PowerDNS receiving or sending
even a single byte.

.. _setting-traceback-handler:

``traceback-handler``
---------------------

-  Boolean
-  Default: yes

Enable the Linux-only traceback handler.

.. _setting-trusted-notification-proxy:

``trusted-notification-proxy``
------------------------------

-  String

IP address of incoming notification proxy

.. _setting-udp-truncation-threshold:

``udp-truncation-threshold``
----------------------------
.. versionchanged:: 4.2.0
  Before 4.2.0, the default was 1680

-  Integer
-  Default: 1232

EDNS0 allows for large UDP response datagrams, which can potentially
raise performance. Large responses however also have downsides in terms
of reflection attacks. Maximum value is 65535, but values above
4096 should probably not be attempted.

.. note:: Why 1232?

  1232 is the largest number of payload bytes that can fit in the smallest IPv6 packet.
  IPv6 has a minimum MTU of 1280 bytes (:rfc:`RFC 8200, section 5 <8200#section-5>`), minus 40 bytes for the IPv6 header, minus 8 bytes for the UDP header gives 1232, the maximum payload size for the DNS response.

.. _setting-version-string:

``version-string``
------------------

-  Any of: ``anonymous``, ``powerdns``, ``full``, String
-  Default: full

When queried for its version over DNS
(``dig chaos txt version.bind @pdns.ip.address``), PowerDNS normally
responds truthfully. With this setting you can overrule what will be
returned. Set the ``version-string`` to ``full`` to get the default
behaviour, to ``powerdns`` to just make it state
``Served by PowerDNS - https://www.powerdns.com/``. The ``anonymous``
setting will return a ServFail, much like Microsoft nameservers do. You
can set this response to a custom value as well.

.. _setting-webserver:

``webserver``
-------------

-  Boolean
-  Default: no

Start a webserver for monitoring. See :doc:`performance`".

.. versionchanged:: 4.1.0
  It was necessary to enable the webserver to use the REST API, this is no longer the case.

.. _setting-webserver-address:

``webserver-address``
---------------------

-  IP Address
-  Default: 127.0.0.1

IP Address for webserver/API to listen on.

.. _setting-webserver-allow-from:

``webserver-allow-from``
------------------------

-  IP ranges, separated by commas or whitespace
-  Default: 127.0.0.1,::1

.. versionchanged:: 4.1.0

    Default is now 127.0.0.1,::1, was 0.0.0.0/0,::/0 before.

Webserver/API access is only allowed from these subnets.

.. _setting-webserver-loglevel:

``webserver-loglevel``
----------------------
.. versionadded:: 4.2.0

-  String, one of "none", "normal", "detailed"

The amount of logging the webserver must do. "none" means no useful webserver information will be logged.
When set to "normal", the webserver will log a line per request that should be familiar::

  [webserver] e235780e-a5cf-415e-9326-9d33383e739e 127.0.0.1:55376 "GET /api/v1/servers/localhost/bla HTTP/1.1" 404 196

When set to "detailed", all information about the request and response are logged::

  [webserver] e235780e-a5cf-415e-9326-9d33383e739e Request Details:
  [webserver] e235780e-a5cf-415e-9326-9d33383e739e  Headers:
  [webserver] e235780e-a5cf-415e-9326-9d33383e739e   accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
  [webserver] e235780e-a5cf-415e-9326-9d33383e739e   accept-encoding: gzip, deflate
  [webserver] e235780e-a5cf-415e-9326-9d33383e739e   accept-language: en-US,en;q=0.5
  [webserver] e235780e-a5cf-415e-9326-9d33383e739e   connection: keep-alive
  [webserver] e235780e-a5cf-415e-9326-9d33383e739e   dnt: 1
  [webserver] e235780e-a5cf-415e-9326-9d33383e739e   host: 127.0.0.1:8081
  [webserver] e235780e-a5cf-415e-9326-9d33383e739e   upgrade-insecure-requests: 1
  [webserver] e235780e-a5cf-415e-9326-9d33383e739e   user-agent: Mozilla/5.0 (X11; Linux x86_64; rv:64.0) Gecko/20100101 Firefox/64.0
  [webserver] e235780e-a5cf-415e-9326-9d33383e739e  No body
  [webserver] e235780e-a5cf-415e-9326-9d33383e739e Response details:
  [webserver] e235780e-a5cf-415e-9326-9d33383e739e  Headers:
  [webserver] e235780e-a5cf-415e-9326-9d33383e739e   Connection: close
  [webserver] e235780e-a5cf-415e-9326-9d33383e739e   Content-Length: 49
  [webserver] e235780e-a5cf-415e-9326-9d33383e739e   Content-Type: text/html; charset=utf-8
  [webserver] e235780e-a5cf-415e-9326-9d33383e739e   Server: PowerDNS/0.0.15896.0.gaba8bab3ab
  [webserver] e235780e-a5cf-415e-9326-9d33383e739e  Full body: 
  [webserver] e235780e-a5cf-415e-9326-9d33383e739e   <!html><title>Not Found</title><h1>Not Found</h1>
  [webserver] e235780e-a5cf-415e-9326-9d33383e739e 127.0.0.1:55376 "GET /api/v1/servers/localhost/bla HTTP/1.1" 404 196

The value between the hooks is a UUID that is generated for each request. This can be used to find all lines related to a single request.

.. note::
  The webserver logs these line on the NOTICE level. The :ref:`setting-loglevel` seting must be 5 or higher for these lines to end up in the log.

.. _setting-webserver-max-bodysize:

``webserver-max-bodysize``
--------------------------
.. versionadded:: 4.2.0

-  Integer
-  Default: 2

Maximum request/response body size in megabytes.

.. _setting-webserver-password:

``webserver-password``
----------------------

-  String

The plaintext password required for accessing the webserver.

.. _setting-webserver-port:

``webserver-port``
------------------

-  Integer
-  Default: 8081

The port where webserver/API will listen on.

.. _setting-webserver-print-arguments:

``webserver-print-arguments``
-----------------------------

-  Boolean
-  Default: no

If the webserver should print arguments.

.. _setting-write-pid:

``write-pid``
-------------

-  Boolean
-  Default: yes

If a PID file should be written.

.. _setting-xfr-max-received-mbytes:

``xfr-max-received-mbytes``
---------------------------

-  Integer
-  Default: 100

Specifies the maximum number of received megabytes allowed on an
incoming AXFR/IXFR update, to prevent resource exhaustion. A value of 0
means no restriction.
