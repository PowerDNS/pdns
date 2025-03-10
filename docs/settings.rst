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

Allow 8 bit DNS queries.

.. _setting-allow-axfr-ips:

``allow-axfr-ips``
------------------

-  IP ranges, separated by commas
-  Default: 127.0.0.0/8,::1

If set, only these IP addresses or netmasks will be able to perform
AXFR without TSIG.

.. warning::
   This setting only applies to AXFR without TSIG keys. If you allow a TSIG key to perform an AXFR,
   this setting will not be checked for that transfer, and the client will be able to perform the AXFR
   from everywhere.

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

.. note::
  IPs allowed by this setting, still go through the normal NOTIFY processing as described in :ref:`secondary-operation`
  The IP the NOTIFY is received from, still needs to be a nameserver for the secondary domain. Explicitly setting this parameter will not bypass those checks.

.. _setting-allow-unsigned-autoprimary:

``allow-unsigned-autoprimary``
------------------------------

.. versionchanged:: 4.5.0
  This was called :ref:`setting-allow-unsigned-supermaster` before 4.5.0.

-  Boolean
-  Default: yes

Turning this off requires all autoprimary notifications to be signed by
valid TSIG signature. It will accept any existing key on secondaries.

.. _setting-allow-unsigned-notify:

``allow-unsigned-notify``
-------------------------

-  Boolean
-  Default: yes

Turning this off requires all notifications that are received to be
signed by valid TSIG signature for the zone.

.. _setting-allow-unsigned-supermaster:

``allow-unsigned-supermaster``
------------------------------

.. deprecated:: 4.5.0
  Renamed to :ref:`setting-allow-unsigned-autoprimary`.
  Removed in 4.9.0

.. _setting-also-notify:

``also-notify``
---------------

-  IP addresses, separated by commas

When notifying a zone, also notify these nameservers. Example:
``also-notify=192.0.2.1, 203.0.113.167``. The IP addresses listed in
``also-notify`` always receive a notification. Even if they do not match
the list in :ref:`setting-only-notify`.

You may specify an alternate port by appending :port. Example:
``also-notify=192.0.2.1:5300``. If no port is specified, port 53
is used.

.. _setting-any-to-tcp:

``any-to-tcp``
--------------

-  Boolean
-  Default: yes

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

.. versionchanged:: 4.6.0
  This setting now accepts a hashed and salted version.

Static pre-shared authentication key for access to the REST API. Since 4.6.0 the key can be hashed and salted using ``pdnsutil hash-password`` instead of being stored in the configuration in plaintext, but the plaintext version is still supported.

.. _setting-autosecondary:

``autosecondary``
-----------------

.. versionchanged:: 4.5.0
  This was called :ref:`setting-superslave` before 4.5.0.

-  Boolean
-  Default: no

Turn on autosecondary support. See :ref:`autoprimary-operation`.

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

Also AXFR a zone from a primary with a lower serial.

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
This is not recommended; instead, we recommend containing PowerDNS using operating system features.
We ship systemd unit files with our packages to make this easy.

Make sure that ``/dev/log`` is available from within the chroot. Logging
will silently fail over time otherwise (on logrotate).

When setting ``chroot``, all other paths in the config (except for
:ref:`setting-config-dir` and :ref:`setting-module-dir`)
set in the configuration are relative to the new root.

When running on a system where systemd manages services, ``chroot`` does
not work out of the box, as PowerDNS cannot use the ``NOTIFY_SOCKET``.
Either don't ``chroot`` on these systems or set the 'Type' of the
service to 'simple' instead of 'notify' (refer to the systemd
documentation on how to modify unit-files).

.. _setting-secondary-check-signature-freshness:

``secondary-check-signature-freshness``
---------------------------------------

.. versionadded:: 4.7.0

-  Boolean
-  Default: yes

Enabled by default, freshness checks for secondary zones will set the DO flag on SOA queries. PowerDNS
can detect (signature) changes on the primary server without serial number bumps using the DNSSEC
signatures in the SOA response.

In some problematic scenarios, primary servers send truncated SOA responses. As a workaround, this setting
can be turned off, and the DO flag as well as the signature checking will be disabled. To avoid additional
drift, primary servers must then always increase the zone serial when it updates signatures.

It is strongly recommended to keep this setting enabled (`yes`).

.. _setting-config-dir:

``config-dir``
--------------

-  Path

Location of configuration directory (the directory containing ``pdns.conf``). Usually
``/etc/powerdns``, but this depends on ``SYSCONFDIR`` during
compile-time.

.. _setting-config-name:

``config-name``
---------------

-  String

Name of this virtual configuration - will rename the binary image. See
:doc:`guides/virtual-instances`.

.. _setting-consistent-backends:

``consistent-backends``
-----------------------

-  Boolean
-  Default: yes

.. versionadded:: 4.4.0

When this is set, PowerDNS assumes that any single zone lives in only one backend.
This allows PowerDNS to send ``ANY`` lookups to its backends, instead of sometimes requesting the exact needed type.
This reduces the load on backends by retrieving all the types for a given name at once, adding all of them to the cache.
It improves performance significantly for latency-sensitive backends, like SQL ones, where a round-trip takes serious time.

.. warning::
  This behaviour is only a meaningful optimization if the returned response to the ``ANY`` query can actually be cached,
  which is not the case if it contains at least one record with a non-zero scope. For this reason ``consistent-backends``
  should be disabled when at least one of the backends in use returns location-based records, like the GeoIP backend.

.. note::
  Pre 4.5.0 the default was no.

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

The value of :ref:`metadata-api-rectify` if it is not set on the zone.

.. note::
  Pre 4.2.0 the default was always no.

.. _setting-default-catalog-zone:

``default-catalog-zone``
------------------------

- String:
- Default: empty

.. versionadded:: 4.8.3

When a primary zone is created via the API, and the request does not specify a catalog zone, the name given here will be used.

.. _setting-default-ksk-algorithms:
.. _setting-default-ksk-algorithm:

``default-ksk-algorithm``
-------------------------

-  String
-  Default: ecdsa256

The default algorithm for creating zone keys when running
:doc:`pdnsutil add-zone-key <manpages/pdnsutil.1>` if no algorithm is specified,
and also the algorithm that should be used for the KSK when running
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
  PowerDNS was compiled against. To check the supported DNSSEC algorithms
  in your build of PowerDNS, run ``pdnsutil list-algorithms``.

.. _setting-default-ksk-size:

``default-ksk-size``
--------------------

-  Integer
-  Default: whichever is default for `default-ksk-algorithm`_

The default keysize for the KSK generated with :doc:`pdnsutil secure-zone <dnssec/pdnsutil>`.
Only relevant for algorithms with non-fixed keysizes (like RSA).

.. _setting-default-publish-cdnskey:

``default-publish-cdnskey``
---------------------------
- Integer
- Default: empty

.. versionadded:: 4.3.0

The default PUBLISH-CDNSKEY value for zones that do not have one individually specified.
See the :ref:`metadata-publish-cdnskey-publish-cds` docs for more information.

.. _setting-default-publish-cds:

``default-publish-cds``
-----------------------

- Comma-separated integers
- Default: empty

.. versionadded:: 4.3.0

The default PUBLISH-CDS value for zones that do not have one individually specified.
See the :ref:`metadata-publish-cdnskey-publish-cds` docs for more information.

.. _setting-default-soa-content:

``default-soa-content``
-----------------------

-  String
-  Default: a.misconfigured.dns.server.invalid hostmaster.@ 0 10800 3600 604800 3600

.. versionadded:: 4.4.0

This value is used when a zone is created without providing a SOA record. @ is replaced by the zone name.

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
  This setting has been removed in 4.4.0

Mail address to insert in the SOA record if none set in the backend.

.. _setting-default-soa-name:

``default-soa-name``
--------------------

-  String
-  Default: a.misconfigured.dns.server.invalid

.. deprecated:: 4.2.0
  This setting has been removed in 4.4.0

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

The default algorithm for creating zone keys when running
:doc:`pdnsutil add-zone-key <manpages/pdnsutil.1>` if no algorithm is specified,
and also the algorithm that should be used for the ZSK when running
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
  PowerDNS was compiled against. To check the supported DNSSEC algorithms
  in your build of PowerDNS, run ``pdnsutil list-algorithms``.

.. _setting-default-zsk-size:

``default-zsk-size``
--------------------

-  Integer
-  Default: 0 (automatic default for `default-zsk-algorithm`_)

The default keysize for the ZSK generated with :doc:`pdnsutil secure-zone <dnssec/pdnsutil>`.
Only relevant for algorithms with non-fixed keysizes (like RSA).

.. _setting-delay-notifications:

``delay-notifications``
-----------------------

-  Integer
-  Default: 0 (no delay, send them directly)

Configure a delay to send out notifications, no delay by default.

.. _setting-direct-dnskey:

``direct-dnskey``
-----------------

-  Boolean
-  Default: no

Read additional DNSKEY, CDS and CDNSKEY records from the records table/your BIND zonefile. If not
set, DNSKEY, CDS and CDNSKEY records in the zonefiles are ignored.

.. _setting-direct-dnskey-signature:

``direct-dnskey-signature``
---------------------------

-  Boolean
-  Default: no

.. versionadded:: 5.0.0

Read signatures of DNSKEY records directly from the backend. 
If not set and the record is not presigned, DNSKEY records will be signed directly by PDNS Authoritative.
Please only use this if you are sure that you need it.

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

Do not log to syslog, only to stderr. Use this setting when running
inside a supervisor that handles logging (like systemd).

.. warning::
  Do not use this setting in combination with :ref:`setting-daemon` as all
  logging will disappear.

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

Turn on DNAME processing (DNAME substitution, CNAME synthesis). This
approximately doubles query load.

If this is turned off, DNAME records are treated as any other and served
only when queried explicitly.

.. _setting-dnsproxy-udp-port-range:

``dnsproxy-udp-port-range``
---------------------------

-  String
-  Default: `10000 60000`

If :ref:`setting-resolver` enables the DNS Proxy, this setting limits the
port range the DNS Proxy's UDP port is chosen from.

Default should be fine on most installs, but if you have conflicting local
services, you may choose to limit the range.

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

.. _setting-dnsupdate-require-tsig:

``dnsupdate-require-tsig``
--------------------------

.. versionadded:: 5.0.0

-  Boolean
-  Default: no

Requires DNS updates to be signed by a valid TSIG signature even if the zone has no associated keys.

.. _setting-do-ipv6-additional-processing:

``do-ipv6-additional-processing``
---------------------------------

-  Boolean
-  Default: yes

.. versionchanged:: 4.4.0
  This setting has been removed

Perform AAAA additional processing. This sends AAAA records in the
ADDITIONAL section when sending a referral.

.. _setting-domain-metadata-cache-ttl:

``domain-metadata-cache-ttl``
-----------------------------

.. deprecated:: 4.5.0
  Renamed to :ref:`setting-zone-metadata-cache-ttl`.

Seconds to cache zone metadata from the database. A value of 0
disables caching.

.. _setting-edns-cookie-secret:

``edns-cookie-secret``
--------------------------

.. versionadded:: 4.6.0

-  String
-  Default: (empty)

When set, PowerDNS will respond with :rfc:`9018` EDNS Cookies to queries that have the EDNS0 Cookie option.
PowerDNS will also respond with BADCOOKIE to clients that have sent only a client cookie, or a bad server cookie (section 5.2.3 and 5.2.4 of :rfc:`7873`).

This setting MUST be 32 hexadecimal characters, as the siphash algorithm's key used to create the cookie requires a 128-bit key.

.. _setting-edns-subnet-processing:

``edns-subnet-processing``
--------------------------

-  Boolean
-  Default: no

Enables EDNS subnet processing, for backends that support it.

.. _setting-enable-gss-tsig:

``enable-gss-tsig``
-------------------

-  Boolean
-  Default: no

Enable accepting GSS-TSIG signed messages.
In addition to this setting, see :doc:`tsig`.

.. _setting-enable-lua-records:

``enable-lua-records``
----------------------

-  One of ``no``, ``yes`` (or empty), or ``shared``, String
-  Default: no

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

If this is enabled, ALIAS records are expanded (synthesized to their
A/AAAA).

If this is disabled (the default), ALIAS records will not be expanded and
the server will return NODATA for A/AAAA queries for such names.

.. note::
  :ref:`setting-resolver` must also be set for ALIAS expansion to work!

.. note::
  In PowerDNS Authoritative Server 4.0.x, this setting did not exist and
  ALIAS was always expanded.

.. _setting-resolve-across-zones:

``resolve-across-zones``
------------------------

.. versionadded:: 5.0.0

-  Boolean
-  Default: yes

If this is enabled, CNAME records and other referrals will be resolved as long as their targets exist in any local backend.
Can be disabled to allow for different authorities managing zones in the same server instance.

Referrals not available in local backends are never resolved.
SVCB referrals are never resolved across zones.
ALIAS is not impacted by this setting.

.. _setting-forward-dnsupdate:

``forward-dnsupdate``
---------------------

-  Boolean
-  Default: no

Forward DNS updates sent to a secondary to the primary.

.. _setting-forward-notify:

``forward-notify``
------------------

-  IP addresses, separated by commas

IP addresses to forward received notifications to regardless of primary
or secondary settings.

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

.. _setting-ignore-unknown-settings:

``ignore-unknown-settings``
---------------------------

.. versionadded:: 4.5.0

-  Setting names, separated by commas
-  Default: empty

Names of settings to be ignored while parsing configuration files, if the setting
name is unknown to PowerDNS.

Useful during upgrade testing.

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
.. versionchanged:: 4.3.0
  now also accepts IPv6 addresses

.. versionchanged:: 4.3.0
  Before 4.3.0, this setting only supported IPv4 addresses.

-  IPv4/IPv6 Addresses, with optional port numbers, separated by commas or whitespace
-  Default: ``0.0.0.0, ::``

Local IP addresses to which we bind. Each address specified can
include a port number; if no port is included then the
:ref:`setting-local-port` port will be used for that address. If a
port number is specified, it must be separated from the address with a
':'; for an IPv6 address the address must be enclosed in square
brackets.

Examples::

  local-address=127.0.0.1 ::1
  local-address=0.0.0.0:5353
  local-address=[::]:8053
  local-address=127.0.0.1:53, [::1]:5353

.. _setting-local-address-nonexist-fail:

``local-address-nonexist-fail``
-------------------------------

-  Boolean
-  Default: yes

Fail to start if one or more of the
:ref:`setting-local-address`'s do not exist on this server.

.. _setting-local-ipv6:

``local-ipv6``
--------------
.. deprecated:: 4.5.0
   Use :ref:`setting-local-address` instead

.. _setting-local-ipv6-nonexist-fail:

``local-ipv6-nonexist-fail``
----------------------------

.. versionchanged:: 4.3.0
  This setting has been removed, use :ref:`setting-local-address-nonexist-fail`

-  Boolean
-  Default: no

Fail to start if one or more of the :ref:`setting-local-ipv6`
addresses do not exist on this server.

.. _setting-local-port:

``local-port``
--------------

-  Integer
-  Default: 53

Local port to bind to.
If an address in :ref:`setting-local-address` does not have an explicit port, this port is used.

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

When printing log lines to stderr, prefix them with timestamps.
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

Amount of logging. The higher the number, the more lines logged.
Corresponds to "syslog" level values (e.g. 0 = emergency, 1 = alert, 2 = critical, 3 = error, 4 = warning, 5 = notice, 6 = info, 7 = debug).
Each level includes itself plus the lower levels before it.
Not recommended to set this below 3.

.. _setting-loglevel-show:

``loglevel-show``
-------------------

-  Bool
-  Default: no

.. versionadded:: 4.9.0

When enabled, log messages are formatted like structured logs, including their log level/priority: ``msg="Unable to launch, no backends configured for querying" prio="Error"``

.. _setting-lua-axfr-script:

``lua-axfr-script``
-------------------

-  String
-  Default: empty

Script to be used to edit incoming AXFRs, see :ref:`modes-of-operation-axfrfilter`

.. _setting-lua-consistent-hashes-cleanup-interval:

``lua-consistent-hashes-cleanup-interval``
------------------------------------------

-  Integer
-  Default: 3600

.. versionadded:: 4.9.0

Amount of time (in seconds) between subsequent cleanup routines for pre-computed hashes related to :func:`pickchashed()`.

.. _setting-lua-consistent-hashes-expire-delay:

``lua-consistent-hashes-expire-delay``
--------------------------------------

-  Integer
-  Default: 86400

.. versionadded:: 4.9.0

Amount of time (in seconds) a pre-computed hash entry will be considered as expired when unused. See :func:`pickchashed()`.

.. _setting-lua-global-include-dir:

``lua-global-include-dir``
---------------------------

-  String
-  Default: empty
-  Example: ``/etc/pdns/lua-global/``

.. versionadded:: 5.0.0

When creating a Lua context, scan this directory for additional lua files. All files that end with
.lua are loaded in order using ``POSIX`` as locale with Lua scripts.

.. _setting-lua-health-checks-expire-delay:

``lua-health-checks-expire-delay``
----------------------------------

-  Integer
-  Default: 3600

.. versionadded:: 4.3.0

Amount of time (in seconds) to expire (remove) a LUA monitoring check when the record
isn't used any more (either deleted or modified).

.. _setting-lua-health-checks-interval:

``lua-health-checks-interval``
------------------------------

-  Integer
-  Default: 5

.. versionadded:: 4.3.0

Amount of time (in seconds) between subsequent monitoring health checks. Does nothing
if the checks take more than that time to execute.

.. _setting-lua-prequery-script:

``lua-prequery-script``
-----------------------

-  Path

Lua script to run before answering a query. This is a feature used
internally for regression testing. The API of this functionality is not
guaranteed to be stable, and is in fact likely to change.

.. _setting-lua-records-exec-limit:

``lua-records-exec-limit``
--------------------------

-  Integer
-  Default: 1000

Limit LUA records scripts to ``lua-records-exec-limit`` instructions.
Setting this to any value less than or equal to 0 will set no limit.

.. _setting-lua-records-insert-whitespace:

``lua-records-insert-whitespace``
---------------------------------

- Boolean
- Default: no in 5.0, yes before that

.. versionadded:: 4.9.1

When combining the ``"`` delimited chunks of a LUA record, whether to insert whitespace between each chunk.

.. _setting-master:

``master``
----------

.. deprecated:: 4.5.0
  Renamed to :ref:`setting-primary`.
  Removed in 4.9.0.

-  Boolean
-  Default: no

Turn on primary support. See :ref:`primary-operation`.

.. _setting-max-cache-entries:

``max-cache-entries``
---------------------

-  Integer
-  Default: 1000000

Maximum number of entries in the query cache. 1 million (the default)
will generally suffice for most installations.

.. _setting-max-ent-entries:

``max-ent-entries``
-------------------

-  Integer
-  Default: 100000

Maximum number of empty non-terminals to add to a zone. This is a
protection measure to avoid database explosion due to long names.

.. _setting-max-include-depth:

``max-include-depth``
----------------------

-  Integer
-  Default: 20

Maximum number of nested ``$INCLUDE`` directives while processing a zone file.
Zero mean no ``$INCLUDE`` directives will be accepted.

.. _setting-max-generate-steps:

``max-generate-steps``
----------------------

-  Integer
-  Default: 0

Maximum number of steps for a '$GENERATE' directive when parsing a
zone file. This is a protection measure to prevent consuming a lot of
CPU and memory when untrusted zones are loaded. Default to 0 which
means unlimited.

.. _setting-max-nsec3-iterations:

``max-nsec3-iterations``
------------------------

-  Integer
-  Default: 100

Limit the number of NSEC3 hash iterations for zone configurations.
For more information see :ref:`dnssec-operational-nsec-modes-params`.

.. note::
  Pre 4.5.0 the default was 500.

.. _setting-max-packet-cache-entries:

``max-packet-cache-entries``
----------------------------

-  Integer
-  Default: 1000000

Maximum number of entries in the packet cache. 1 million (the default)
will generally suffice for most installations.

.. _setting-max-queue-length:

``max-queue-length``
--------------------

-  Integer
-  Default: 5000

If this many packets are waiting for database attention, consider the
situation hopeless and respawn the server process.
This limit is per receiver thread.

.. _setting-max-signature-cache-entries:

``max-signature-cache-entries``
-------------------------------

-  Integer
-  Default: 2^31-1 (on most systems), 2^63-1 (on ILP64 systems)

Maximum number of DNSSEC signature cache entries. This cache is
automatically reset once per week or when the cache is full. If you
use NSEC narrow mode, this cache can grow large.

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

For type=MASTER zones (or SLAVE zones with :ref:`setting-secondary-do-renotify` enabled)
PowerDNS automatically sends NOTIFYs to the name servers specified in
the NS records. By specifying networks/mask as whitelist, the targets
can be limited. The default is to notify the world. To completely
disable these NOTIFYs set ``only-notify`` to an empty value. Independent
of this setting, the IP addresses or netmasks configured with
:ref:`setting-also-notify` and ``ALSO-NOTIFY`` zone metadata
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
  :ref:`metadata-also-notify` zone metadata to avoid this potential bottleneck.

.. note::
  If your secondaries support an Internet Protocol version, which your primary does not,
  then set ``only-notify`` to include only supported protocol version.
  Otherwise there will be error trying to resolve address.

  For example, secondaries support both IPv4 and IPv6, but PowerDNS primary have only IPv4,
  so allow only IPv4 with ``only-notify``:

  .. code-block:: ini

    only-notify=0.0.0.0/0

.. _setting-outgoing-axfr-expand-alias:

``outgoing-axfr-expand-alias``
------------------------------

-  One of ``no``, ``yes``, or ``ignore-errors``, String
-  Default: no

.. versionchanged:: 4.9.0
  Option `ignore-errors` added.

If this is enabled, ALIAS records are expanded (synthesized to their
A/AAAA) during outgoing AXFR. This means slaves will not automatically
follow changes in those A/AAAA records unless you AXFR regularly!

If this is disabled (the default), ALIAS records are sent verbatim
during outgoing AXFR. Note that if your slaves do not support ALIAS,
they will return NODATA for A/AAAA queries for such names.

If the ALIAS target cannot be resolved during AXFR the AXFR will fail.
To allow outgoing AXFR also if the ALIAS targets are broken set this
setting to `ignore-errors`.
Be warned, this will lead to inconsistent zones between Primary and
Secondary name servers.

.. _setting-overload-queue-length:

``overload-queue-length``
-------------------------

-  Integer
-  Default: 0 (disabled)

If this many packets are waiting for database attention, answer any new
questions strictly from the packet cache. Packets not in the cache will
be dropped, and :ref:`stat-overload-drops` will be incremented.

.. _setting-prevent-self-notification:

``prevent-self-notification``
-----------------------------

-  Boolean
-  Default: yes

PowerDNS Authoritative Server attempts to not send out notifications to
itself in primary mode. In very complicated situations we could guess
wrong and not notify a server that should be notified. In that case, set
prevent-self-notification to "no".

.. _setting-primary:

``primary``
-----------

.. versionchanged:: 4.5.0
  This was called :ref:`setting-master` before 4.5.0.

-  Boolean
-  Default: no

Turn on operating as a primary. See :ref:`primary-operation`.

.. _setting-proxy-protocol-from:

``proxy-protocol-from``
-----------------------
.. versionadded:: 4.6.0

-  IP addresses or netmasks, separated by commas
-  Default: empty

Ranges that are required to send a Proxy Protocol version 2 header in front of UDP and TCP queries, to pass the original source and destination addresses and ports to the Authoritative.
Queries that are not prefixed with such a header will not be accepted from clients in these ranges. Queries prefixed by headers from clients that are not listed in these ranges will be dropped.

Note that once a Proxy Protocol header has been received, the source address from the proxy header instead of the address of the proxy will be checked against primary addresses sending NOTIFYs, and the ACLs for any client requesting AXFRs.
When using this setting combined with :ref:`setting-trusted-notification-proxy`, please be aware that the trusted address will also be checked against the source address in the PROXY header.

The dnsdist docs have `more information about the PROXY protocol <https://dnsdist.org/advanced/passing-source-address.html#proxy-protocol>`_.

.. _setting-proxy-protocol-maximum-size:

``proxy-protocol-maximum-size``
-------------------------------
.. versionadded:: 4.6.0

-  Integer
-  Default: 512

The maximum size, in bytes, of a Proxy Protocol payload (header, addresses and ports, and TLV values). Queries with a larger payload will be dropped.

.. _setting-query-cache-ttl:

``query-cache-ttl``
-------------------

-  Integer
-  Default: 20

Seconds to store queries with an answer in the Query Cache. See :ref:`query-cache`.

.. _setting-query-local-address:

``query-local-address``
-----------------------
.. versionchanged:: 4.4.0
  Accepts both IPv4 and IPv6 addresses. Also accept more than one address per
  address family.

-  IP addresses, separated by spaces or commas
-  Default: `0.0.0.0 ::`

The IP addresses to use as a source address for sending queries. Useful if
you have multiple IPs and PowerDNS is not bound to the IP address your
operating system uses by default for outgoing packets.

PowerDNS will pick the correct address family based on the remote's address (v4
for outgoing v4, v6 for outgoing v6). However, addresses are selected at random
without taking into account ip subnet reachability. It is highly recommended to
use the defaults in that case (the kernel will pick the right source address for
the network).

.. _setting-query-local-address6:

``query-local-address6``
------------------------
.. deprecated:: 4.5.0
  Removed. Use :ref:`setting-query-local-address`.

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

.. _setting-resolver:

``resolver``
------------

-  IP Address with optional port
-  Default: unset

Recursive DNS server to use for ALIAS lookups and the internal stub resolver. Only one address can be given.

It is assumed that the specified recursive DNS server, and the network path to it, are trusted.

Examples::

  resolver=127.0.0.1
  resolver=[::1]:5300

.. _setting-retrieval-threads:

``retrieval-threads``
---------------------

-  Integer
-  Default: 2

Number of AXFR secondary threads to start.

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

Specify which random number generator to use. Permissible choices are:

- auto - choose automatically
- sodium - Use libsodium ``randombytes_uniform``
- openssl - Use libcrypto ``RAND_bytes``
- getrandom - Use libc getrandom, falls back to urandom if it does not really work
- arc4random - Use BSD ``arc4random_uniform``
- urandom - Use ``/dev/urandom``
- kiss - Use simple settable deterministic RNG. **FOR TESTING PURPOSES ONLY!**

.. note::
  Not all choices are available on all systems.

.. _setting-secondary:

``secondary``
-------------

.. versionchanged:: 4.5.0
  This was called :ref:`setting-slave` before 4.5.0.

-  Boolean
-  Default: no

Turn on operating as a secondary. See :ref:`secondary-operation`.

.. _setting-secondary-do-renotify:

``secondary-do-renotify``
-------------------------

.. versionchanged:: 4.5.0
  This was called :ref:`setting-slave-renotify` before 4.5.0.

-  Boolean
-  Default: no

This setting will make PowerDNS renotify the secondaries after an AXFR is
*received* from a primary. This is useful, among other situations, when running a
signing secondary.

See :ref:`metadata-slave-renotify` to set this per-zone.

.. _setting-security-poll-suffix:

``security-poll-suffix``
------------------------

-  String
-  Default: secpoll.powerdns.com.

Zone name from which to query security update notifications. Setting
this to an empty string disables secpoll.

.. _setting-send-signed-notify:

``send-signed-notify``
----------------------

-  Boolean
-  Default: yes

If yes, outgoing NOTIFYs will be signed if a TSIG key is configured for the zone.
If there are multiple TSIG keys configured for a zone, PowerDNS will use the
first one retrieved from the backend, which may not be the correct one for the
respective secondary. Hence, in setups with multiple slaves with different TSIG keys
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

.. deprecated:: 4.5.0
  Renamed to :ref:`setting-secondary`.
  Removed in 4.9.0.

.. _setting-slave-cycle-interval:

``slave-cycle-interval``
------------------------

.. deprecated:: 4.5.0
  Renamed to :ref:`setting-xfr-cycle-interval`.
  Removed in 4.9.0.

.. _setting-slave-renotify:

``slave-renotify``
------------------

.. deprecated:: 4.5.0
  Renamed to :ref:`setting-secondary-do-renotify`.
  Removed in 4.9.0.

-  Boolean
-  Default: no

This setting will make PowerDNS renotify the secondaries after an AXFR is
*received* from a primary. This is useful when running a
signing-secondary.

See :ref:`metadata-slave-renotify` to set this per-zone.

.. _setting-soa-expire-default:

``soa-expire-default``
----------------------

-  Integer
-  Default: 604800

.. deprecated:: 4.2.0
  This setting has been removed in 4.4.0

Default :ref:`types-soa` expire.

.. _setting-soa-minimum-ttl:

``soa-minimum-ttl``
-------------------

-  Integer
-  Default: 3600

.. deprecated:: 4.2.0
  This setting has been removed in 4.4.0

Default :ref:`types-soa` minimum ttl.

.. _setting-soa-refresh-default:

``soa-refresh-default``
-----------------------

-  Integer
-  Default: 10800

.. deprecated:: 4.2.0
  This setting has been removed in 4.4.0

Default :ref:`types-soa` refresh.

.. _setting-soa-retry-default:

``soa-retry-default``
---------------------

-  Integer
-  Default: 3600

.. deprecated:: 4.2.0
  This setting has been removed in 4.4.0

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

.. deprecated:: 4.5.0
  Renamed to :ref:`setting-autosecondary`.
  Removed in 4.9.0.

-  Boolean
-  Default: no

Turn on autosecondary support. See :ref:`autoprimary-operation`.

.. _setting-svc-autohints:

``svc-autohints``
-----------------

- Boolean
- Default: no

.. versionadded:: 4.5.0

Whether or not to enable IPv4 and IPv6 :ref:`autohints <svc-autohints>`.

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

.. versionchanged:: 4.4.0
   This option now accepts a comma-separated list of IP ranges. This was a list of IP addresses before.

-  IP ranges, separated by commas

IP ranges of incoming notification proxies.

.. _setting-udp-truncation-threshold:

``udp-truncation-threshold``
----------------------------
-  Integer
-  Default: 1232

EDNS0 allows for large UDP response datagrams, which can potentially
raise performance. Large responses however also have downsides in terms
of reflection attacks. Maximum value is 65535, but values above
4096 should probably not be attempted.

.. note:: Why 1232?

  1232 is the largest number of payload bytes that can fit in the smallest IPv6 packet.
  IPv6 has a minimum MTU of 1280 bytes (:rfc:`RFC 8200, section 5 <8200#section-5>`), minus 40 bytes for the IPv6 header, minus 8 bytes for the UDP header gives 1232, the maximum payload size for the DNS response.

.. _setting-upgrade-unknown-types:

``upgrade-unknown-types``
-------------------------

-  Boolean
-  Default: no

.. versionadded:: 4.4.0

Transparently upgrade records stored as `TYPE#xxx` and RFC 3597 (hex format)
contents, if the type is natively supported.
When this is disabled, records stored in this format cannot be served.

Recommendation: keep disabled for better performance.
Enable for testing PowerDNS upgrades, without changing stored records.
Enable for upgrading record content on secondaries, or when using the API (see :doc:`upgrade notes <../upgrading>`).
Disable after record contents have been upgraded.

This option is supported by the bind and Generic SQL backends.

.. note::
  When using a generic SQL backend, records with an unknown record type (see :doc:`../appendices/types`) can be identified with the following SQL query::

      SELECT * from records where type like 'TYPE%';

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

.. _setting-webserver-address:

``webserver-address``
---------------------

-  IP Address
-  Default: 127.0.0.1

IP Address or path to UNIX domain socket for webserver/API to listen on.

.. _setting-webserver-allow-from:

``webserver-allow-from``
------------------------

-  IP ranges, separated by commas or whitespace
-  Default: 127.0.0.1,::1

Webserver/API access is only allowed from these subnets.
Ignored if ``webserver-address`` is set to a UNIX domain socket.

.. _setting-webserver-hash-plaintext-credentials:

``webserver-hash-plaintext-credentials``
----------------------------------------
.. versionadded:: 4.6.0

-  Boolean
-  Default: no

Whether passwords and API keys supplied in the configuration as plaintext should be hashed during startup, to prevent the plaintext versions from staying in memory. Doing so increases significantly the cost of verifying credentials and is thus disabled by default.
Note that this option only applies to credentials stored in the configuration as plaintext, but hashed credentials are supported without enabling this option.

.. _setting-webserver-loglevel:

``webserver-loglevel``
----------------------

-  String, one of "none", "normal", "detailed"
-  Default: normal

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
  The webserver logs these line on the NOTICE level. The :ref:`setting-loglevel` setting must be 5 or higher for these lines to end up in the log.

.. _setting-webserver-max-bodysize:

``webserver-max-bodysize``
--------------------------

-  Integer
-  Default: 2

Maximum request/response body size in megabytes.

.. _setting-webserver-connection-timeout:

``webserver-connection-timeout``
--------------------------------
.. versionadded:: 4.8.5

-  Integer
-  Default: 5

Request/response timeout in seconds.

.. _setting-webserver-password:

``webserver-password``
----------------------
.. versionchanged:: 4.6.0
  This setting now accepts a hashed and salted version.

-  String

Password required to access the webserver. Since 4.6.0 the password can be hashed and salted using ``pdnsutil hash-password`` instead of being present in the configuration in plaintext, but the plaintext version is still supported.

.. _setting-webserver-port:

``webserver-port``
------------------

-  Integer
-  Default: 8081

The port where webserver/API will listen on.
Ignored if ``webserver-address`` is set to a UNIX domain socket.

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

.. _setting-workaround-11804:

``workaround-11804``
--------------------

-  Boolean
-  Default: no

Workaround for `issue #11804 (outgoing AXFR may try to overfill a chunk and fail) <https://github.com/PowerDNS/pdns/issues/11804>`_.

Default of no implies the pre-4.8 behaviour of up to 100 RRs per AXFR chunk.

If enabled, only a single RR will be put into each AXFR chunk, making some zones transferable when they were not otherwise.

.. _setting-xfr-cycle-interval:

``xfr-cycle-interval``
----------------------

.. versionchanged:: 4.5.0
  This was called :ref:`setting-slave-cycle-interval` before 4.5.0.

-  Integer
-  Default: 60

On a primary, this is the amount of seconds between the primary checking
the SOA serials in its database to determine to send out NOTIFYs to the
secondaries. On secondaries, this is the number of seconds between the secondary
checking for updates to zones.

.. _setting-xfr-max-received-mbytes:

``xfr-max-received-mbytes``
---------------------------

-  Integer
-  Default: 100

Specifies the maximum number of received megabytes allowed on an
incoming AXFR/IXFR update, to prevent resource exhaustion. A value of 0
means no restriction.

.. _setting-zone-cache-refresh-interval:

``zone-cache-refresh-interval``
-------------------------------

-  Integer
-  Default: 300

Seconds to cache a list of all known zones. A value of 0 will disable the cache.

If your backends do not respond to unknown or dynamically generated zones, it is suggested to enable :ref:`setting-consistent-backends` (default since 4.5) and leave this option at its default of `300`.

.. _setting-zone-metadata-cache-ttl:

``zone-metadata-cache-ttl``
-----------------------------

.. versionchanged:: 4.5.0
  This was called :ref:`setting-domain-metadata-cache-ttl` before 4.5.0.

-  Integer
-  Default: 60

Seconds to cache zone metadata from the database. A value of 0
disables caching.
