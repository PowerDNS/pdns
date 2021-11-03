PowerDNS Recursor Settings
==========================
Each setting can appear on the command line, prefixed by '--', or in the configuration file.
The command line overrides the configuration file.

**Note**: Settings marked as 'Boolean' can either be set to an empty value, which means on, or to 'no' or 'off' which means off.
Anything else means on.

As an example:

 - ``serve-rfc1918`` on its own means: do serve those zones.
 - ``serve-rfc1918=off`` or ``serve-rfc1918=no`` means: do not serve those zones.
 - Anything else means: do serve those zones.

You can use ``+=`` syntax to set some variables incrementally, but this
requires you to have at least one non-incremental setting for the
variable to act as base setting. This is mostly useful for
:ref:`setting-include-dir` directive. An example::

  forward-zones = foo.example.com=192.168.100.1;
  forward-zones += bar.example.com=[1234::abcde]:5353;


.. _setting-aggressive-nsec-cache-size:

``aggressive-nsec-cache-size``
------------------------------
.. versionadded:: 4.5.0

-  Integer
-  Default: 100000

The number of records to cache in the aggressive cache. If set to a value greater than 0, the recursor will cache NSEC and NSEC3 records to generate negative answers, as defined in :rfc:`8198`.
To use this, DNSSEC processing or validation must be enabled by setting `dnssec`_ to ``process``, ``log-fail`` or ``validate``.

.. _setting-allow-from:

``allow-from``
--------------
-  IP addresses or netmasks, separated by commas
-  Default: 127.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 192.168.0.0/16, 172.16.0.0/12, ::1/128, fc00::/7, fe80::/10

Netmasks (both IPv4 and IPv6) that are allowed to use the server.
The default allows access only from :rfc:`1918` private IP addresses.
Due to the aggressive nature of the internet these days, it is highly recommended to not open up the recursor for the entire internet.
Questions from IP addresses not listed here are ignored and do not get an answer.

When the Proxy Protocol is enabled (see `proxy-protocol-from`_), the recursor will check the address of the client IP advertised in the Proxy Protocol header instead of the one of the proxy.

Note that specifying an IP address without a netmask uses an implicit netmask of /32 or /128.

.. _setting-allow-from-file:

``allow-from-file``
-------------------
-  Path

Like `allow-from`_, except reading from file.
Overrides the `allow-from`_ setting. To use this feature, supply one netmask per line, with optional comments preceded by a "#".

.. _setting-any-to-tcp:

``any-to-tcp``
--------------
-  Boolean
-  Default: no

Answer questions for the ANY type on UDP with a truncated packet that refers the remote server to TCP.
Useful for mitigating ANY reflection attacks.

.. _setting-allow-trust-anchor-query:

``allow-trust-anchor-query``
----------------------------
.. versionadded:: 4.3.0

-  Boolean
-  Default: no

Allow ``trustanchor.server CH TXT`` and ``negativetrustanchor.server CH TXT`` queries to view the configured :doc:`DNSSEC <dnssec>` (negative) trust anchors.

.. _setting-api-config-dir:

``api-config-dir``
------------------
.. versionadded:: 4.0.0

-  Path
-  Default: unset

Directory where the REST API stores its configuration and zones.

.. _setting-api-key:

``api-key``
-----------
.. versionadded:: 4.0.0
.. versionchanged:: 4.6.0
  This setting now accepts a hashed and salted version.

-  String
-  Default: unset

Static pre-shared authentication key for access to the REST API. Since 4.6.0 the key can be hashed and salted using ``rec_control hash-password`` instead of being stored in the configuration in plaintext, but the plaintext version is still supported.

.. _setting-api-readonly:

``api-readonly``
----------------
.. versionchanged:: 4.2.0
  This setting has been removed.

-  Boolean
-  Default: no

Disallow data modification through the REST API when set.

.. _setting-api-logfile:

``api-logfile``
---------------
.. versionchanged:: 4.2.0
  This setting has been removed.

-  Path
-  Default: unset

Location of the server logfile (used by the REST API).

.. _setting-auth-can-lower-ttl:

``auth-can-lower-ttl``
----------------------
-  Boolean
-  Default: no

Authoritative zones can transmit a TTL value that is lower than that specified in the parent zone.
This is called a 'delegation inconsistency'.
To follow :rfc:`RFC 2181 section 5.2<2181#section-5.2>` and :rfc:`5.4 <2181#section-5.4>` to the letter, enable this feature.
This will mean a slight deterioration of performance, and it will not solve any problems, but does make the recursor more standards compliant.
Not recommended unless you have to tick an 'RFC 2181 compliant' box.

.. _setting-auth-zones:

``auth-zones``
--------------
-  Comma separated list of 'zonename=filename' pairs

Zones read from these files (in BIND format) are served authoritatively (but without the AA bit set in responses).
DNSSEC is not supported. Example:

.. code-block:: none

    auth-zones=example.org=/var/zones/example.org, powerdns.com=/var/zones/powerdns.com

.. _setting-carbon-interval:

``carbon-interval``
-------------------
-  Integer
-  Default: 30

If sending carbon updates, this is the interval between them in seconds.
See :doc:`metrics`.

.. _setting-carbon-namespace:

``carbon-namespace``
--------------------
.. versionadded:: 4.2.0

-  String

Change the namespace or first string of the metric key. The default is pdns.

.. _setting-carbon-ourname:

``carbon-ourname``
------------------
-  String

If sending carbon updates, if set, this will override our hostname.
Be careful not to include any dots in this setting, unless you know what you are doing.
See :ref:`metricscarbon`.

.. _setting-carbon-instance:

``carbon-instance``
--------------------
.. versionadded:: 4.2.0

-  String

Change the instance or third string of the metric key. The default is recursor.

.. _setting-carbon-server:

``carbon-server``
-----------------
-  IP address

If set to an IP or IPv6 address, will send all available metrics to this server via the carbon protocol, which is used by graphite and metronome. Moreover you can specify more than one server using a comma delimited list, ex: carbon-server=10.10.10.10,10.10.10.20.
You may specify an alternate port by appending :port, for example: ``127.0.0.1:2004``.
See :doc:`metrics`.

.. _setting-chroot:

``chroot``
----------
-  Path to a Directory

If set, chroot to this directory for more security.
See :doc:`security`

Make sure that ``/dev/log`` is available from within the chroot.
Logging will silently fail over time otherwise (on logrotate).

When using ``chroot``, all other paths (except for `config-dir`_) set in the configuration are relative to the new root.

When using ``chroot`` and the API (`webserver`_), `api-readonly`_ **must** be set and `api-config-dir`_ unset.

When running on a system where systemd manages services, ``chroot`` does not work out of the box, as PowerDNS cannot use the ``NOTIFY_SOCKET``.
Either do not ``chroot`` on these systems or set the 'Type' of this service to 'simple' instead of 'notify' (refer to the systemd documentation on how to modify unit-files).

.. _setting-client-tcp-timeout:

``client-tcp-timeout``
----------------------
-  Integer
-  Default: 2

Time to wait for data from TCP clients.

.. _setting-config-dir:

``config-dir``
--------------
-  Path

Location of configuration directory (``recursor.conf``).
Usually ``/etc/powerdns``, but this depends on ``SYSCONFDIR`` during compile-time.

.. _setting-config-name:

``config-name``
---------------
-  String
-  Default: unset

When running multiple recursors on the same server, read settings from :file:`recursor-{name}.conf`, this will also rename the binary image.

.. _setting-cpu-map:

``cpu-map``
-----------
.. versionadded:: 4.1.0

- String
- Default: unset

Set CPU affinity for worker threads, asking the scheduler to run those threads on a single CPU, or a set of CPUs.
This parameter accepts a space separated list of thread-id=cpu-id, or thread-id=cpu-id-1,cpu-id-2,...,cpu-id-N.
For example, to make the worker thread 0 run on CPU id 0 and the worker thread 1 on CPUs 1 and 2::

  cpu-map=0=0 1=1,2

The number of worker threads is determined by the :ref:`setting-threads` setting.
If :ref:`setting-pdns-distributes-queries` is set, an additional thread is started, assigned the id 0,
and is the only one listening on client sockets and accepting queries, distributing them to the other worker threads afterwards.

Starting with version 4.2.0, the thread handling the control channel, the webserver and other internal stuff has been assigned
id 0 and more than one distributor thread can be started using the :ref:`setting-distributor-threads` setting, so the distributor
threads if any are assigned id 1 and counting, and the other threads follow behind.

This parameter is only available on OS that provides the `pthread_setaffinity_np()` function.

.. _setting-daemon:

``daemon``
----------
-  Boolean
-  Default: no

.. versionchanged:: 4.0.0

    Default is now "no", was "yes" before.

Operate in the background.

.. _setting-dont-throttle-names:

``dont-throttle-names``
----------------------------
.. versionadded:: 4.2.0

-  Comma separated list of domain-names
-  Default: (empty)

When an authoritative server does not answer a query or sends a reply the recursor does not like, it is throttled.
Any servers' name suffix-matching the supplied names will never be throttled.

.. warning::
  Most servers on the internet do not respond for a good reason (overloaded or unreachable), ``dont-throttle-names`` could make this load on the upstream server even higher, resulting in further service degradation.

.. _setting-dont-throttle-netmasks:

``dont-throttle-netmasks``
----------------------------
.. versionadded:: 4.2.0

-  Comma separated list of netmasks
-  Default: (empty)

When an authoritative server does not answer a query or sends a reply the recursor does not like, it is throttled.
Any servers matching the supplied netmasks will never be throttled.

This can come in handy on lossy networks when forwarding, where the same server is configured multiple times (e.g. with ``forward-zones-recurse=example.com=192.0.2.1;192.0.2.1``).
By default, the PowerDNS Recursor would throttle the "first" server on a timeout and hence not retry the "second" one.
In this case, ``dont-throttle-netmasks`` could be set to ``192.0.2.1``.

.. warning::
  Most servers on the internet do not respond for a good reason (overloaded or unreachable), ``dont-throttle-netmasks`` could make this load on the upstream server even higher, resulting in further service degradation.

.. _setting-disable-packetcache:

``disable-packetcache``
-----------------------
-  Boolean
-  Default: no

Turn off the packet cache. Useful when running with Lua scripts that can not be cached, though individual query caching can be controlled from Lua as well.

.. _setting-disable-syslog:

``disable-syslog``
------------------
-  Boolean
-  Default: no

Do not log to syslog, only to stdout.
Use this setting when running inside a supervisor that handles logging (like systemd).
**Note**: do not use this setting in combination with `daemon`_ as all logging will disappear.

.. _setting-distribution-load-factor:

``distribution-load-factor``
----------------------------
.. versionadded:: 4.1.12

-  Double
-  Default: 0.0

If `pdns-distributes-queries`_ is set and this setting is set to another value
than 0, the distributor thread will use a bounded load-balancing algorithm while
distributing queries to worker threads, making sure that no thread is assigned
more queries than distribution-load-factor times the average number of queries
currently processed by all the workers.
For example, with a value of 1.25, no server should get more than 125 % of the
average load. This helps making sure that all the workers have roughly the same
share of queries, even if the incoming traffic is very skewed, with a larger
number of requests asking for the same qname.

.. _setting-distribution-pipe-buffer-size:

``distribution-pipe-buffer-size``
---------------------------------
.. versionadded:: 4.2.0

-  Integer
-  Default: 0

Size in bytes of the internal buffer of the pipe used by the distributor to pass incoming queries to a worker thread.
Requires support for `F_SETPIPE_SZ` which is present in Linux since 2.6.35. The actual size might be rounded up to
a multiple of a page size. 0 means that the OS default size is used.
A large buffer might allow the recursor to deal with very short-lived load spikes during which a worker thread gets
overloaded, but it will be at the cost of an increased latency.

.. _setting-distributor-threads:

``distributor-threads``
-----------------------
.. versionadded:: 4.2.0

-  Integer
-  Default: 1 if `pdns-distributes-queries`_ is set, 0 otherwise

If `pdns-distributes-queries`_ is set, spawn this number of distributor threads on startup. Distributor threads
handle incoming queries and distribute them to other threads based on a hash of the query, to maximize the cache hit
ratio.

.. _setting-dot-to-auth-names:

``dot-to-auth-names``
---------------------
.. versionadded:: 4.6.0

- Comma separated list of domain-names or suffixes
- Default: (empty).

Force DoT to the listed authoritative nameservers. For this to work, DoT support has to be compiled in.
Currently, the certificate is not checked for validity in any way.

.. _setting-dot-to-port-853:

``dot-to-port-853``
-------------------
.. versionadded:: 4.6.0

- Boolean
- Default: ``yes`` if DoT support is compiled in, ``no`` otherwise.

Enable DoT to forwarders that specify port 853.

.. _setting-dns64-prefix:

``dns64-prefix``
----------------
.. versionadded:: 4.4.0

-  Netmask, as a string
-  Default: None

Enable DNS64 (:rfc:`6147`) support using the supplied /96 IPv6 prefix. This will generate 'fake' ``AAAA`` records for names
with only ``A`` records, as well as 'fake' ``PTR`` records to make sure that reverse lookup of DNS64-generated IPv6 addresses
generate the right name.
See :doc:`dns64` for more flexible but slower alternatives using Lua.

.. _setting-dnssec:

``dnssec``
----------
.. versionadded:: 4.0.0

.. versionchanged:: 4.5.0
   The default changed from ``process-no-validate`` to ``process``

-  One of ``off``, ``process-no-validate``, ``process``, ``log-fail``, ``validate``, String
-  Default: ``process``

Set the mode for DNSSEC processing, as detailed in :doc:`dnssec`.

``off``
   No DNSSEC processing whatsoever.
   Ignore DO-bits in queries, don't request any DNSSEC information from authoritative servers.
   This behaviour is similar to PowerDNS Recursor pre-4.0.
``process-no-validate``
   Respond with DNSSEC records to clients that ask for it, set the DO bit on all outgoing queries.
   Don't do any validation.
``process``
   Respond with DNSSEC records to clients that ask for it, set the DO bit on all outgoing queries.
   Do validation for clients that request it (by means of the AD- bit or DO-bit in the query).
``log-fail``
   Similar behaviour to ``process``, but validate RRSIGs on responses and log bogus responses.
``validate``
   Full blown DNSSEC validation. Send SERVFAIL to clients on bogus responses.

.. _setting-dnssec-log-bogus:

``dnssec-log-bogus``
--------------------
-  Boolean
-  Default: no

Log every DNSSEC validation failure.
**Note**: This is not logged per-query but every time records are validated as Bogus.

.. _setting-dont-query:

``dont-query``
--------------
-  Netmasks, comma separated
-  Default: 127.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 192.168.0.0/16, 172.16.0.0/12, ::1/128, fc00::/7, fe80::/10, 0.0.0.0/8, 192.0.0.0/24, 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 240.0.0.0/4, ::/96, ::ffff:0:0/96, 100::/64, 2001:db8::/32

The DNS is a public database, but sometimes contains delegations to private IP addresses, like for example 127.0.0.1.
This can have odd effects, depending on your network, and may even be a security risk.
Therefore, the PowerDNS Recursor by default does not query private space IP addresses.
This setting can be used to expand or reduce the limitations.

Queries for names in forward zones and to addresses as configured in any of the settings `forward-zones`_, `forward-zones-file`_ or `forward-zones-recurse`_ are performed regardless of these limitations.

.. _setting-ecs-add-for:

``ecs-add-for``
---------------
.. versionadded:: 4.2.0

-  Comma separated list of netmasks
-  Default: 0.0.0.0/0, ::/0, !127.0.0.0/8, !10.0.0.0/8, !100.64.0.0/10, !169.254.0.0/16, !192.168.0.0/16, !172.16.0.0/12, !::1/128, !fc00::/7, !fe80::/10

List of requestor netmasks for which the requestor IP Address should be used as the :rfc:`EDNS Client Subnet <7871>` for outgoing queries. Outgoing queries for requestors that do not match this list will use the `ecs-scope-zero-address`_ instead.
Valid incoming ECS values from `use-incoming-edns-subnet`_ are not replaced.

Regardless of the value of this setting, ECS values are only sent for outgoing queries matching the conditions in the `edns-subnet-allow-list`_ setting. This setting only controls the actual value being sent.

This defaults to not using the requestor address inside RFC1918 and similar "private" IP address spaces.

.. _setting-ecs-ipv4-bits:

``ecs-ipv4-bits``
-----------------
.. versionadded:: 4.1.0

-  Integer
-  Default: 24

Number of bits of client IPv4 address to pass when sending EDNS Client Subnet address information.

.. _setting-ecs-ipv4-cache-bits:

``ecs-ipv4-cache-bits``
-----------------------
.. versionadded:: 4.1.12

-  Integer
-  Default: 24

Maximum number of bits of client IPv4 address used by the authoritative server (as indicated by the EDNS Client Subnet scope in the answer) for an answer to be inserted into the query cache. This condition applies in conjunction with ``ecs-cache-limit-ttl``.
That is, only if both the limits apply, the record will not be cached. This decision can be overridden by ``ecs-ipv4-never-cache`` and ``ecs-ipv6-never-cache``.

.. _setting-ecs-ipv6-bits:

``ecs-ipv6-bits``
-----------------
.. versionadded:: 4.1.0

-  Integer
-  Default: 56

Number of bits of client IPv6 address to pass when sending EDNS Client Subnet address information.

.. _setting-ecs-ipv6-cache-bits:

``ecs-ipv6-cache-bits``
-----------------------
.. versionadded:: 4.1.12

-  Integer
-  Default: 56

Maximum number of bits of client IPv6 address used by the authoritative server (as indicated by the EDNS Client Subnet scope in the answer) for an answer to be inserted into the query cache. This condition applies in conjunction with ``ecs-cache-limit-ttl``.
That is, only if both the limits apply, the record will not be cached. This decision can be overridden by ``ecs-ipv4-never-cache`` and ``ecs-ipv6-never-cache``.

.. _setting-ecs-ipv4-never-cache:

``ecs-ipv4-never-cache``
------------------------
.. versionadded:: 4.5.0

-  Boolean
-  Default: no

When set, never cache replies carrying EDNS IPv4 Client Subnet scope in the record cache.
In this case the decision made by ```ecs-ipv4-cache-bits`` and ``ecs-cache-limit-ttl`` is no longer relevant.

.. _setting-ecs-ipv6-never-cache:

``ecs-ipv6-never-cache``
------------------------
.. versionadded:: 4.5.0

-  Boolean
-  Default: no

When set, never cache replies carrying EDNS IPv6 Client Subnet scope in the record cache.
In this case the decision made by ```ecs-ipv6-cache-bits`` and ``ecs-cache-limit-ttl`` is no longer relevant.

.. _setting-ecs-minimum-ttl-override:

``ecs-minimum-ttl-override``
----------------------------
.. versionchanged:: 4.5.0
  Old versions used default 0.

-  Integer
-  Default: 1

This setting artificially raises the TTLs of records in the ANSWER section of ECS-specific answers to be at least this long.
Setting this to a value greater than 1 technically is an RFC violation, but might improve performance a lot.
Using a value of 0 impacts performance of TTL 0 records greatly, since it forces the recursor to contact
authoritative servers every time a client requests them.
Can be set at runtime using ``rec_control set-ecs-minimum-ttl 3600``.

.. _setting-ecs-cache-limit-ttl:

``ecs-cache-limit-ttl``
-----------------------
.. versionadded:: 4.1.12

-  Integer
-  Default: 0 (disabled)

The minimum TTL for an ECS-specific answer to be inserted into the query cache. This condition applies in conjunction with ``ecs-ipv4-cache-bits`` or ``ecs-ipv6-cache-bits``.
That is, only if both the limits apply, the record will not be cached. This decision can be overridden by ``ecs-ipv4-never-cache`` and ``ecs-ipv6-never-cache``.

.. _setting-ecs-scope-zero-address:

``ecs-scope-zero-address``
--------------------------
.. versionadded:: 4.1.0

- IPv4 or IPv6 Address
- Default: empty

The IP address sent via EDNS Client Subnet to authoritative servers listed in
`edns-subnet-allow-list`_ when `use-incoming-edns-subnet`_ is set and the query has
an ECS source prefix-length set to 0.
The default is to look for the first usable (not an ``any`` one) address in
`query-local-address`_ (starting with IPv4). If no suitable address is
found, the recursor fallbacks to sending 127.0.0.1.

.. _setting-edns-outgoing-bufsize:

``edns-outgoing-bufsize``
-------------------------
.. versionchanged:: 4.2.0
  Before 4.2.0, the default was 1680

-  Integer
-  Default: 1232

.. note:: Why 1232?

  1232 is the largest number of payload bytes that can fit in the smallest IPv6 packet.
  IPv6 has a minimum MTU of 1280 bytes (:rfc:`RFC 8200, section 5 <8200#section-5>`), minus 40 bytes for the IPv6 header, minus 8 bytes for the UDP header gives 1232, the maximum payload size for the DNS response.

This is the value set for the EDNS0 buffer size in outgoing packets.
Lower this if you experience timeouts.

.. _setting-edns-padding-from:

``edns-padding-from``
---------------------
.. versionadded:: 4.5.0

-  Comma separated list of netmasks
-  Default: (none)

List of netmasks (proxy IP in case of proxy-protocol presence, client IP otherwise) for which EDNS padding will be enabled in responses, provided that `edns-padding-mode`_ applies.

.. _setting-edns-padding-mode:

``edns-padding-mode``
---------------------
.. versionadded:: 4.5.0

-  One of ``always``, ``padded-queries-only``, String
-  Default: ``padded-queries-only``

Whether to add EDNS padding to all responses (``always``) or only to responses for queries containing the EDNS padding option (``padded-queries-only``, the default).
In both modes, padding will only be added to responses for queries coming from `edns-padding-from`_ sources.

.. _setting-edns-padding-tag:

``edns-padding-tag``
--------------------
.. versionadded:: 4.5.0

-  Integer
-  Default: 7830

The packetcache tag to use for padded responses, to prevent a client not allowed by the `edns-padding-from`_ list to be served a cached answer generated for an allowed one. This
effectively divides the packet cache in two when `edns-padding-from`_ is used. Note that this will not override a tag set from one of the ``Lua`` hooks.

.. _setting-edns-subnet-whitelist:

``edns-subnet-whitelist``
-------------------------
.. deprecated:: 4.5.0
 Use :ref:`setting-edns-subnet-allow-list`.

.. _setting-edns-subnet-allow-list:

``edns-subnet-allow-list``
--------------------------
.. versionadded:: 4.5.0

-  Comma separated list of domain names and netmasks
-  Default: (none)

List of netmasks and domains that :rfc:`EDNS Client Subnet <7871>` should be enabled for in outgoing queries.

For example, an EDNS Client Subnet option containing the address of the initial requestor (but see `ecs-add-for`_) will be added to an outgoing query sent to server 192.0.2.1 for domain X if 192.0.2.1 matches one of the supplied netmasks, or if X matches one of the supplied domains.
The initial requestor address will be truncated to 24 bits for IPv4 (see `ecs-ipv4-bits`_) and to 56 bits for IPv6 (see `ecs-ipv6-bits`_), as recommended in the privacy section of RFC 7871.

By default, this option is empty, meaning no EDNS Client Subnet information is sent.

.. _setting-entropy-source:

``entropy-source``
------------------
-  Path
-  Default: /dev/urandom

PowerDNS can read entropy from a (hardware) source.
This is used for generating random numbers which are very hard to predict.
Generally on UNIX platforms, this source will be ``/dev/urandom``, which will always supply random numbers, even if entropy is lacking.
Change to ``/dev/random`` if PowerDNS should block waiting for enough entropy to arrive.

.. _setting-etc-hosts-file:

``etc-hosts-file``
------------------
-  Path
-  Default: /etc/hosts

The path to the /etc/hosts file, or equivalent.
This file can be used to serve data authoritatively using `export-etc-hosts`_.

.. _setting-event-trace-enabled:

``event-trace-enabled``
-----------------------
.. versionadded:: 4.6.0

- Integer
- Default: 0

Enable the recording and logging of ref:`event traces`. This is an experimental feature subject to change.
Possible values are 0: (disabled), 1 (add information to protobuf logging messages) and 2 (write to log) and 3 (both).

.. _setting-export-etc-hosts:

``export-etc-hosts``
--------------------
-  Boolean
-  Default: no

If set, this flag will export the host names and IP addresses mentioned in ``/etc/hosts``.

.. _setting-export-etc-hosts-search-suffix:

``export-etc-hosts-search-suffix``
----------------------------------
-  String

If set, all hostnames in the `export-etc-hosts`_ file are loaded in canonical form, based on this suffix, unless the name contains a '.', in which case the name is unchanged.
So an entry called 'pc' with ``export-etc-hosts-search-suffix='home.com'`` will lead to the generation of 'pc.home.com' within the recursor.
An entry called 'server1.home' will be stored as 'server1.home', regardless of this setting.

.. _setting-extended-resolution-errors:

``extended-resolution-errors``
------------------------------
.. versionadded:: 4.5.0

-  Boolean
-  Default: no

If set, the recursor will add an EDNS Extended Error (:rfc:`8914`) to responses when resolution failed, like DNSSEC validation errors, explaining the reason it failed. This setting is not needed to allow setting custom error codes from Lua or from a RPZ hit.

.. _setting-forward-zones:

``forward-zones``
-----------------
-  'zonename=IP' pairs, comma separated

Queries for zones listed here will be forwarded to the IP address listed. i.e.

.. code-block:: none

    forward-zones=example.org=203.0.113.210, powerdns.com=2001:DB8::BEEF:5

Multiple IP addresses can be specified and port numbers other than 53 can be configured:

.. code-block:: none

    forward-zones=example.org=203.0.113.210:5300;127.0.0.1, powerdns.com=127.0.0.1;198.51.100.10:530;[2001:DB8::1:3]:5300

Forwarded queries have the 'recursion desired' bit set to 0, meaning that this setting is intended to forward queries to authoritative servers.

**IMPORTANT**: When using DNSSEC validation (which is default), forwards to non-delegated (e.g. internal) zones that have a DNSSEC signed parent zone will validate as Bogus.
To prevent this, add a Negative Trust Anchor (NTA) for this zone in the `lua-config-file`_ with ``addNTA("your.zone", "A comment")``.
If this forwarded zone is signed, instead of adding NTA, add the DS record to the `lua-config-file`_.
See the :doc:`dnssec` information.

.. _setting-forward-zones-file:

``forward-zones-file``
----------------------
-  Path

Same as `forward-zones`_, parsed from a file. Only 1 zone is allowed per line, specified as follows:

.. code-block:: none

    example.org=203.0.113.210, 192.0.2.4:5300

Zones prefixed with a '+' are forwarded with the recursion-desired bit set, for which see `forward-zones-recurse`_.
Default behaviour without '+' is as with `forward-zones`_.

.. versionchanged:: 4.0.0

  Comments are allowed, everything behind '#' is ignored.

The DNSSEC notes from `forward-zones`_ apply here as well.

.. _setting-forward-zones-recurse:

``forward-zones-recurse``
-------------------------
-  'zonename=IP' pairs, comma separated

Like regular `forward-zones`_, but forwarded queries have the 'recursion desired' bit set to 1, meaning that this setting is intended to forward queries to other recursive servers.

The DNSSEC notes from `forward-zones`_ apply here as well.

.. _setting-gettag-needs-edns-options:

``gettag-needs-edns-options``
-----------------------------
.. versionadded:: 4.1.0

-  Boolean
-  Default: no

If set, EDNS options in incoming queries are extracted and passed to the :func:`gettag` hook in the ``ednsoptions`` table.

.. _setting-hint-file:

``hint-file``
-------------
-  Path

If set, the root-hints are read from this file. If unset, default root hints are used.

.. _setting-ignore-unknown-settings:

``ignore-unknown-settings``
---------------------------

.. versionadded:: 4.6.0

-  Setting names, separated by commas
-  Default: empty

Names of settings to be ignored while parsing configuration files, if the setting
name is unknown to PowerDNS.

Useful during upgrade testing.

.. _setting-include-dir:

``include-dir``
---------------
-  Path

Directory to scan for additional config files. All files that end with .conf are loaded in order using ``POSIX`` as locale.

.. _setting-latency-statistic-size:

``latency-statistic-size``
--------------------------
-  Integer
-  Default: 10000

Indication of how many queries will be averaged to get the average latency reported by the 'qa-latency' metric.

.. _setting-local-address:

``local-address``
-----------------
-  IPv4/IPv6 Addresses, with optional port numbers, separated by commas or whitespace
-  Default: ``127.0.0.1``

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

.. _setting-local-port:

``local-port``
--------------
-  Integer
-  Default: 53

Local port to bind to.
If an address in `local-address`_ does not have an explicit port, this port is used.

.. _setting-log-timestamp:

``log-timestamp``
-----------------

.. versionadded:: 4.1.0

- Bool
- Default: yes

When printing log lines to stdout, prefix them with timestamps.
Disable this if the process supervisor timestamps these lines already.

.. note::
  The systemd unit file supplied with the source code already disables timestamp printing

.. _setting-non-local-bind:

``non-local-bind``
------------------
-  Boolean
-  Default: no

Bind to addresses even if one or more of the `local-address`_'s do not exist on this server.
Setting this option will enable the needed socket options to allow binding to non-local addresses.
This feature is intended to facilitate ip-failover setups, but it may also mask configuration issues and for this reason it is disabled by default.

.. _setting-loglevel:

``loglevel``
------------
-  Integer between 0 and 9
-  Default: 6

Amount of logging.
Higher is more, more logging may destroy performance.
It is recommended not to set this below 3.

.. _setting-log-common-errors:

``log-common-errors``
---------------------
-  Boolean
-  Default: no

Some DNS errors occur rather frequently and are no cause for alarm.

``log-rpz-changes``
-------------------
.. versionadded:: 4.1.0

-  Boolean
-  Default: no

Log additions and removals to RPZ zones at Info (6) level instead of Debug (7).

.. _setting-logging-facility:

``logging-facility``
--------------------
-  Integer

If set to a digit, logging is performed under this LOCAL facility.
See :ref:`logging`.
Do not pass names like 'local0'!

.. _setting-lowercase-outgoing:

``lowercase-outgoing``
----------------------
-  Boolean
-  Default: no

Set to true to lowercase the outgoing queries.
When set to 'no' (the default) a query from a client using mixed case in the DNS labels (such as a user entering mixed-case names or `draft-vixie-dnsext-dns0x20-00 <http://tools.ietf.org/html/draft-vixie-dnsext-dns0x20-00>`_), PowerDNS preserves the case of the query.
Broken authoritative servers might give a wrong or broken answer on this encoding.
Setting ``lowercase-outgoing`` to 'yes' makes the PowerDNS Recursor lowercase all the labels in the query to the authoritative servers, but still return the proper case to the client requesting.

.. _setting-lua-config-file:

``lua-config-file``
-------------------
-  Filename

If set, and Lua support is compiled in, this will load an additional configuration file for newer features and more complicated setups.
See :doc:`lua-config/index` for the options that can be set in this file.

.. _setting-lua-dns-script:

``lua-dns-script``
------------------
-  Path
-  Default: unset

Path to a lua file to manipulate the Recursor's answers. See :doc:`lua-scripting/index` for more information.

.. _setting-maintenance-interval:

``lua-maintenance-interval``
----------------------------
.. versionadded:: 4.2.0

-  Integer
-  Default: 1


The interval between calls to the Lua user defined `maintenance()` function in seconds.
See :ref:`hooks-maintenance-callback`

.. _setting-max-cache-bogus-ttl:

``max-cache-bogus-ttl``
-----------------------
.. versionadded:: 4.2.0

-  Integer
-  Default: 3600

Maximum number of seconds to cache an item in the DNS cache (negative or positive) if its DNSSEC validation failed, no matter what the original TTL specified, to reduce the impact of a broken domain.

.. _setting-max-cache-entries:

``max-cache-entries``
---------------------
-  Integer
-  Default: 1000000

Maximum number of DNS record cache entries, shared by all threads since 4.4.0.
Each entry associates a name and type with a record set.
The size of the negative cache is 10% of this number.

.. _setting-max-cache-ttl:

``max-cache-ttl``
-----------------
-  Integer
-  Default: 86400

Maximum number of seconds to cache an item in the DNS cache, no matter what the original TTL specified.

.. versionchanged:: 4.1.0

    The minimum value of this setting is 15. i.e. setting this to lower than 15 will make this value 15.

.. _setting-max-concurrent-requests-per-tcp-connection:

``max-concurrent-requests-per-tcp-connection``
----------------------------------------------

.. versionadded:: 4.3.0

-  Integer
-  Default: 10

Maximum number of incoming requests handled concurrently per tcp
connection. This number must be larger than 0 and smaller than 65536
and also smaller than `max-mthreads`.

.. _setting-max-generate-steps:

``max-generate-steps``
----------------------

.. versionadded:: 4.3.0

-  Integer
-  Default: 0

Maximum number of steps for a '$GENERATE' directive when parsing a
zone file. This is a protection measure to prevent consuming a lot of
CPU and memory when untrusted zones are loaded. Default to 0 which
means unlimited.

.. _setting-max-mthreads:

``max-mthreads``
----------------
-  Integer
-  Default: 2048

Maximum number of simultaneous MTasker threads.

.. _setting-max-packetcache-entries:

``max-packetcache-entries``
---------------------------
-  Integer
-  Default: 500000

Maximum number of Packet Cache entries. Each worker and each distributor thread has a packet cache instance.
This number will be divided by the number of worker plus the number of distributor threads to compute the maximum number of entries per cache instance.

.. _setting-max-qperq:

``max-qperq``
-------------
-  Integer
-  Default: 60

The maximum number of outgoing queries that will be sent out during the resolution of a single client query.
This is used to limit endlessly chasing CNAME redirections.
If qname-minimization is enabled, the number will be forced to be 100
at a minimum to allow for the extra queries qname-minimization generates when the cache is empty.

.. _setting-max-ns-address-qperq:

``max-ns-address-qperq``
------------------------
.. versionadded:: 4.1.16
.. versionadded:: 4.2.2
.. versionadded:: 4.3.1

-  Integer
-  Default: 10

The maximum number of outgoing queries with empty replies for
resolving nameserver names to addresses we allow during the resolution
of a single client query. If IPv6 is enabled, an A and a AAAA query
for a name counts as 1. If a zone publishes more than this number of
NS records, the limit is further reduced for that zone by lowering
it by the number of NS records found above the
`max-ns-address-qperq`_ value. The limit wil not be reduced to a
number lower than 5.

.. _setting-max-negative-ttl:

``max-negative-ttl``
--------------------
-  Integer
-  Default: 3600

A query for which there is authoritatively no answer is cached to quickly deny a record's existence later on, without putting a heavy load on the remote server.
In practice, caches can become saturated with hundreds of thousands of hosts which are tried only once.
This setting, which defaults to 3600 seconds, puts a maximum on the amount of time negative entries are cached.

.. _setting-max-recursion-depth:

``max-recursion-depth``
-----------------------
-  Integer
-  Default: 40

Total maximum number of internal recursion calls the server may use to answer a single query.
0 means unlimited.
The value of `stack-size`_ should be increased together with this one to prevent the stack from overflowing.
If `qname-minimization`_ is enabled, the fallback code in case of a failing resolve is allowed an additional `max-recursion-depth/2`.


.. versionchanged:: 4.1.0

    Before 4.1.0, this settings was unlimited.

.. _setting-max-tcp-clients:

``max-tcp-clients``
-------------------
-  Integer
-  Default: 128

Maximum number of simultaneous incoming TCP connections allowed.

.. _setting-max-tcp-per-client:

``max-tcp-per-client``
----------------------
-  Integer
-  Default: 0 (unlimited)

Maximum number of simultaneous incoming TCP connections allowed per client (remote IP address).

.. _setting-max-tcp-queries-per-connection:

``max-tcp-queries-per-connection``
----------------------------------
.. versionadded:: 4.1.0

-  Integer
-  Default: 0 (unlimited)

Maximum number of DNS queries in a TCP connection.

.. _setting-max-total-msec:

``max-total-msec``
------------------
-  Integer
-  Default: 7000

Total maximum number of milliseconds of wallclock time the server may use to answer a single query.

.. _setting-max-udp-queries-per-round:

``max-udp-queries-per-round``
----------------------------------
.. versionadded:: 4.1.4

-  Integer
-  Default: 10000

Under heavy load the recursor might be busy processing incoming UDP queries for a long while before there is no more of these, and might therefore
neglect scheduling new ``mthreads``, handling responses from authoritative servers or responding to :doc:`rec_control <manpages/rec_control.1>`
requests.
This setting caps the maximum number of incoming UDP DNS queries processed in a single round of looping on ``recvmsg()`` after being woken up by the multiplexer, before
returning back to normal processing and handling other events.

.. _setting-minimum-ttl-override:

``minimum-ttl-override``
------------------------
.. versionchanged:: 4.5.0
  Old versions used default 0.

-  Integer
-  Default: 1

This setting artificially raises all TTLs to be at least this long.
Setting this to a value greater than 1 technically is an RFC violation, but might improve performance a lot.
Using a value of 0 impacts performance of TTL 0 records greatly, since it forces the recursor to contact
authoritative servers each time a client requests them.
Can be set at runtime using ``rec_control set-minimum-ttl 3600``.

.. _setting-new-domain-tracking:

``new-domain-tracking``
-----------------------
.. versionadded:: 4.2.0

- Boolean
- Default: no (disabled)

Whether to track newly observed domains, i.e. never seen before. This
is a probabilistic algorithm, using a stable bloom filter to store
records of previously seen domains. When enabled for the first time,
all domains will appear to be newly observed, so the feature is best
left enabled for e.g. a week or longer before using the results. Note
that this feature is optional and must be enabled at compile-time,
thus it may not be available in all pre-built packages.
If protobuf is enabled and configured, then the newly observed domain
status will appear as a flag in Response messages.

.. _setting-new-domain-log:

``new-domain-log``
------------------
.. versionadded:: 4.2.0

- Boolean
- Default: yes (enabled)

If a newly observed domain is detected, log that domain in the
recursor log file. The log line looks something like::

  Jul 18 11:31:25 Newly observed domain nod=sdfoijdfio.com

.. _setting-new-domain-lookup:

``new-domain-lookup``
---------------------
.. versionadded:: 4.2.0

- Domain Name
- Example: nod.powerdns.com

If a domain is specified, then each time a newly observed domain is
detected, the recursor will perform an A record lookup of "<newly
observed domain>.<lookup domain>". For example if 'new-domain-lookup'
is configured as 'nod.powerdns.com', and a new domain 'xyz123.tv' is
detected, then an A record lookup will be made for
'xyz123.tv.nod.powerdns.com'. This feature gives a way to share the
newly observed domain with partners, vendors or security teams. The
result of the DNS lookup will be ignored by the recursor.

.. _setting-new-domain-db-size:

``new-domain-db-size``
----------------------
.. versionadded:: 4.2.0

- Integer
- Example: 67108864

The default size of the stable bloom filter used to store previously
observed domains is 67108864. To change the number of cells, use this
setting. For each cell, the SBF uses 1 bit of memory, and one byte of
disk for the persistent file.
If there are already persistent files saved to disk, this setting will
have no effect unless you remove the existing files.

.. _setting-new-domain-history-dir:

``new-domain-history-dir``
--------------------------
.. versionadded:: 4.2.0

- Path

This setting controls which directory is used to store the on-disk
cache of previously observed domains.

The default depends on ``LOCALSTATEDIR`` when building the software.
Usually this comes down to ``/var/lib/pdns-recursor/nod`` or ``/usr/local/var/lib/pdns-recursor/nod``).

The newly observed domain feature uses a stable bloom filter to store
a history of previously observed domains. The data structure is
synchronized to disk every 10 minutes, and is also initialized from
disk on startup. This ensures that previously observed domains are
preserved across recursor restarts.
If you change the new-domain-db-size setting, you must remove any files
from this directory.

.. _setting-new-domain-whitelist:

``new-domain-whitelist``
------------------------
.. versionadded:: 4.2.0
.. deprecated:: 4.5.0
  Use :ref:`setting-new-domain-ignore-list`.

.. _setting-new-domain-ignore-list:

``new-domain-ignore-list``
--------------------------
.. versionadded:: 4.5.0

- List of Domain Names, comma separated
- Example: xyz.com, abc.com

This setting is a list of all domains (and implicitly all subdomains)
that will never be considered a new domain. For example, if the domain
'xyz123.tv' is in the list, then 'foo.bar.xyz123.tv' will never be
considered a new domain. One use-case for the ignore list is to never
reveal details of internal subdomains via the new-domain-lookup
feature.

.. _setting-new-domain-pb-tag:

``new-domain-pb-tag``
---------------------
.. versionadded:: 4.2.0

- String
- Default: pnds-nod

If protobuf is configured, then this tag will be added to all protobuf response messages when
a new domain is observed.

.. _setting-network-timeout:

``network-timeout``
-------------------
-  Integer
-  Default: 1500

Number of milliseconds to wait for a remote authoritative server to respond.

.. _setting-non-resolving-ns-max-fails:

``non-resolving-ns-max-fails``
------------------------------
.. versionadded:: 4.5.0

- Integer
- Default: 5

Number of failed address resolves of a nameserver name to start throttling it, 0 is disabled.
Nameservers matching :ref:`setting-dont-throttle-names` will not be throttled.


.. _setting-non-resolving-ns-throttle-time:

``non-resolving-ns-max-throttle-time``
--------------------------------------
.. versionadded:: 4.5.0

- Integer
- Default: 60

Number of seconds to throttle a nameserver with a name failing to resolve.

.. _setting-nothing-below-nxdomain:

``nothing-below-nxdomain``
--------------------------
.. versionadded:: 4.3.0

- One of ``no``, ``dnssec``, ``yes``, String
- Default: ``dnssec``

The type of :rfc:`8020` handling using cached NXDOMAIN responses.
This RFC specifies that NXDOMAIN means that the DNS tree under the denied name MUST be empty.
When an NXDOMAIN exists in the cache for a shorter name than the qname, no lookup is done and an NXDOMAIN is sent to the client.

For instance, when ``foo.example.net`` is negatively cached, any query
matching ``*.foo.example.net`` will be answered with NXDOMAIN directly
without consulting authoritative servers.

``no``
  No :rfc:`8020` processing is done.

``dnssec``
  :rfc:`8020` processing is only done using cached NXDOMAIN records that are
  DNSSEC validated.

``yes``
  :rfc:`8020` processing is done using any non-Bogus NXDOMAIN record
  available in the cache.

.. _setting-nsec3-max-iterations:

``nsec3-max-iterations``
------------------------
.. versionadded:: 4.1.0

-  Integer
-  Default: 150

Maximum number of iterations allowed for an NSEC3 record.
If an answer containing an NSEC3 record with more iterations is received, its DNSSEC validation status is treated as Insecure.

.. versionchanged:: 4.5.2

   Default is now 150, was 2500 before.

.. _setting-packetcache-ttl:

``packetcache-ttl``
-------------------
-  Integer
-  Default: 3600

Maximum number of seconds to cache an item in the packet cache, no matter what the original TTL specified.

.. _setting-packetcache-servfail-ttl:

``packetcache-servfail-ttl``
----------------------------
-  Integer
-  Default: 60

Maximum number of seconds to cache an answer indicating a failure to resolve in the packet cache.
Before version 4.6.0 only ``ServFail`` answers were considered as such. Starting with 4.6.0, all responses with a code other than ``NoError`` and ``NXDomain``, or without records in the answer and authority sections, are considered as a failure to resolve.

.. versionchanged:: 4.0.0

    This setting's maximum is capped to `packetcache-ttl`_.
    i.e. setting ``packetcache-ttl=15`` and keeping ``packetcache-servfail-ttl`` at the default will lower ``packetcache-servfail-ttl`` to ``15``.

.. _setting-pdns-distributes-queries:

``pdns-distributes-queries``
----------------------------
-  Boolean
-  Default: yes

If set, PowerDNS will use distinct threads to listen to client sockets and distribute that work to worker-threads using a hash of the query.
This feature should maximize the cache hit ratio.
To use more than one thread set `distributor-threads` in version 4.2.0 or newer.
Enabling should improve performance for medium sized resolvers.

.. _setting-protobuf-use-kernel-timestamp:

``protobuf-use-kernel-timestamp``
---------------------------------
.. versionadded:: 4.2.0

- Boolean
- Default: false

Whether to compute the latency of responses in protobuf messages using the timestamp set by the kernel when the query packet was received (when available), instead of computing it based on the moment we start processing the query.

.. _setting-proxy-protocol-from:

``proxy-protocol-from``
-----------------------
.. versionadded:: 4.4.0

-  IP addresses or netmasks, separated by commas
-  Default: empty

Ranges that are required to send a Proxy Protocol version 2 header in front of UDP and TCP queries, to pass the original source and destination addresses and ports to the recursor, as well as custom values.
Queries that are not prefixed with such a header will not be accepted from clients in these ranges. Queries prefixed by headers from clients that are not listed in these ranges will be dropped.

Note that once a Proxy Protocol header has been received, the source address from the proxy header instead of the address of the proxy will be checked against the `allow-from`_ ACL.

The dnsdist docs have `more information about the PROXY protocol <https://dnsdist.org/advanced/passing-source-address.html#proxy-protocol>`_.

.. _setting-proxy-protocol-maximum-size:

``proxy-protocol-maximum-size``
-------------------------------
.. versionadded:: 4.4.0

-  Integer
-  Default: 512

The maximum size, in bytes, of a Proxy Protocol payload (header, addresses and ports, and TLV values). Queries with a larger payload will be dropped.

.. _setting-public-suffix-list-file:

``public-suffix-list-file``
---------------------------
.. versionadded:: 4.2.0

- Path
- Default: unset

Path to the Public Suffix List file, if any. If set, PowerDNS will try to load the Public Suffix List from this file instead of using the built-in list. The PSL is used to group the queries by relevant domain names when displaying the top queries.

.. _setting-qname-minimization:

``qname-minimization``
----------------------
.. versionadded:: 4.3.0

-  Boolean
-  Default: yes

Enable Query Name Minimization. This implements a relaxed form of Query Name Mimimization as
described in :rfc:`7816`.

.. _setting-query-local-address:

``query-local-address``
-----------------------
.. versionchanged:: 4.4.0
  IPv6 addresses can be set with this option as well.

-  IP addresses, comma separated
-  Default: 0.0.0.0

Send out local queries from this address, or addresses. By adding multiple
addresses, increased spoofing resilience is achieved. When no address of a certain
address family is configured, there are *no* queries sent with that address family.
In the default configuration this means that IPv6 is not used for outgoing queries.

.. _setting-query-local-address6:

``query-local-address6``
------------------------
.. deprecated:: 4.4.0
  Use :ref:`setting-query-local-address` for IPv4 and IPv6.

.. deprecated:: 4.5.0
  Removed, use :ref:`setting-query-local-address`.

-  IPv6 addresses, comma separated
-  Default: unset

Send out local IPv6 queries from this address or addresses.
Disabled by default, which also disables outgoing IPv6 support.

.. _setting-quiet:

``quiet``
---------
-  Boolean
-  Default: yes

Don't log queries.

.. _setting-record-cache-shards:

``record-cache-shards``
------------------------
.. versionadded:: 4.4.0

-  Integer
-  Default: 1024

Sets the number of shards in the record cache. If you have high
contention as reported by
``record-cache-contented/record-cache-acquired``, you can try to
enlarge this value or run with fewer threads.

.. _setting-refresh-on-ttl-perc:

``refresh-on-ttl-perc``
-----------------------
.. versionadded:: 4.5.0

-  Integer
-  Default: 0

Sets the "refresh almost expired" percentage of the record cache. Whenever a record is fetched from the packet or record cache
and only ``refresh-on-ttl-perc`` percent or less of its original TTL is left, a task is queued to refetch the name/type combination to
update the record cache. In most cases this causes future queries to always see a non-expired record cache entry.
A typical value is 10. If the value is zero, this functionality is disabled.

.. _setting-reuseport:

``reuseport``
-------------
-  Boolean
-  Default: no

If ``SO_REUSEPORT`` support is available, allows multiple threads and processes to open listening sockets for the same port.

Since 4.1.0, when ``pdns-distributes-queries`` is set to false and ``reuseport`` is enabled, every worker-thread will open a separate listening socket to let the kernel distribute the incoming queries instead of running a distributor thread (which could otherwise be a bottleneck) and avoiding thundering herd issues, thus leading to much higher performance on multi-core boxes.

.. _setting-rng:

``rng``
-------

- String
- Default: auto

Specify which random number generator to use. Permissible choices are
 - auto - choose automatically
 - sodium - Use libsodium ``randombytes_uniform``
 - openssl - Use libcrypto ``RAND_bytes``
 - getrandom - Use libc getrandom, falls back to urandom if it does not really work
 - arc4random - Use BSD ``arc4random_uniform``
 - urandom - Use ``/dev/urandom``
 - kiss - Use simple settable deterministic RNG. **FOR TESTING PURPOSES ONLY!**

.. note::
  Not all choices are available on all systems.

.. _setting-root-nx-trust:

``root-nx-trust``
-----------------
-  Boolean
-  Default: yes

If set, an NXDOMAIN from the root-servers will serve as a blanket NXDOMAIN for the entire TLD the query belonged to.
The effect of this is far fewer queries to the root-servers.

.. versionchanged:: 4.0.0

    Default is 'yes' now, was 'no' before 4.0.0

.. _setting-security-poll-suffix:

``security-poll-suffix``
------------------------
-  String
-  Default: secpoll.powerdns.com.

Domain name from which to query security update notifications.
Setting this to an empty string disables secpoll.

.. _setting-serve-rfc1918:

``serve-rfc1918``
-----------------
-  Boolean
-  Default: yes

This makes the server authoritatively aware of: ``10.in-addr.arpa``, ``168.192.in-addr.arpa``, ``16-31.172.in-addr.arpa``, which saves load on the AS112 servers.
Individual parts of these zones can still be loaded or forwarded.

.. _setting-server-down-max-fails:

``server-down-max-fails``
-------------------------
-  Integer
-  Default: 64

If a server has not responded in any way this many times in a row, no longer send it any queries for `server-down-throttle-time`_ seconds.
Afterwards, we will try a new packet, and if that also gets no response at all, we again throttle for `server-down-throttle-time`_ seconds.
Even a single response packet will drop the block.

.. _setting-server-down-throttle-time:

``server-down-throttle-time``
-----------------------------
-  Integer
-  Default: 60

Throttle a server that has failed to respond `server-down-max-fails`_ times for this many seconds.

.. _setting-server-id:

``server-id``
-------------
-  String
-  Default: The hostname of the server

The reply given by The PowerDNS recursor to a query for 'id.server' with its hostname, useful for in clusters.
When a query contains the :rfc:`NSID EDNS0 Option <5001>`, this value is returned in the response as the NSID value.

This setting can be used to override the answer given to these queries.
Set to "disabled" to disable NSID and 'id.server' answers.

Query example (where 192.0.2.14 is your server):

.. code-block:: sh

    dig @192.0.2.14 CHAOS TXT id.server.
    dig @192.0.2.14 example.com IN A +nsid

``setgid``, ``setuid``
----------------------
-  String
-  Default: unset

PowerDNS can change its user and group id after binding to its socket.
Can be used for better :doc:`security <security>`.

.. _setting-signature-inception-skew:

``signature-inception-skew``
----------------------------------
.. versionadded:: 4.1.5

-  Integer
-  Default: 60

Allow the signature inception to be off by this number of seconds. Negative values are not allowed.

.. versionchanged:: 4.2.0

    Default is now 60, was 0 before.

.. _setting-single-socket:

``single-socket``
-----------------
-  Boolean
-  Default: no

Use only a single socket for outgoing queries.

.. _setting-snmp-agent:

``snmp-agent``
--------------
.. versionadded:: 4.1.0

-  Boolean
-  Default: no

If set to true and PowerDNS has been compiled with SNMP support, it will register as an SNMP agent to provide statistics and be able to send traps.

.. _setting-snmp-master-socket:

``snmp-master-socket``
----------------------

.. versionadded:: 4.1.0
.. deprecated:: 4.5.0
  Use :ref:`setting-snmp-daemon-socket`.

.. _setting-snmp-daemon-socket:

``snmp-daemon-socket``
----------------------
.. versionadded:: 4.5.0

-  String
-  Default: empty

If not empty and ``snmp-agent`` is set to true, indicates how PowerDNS should contact the SNMP daemon to register as an SNMP agent.

.. _setting-socket-dir:

``socket-dir``
--------------
-  Path

Where to store the control socket and pidfile.
The default depends on ``LOCALSTATEDIR`` or the ``--with-socketdir`` setting when building (usually ``/var/run`` or ``/run``).

When using `chroot`_ the default becomes to ``/``.

``socket-owner``, ``socket-group``, ``socket-mode``
---------------------------------------------------
Owner, group and mode of the controlsocket.
Owner and group can be specified by name, mode is in octal.

.. _setting-spoof-nearmiss-max:

``spoof-nearmiss-max``
----------------------
.. versionchanged:: 4.5.0
  Older versions used 20 as the default value.

-  Integer
-  Default: 1

If set to non-zero, PowerDNS will assume it is being spoofed after seeing this many answers with the wrong id.

.. _setting-stack-size:

``stack-size``
--------------
-  Integer
-  Default: 200000

Size of the stack of each mthread.

.. _setting-statistics-interval:

``statistics-interval``
-----------------------
.. versionadded:: 4.1.0

-  Integer
-  Default: 1800

Interval between logging statistical summary on recursor performance.
Use 0 to disable.

.. _setting-stats-api-blacklist:

``stats-api-blacklist``
-----------------------
.. versionadded:: 4.2.0
.. deprecated:: 4.5.0
  Use :ref:`setting-stats-api-disabled-list`.

.. _setting-stats-api-disabled-list:

``stats-api-disabled-list``
---------------------------
.. versionadded:: 4.5.0

-  String
-  Default: "cache-bytes, packetcache-bytes, special-memory-usage, ecs-v4-response-bits-*, ecs-v6-response-bits-*"

A list of comma-separated statistic names, that are disabled when retrieving the complete list of statistics via the API for performance reasons.
These statistics can still be retrieved individually by specifically asking for it.

.. _setting-stats-carbon-blacklist:

``stats-carbon-blacklist``
--------------------------
.. versionadded:: 4.2.0
.. deprecated:: 4.5.0
  Use :ref:`setting-stats-carbon-disabled-list`.

.. _setting-stats-carbon-disabled-list:

``stats-carbon-disabled-list``
------------------------------
.. versionadded:: 4.5.0

-  String
-  Default: "cache-bytes, packetcache-bytes, special-memory-usage, ecs-v4-response-bits-\*, ecs-v6-response-bits-\*, cumul-answers-\*, cumul-auth4answers-\*, cumul-auth6answers-\*"

A list of comma-separated statistic names, that are prevented from being exported via carbon for performance reasons.

.. _setting-stats-rec-control-blacklist:

``stats-rec-control-blacklist``
-------------------------------
.. versionadded:: 4.2.0
.. deprecated:: 4.5.0
  Use :ref:`setting-stats-rec-control-disabled-list`.

.. _setting-stats-rec-control-disabled-list:

``stats-rec-control-disabled-list``
------------------------------------
.. versionadded:: 4.5.0

-  String
-  Default: "cache-bytes, packetcache-bytes, special-memory-usage, ecs-v4-response-bits-\*, ecs-v6-response-bits-\*, cumul-answers-\*, cumul-auth4answers-\*, cumul-auth6answers-\*"

A list of comma-separated statistic names, that are disabled when retrieving the complete list of statistics via `rec_control get-all`, for performance reasons.
These statistics can still be retrieved individually.

.. _setting-stats-ringbuffer-entries:

``stats-ringbuffer-entries``
----------------------------
-  Integer
-  Default: 10000

Number of entries in the remotes ringbuffer, which keeps statistics on who is querying your server.
Can be read out using ``rec_control top-remotes``.

.. _setting-stats-snmp-blacklist:

``stats-snmp-blacklist``
------------------------
.. versionadded:: 4.2.0
.. deprecated:: 4.5.0
  Use :ref:`setting-stats-snmp-disabled-list`.

.. _setting-stats-snmp-disabled-list:

``stats-snmp-disabled-list``
----------------------------
.. versionadded:: 4.5.0

-  String
-  Default: "cache-bytes, packetcache-bytes, special-memory-usage, ecs-v4-response-bits-*, ecs-v6-response-bits-*"

A list of comma-separated statistic names, that are prevented from being exported via SNMP, for performance reasons.

.. _setting-structured-logging:

``structured-logging``
----------------------
.. versionadded:: 4.6.0

- Boolean
- Default: yes

Prefer structured logging when both an old style and a structured log messages is available.

.. _setting-tcp-fast-open:

``tcp-fast-open``
-----------------
.. versionadded:: 4.1.0

-  Integer
-  Default: 0 (Disabled)

Enable TCP Fast Open support, if available, on the listening sockets.
The numerical value supplied is used as the queue size, 0 meaning disabled. See :ref:`tcp-fast-open-support`.

.. _setting-tcp-fast-open-connect:

``tcp-fast-open-connect``
-------------------------
.. versionadded:: 4.5.0

-  Boolean
-  Default: no (disabled)

Enable TCP Fast Open Connect support, if available, on the outgoing connections to authoritative servers. See :ref:`tcp-fast-open-support`.

.. _setting-tcp-out-max-idle-ms:

``tcp-out-max-idle-ms``
-----------------------
.. versionadded:: 4.6.0

-  Integer
-  Default : 10000

Time outgoing TCP/DoT connections are left idle in milliseconds or 0 if no limit. After having been idle for this time, the connection is eligible for closing.

.. _setting-tcp-out-max-idle-per-auth:

``tcp-out-max-idle-per-auth``
-----------------------------
.. versionadded:: 4.6.0

-  Integer
-  Default : 10

Maximum number of idle outgoing TCP/DoT connections to a specific IP per thread, 0 means do not keep idle connections open.

.. _setting-tcp-out-max-queries:

``tcp-out-max-queries``
-----------------------
-  Integer
-  Default : 0

Maximum total number of queries per outgoing TCP/DoT connection, 0 means no limit. After this number of queries, the connection is
closed and a new one will be created if needed.

.. versionadded:: 4.6.0

.. _setting-tcp-out-max-idle-per-thread:

``tcp-out-max-idle-per-thread``
-------------------------------
.. versionadded:: 4.6.0

-  Integer
-  Default : 0

Maximum number of idle outgoing TCP/DoT connections per thread, 0 means do not keep idle connections open.

.. _setting-threads:

``threads``
-----------
-  Integer
-  Default: 2

Spawn this number of threads on startup.

.. _setting-trace:

``trace``
---------
-  String, one of ``no``, ``yes`` or ``fail``
-  Default: ``no``

If turned on, output impressive heaps of logging.
May destroy performance under load.
To log only queries resulting in a ``ServFail`` answer from the resolving process, this value can be set to ``fail``, but note that the performance impact is still large.
Also note that queries that do produce a result but with a failing DNSSEC validation are not written to the log

.. _setting-udp-source-port-min:

``udp-source-port-min``
-----------------------
.. versionadded:: 4.2.0

-  Integer
-  Default: 1024

This option sets the low limit of UDP port number to bind on.

In combination with `udp-source-port-max`_ it configures the UDP
port range to use. Port numbers are randomized within this range on
initialization, and exceptions can be configured with `udp-source-port-avoid`_

.. _setting-udp-source-port-max:

``udp-source-port-max``
-----------------------
.. versionadded:: 4.2.0

-  Integer
-  Default: 65535

This option sets the maximum limit of UDP port number to bind on.

See `udp-source-port-min`_.

.. _setting-udp-source-port-avoid:

``udp-source-port-avoid``
-------------------------
.. versionadded:: 4.2.0

-  String
-  Default: 11211

A list of comma-separated UDP port numbers to avoid when binding.
Ex: `5300,11211`

See `udp-source-port-min`_.

.. _setting-udp-truncation-threshold:

``udp-truncation-threshold``
----------------------------
.. versionchanged:: 4.2.0
  Before 4.2.0, the default was 1680

-  Integer
-  Default: 1232

EDNS0 allows for large UDP response datagrams, which can potentially raise performance.
Large responses however also have downsides in terms of reflection attacks.
This setting limits the accepted size.
Maximum value is 65535, but values above 4096 should probably not be attempted.

To know why 1232, see the note at :ref:`setting-edns-outgoing-bufsize`.

.. _setting-unique-response-tracking:

``unique-response-tracking``
----------------------------
.. versionadded:: 4.2.0

- Boolean
- Default: no (disabled)

Whether to track unique DNS responses, i.e. never seen before combinations
of the triplet (query name, query type, RR[rrname, rrtype, rrdata]).
This can be useful for tracking potentially suspicious domains and
behaviour, e.g. DNS fast-flux.
If protobuf is enabled and configured, then the Protobuf Response message
will contain a flag with udr set to true for each RR that is considered
unique, i.e. never seen before.
This feature uses a probabilistic data structure (stable bloom filter) to
track unique responses, which can have false positives as well as false
negatives, thus it is a best-effort feature. Increasing the number of cells
in the SBF using the unique-response-db-size setting can reduce FPs and FNs.

.. _setting-unique-response-log:

``unique-response-log``
-----------------------
.. versionadded:: 4.2.0

- Boolean
- Default: no (disabled)

Whether to log when a unique response is detected. The log line
looks something like:

Oct 24 12:11:27 Unique response observed: qname=foo.com qtype=A rrtype=AAAA rrname=foo.com rrcontent=1.2.3.4

.. _setting-unique-response-db-size:

``unique-response-db-size``
---------------------------
.. versionadded:: 4.2.0

- Integer
- Example: 67108864

The default size of the stable bloom filter used to store previously
observed responses is 67108864. To change the number of cells, use this
setting. For each cell, the SBF uses 1 bit of memory, and one byte of
disk for the persistent file.
If there are already persistent files saved to disk, this setting will
have no effect unless you remove the existing files.

.. _setting-unique-response-history-dir:

``unique-response-history-dir``
-------------------------------
.. versionadded:: 4.2.0

- Path

This setting controls which directory is used to store the on-disk
cache of previously observed responses.

The default depends on ``LOCALSTATEDIR`` when building the software.
Usually this comes down to ``/var/lib/pdns-recursor/udr`` or ``/usr/local/var/lib/pdns-recursor/udr``).

The newly observed domain feature uses a stable bloom filter to store
a history of previously observed responses. The data structure is
synchronized to disk every 10 minutes, and is also initialized from
disk on startup. This ensures that previously observed responses are
preserved across recursor restarts. If you change the
unique-response-db-size, you must remove any files from this directory.

.. _setting-unique-response-pb-tag:

``unique-response-pb-tag``
--------------------------
.. versionadded:: 4.2.0

- String
- Default: pnds-udr

If protobuf is configured, then this tag will be added to all protobuf response messages when
a unique DNS response is observed.

.. _setting-use-incoming-edns-subnet:

``use-incoming-edns-subnet``
----------------------------
-  Boolean
-  Default: no

Whether to process and pass along a received EDNS Client Subnet to authoritative servers.
The ECS information will only be sent for netmasks and domains listed in `edns-subnet-allow-list`_ and will be truncated if the received scope exceeds `ecs-ipv4-bits`_ for IPv4 or `ecs-ipv6-bits`_ for IPv6.

.. _setting-version:

``version``
-----------
Print version of this binary. Useful for checking which version of the PowerDNS recursor is installed on a system.

.. _setting-version-string:

``version-string``
------------------
-  String
-  Default: PowerDNS Recursor version number

By default, PowerDNS replies to the 'version.bind' query with its version number.
Security conscious users may wish to override the reply PowerDNS issues.

.. _setting-webserver:

``webserver``
-------------
-  Boolean
-  Default: no

Start the webserver (for REST API).

.. _setting-webserver-address:

``webserver-address``
---------------------
-  IP Address
-  Default: 127.0.0.1

IP address for the webserver to listen on.

.. _setting-webserver-allow-from:

``webserver-allow-from``
------------------------
-  IP addresses or netmasks, comma separated
-  Default: 127.0.0.1,::1

.. versionchanged:: 4.1.0

    Default is now 127.0.0.1,::1, was 0.0.0.0/0,::/0 before.

These IPs and subnets are allowed to access the webserver. Note that
specifying an IP address without a netmask uses an implicit netmask
of /32 or /128.

.. _setting-webserver-hash-plaintext-credentials:

``webserver-hash-plaintext-credentials``
----------------------------------------
..versionadded:: 4.6.0

-  Boolean
-  Default: no

Whether passwords and API keys supplied in the configuration as plaintext should be hashed during startup, to prevent the plaintext versions from staying in memory. Doing so increases significantly the cost of verifying credentials and is thus disabled by default.
Note that this option only applies to credentials stored in the configuration as plaintext, but hashed credentials are supported without enabling this option.

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

.. _setting-webserver-password:

``webserver-password``
----------------------
.. versionchanged:: 4.6.0
  This setting now accepts a hashed and salted version.

-  String
-  Default: unset

Password required to access the webserver. Since 4.6.0 the password can be hashed and salted using ``rec_control hash-password`` instead of being present in the configuration in plaintext, but the plaintext version is still supported.

.. _setting-webserver-port:

``webserver-port``
------------------
-  Integer
-  Default: 8082

TCP port where the webserver should listen on.

.. _setting-write-pid:

``write-pid``
-------------
-  Boolean
-  Default: yes

If a PID file should be written to `socket-dir`_

.. _setting-xpf-allow-from:

``xpf-allow-from``
------------------
.. versionadded:: 4.2.0
.. deprecated:: 4.7.0
   Removed, use the proxy-protocol instead

-  IP addresses or netmasks, separated by commas
-  Default: empty

.. note::
  This is an experimental implementation of `draft-bellis-dnsop-xpf <https://datatracker.ietf.org/doc/draft-bellis-dnsop-xpf/>`_.

The server will trust XPF records found in queries sent from those netmasks (both IPv4 and IPv6),
and will adjust queries' source and destination accordingly. This is especially useful when the recursor
is placed behind a proxy like `dnsdist <https://dnsdist.org>`_.
Note that the :ref:`setting-allow-from` setting is still applied to the original source address, and thus access restriction
should be done on the proxy.

.. _setting-xpf-rr-code:

``xpf-rr-code``
---------------
.. versionadded:: 4.2.0
.. deprecated:: 4.7.0
   Removed, use the proxy-protocol instead

-  Integer
-  Default: 0

.. note::
  This is an experimental implementation of `draft-bellis-dnsop-xpf <https://datatracker.ietf.org/doc/draft-bellis-dnsop-xpf/>`_.

This option sets the resource record code to use for XPF records, as long as an official code has not been assigned to it.
0 means that XPF is disabled.

.. _setting-x-dnssec-names:

``x-dnssec-names``
------------------
.. versionadded:: 4.5.0

-  Comma separated list of domain-names
-  Default: (empty)

List of names whose DNSSEC validation metrics will be counted in a separate set of metrics that start
with ``x-dnssec-result-``.
The names are suffix-matched.
This can be used to not count known failing (test) name validations in the ordinary DNSSEC metrics.
