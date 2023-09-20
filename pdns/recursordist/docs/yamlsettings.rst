.. THIS IS A GENERATED FILE. DO NOT EDIT. SOURCE: see settings dir
   START INCLUDE docs-new-preamble-in.rst

PowerDNS Recursor New Style (YAML) Settings
===========================================

Each setting can appear on the command line, prefixed by ``--`` and using the old style name, or in configuration files.
Settings on the command line are processed after the file-based settings are processed.

.. note::
   Starting with version 5.0.0., :program:`Recursor` supports a new YAML syntax for configuration files
   as described here.
   A configuration using the old style syntax can be converted to a YAML configuration using the instructions in :doc:`appendices/yamlconversion`.
   In a future release support for the "old-style" settings will be dropped.


YAML settings file
------------------
Please refer to e.g. `<https://docs.ansible.com/ansible/latest/reference_appendices/YAMLSyntax.html>`_
for a description of YAML syntax.

A :program:`Recursor` configuration file has several sections. For example, ``incoming`` for
settings related to receiving queries and ``dnssec`` for settings related to DNSSEC processing.

An example :program:`Recursor` YAML configuration file looks like:

.. code-block:: yaml

  dnssec:
    log_bogus: true
  incoming:
    listen:
      - 0.0.0.0:5301
      - '[::]:5301'
  recursor:
    extended_resolution_errors: true
    forward_zones:
      - zone: example.com
        forwarders:
          - 127.0.0.1:5301
  outgoing:
    query_local_address:
      - 0.0.0.0
      - '::'
  logging:
    loglevel: 6

Take care when listing IPv6 addresses, as characters used for these are special to YAML.
If in doubt, quote any string containing ``:``, ``[`` or ``]`` and use (online) tools to check your YAML syntax.
Specify an empty sequence using ``[]``.

The main setting file is called ``recursor.yml`` and will be processed first.
This settings file might refer to other files via the `recursor.include_dir`_ setting.
The next section will describe how settings specified in multiple files are merged.

Merging multiple setting files
------------------------------
If `recursor.include_dir`_ is set, all ``.yml`` files in it will be processed in alphabetical order, modifying the  settings processed so far.

For simple values like an boolean or number setting, a value in the processed file will overwrite an existing setting.

For values of type sequence, the new value will *replace* the existing value if the existing value is equal to the ``default`` or if the new value is marked with the ``!override`` tag.
Otherwise, the existing value will be *extended* with the new value by appending the new sequence to the existing.

For example, with the above example ``recursor.yml`` and an include directory containing a file ``extra.yml``:

.. code-block:: yaml

  dnssec:
    log_bogus: false
  recursor:
    forward_zones:
      - zone: example.net
        forwarders:
          - '::1'
  outgoing:
     query_local_address: !override
       - 0.0.0.0
     dont_query: []

After merging, ``dnssec.log_bogus`` will be ``false``, the sequence of ``recursor.forward_zones`` will contain 2 zones and the ``outgoing`` addresses used will contain one entry, as the ``extra.yml`` entry has overwritten the existing one.

``outgoing.dont-query`` has a non-empty sequence as default value. The main ``recursor.yml`` did not set it, so before processing ``extra.yml`` had the default value.
After processing ``extra.yml`` the value will be set to the empty sequence, as existing default values are overwritten by new values.

.. warning::
   The merging process does not process values deeper than the second level.
   For example if the main ``recursor.yml`` specified a forward zone

   .. code-block:: yaml

     forward_zones:
       - zone: example.net
         forwarders:
           - '::1'

   and another settings file contains

   .. code-block:: yaml

     forward_zones:
       - zone: example.net
         forwarders:
           - '::2'

   The result will *not* be a a single forward with two IP addresses, but two entries for ``example.net``.
   It depends on the specific setting how the sequence is processed further.
   In the future we might add a check for this case.

Socket Address
^^^^^^^^^^^^^^
A socket address is either an IP or and IP:port combination
For example:

.. code-block:: yaml

   some_key: 127.0.0.1
   another_key: '[::1]:8080'

Subnet
^^^^^^
A subnet is a single IP address or an IP address followed by a slash and a prefix length.
If no prefix length is specified, ``/32`` or ``/128`` is assumed, indicating a single IP address.
Subnets can also be prefixed with a ``!``, specifying negation.
This can be used to deny addresses from a previously allowed range.

For example, ``alow-from`` takes a sequence of subnets:

.. code-block:: yaml

   allow_from:
     - '2001:DB8::/32'
     - 128.66.0.0/16
     - !128.66.1.2

In this case the address ``128.66.1.2`` is excluded from the addresses allowed access.

Forward Zone
^^^^^^^^^^^^
A forward zone is defined as:

.. code-block:: yaml

  zone: zonename
  forwarders:
    - Socket Address
    - ...
  recurse: Boolean, default false
  allow_notify:  Boolean, default false

An example of a ``forward_zones`` entry, which consists of a sequence of forward zone entries:

.. code-block:: yaml

  - zone: example1.com
    forwarders:
      - 127.0.0.1
      - 127.0.0.1:5353
      - '[::1]53'
  - zone: example2.com
    forwarders:
      - '::1'
    recurse: true
    notify_allowed: true


Auth Zone
^^^^^^^^^
A auth zone is defined as:

.. code-block:: yaml

  zone: name
  file: filename

An example of a ``auth_zones`` entry, consisting of a sequence of auth zones:

.. code-block:: yaml

   auth_zones:
     - zone: example.com
       file: zones/example.com.zone
     - zone: example.net
       file: zones/example.net.zone

The YAML settings
-----------------

.. END INCLUDE docs-new-preamble-in.rst

.. _setting-yaml-carbon.instance:

``carbon.instance``
^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.2.0

-  String
-  Default: ``recursor``

- Old style setting: :ref:`setting-carbon-instance`

Change the instance or third string of the metric key. The default is recursor.

.. _setting-yaml-carbon.interval:

``carbon.interval``
^^^^^^^^^^^^^^^^^^^

-  Integer
-  Default: ``30``

- Old style setting: :ref:`setting-carbon-interval`

If sending carbon updates, this is the interval between them in seconds.
See :doc:`metrics`.

.. _setting-yaml-carbon.ns:

``carbon.ns``
^^^^^^^^^^^^^
.. versionadded:: 4.2.0

-  String
-  Default: ``pdns``

- Old style setting: :ref:`setting-carbon-namespace`

Change the namespace or first string of the metric key. The default is pdns.

.. _setting-yaml-carbon.ourname:

``carbon.ourname``
^^^^^^^^^^^^^^^^^^

-  String
-  Default: (empty)

- Old style setting: :ref:`setting-carbon-ourname`

If sending carbon updates, if set, this will override our hostname.
Be careful not to include any dots in this setting, unless you know what you are doing.
See :ref:`metricscarbon`.

.. _setting-yaml-carbon.server:

``carbon.server``
^^^^^^^^^^^^^^^^^

-  Sequence of `Socket Address`_ (IP or IP:port combinations)
-  Default: ``[]``

- Old style setting: :ref:`setting-carbon-server`

Will send all available metrics to these servers via the carbon protocol, which is used by graphite and metronome.
See :doc:`metrics`.

.. _setting-yaml-dnssec.aggressive_cache_min_nsec3_hit_ratio:

``dnssec.aggressive_cache_min_nsec3_hit_ratio``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.9.0

-  Integer
-  Default: ``2000``

- Old style setting: :ref:`setting-aggressive-cache-min-nsec3-hit-ratio`

The limit for which to put NSEC3 records into the aggressive cache.
A value of ``n`` means that an NSEC3 record is only put into the aggressive cache if the estimated probability of a random name hitting the NSEC3 record is higher than ``1/n``.
A higher ``n`` will cause more records to be put into the aggressive cache, e.g. a value of 4000 will cause records to be put in the aggressive cache even if the estimated probability of hitting them is twice as low as would be the case for ``n=2000``.
A value of 0 means no NSEC3 records will be put into the aggressive cache.

For large zones the effectiveness of the NSEC3 cache is reduced since each NSEC3 record only covers a randomly distributed subset of all possible names.
This setting avoids doing unnecessary work for such large zones.

.. _setting-yaml-dnssec.aggressive_nsec_cache_size:

``dnssec.aggressive_nsec_cache_size``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.5.0

-  Integer
-  Default: ``100000``

- Old style setting: :ref:`setting-aggressive-nsec-cache-size`

The number of records to cache in the aggressive cache. If set to a value greater than 0, the recursor will cache NSEC and NSEC3 records to generate negative answers, as defined in :rfc:`8198`.
To use this, DNSSEC processing or validation must be enabled by setting :ref:`setting-yaml-dnssec.validation` to ``process``, ``log-fail`` or ``validate``.

.. _setting-yaml-dnssec.disabled_algorithms:

``dnssec.disabled_algorithms``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.9.0

-  Sequence of strings
-  Default: ``[]``

- Old style setting: :ref:`setting-dnssec-disabled-algorithms`

A list of DNSSEC algorithm numbers that should be considered disabled.
These algorithms will not be used to validate DNSSEC signatures.
Zones (only) signed with these algorithms will be considered ``Insecure``.

If this setting is empty (the default), :program:`Recursor` will determine which algorithms to disable automatically.
This is done for specific algorithms only, currently algorithms 5 (``RSASHA1``) and 7 (``RSASHA1NSEC3SHA1``).

This is important on systems that have a default strict crypto policy, like RHEL9 derived systems.
On such systems not disabling some algorithms (or changing the security policy) will make affected zones to be considered ``Bogus`` as using these algorithms fails.

.. _setting-yaml-dnssec.log_bogus:

``dnssec.log_bogus``
^^^^^^^^^^^^^^^^^^^^

-  Boolean
-  Default: ``false``

- Old style setting: :ref:`setting-dnssec-log-bogus`

Log every DNSSEC validation failure.
**Note**: This is not logged per-query but every time records are validated as Bogus.

.. _setting-yaml-dnssec.nsec3_max_iterations:

``dnssec.nsec3_max_iterations``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.1.0
.. versionchanged:: 4.5.2

  Default is now 150, was 2500 before.

-  Integer
-  Default: ``150``

- Old style setting: :ref:`setting-nsec3-max-iterations`

Maximum number of iterations allowed for an NSEC3 record.
If an answer containing an NSEC3 record with more iterations is received, its DNSSEC validation status is treated as Insecure.

.. _setting-yaml-dnssec.signature_inception_skew:

``dnssec.signature_inception_skew``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.1.5
.. versionchanged:: 4.2.0

  Default is now 60, was 0 before.

-  Integer
-  Default: ``60``

- Old style setting: :ref:`setting-signature-inception-skew`

Allow the signature inception to be off by this number of seconds. Negative values are not allowed.

.. _setting-yaml-dnssec.validation:

``dnssec.validation``
^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.0.0
.. versionchanged:: 4.5.0

  The default changed from ``process-no-validate`` to ``process``

-  String
-  Default: ``process``

- Old style setting: :ref:`setting-dnssec`

One of ``off``, ``process-no-validate``, ``process``, ``log-fail``, ``validate``

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

.. _setting-yaml-dnssec.x_dnssec_names:

``dnssec.x_dnssec_names``
^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.5.0

-  Sequence of strings
-  Default: ``[]``

- Old style setting: :ref:`setting-x-dnssec-names`

List of names whose DNSSEC validation metrics will be counted in a separate set of metrics that start
with ``x-dnssec-result-``.
The names are suffix-matched.
This can be used to not count known failing (test) name validations in the ordinary DNSSEC metrics.

.. _setting-yaml-ecs.add_for:

``ecs.add_for``
^^^^^^^^^^^^^^^
.. versionadded:: 4.2.0

-  Sequence of `Subnet`_ (IP addresses or subnets, negation supported)
-  Default: ``[0.0.0.0/0, ::/0, !127.0.0.0/8, !10.0.0.0/8, !100.64.0.0/10, !169.254.0.0/16, !192.168.0.0/16, !172.16.0.0/12, !::1/128, !fc00::/7, !fe80::/10]``

- Old style setting: :ref:`setting-ecs-add-for`

List of requestor netmasks for which the requestor IP Address should be used as the :rfc:`EDNS Client Subnet <7871>` for outgoing queries. Outgoing queries for requestors that do not match this list will use the :ref:`setting-yaml-ecs.scope_zero_address` instead.
Valid incoming ECS values from :ref:`setting-yaml-incoming.use_incoming_edns_subnet` are not replaced.

Regardless of the value of this setting, ECS values are only sent for outgoing queries matching the conditions in the :ref:`setting-yaml-outgoing.edns_subnet_allow_list` setting. This setting only controls the actual value being sent.

This defaults to not using the requestor address inside RFC1918 and similar 'private' IP address spaces.

.. _setting-yaml-ecs.cache_limit_ttl:

``ecs.cache_limit_ttl``
^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.1.12

-  Integer
-  Default: ``0``

- Old style setting: :ref:`setting-ecs-cache-limit-ttl`

The minimum TTL for an ECS-specific answer to be inserted into the query cache. This condition applies in conjunction with ``ecs-ipv4-cache-bits`` or ``ecs-ipv6-cache-bits``.
That is, only if both the limits apply, the record will not be cached. This decision can be overridden by ``ecs-ipv4-never-cache`` and ``ecs-ipv6-never-cache``.

.. _setting-yaml-ecs.ipv4_bits:

``ecs.ipv4_bits``
^^^^^^^^^^^^^^^^^
.. versionadded:: 4.1.0

-  Integer
-  Default: ``24``

- Old style setting: :ref:`setting-ecs-ipv4-bits`

Number of bits of client IPv4 address to pass when sending EDNS Client Subnet address information.

.. _setting-yaml-ecs.ipv4_cache_bits:

``ecs.ipv4_cache_bits``
^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.1.12

-  Integer
-  Default: ``24``

- Old style setting: :ref:`setting-ecs-ipv4-cache-bits`

Maximum number of bits of client IPv4 address used by the authoritative server (as indicated by the EDNS Client Subnet scope in the answer) for an answer to be inserted into the query cache. This condition applies in conjunction with ``ecs-cache-limit-ttl``.
That is, only if both the limits apply, the record will not be cached. This decision can be overridden by ``ecs-ipv4-never-cache`` and ``ecs-ipv6-never-cache``.

.. _setting-yaml-ecs.ipv4_never_cache:

``ecs.ipv4_never_cache``
^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.5.0

-  Boolean
-  Default: ``false``

- Old style setting: :ref:`setting-ecs-ipv4-never-cache`

When set, never cache replies carrying EDNS IPv4 Client Subnet scope in the record cache.
In this case the decision made by ```ecs-ipv4-cache-bits`` and ``ecs-cache-limit-ttl`` is no longer relevant.

.. _setting-yaml-ecs.ipv6_bits:

``ecs.ipv6_bits``
^^^^^^^^^^^^^^^^^
.. versionadded:: 4.1.0

-  Integer
-  Default: ``56``

- Old style setting: :ref:`setting-ecs-ipv6-bits`

Number of bits of client IPv6 address to pass when sending EDNS Client Subnet address information.

.. _setting-yaml-ecs.ipv6_cache_bits:

``ecs.ipv6_cache_bits``
^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.1.12

-  Integer
-  Default: ``56``

- Old style setting: :ref:`setting-ecs-ipv6-cache-bits`

Maximum number of bits of client IPv6 address used by the authoritative server (as indicated by the EDNS Client Subnet scope in the answer) for an answer to be inserted into the query cache. This condition applies in conjunction with ``ecs-cache-limit-ttl``.
That is, only if both the limits apply, the record will not be cached. This decision can be overridden by ``ecs-ipv4-never-cache`` and ``ecs-ipv6-never-cache``.

.. _setting-yaml-ecs.ipv6_never_cache:

``ecs.ipv6_never_cache``
^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.5.0

-  Boolean
-  Default: ``false``

- Old style setting: :ref:`setting-ecs-ipv6-never-cache`

When set, never cache replies carrying EDNS IPv6 Client Subnet scope in the record cache.
In this case the decision made by ```ecs-ipv6-cache-bits`` and ``ecs-cache-limit-ttl`` is no longer relevant.

.. _setting-yaml-ecs.minimum_ttl_override:

``ecs.minimum_ttl_override``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionchanged:: 4.5.0

  Old versions used default 0.

-  Integer
-  Default: ``1``

- Old style setting: :ref:`setting-ecs-minimum-ttl-override`

This setting artificially raises the TTLs of records in the ANSWER section of ECS-specific answers to be at least this long.
Setting this to a value greater than 1 technically is an RFC violation, but might improve performance a lot.
Using a value of 0 impacts performance of TTL 0 records greatly, since it forces the recursor to contact
authoritative servers every time a client requests them.
Can be set at runtime using ``rec_control set-ecs-minimum-ttl 3600``.

.. _setting-yaml-ecs.scope_zero_address:

``ecs.scope_zero_address``
^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.1.0

-  String
-  Default: (empty)

- Old style setting: :ref:`setting-ecs-scope-zero-address`

The IP address sent via EDNS Client Subnet to authoritative servers listed in
:ref:`setting-yaml-outgoing.edns_subnet_allow_list` when :ref:`setting-yaml-incoming.use_incoming_edns_subnet` is set and the query has
an ECS source prefix-length set to 0.
The default is to look for the first usable (not an ``any`` one) address in
:ref:`setting-yaml-outgoing.source_address` (starting with IPv4). If no suitable address is
found, the recursor fallbacks to sending 127.0.0.1.

.. _setting-yaml-incoming.allow_from:

``incoming.allow_from``
^^^^^^^^^^^^^^^^^^^^^^^

-  Sequence of `Subnet`_ (IP addresses or subnets, negation supported)
-  Default: ``[127.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 192.168.0.0/16, 172.16.0.0/12, ::1/128, fc00::/7, fe80::/10]``

- Old style setting: :ref:`setting-allow-from`

Netmasks (both IPv4 and IPv6) that are allowed to use the server.
The default allows access only from :rfc:`1918` private IP addresses.
An empty value means no checking is done, all clients are allowed.
Due to the aggressive nature of the internet these days, it is highly recommended to not open up the recursor for the entire internet.
Questions from IP addresses not listed here are ignored and do not get an answer.

When the Proxy Protocol is enabled (see :ref:`setting-yaml-incoming.proxy_protocol_from`), the recursor will check the address of the client IP advertised in the Proxy Protocol header instead of the one of the proxy.

Note that specifying an IP address without a netmask uses an implicit netmask of /32 or /128.

.. _setting-yaml-incoming.allow_from_file:

``incoming.allow_from_file``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  String
-  Default: (empty)

- Old style setting: :ref:`setting-allow-from-file`

Like :ref:`setting-yaml-incoming.allow_from`, except reading a sequence of `Subnet`_ from file.
Overrides the :ref:`setting-yaml-incoming.allow_from` setting. Example content of th specified file:

.. code-block:: yaml

 - 127.0.01
 - ::1

.. _setting-yaml-incoming.allow_notify_for:

``incoming.allow_notify_for``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.6.0

-  Sequence of strings
-  Default: ``[]``

- Old style setting: :ref:`setting-allow-notify-for`

Domain names specified in this list are used to permit incoming
NOTIFY operations to wipe any cache entries that match the domain
name. If this list is empty, all NOTIFY operations will be ignored.

.. _setting-yaml-incoming.allow_notify_for_file:

``incoming.allow_notify_for_file``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.6.0

-  String
-  Default: (empty)

- Old style setting: :ref:`setting-allow-notify-for-file`

Like :ref:`setting-yaml-incoming.allow_notify_for`, except reading a sequence of names from file. Example contents of specified file:

.. code-block:: yaml

 - example.com
 - example.org

.. _setting-yaml-incoming.allow_notify_from:

``incoming.allow_notify_from``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.6.0

-  Sequence of `Subnet`_ (IP addresses or subnets, negation supported)
-  Default: ``[]``

- Old style setting: :ref:`setting-allow-notify-from`

Subnets (both IPv4 and IPv6) that are allowed to issue NOTIFY operations
to the server.  NOTIFY operations from IP addresses not listed here are
ignored and do not get an answer.

When the Proxy Protocol is enabled (see :ref:`setting-yaml-incoming.proxy_protocol_from`), the
recursor will check the address of the client IP advertised in the
Proxy Protocol header instead of the one of the proxy.

Note that specifying an IP address without a netmask uses an implicit
netmask of /32 or /128.

NOTIFY operations received from a client listed in one of these netmasks
will be accepted and used to wipe any cache entries whose zones match
the zone specified in the NOTIFY operation, but only if that zone (or
one of its parents) is included in :ref:`setting-yaml-incoming.allow_notify_for`,
:ref:`setting-yaml-incoming.allow_notify_for_file`, or :ref:`setting-yaml-recursor.forward_zones_file` with a ``allow_notify`` set to ``true``.

.. _setting-yaml-incoming.allow_notify_from_file:

``incoming.allow_notify_from_file``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.6.0

-  String
-  Default: (empty)

- Old style setting: :ref:`setting-allow-notify-from-file`

Like :ref:`setting-yaml-incoming.allow_notify_from`, except reading a sequence of `Subnet`_ from file.

.. _setting-yaml-incoming.distribution_load_factor:

``incoming.distribution_load_factor``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.1.12

-  Double
-  Default: ``0.0``

- Old style setting: :ref:`setting-distribution-load-factor`

If :ref:`setting-yaml-incoming.pdns_distributes_queries` is set and this setting is set to another value
than 0, the distributor thread will use a bounded load-balancing algorithm while
distributing queries to worker threads, making sure that no thread is assigned
more queries than distribution-load-factor times the average number of queries
currently processed by all the workers.
For example, with a value of 1.25, no server should get more than 125 % of the
average load. This helps making sure that all the workers have roughly the same
share of queries, even if the incoming traffic is very skewed, with a larger
number of requests asking for the same qname.

.. _setting-yaml-incoming.distribution_pipe_buffer_size:

``incoming.distribution_pipe_buffer_size``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.2.0

-  Integer
-  Default: ``0``

- Old style setting: :ref:`setting-distribution-pipe-buffer-size`

Size in bytes of the internal buffer of the pipe used by the distributor to pass incoming queries to a worker thread.
Requires support for `F_SETPIPE_SZ` which is present in Linux since 2.6.35. The actual size might be rounded up to
a multiple of a page size. 0 means that the OS default size is used.
A large buffer might allow the recursor to deal with very short-lived load spikes during which a worker thread gets
overloaded, but it will be at the cost of an increased latency.

.. _setting-yaml-incoming.distributor_threads:

``incoming.distributor_threads``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.2.0

-  Integer
-  Default: 1 if :ref:`setting-pdns-distributes-queries` is set, 0 otherwise

- Old style setting: :ref:`setting-distributor-threads`

If :ref:`setting-yaml-incoming.pdns_distributes_queries` is set, spawn this number of distributor threads on startup. Distributor threads
handle incoming queries and distribute them to other threads based on a hash of the query.

.. _setting-yaml-incoming.edns_padding_from:

``incoming.edns_padding_from``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.5.0

-  String
-  Default: (empty)

- Old style setting: :ref:`setting-edns-padding-from`

List of netmasks (proxy IP in case of proxy-protocol presence, client IP otherwise) for which EDNS padding will be enabled in responses, provided that :ref:`setting-yaml-incoming.edns_padding_mode` applies.

.. _setting-yaml-incoming.edns_padding_mode:

``incoming.edns_padding_mode``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.5.0

-  String
-  Default: ``padded-queries-only``

- Old style setting: :ref:`setting-edns-padding-mode`

One of ``always``, ``padded-queries-only``.
Whether to add EDNS padding to all responses (``always``) or only to responses for queries containing the EDNS padding option (``padded-queries-only``, the default).
In both modes, padding will only be added to responses for queries coming from :ref:`setting-yaml-incoming.edns_padding_from` sources.

.. _setting-yaml-incoming.edns_padding_tag:

``incoming.edns_padding_tag``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.5.0

-  Integer
-  Default: ``7830``

- Old style setting: :ref:`setting-edns-padding-tag`

The packetcache tag to use for padded responses, to prevent a client not allowed by the :ref::`setting-edns-padding-from` list to be served a cached answer generated for an allowed one. This
effectively divides the packet cache in two when :ref:`setting-yaml-incoming.edns_padding_from` is used. Note that this will not override a tag set from one of the ``Lua`` hooks.

.. _setting-yaml-incoming.gettag_needs_edns_options:

``incoming.gettag_needs_edns_options``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.1.0

-  Boolean
-  Default: ``false``

- Old style setting: :ref:`setting-gettag-needs-edns-options`

If set, EDNS options in incoming queries are extracted and passed to the :func:`gettag` hook in the ``ednsoptions`` table.

.. _setting-yaml-incoming.listen:

``incoming.listen``
^^^^^^^^^^^^^^^^^^^

-  Sequence of `Socket Address`_ (IP or IP:port combinations)
-  Default: ``[127.0.0.1]``

- Old style setting: :ref:`setting-local-address`

Local IP addresses to which we bind. Each address specified can
include a port number; if no port is included then the
:ref:`setting-yaml-incoming.port` port will be used for that address. If a
port number is specified, it must be separated from the address with a
':'; for an IPv6 address the address must be enclosed in square
brackets.

Examples::

  local-address=127.0.0.1 ::1
  local-address=0.0.0.0:5353
  local-address=[::]:8053
  local-address=127.0.0.1:53, [::1]:5353

.. _setting-yaml-incoming.max_concurrent_requests_per_tcp_connection:

``incoming.max_concurrent_requests_per_tcp_connection``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.3.0

-  Integer
-  Default: ``10``

- Old style setting: :ref:`setting-max-concurrent-requests-per-tcp-connection`

Maximum number of incoming requests handled concurrently per tcp
connection. This number must be larger than 0 and smaller than 65536
and also smaller than `max-mthreads`.

.. _setting-yaml-incoming.max_tcp_clients:

``incoming.max_tcp_clients``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  Integer
-  Default: ``128``

- Old style setting: :ref:`setting-max-tcp-clients`

Maximum number of simultaneous incoming TCP connections allowed.

.. _setting-yaml-incoming.max_tcp_per_client:

``incoming.max_tcp_per_client``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  Integer
-  Default: ``0``

- Old style setting: :ref:`setting-max-tcp-per-client`

Maximum number of simultaneous incoming TCP connections allowed per client (remote IP address).
 0 means unlimited.

.. _setting-yaml-incoming.max_tcp_queries_per_connection:

``incoming.max_tcp_queries_per_connection``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.1.0

-  Integer
-  Default: ``0``

- Old style setting: :ref:`setting-max-tcp-queries-per-connection`

Maximum number of DNS queries in a TCP connection.
0 means unlimited.

.. _setting-yaml-incoming.max_udp_queries_per_round:

``incoming.max_udp_queries_per_round``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.1.4

-  Integer
-  Default: ``10000``

- Old style setting: :ref:`setting-max-udp-queries-per-round`

Under heavy load the recursor might be busy processing incoming UDP queries for a long while before there is no more of these, and might therefore
neglect scheduling new ``mthreads``, handling responses from authoritative servers or responding to :doc:`rec_control <manpages/rec_control.1>`
requests.
This setting caps the maximum number of incoming UDP DNS queries processed in a single round of looping on ``recvmsg()`` after being woken up by the multiplexer, before
returning back to normal processing and handling other events.

.. _setting-yaml-incoming.non_local_bind:

``incoming.non_local_bind``
^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  Boolean
-  Default: ``false``

- Old style setting: :ref:`setting-non-local-bind`

Bind to addresses even if one or more of the :ref:`setting-yaml-incoming.listen`'s do not exist on this server.
Setting this option will enable the needed socket options to allow binding to non-local addresses.
This feature is intended to facilitate ip-failover setups, but it may also mask configuration issues and for this reason it is disabled by default.

.. _setting-yaml-incoming.pdns_distributes_queries:

``incoming.pdns_distributes_queries``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionchanged:: 4.9.0

  Default changed to ``no``, previously it was ``yes``.

-  Boolean
-  Default: ``false``

- Old style setting: :ref:`setting-pdns-distributes-queries`

If set, PowerDNS will use distinct threads to listen to client sockets and distribute that work to worker-threads using a hash of the query.
This feature should maximize the cache hit ratio on versions before 4.9.0.
To use more than one thread set :ref:`setting-yaml-incoming.distributor_threads` in version 4.2.0 or newer.
Enabling should improve performance on systems where :ref:`setting-yaml-incoming.reuseport` does not have the effect of
balancing the queries evenly over multiple worker threads.

.. _setting-yaml-incoming.port:

``incoming.port``
^^^^^^^^^^^^^^^^^

-  Integer
-  Default: ``53``

- Old style setting: :ref:`setting-local-port`

Local port to bind to.
If an address in :ref:`setting-yaml-incoming.listen` does not have an explicit port, this port is used.

.. _setting-yaml-incoming.proxy_protocol_from:

``incoming.proxy_protocol_from``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.4.0

-  String
-  Default: (empty)

- Old style setting: :ref:`setting-proxy-protocol-from`

Ranges that are required to send a Proxy Protocol version 2 header in front of UDP and TCP queries, to pass the original source and destination addresses and ports to the recursor, as well as custom values.
Queries that are not prefixed with such a header will not be accepted from clients in these ranges. Queries prefixed by headers from clients that are not listed in these ranges will be dropped.

Note that once a Proxy Protocol header has been received, the source address from the proxy header instead of the address of the proxy will be checked against the :ref:`setting-yaml-incoming.allow_from` ACL.

The dnsdist docs have `more information about the PROXY protocol <https://dnsdist.org/advanced/passing-source-address.html#proxy-protocol>`_.

.. _setting-yaml-incoming.proxy_protocol_maximum_size:

``incoming.proxy_protocol_maximum_size``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.4.0

-  Integer
-  Default: ``512``

- Old style setting: :ref:`setting-proxy-protocol-maximum-size`

The maximum size, in bytes, of a Proxy Protocol payload (header, addresses and ports, and TLV values). Queries with a larger payload will be dropped.

.. _setting-yaml-incoming.reuseport:

``incoming.reuseport``
^^^^^^^^^^^^^^^^^^^^^^
.. versionchanged:: 4.9.0

  The default is changed to ``yes``, previously it was ``no``. If ``SO_REUSEPORT`` support is not available, the setting defaults to ``no``.

-  Boolean
-  Default: ``true``

- Old style setting: :ref:`setting-reuseport`

If ``SO_REUSEPORT`` support is available, allows multiple threads and processes to open listening sockets for the same port.

Since 4.1.0, when :ref:`setting-yaml-incoming.pdns_distributes_queries` is disabled and :ref:`setting-yaml-incoming.reuseport` is enabled, every worker-thread will open a separate listening socket to let the kernel distribute the incoming queries instead of running a distributor thread (which could otherwise be a bottleneck) and avoiding thundering herd issues, thus leading to much higher performance on multi-core boxes.

.. _setting-yaml-incoming.tcp_fast_open:

``incoming.tcp_fast_open``
^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.1.0

-  Integer
-  Default: ``0``

- Old style setting: :ref:`setting-tcp-fast-open`

Enable TCP Fast Open support, if available, on the listening sockets.
The numerical value supplied is used as the queue size, 0 meaning disabled. See :ref:`tcp-fast-open-support`.

.. _setting-yaml-incoming.tcp_timeout:

``incoming.tcp_timeout``
^^^^^^^^^^^^^^^^^^^^^^^^

-  Integer
-  Default: ``2``

- Old style setting: :ref:`setting-client-tcp-timeout`

Time to wait for data from TCP clients.

.. _setting-yaml-incoming.udp_truncation_threshold:

``incoming.udp_truncation_threshold``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionchanged:: 4.2.0

  Before 4.2.0, the default was 1680.

-  Integer
-  Default: ``1232``

- Old style setting: :ref:`setting-udp-truncation-threshold`

EDNS0 allows for large UDP response datagrams, which can potentially raise performance.
Large responses however also have downsides in terms of reflection attacks.
This setting limits the accepted size.
Maximum value is 65535, but values above 4096 should probably not be attempted.

To know why 1232, see the note at :ref:`setting-yaml-outgoing.edns_bufsize`.

.. _setting-yaml-incoming.use_incoming_edns_subnet:

``incoming.use_incoming_edns_subnet``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  Boolean
-  Default: ``false``

- Old style setting: :ref:`setting-use-incoming-edns-subnet`

Whether to process and pass along a received EDNS Client Subnet to authoritative servers.
The ECS information will only be sent for netmasks and domains listed in :ref:`setting-yaml-outgoing.edns_subnet_allow_list` and will be truncated if the received scope exceeds :ref:`setting-yaml-ecs.ipv4_bits` for IPv4 or :ref:`setting-yaml-ecs.ipv6_bits` for IPv6.

.. _setting-yaml-logging.common_errors:

``logging.common_errors``
^^^^^^^^^^^^^^^^^^^^^^^^^

-  Boolean
-  Default: ``false``

- Old style setting: :ref:`setting-log-common-errors`

Some DNS errors occur rather frequently and are no cause for alarm.

.. _setting-yaml-logging.disable_syslog:

``logging.disable_syslog``
^^^^^^^^^^^^^^^^^^^^^^^^^^

-  Boolean
-  Default: ``false``

- Old style setting: :ref:`setting-disable-syslog`

Do not log to syslog, only to stdout.
Use this setting when running inside a supervisor that handles logging (like systemd).
**Note**: do not use this setting in combination with :ref:`setting-yaml-recursor.daemon` as all logging will disappear.

.. _setting-yaml-logging.facility:

``logging.facility``
^^^^^^^^^^^^^^^^^^^^

-  String
-  Default: (empty)

- Old style setting: :ref:`setting-logging-facility`

If set to a digit, logging is performed under this LOCAL facility.
See :ref:`logging`.
Do not pass names like 'local0'!

.. _setting-yaml-logging.loglevel:

``logging.loglevel``
^^^^^^^^^^^^^^^^^^^^
.. versionchanged:: 5.0.0

  Previous version would not allow setting a level below ``3 (error)``.

-  Integer
-  Default: ``6``

- Old style setting: :ref:`setting-loglevel`

Amount of logging. The higher the number, the more lines logged.
Corresponds to ``syslog`` level values (e.g. 0 = ``emergency``, 1 = ``alert``, 2 = ``critical``, 3 = ``error``, 4 = ``warning``, 5 = ``notice``, 6 = ``info``, 7 = ``debug``).
Each level includes itself plus the lower levels before it.
Not recommended to set this below 3.
If :ref:`setting-yaml-logging.quiet` is ``no/false``, :ref:`setting-yaml-logging.loglevel` will be minimally set to ``6 (info)``.

.. _setting-yaml-logging.protobuf_use_kernel_timestamp:

``logging.protobuf_use_kernel_timestamp``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.2.0

-  Boolean
-  Default: ``false``

- Old style setting: :ref:`setting-protobuf-use-kernel-timestamp`

Whether to compute the latency of responses in protobuf messages using the timestamp set by the kernel when the query packet was received (when available), instead of computing it based on the moment we start processing the query.

.. _setting-yaml-logging.quiet:

``logging.quiet``
^^^^^^^^^^^^^^^^^

-  Boolean
-  Default: ``true``

- Old style setting: :ref:`setting-quiet`

Don't log queries.

.. _setting-yaml-logging.rpz_changes:

``logging.rpz_changes``
^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.1.0

-  Boolean
-  Default: ``false``

- Old style setting: :ref:`setting-log-rpz-changes`

Log additions and removals to RPZ zones at Info (6) level instead of Debug (7).

.. _setting-yaml-logging.statistics_interval:

``logging.statistics_interval``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.1.0

-  Integer
-  Default: ``1800``

- Old style setting: :ref:`setting-statistics-interval`

Interval between logging statistical summary on recursor performance.
Use 0 to disable.

.. _setting-yaml-logging.structured_logging:

``logging.structured_logging``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.6.0

-  Boolean
-  Default: ``true``

- Old style setting: :ref:`setting-structured-logging`

Prefer structured logging when both an old style and a structured log messages is available.

.. _setting-yaml-logging.structured_logging_backend:

``logging.structured_logging_backend``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.8.0

-  String
-  Default: ``default``

- Old style setting: :ref:`setting-structured-logging-backend`

The backend used for structured logging output.
This setting must be set on the command line (``--structured-logging-backend=...``) to be effective.
Available backends are:

- ``default``: use the traditional logging system to output structured logging information.
- ``systemd-journal``: use systemd-journal.
  When using this backend, provide ``-o verbose`` or simular output option to ``journalctl`` to view the full information.

.. _setting-yaml-logging.timestamp:

``logging.timestamp``
^^^^^^^^^^^^^^^^^^^^^

-  Boolean
-  Default: ``true``

- Old style setting: :ref:`setting-log-timestamp`



.. _setting-yaml-logging.trace:

``logging.trace``
^^^^^^^^^^^^^^^^^

-  String
-  Default: ``no``

- Old style setting: :ref:`setting-trace`

One of ``no``, ``yes`` or ``fail``.
If turned on, output impressive heaps of logging.
May destroy performance under load.
To log only queries resulting in a ``ServFail`` answer from the resolving process, this value can be set to ``fail``, but note that the performance impact is still large.
Also note that queries that do produce a result but with a failing DNSSEC validation are not written to the log

.. _setting-yaml-nod.db_size:

``nod.db_size``
^^^^^^^^^^^^^^^
.. versionadded:: 4.2.0

-  Integer
-  Default: ``67108864``

- Old style setting: :ref:`setting-new-domain-db-size`

The default size of the stable bloom filter used to store previously
observed domains is 67108864. To change the number of cells, use this
setting. For each cell, the SBF uses 1 bit of memory, and one byte of
disk for the persistent file.
If there are already persistent files saved to disk, this setting will
have no effect unless you remove the existing files.

.. _setting-yaml-nod.history_dir:

``nod.history_dir``
^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.2.0

-  String
-  Default: ``/usr/local/var/lib/pdns-recursor/nod``

- Old style setting: :ref:`setting-new-domain-history-dir`

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

.. _setting-yaml-nod.ignore_list:

``nod.ignore_list``
^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.5.0

-  Sequence of strings
-  Default: ``[]``

- Old style setting: :ref:`setting-new-domain-ignore-list`

This setting is a list of all domains (and implicitly all subdomains)
that will never be considered a new domain. For example, if the domain
'xyz123.tv' is in the list, then 'foo.bar.xyz123.tv' will never be
considered a new domain. One use-case for the ignore list is to never
reveal details of internal subdomains via the new-domain-lookup
feature.

.. _setting-yaml-nod.log:

``nod.log``
^^^^^^^^^^^
.. versionadded:: 4.2.0

-  Boolean
-  Default: ``true``

- Old style setting: :ref:`setting-new-domain-log`

If a newly observed domain is detected, log that domain in the
recursor log file. The log line looks something like::

 Jul 18 11:31:25 Newly observed domain nod=sdfoijdfio.com

.. _setting-yaml-nod.lookup:

``nod.lookup``
^^^^^^^^^^^^^^
.. versionadded:: 4.2.0

-  String
-  Default: (empty)

- Old style setting: :ref:`setting-new-domain-lookup`

If a domain is specified, then each time a newly observed domain is
detected, the recursor will perform an A record lookup of '<newly
observed domain>.<lookup domain>'. For example if 'new-domain-lookup'
is configured as 'nod.powerdns.com', and a new domain 'xyz123.tv' is
detected, then an A record lookup will be made for
'xyz123.tv.nod.powerdns.com'. This feature gives a way to share the
newly observed domain with partners, vendors or security teams. The
result of the DNS lookup will be ignored by the recursor.

.. _setting-yaml-nod.pb_tag:

``nod.pb_tag``
^^^^^^^^^^^^^^
.. versionadded:: 4.2.0

-  String
-  Default: ``pdns-nod``

- Old style setting: :ref:`setting-new-domain-pb-tag`

If protobuf is configured, then this tag will be added to all protobuf response messages when
a new domain is observed.

.. _setting-yaml-nod.tracking:

``nod.tracking``
^^^^^^^^^^^^^^^^
.. versionadded:: 4.2.0

-  Boolean
-  Default: ``false``

- Old style setting: :ref:`setting-new-domain-tracking`

Whether to track newly observed domains, i.e. never seen before. This
is a probabilistic algorithm, using a stable bloom filter to store
records of previously seen domains. When enabled for the first time,
all domains will appear to be newly observed, so the feature is best
left enabled for e.g. a week or longer before using the results. Note
that this feature is optional and must be enabled at compile-time,
thus it may not be available in all pre-built packages.
If protobuf is enabled and configured, then the newly observed domain
status will appear as a flag in Response messages.

.. _setting-yaml-nod.unique_response_db_size:

``nod.unique_response_db_size``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.2.0

-  Integer
-  Default: ``67108864``

- Old style setting: :ref:`setting-unique-response-db-size`

The default size of the stable bloom filter used to store previously
observed responses is 67108864. To change the number of cells, use this
setting. For each cell, the SBF uses 1 bit of memory, and one byte of
disk for the persistent file.
If there are already persistent files saved to disk, this setting will
have no effect unless you remove the existing files.

.. _setting-yaml-nod.unique_response_history_dir:

``nod.unique_response_history_dir``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.2.0

-  String
-  Default: ``/usr/local/var/lib/pdns-recursor/udr``

- Old style setting: :ref:`setting-unique-response-history-dir`

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

.. _setting-yaml-nod.unique_response_log:

``nod.unique_response_log``
^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.2.0

-  Boolean
-  Default: ``true``

- Old style setting: :ref:`setting-unique-response-log`

Whether to log when a unique response is detected. The log line
looks something like:

Oct 24 12:11:27 Unique response observed: qname=foo.com qtype=A rrtype=AAAA rrname=foo.com rrcontent=1.2.3.4

.. _setting-yaml-nod.unique_response_pb_tag:

``nod.unique_response_pb_tag``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.2.0

-  String
-  Default: ``pdns-udr``

- Old style setting: :ref:`setting-unique-response-pb-tag`

If protobuf is configured, then this tag will be added to all protobuf response messages when
a unique DNS response is observed.

.. _setting-yaml-nod.unique_response_tracking:

``nod.unique_response_tracking``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.2.0

-  Boolean
-  Default: ``false``

- Old style setting: :ref:`setting-unique-response-tracking`

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

.. _setting-yaml-outgoing.dont_query:

``outgoing.dont_query``
^^^^^^^^^^^^^^^^^^^^^^^

-  Sequence of `Subnet`_ (IP addresses or subnets, negation supported)
-  Default: ``[127.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 192.168.0.0/16, 172.16.0.0/12, ::1/128, fc00::/7, fe80::/10, 0.0.0.0/8, 192.0.0.0/24, 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 240.0.0.0/4, ::/96, ::ffff:0:0/96, 100::/64, 2001:db8::/32]``

- Old style setting: :ref:`setting-dont-query`

The DNS is a public database, but sometimes contains delegations to private IP addresses, like for example 127.0.0.1.
This can have odd effects, depending on your network, and may even be a security risk.
Therefore, the PowerDNS Recursor by default does not query private space IP addresses.
This setting can be used to expand or reduce the limitations.

Queries for names in forward zones and to addresses as configured in any of the settings :ref:`setting-yaml-recursor.forward_zones`, :ref:`setting-yaml-recursor.forward_zones_file` or :ref:`setting-yaml-recursor.forward_zones_recurse` are performed regardless of these limitations.

.. _setting-yaml-outgoing.dont_throttle_names:

``outgoing.dont_throttle_names``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.2.0

-  Sequence of strings
-  Default: ``[]``

- Old style setting: :ref:`setting-dont-throttle-names`

When an authoritative server does not answer a query or sends a reply the recursor does not like, it is throttled.
Any servers' name suffix-matching the supplied names will never be throttled.

.. warning::
  Most servers on the internet do not respond for a good reason (overloaded or unreachable), ``dont-throttle-names`` could make this load on the upstream server even higher, resulting in further service degradation.

.. _setting-yaml-outgoing.dont_throttle_netmasks:

``outgoing.dont_throttle_netmasks``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.2.0

-  Sequence of `Subnet`_ (IP addresses or subnets, negation supported)
-  Default: ``[]``

- Old style setting: :ref:`setting-dont-throttle-netmasks`

When an authoritative server does not answer a query or sends a reply the recursor does not like, it is throttled.
Any servers matching the supplied netmasks will never be throttled.

This can come in handy on lossy networks when forwarding, where the same server is configured multiple times (e.g. with ``forward-zones-recurse=example.com=192.0.2.1;192.0.2.1``).
By default, the PowerDNS Recursor would throttle the 'first' server on a timeout and hence not retry the 'second' one.
In this case, ``dont-throttle-netmasks`` could be set to ``192.0.2.1``.

.. warning::
  Most servers on the internet do not respond for a good reason (overloaded or unreachable), ``dont-throttle-netmasks`` could make this load on the upstream server even higher, resulting in further service degradation.

.. _setting-yaml-outgoing.dot_to_auth_names:

``outgoing.dot_to_auth_names``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.6.0

-  Sequence of strings
-  Default: ``[]``

- Old style setting: :ref:`setting-dot-to-auth-names`

Force DoT to the listed authoritative nameservers. For this to work, DoT support has to be compiled in.
Currently, the certificate is not checked for validity in any way.

.. _setting-yaml-outgoing.dot_to_port_853:

``outgoing.dot_to_port_853``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.6.0

-  Boolean
-  Default: ``true``

- Old style setting: :ref:`setting-dot-to-port-853`

Enable DoT to forwarders that specify port 853.

.. _setting-yaml-outgoing.edns_bufsize:

``outgoing.edns_bufsize``
^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionchanged:: 4.2.0

  Before 4.2.0, the default was 1680

-  Integer
-  Default: ``1232``

- Old style setting: :ref:`setting-edns-outgoing-bufsize`

.. note:: Why 1232?

  1232 is the largest number of payload bytes that can fit in the smallest IPv6 packet.
  IPv6 has a minimum MTU of 1280 bytes (:rfc:`RFC 8200, section 5 <8200#section-5>`), minus 40 bytes for the IPv6 header, minus 8 bytes for the UDP header gives 1232, the maximum payload size for the DNS response.

This is the value set for the EDNS0 buffer size in outgoing packets.
Lower this if you experience timeouts.

.. _setting-yaml-outgoing.edns_padding:

``outgoing.edns_padding``
^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.8.0

-  Boolean
-  Default: ``true``

- Old style setting: :ref:`setting-edns-padding-out`

Whether to add EDNS padding to outgoing DoT queries.

.. _setting-yaml-outgoing.edns_subnet_allow_list:

``outgoing.edns_subnet_allow_list``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.5.0

-  Sequence of strings
-  Default: ``[]``

- Old style setting: :ref:`setting-edns-subnet-allow-list`

List of netmasks and domains that :rfc:`EDNS Client Subnet <7871>` should be enabled for in outgoing queries.

For example, an EDNS Client Subnet option containing the address of the initial requestor (but see :ref:`setting-yaml-ecs.add_for`) will be added to an outgoing query sent to server 192.0.2.1 for domain X if 192.0.2.1 matches one of the supplied netmasks, or if X matches one of the supplied domains.
The initial requestor address will be truncated to 24 bits for IPv4 (see :ref:`setting-yaml-ecs.ipv4_bits`) and to 56 bits for IPv6 (see :ref:`setting-yaml-ecs.ipv6_bits`), as recommended in the privacy section of RFC 7871.


Note that this setting describes the destination of outgoing queries, not the sources of incoming queries, nor the subnets described in the EDNS Client Subnet option.

By default, this option is empty, meaning no EDNS Client Subnet information is sent.

.. _setting-yaml-outgoing.lowercase:

``outgoing.lowercase``
^^^^^^^^^^^^^^^^^^^^^^

-  Boolean
-  Default: ``false``

- Old style setting: :ref:`setting-lowercase-outgoing`

Set to true to lowercase the outgoing queries.
When set to 'no' (the default) a query from a client using mixed case in the DNS labels (such as a user entering mixed-case names or `draft-vixie-dnsext-dns0x20-00 <http://tools.ietf.org/html/draft-vixie-dnsext-dns0x20-00>`_), PowerDNS preserves the case of the query.
Broken authoritative servers might give a wrong or broken answer on this encoding.
Setting ``lowercase-outgoing`` to 'yes' makes the PowerDNS Recursor lowercase all the labels in the query to the authoritative servers, but still return the proper case to the client requesting.

.. _setting-yaml-outgoing.max_busy_dot_probes:

``outgoing.max_busy_dot_probes``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.7.0

-  Integer
-  Default: ``0``

- Old style setting: :ref:`setting-max-busy-dot-probes`

Limit the maximum number of simultaneous DoT probes the Recursor will schedule.
The default value 0 means no DoT probes are scheduled.

DoT probes are used to check if an authoritative server's IP address supports DoT.
If the probe determines an IP address supports DoT, the Recursor will use DoT to contact it for subsequent queries until a failure occurs.
After a failure, the Recursor will stop using DoT for that specific IP address for a while.
The results of probes are remembered and can be viewed by the ``rec_control dump-dot-probe-map`` command.
If the maximum number of pending probes is reached, no probes will be scheduled, even if no DoT status is known for an address.
If the result of a probe is not yet available, the Recursor will contact the authoritative server in the regular way, unless an authoritative server is configured to be contacted over DoT always using :ref:`setting-yaml-outgoing.dot_to_auth_names`.
In that case no probe will be scheduled.

.. note::
  DoT probing is an experimental feature.
  Please test thoroughly to determine if it is suitable in your specific production environment before enabling.

.. _setting-yaml-outgoing.network_timeout:

``outgoing.network_timeout``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  Integer
-  Default: ``1500``

- Old style setting: :ref:`setting-network-timeout`

Number of milliseconds to wait for a remote authoritative server to respond.

.. _setting-yaml-outgoing.single_socket:

``outgoing.single_socket``
^^^^^^^^^^^^^^^^^^^^^^^^^^

-  Boolean
-  Default: ``false``

- Old style setting: :ref:`setting-single-socket`

Use only a single socket for outgoing queries.

.. _setting-yaml-outgoing.source_address:

``outgoing.source_address``
^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionchanged:: 4.4.0

  IPv6 addresses can be set with this option as well.

-  Sequence of `Subnet`_ (IP addresses or subnets, negation supported)
-  Default: ``[0.0.0.0]``

- Old style setting: :ref:`setting-query-local-address`

Send out local queries from this address, or addresses. By adding multiple
addresses, increased spoofing resilience is achieved. When no address of a certain
address family is configured, there are *no* queries sent with that address family.
In the default configuration this means that IPv6 is not used for outgoing queries.

.. _setting-yaml-outgoing.tcp_fast_open_connect:

``outgoing.tcp_fast_open_connect``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.5.0

-  Boolean
-  Default: ``false``

- Old style setting: :ref:`setting-tcp-fast-open-connect`

Enable TCP Fast Open Connect support, if available, on the outgoing connections to authoritative servers. See :ref:`tcp-fast-open-support`.

.. _setting-yaml-outgoing.tcp_max_idle_ms:

``outgoing.tcp_max_idle_ms``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.6.0

-  Integer
-  Default: ``10000``

- Old style setting: :ref:`setting-tcp-out-max-idle-ms`

Time outgoing TCP/DoT connections are left idle in milliseconds or 0 if no limit. After having been idle for this time, the connection is eligible for closing.

.. _setting-yaml-outgoing.tcp_max_idle_per_auth:

``outgoing.tcp_max_idle_per_auth``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.6.0

-  Integer
-  Default: ``10``

- Old style setting: :ref:`setting-tcp-out-max-idle-per-auth`

Maximum number of idle outgoing TCP/DoT connections to a specific IP per thread, 0 means do not keep idle connections open.

.. _setting-yaml-outgoing.tcp_max_idle_per_thread:

``outgoing.tcp_max_idle_per_thread``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.6.0

-  Integer
-  Default: ``100``

- Old style setting: :ref:`setting-tcp-out-max-idle-per-thread`

Maximum number of idle outgoing TCP/DoT connections per thread, 0 means do not keep idle connections open.

.. _setting-yaml-outgoing.tcp_max_queries:

``outgoing.tcp_max_queries``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  Integer
-  Default: ``0``

- Old style setting: :ref:`setting-tcp-out-max-queries`

Maximum total number of queries per outgoing TCP/DoT connection, 0 means no limit. After this number of queries, the connection is
closed and a new one will be created if needed.

.. _setting-yaml-outgoing.udp_source_port_avoid:

``outgoing.udp_source_port_avoid``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.2.0

-  Sequence of strings
-  Default: ``[11211]``

- Old style setting: :ref:`setting-udp-source-port-avoid`

A sequence of UDP port numbers to avoid when binding. For example:

.. code-block:: yaml

 outgoing:
   udp_source_port_avoid:
   - 5300
   - 11211

See :ref:`setting-yaml-outgoing.udp_source_port_min`.

.. _setting-yaml-outgoing.udp_source_port_max:

``outgoing.udp_source_port_max``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.2.0

-  Integer
-  Default: ``65535``

- Old style setting: :ref:`setting-udp-source-port-max`

This option sets the maximum limit of UDP port number to bind on.

See :ref:`setting-yaml-outgoing.udp_source_port_min`.

.. _setting-yaml-outgoing.udp_source_port_min:

``outgoing.udp_source_port_min``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.2.0

-  Integer
-  Default: ``1024``

- Old style setting: :ref:`setting-udp-source-port-min`

This option sets the low limit of UDP port number to bind on.

In combination with :ref:`setting-yaml-outgoing.udp_source_port_max` it configures the UDP
port range to use. Port numbers are randomized within this range on
initialization, and exceptions can be configured with :ref:`setting-yaml-outgoing.udp_source_port_avoid`

.. _setting-yaml-packetcache.disable:

``packetcache.disable``
^^^^^^^^^^^^^^^^^^^^^^^

-  Boolean
-  Default: ``false``

- Old style setting: :ref:`setting-disable-packetcache`

Turn off the packet cache. Useful when running with Lua scripts that can not be cached, though individual query caching can be controlled from Lua as well.

.. _setting-yaml-packetcache.max_entries:

``packetcache.max_entries``
^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  Integer
-  Default: ``500000``

- Old style setting: :ref:`setting-max-packetcache-entries`

Maximum number of Packet Cache entries. Sharded and shared by all threads since 4.9.0.

.. _setting-yaml-packetcache.negative_ttl:

``packetcache.negative_ttl``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.9.0

-  Integer
-  Default: ``60``

- Old style setting: :ref:`setting-packetcache-negative-ttl`

Maximum number of seconds to cache an ``NxDomain`` or ``NoData`` answer in the packetcache.
This setting's maximum is capped to :ref:`setting-yaml-packetcache.ttl`.
i.e. setting ``packetcache-ttl=15`` and keeping ``packetcache-negative-ttl`` at the default will lower ``packetcache-negative-ttl`` to ``15``.

.. _setting-yaml-packetcache.servfail_ttl:

``packetcache.servfail_ttl``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^
'versionchanged': ('4.0.0', "This setting's maximum is capped to :ref:`setting-yaml-packetcache.ttl`.
    i.e. setting ``packetcache-ttl=15`` and keeping ``packetcache-servfail-ttl`` at the default will lower ``packetcache-servfail-ttl`` to ``15``.")

-  Integer
-  Default: ``60``

- Old style setting: :ref:`setting-packetcache-servfail-ttl`

Maximum number of seconds to cache an answer indicating a failure to resolve in the packet cache.
Before version 4.6.0 only ``ServFail`` answers were considered as such. Starting with 4.6.0, all responses with a code other than ``NoError`` and ``NXDomain``, or without records in the answer and authority sections, are considered as a failure to resolve.
Since 4.9.0, negative answers are handled separately from resolving failures.

.. _setting-yaml-packetcache.shards:

``packetcache.shards``
^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.9.0

-  Integer
-  Default: ``1024``

- Old style setting: :ref:`setting-packetcache-shards`

Sets the number of shards in the packet cache. If you have high contention as reported by ``packetcache-contented/packetcache-acquired``,
you can try to enlarge this value or run with fewer threads.

.. _setting-yaml-packetcache.ttl:

``packetcache.ttl``
^^^^^^^^^^^^^^^^^^^
.. versionchanged:: 4.9.0

  The default was changed from 3600 (1 hour) to 86400 (24 hours).

-  Integer
-  Default: ``86400``

- Old style setting: :ref:`setting-packetcache-ttl`

Maximum number of seconds to cache an item in the packet cache, no matter what the original TTL specified.

.. _setting-yaml-recordcache.locked_ttl_perc:

``recordcache.locked_ttl_perc``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.8.0

-  Integer
-  Default: ``0``

- Old style setting: :ref:`setting-record-cache-locked-ttl-perc`

Replace record sets in the record cache only after this percentage of the original TTL has passed.
The PowerDNS Recursor already has several mechanisms to protect against spoofing attempts.
This adds an extra layer of protection---as it limits the window of time cache updates are accepted---at the cost of a less efficient record cache.

The default value of 0 means no extra locking occurs.
When non-zero, record sets received (e.g. in the Additional Section) will not replace existing record sets in the record cache until the given percentage of the original TTL has expired.
A value of 100 means only expired record sets will be replaced.

There are a few cases where records will be replaced anyway:

- Record sets that are expired will always be replaced.
- Authoritative record sets will replace unauthoritative record sets unless DNSSEC validation of the new record set failed.
- If the new record set belongs to a DNSSEC-secure zone and successfully passed validation it will replace an existing entry.
- Record sets produced by :ref:`setting-yaml-recordcache.refresh_on_ttl_perc` tasks will also replace existing record sets.

.. _setting-yaml-recordcache.max_cache_bogus_ttl:

``recordcache.max_cache_bogus_ttl``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.2.0

-  Integer
-  Default: ``3600``

- Old style setting: :ref:`setting-max-cache-bogus-ttl`

Maximum number of seconds to cache an item in the DNS cache (negative or positive) if its DNSSEC validation failed, no matter what the original TTL specified, to reduce the impact of a broken domain.

.. _setting-yaml-recordcache.max_entries:

``recordcache.max_entries``
^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  Integer
-  Default: ``1000000``

- Old style setting: :ref:`setting-max-cache-entries`

Maximum number of DNS record cache entries, shared by all threads since 4.4.0.
Each entry associates a name and type with a record set.
The size of the negative cache is 10% of this number.

.. _setting-yaml-recordcache.max_negative_ttl:

``recordcache.max_negative_ttl``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  Integer
-  Default: ``3600``

- Old style setting: :ref:`setting-max-negative-ttl`

A query for which there is authoritatively no answer is cached to quickly deny a record's existence later on, without putting a heavy load on the remote server.
In practice, caches can become saturated with hundreds of thousands of hosts which are tried only once.
This setting, which defaults to 3600 seconds, puts a maximum on the amount of time negative entries are cached.

.. _setting-yaml-recordcache.max_ttl:

``recordcache.max_ttl``
^^^^^^^^^^^^^^^^^^^^^^^
.. versionchanged:: 4.1.0

  The minimum value of this setting is 15. i.e. setting this to lower than 15 will make this value 15.

-  Integer
-  Default: ``86400``

- Old style setting: :ref:`setting-max-cache-ttl`

Maximum number of seconds to cache an item in the DNS cache, no matter what the original TTL specified.
This value also controls the refresh period of cached root data.
See :ref:`handling-of-root-hints` for more information on this.

.. _setting-yaml-recordcache.refresh_on_ttl_perc:

``recordcache.refresh_on_ttl_perc``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.5.0

-  Integer
-  Default: ``0``

- Old style setting: :ref:`setting-refresh-on-ttl-perc`

Sets the 'refresh almost expired' percentage of the record cache. Whenever a record is fetched from the packet or record cache
and only ``refresh-on-ttl-perc`` percent or less of its original TTL is left, a task is queued to refetch the name/type combination to
update the record cache. In most cases this causes future queries to always see a non-expired record cache entry.
A typical value is 10. If the value is zero, this functionality is disabled.

.. _setting-yaml-recordcache.shards:

``recordcache.shards``
^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.4.0

-  Integer
-  Default: ``1024``

- Old style setting: :ref:`setting-record-cache-shards`

Sets the number of shards in the record cache. If you have high
contention as reported by
``record-cache-contented/record-cache-acquired``, you can try to
enlarge this value or run with fewer threads.

.. _setting-yaml-recursor.allow_trust_anchor_query:

``recursor.allow_trust_anchor_query``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.3.0

-  Boolean
-  Default: ``false``

- Old style setting: :ref:`setting-allow-trust-anchor-query`

Allow ``trustanchor.server CH TXT`` and ``negativetrustanchor.server CH TXT`` queries to view the configured :doc:`DNSSEC <dnssec>` (negative) trust anchors.

.. _setting-yaml-recursor.any_to_tcp:

``recursor.any_to_tcp``
^^^^^^^^^^^^^^^^^^^^^^^

-  Boolean
-  Default: ``false``

- Old style setting: :ref:`setting-any-to-tcp`

Answer questions for the ANY type on UDP with a truncated packet that refers the remote server to TCP.
Useful for mitigating ANY reflection attacks.

.. _setting-yaml-recursor.auth_zones:

``recursor.auth_zones``
^^^^^^^^^^^^^^^^^^^^^^^

-  Sequence of `Auth Zone`_
-  Default: ``[]``

- Old style setting: :ref:`setting-auth-zones`

Zones read from these files (in BIND format) are served authoritatively (but without the AA bit set in responses).
DNSSEC is not supported. Example:

.. code-block:: yaml

 recursor:
    auth-zones:
    - zone: example.org
      file: /var/zones/example.org
    - zone: powerdns.com
      file: /var/zones/powerdns.com

.. _setting-yaml-recursor.chroot:

``recursor.chroot``
^^^^^^^^^^^^^^^^^^^

-  String
-  Default: (empty)

- Old style setting: :ref:`setting-chroot`

If set, chroot to this directory for more security.
This is not recommended; instead, we recommend containing PowerDNS using operating system features.
We ship systemd unit files with our packages to make this easy.

Make sure that ``/dev/log`` is available from within the chroot.
Logging will silently fail over time otherwise (on logrotate).

When using ``chroot``, all other paths (except for :ref:`setting-yaml-recursor.config_dir`) set in the configuration are relative to the new root.

When running on a system where systemd manages services, ``chroot`` does not work out of the box, as PowerDNS cannot use the ``NOTIFY_SOCKET``.
Either do not ``chroot`` on these systems or set the 'Type' of this service to 'simple' instead of 'notify' (refer to the systemd documentation on how to modify unit-files).

.. _setting-yaml-recursor.config_dir:

``recursor.config_dir``
^^^^^^^^^^^^^^^^^^^^^^^

-  String
-  Default: ``SYSCONFDIR``

- Old style setting: :ref:`setting-config-dir`

Location of configuration directory (where ``recursor.conf`` or ``recursor.yml`` is stored).
Usually ``/etc/powerdns``, but this depends on ``SYSCONFDIR`` during compile-time.
Use default or set on command line.

.. _setting-yaml-recursor.config_name:

``recursor.config_name``
^^^^^^^^^^^^^^^^^^^^^^^^

-  String
-  Default: (empty)

- Old style setting: :ref:`setting-config-name`

When running multiple recursors on the same server, read settings from :file:`recursor-{name}.conf`, this will also rename the binary image.

.. _setting-yaml-recursor.cpu_map:

``recursor.cpu_map``
^^^^^^^^^^^^^^^^^^^^

-  String
-  Default: (empty)

- Old style setting: :ref:`setting-cpu-map`

Set CPU affinity for threads, asking the scheduler to run those threads on a single CPU, or a set of CPUs.
This parameter accepts a space separated list of thread-id=cpu-id, or thread-id=cpu-id-1,cpu-id-2,...,cpu-id-N.
For example, to make the worker thread 0 run on CPU id 0 and the worker thread 1 on CPUs 1 and 2::

.. code-block:: yaml

  recursor:
    cpu_map: 0=0 1=1,2

The thread handling the control channel, the webserver and other internal stuff has been assigned id 0, the distributor
threads if any are assigned id 1 and counting, and the worker threads follow behind.
The number of distributor threads is determined by :ref:`setting-yaml-incoming.distributor_threads`, the number of worker threads is determined by the :ref:`setting-yaml-recursor.threads` setting.

This parameter is only available if the OS provides the ``pthread_setaffinity_np()`` function.

Note that depending on the configuration the Recursor can start more threads.
Typically these threads will sleep most of the time.
These threads cannot be specified in this setting as their thread-ids are left unspecified.

.. _setting-yaml-recursor.daemon:

``recursor.daemon``
^^^^^^^^^^^^^^^^^^^
.. versionchanged:: 4.0.0

  Default is now ``no``, was ``yes`` before.

-  Boolean
-  Default: ``false``

- Old style setting: :ref:`setting-daemon`

Operate in the background.

.. _setting-yaml-recursor.dns64_prefix:

``recursor.dns64_prefix``
^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.4.0

-  String
-  Default: (empty)

- Old style setting: :ref:`setting-dns64-prefix`

Enable DNS64 (:rfc:`6147`) support using the supplied /96 IPv6 prefix. This will generate 'fake' ``AAAA`` records for names
with only ``A`` records, as well as 'fake' ``PTR`` records to make sure that reverse lookup of DNS64-generated IPv6 addresses
generate the right name.
See :doc:`dns64` for more flexible but slower alternatives using Lua.

.. _setting-yaml-recursor.entropy_source:

``recursor.entropy_source``
^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  String
-  Default: ``/dev/urandom``

- Old style setting: :ref:`setting-entropy-source`

PowerDNS can read entropy from a (hardware) source.
This is used for generating random numbers which are very hard to predict.
Generally on UNIX platforms, this source will be ``/dev/urandom``, which will always supply random numbers, even if entropy is lacking.
Change to ``/dev/random`` if PowerDNS should block waiting for enough entropy to arrive.

.. _setting-yaml-recursor.etc_hosts_file:

``recursor.etc_hosts_file``
^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  String
-  Default: ``/etc/hosts``

- Old style setting: :ref:`setting-etc-hosts-file`

The path to the /etc/hosts file, or equivalent.
This file can be used to serve data authoritatively using :ref:`setting-yaml-recursor.export_etc_hosts`.

.. _setting-yaml-recursor.event_trace_enabled:

``recursor.event_trace_enabled``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.6.0

-  Integer
-  Default: ``0``

- Old style setting: :ref:`setting-event-trace-enabled`

Enable the recording and logging of ref:`event traces`. This is an experimental feature and subject to change.
Possible values are 0: (disabled), 1 (add information to protobuf logging messages) and 2 (write to log) and 3 (both).

.. _setting-yaml-recursor.export_etc_hosts:

``recursor.export_etc_hosts``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  Boolean
-  Default: ``false``

- Old style setting: :ref:`setting-export-etc-hosts`

If set, this flag will export the host names and IP addresses mentioned in ``/etc/hosts``.

.. _setting-yaml-recursor.export_etc_hosts_search_suffix:

``recursor.export_etc_hosts_search_suffix``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  String
-  Default: (empty)

- Old style setting: :ref:`setting-export-etc-hosts-search-suffix`

If set, all hostnames in the :ref:`setting-yaml-recursor.export_etc_hosts` file are loaded in canonical form, based on this suffix, unless the name contains a '.', in which case the name is unchanged.
So an entry called 'pc' with ``export-etc-hosts-search-suffix='home.com'`` will lead to the generation of 'pc.home.com' within the recursor.
An entry called 'server1.home' will be stored as 'server1.home', regardless of this setting.

.. _setting-yaml-recursor.extended_resolution_errors:

``recursor.extended_resolution_errors``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.5.0

-  Boolean
-  Default: ``false``

- Old style setting: :ref:`setting-extended-resolution-errors`

If set, the recursor will add an EDNS Extended Error (:rfc:`8914`) to responses when resolution failed, like DNSSEC validation errors, explaining the reason it failed. This setting is not needed to allow setting custom error codes from Lua or from a RPZ hit.

.. _setting-yaml-recursor.forward_zones:

``recursor.forward_zones``
^^^^^^^^^^^^^^^^^^^^^^^^^^

-  Sequence of `Forward Zone`_
-  Default: ``[]``

- Old style setting: :ref:`setting-forward-zones`

Queries for zones listed here will be forwarded to the IP address listed. i.e.

.. code-block:: yaml

 recursor:
    forward-zones:
      - zone: example.org
        forwarders:
        - 203.0.113.210
      - zone: powerdns.com
        forwarders:
        - 2001:DB8::BEEF:5

Multiple IP addresses can be specified and port numbers other than 53 can be configured:

.. code-block:: yaml

  recursor:
    forward-zones:
    - zone: example.org
      forwarders:
      - 203.0.113.210:5300
      - 127.0.0.1
    - zone: powerdns.com
      forwarders:
      - 127.0.0.1
      - 198.51.100.10:530
      - '[2001:DB8::1:3]:5300'

Forwarded queries have the ``recursion desired (RD)`` bit set to ``0``, meaning that this setting is intended to forward queries to authoritative servers.
If an ``NS`` record set for a subzone of the forwarded zone is learned, that record set will be used to determine addresses for name servers of the subzone.
This allows e.g. a forward to a local authoritative server holding a copy of the root zone, delegations received from that server will work.

**IMPORTANT**: When using DNSSEC validation (which is default), forwards to non-delegated (e.g. internal) zones that have a DNSSEC signed parent zone will validate as Bogus.
To prevent this, add a Negative Trust Anchor (NTA) for this zone in the :ref:`setting-yaml-recursor.lua_config_file` with ``addNTA('your.zone', 'A comment')``.
If this forwarded zone is signed, instead of adding NTA, add the DS record to the :ref:`setting-yaml-recursor.lua_config_file`.
See the :doc:`dnssec` information.

.. _setting-yaml-recursor.forward_zones_file:

``recursor.forward_zones_file``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionchanged:: 4.0.0

  (Old style settings only) Comments are allowed, everything behind ``#`` is ignored.
.. versionchanged:: 4.6.0

  (Old style settings only) Zones prefixed with a ``^`` are added to the :ref:`setting-allow-notify-for` list. Both prefix characters can be used if desired, in any order.

-  String
-  Default: (empty)

- Old style setting: :ref:`setting-forward-zones-file`

Same as :ref:`setting-yaml-recursor.forward_zones`, parsed from a file as a sequence of `ZoneForward`.

.. code-block:: yaml

  - zone: example1.com
    forwarders:
    - 127.0.0.1
    - 127.0.0.1:5353
    - '[::1]53'
  - zone: example2.com
    forwarders:
    - ::1
    recurse: true
    notify_allowed: true

The DNSSEC notes from :ref:`setting-yaml-recursor.forward_zones` apply here as well.

.. _setting-yaml-recursor.forward_zones_recurse:

``recursor.forward_zones_recurse``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  Sequence of `Forward Zone`_
-  Default: ``[]``

- Old style setting: :ref:`setting-forward-zones-recurse`

Like regular :ref:`setting-yaml-recursor.forward_zones`, but forwarded queries have the ``recursion desired (RD)`` bit set to ``1``, meaning that this setting is intended to forward queries to other recursive servers.
In contrast to regular forwarding, the rule that delegations of the forwarded subzones are respected is not active.
This is because we rely on the forwarder to resolve the query fully.

See :ref:`setting-yaml-recursor.forward_zones` for additional options (such as supplying multiple recursive servers) and an important note about DNSSEC.

.. _setting-yaml-recursor.hint_file:

``recursor.hint_file``
^^^^^^^^^^^^^^^^^^^^^^
.. versionchanged:: 4.6.2

  Introduced the value ``no`` to disable root-hints processing.
.. versionchanged:: 4.9.0

  Introduced the value ``no-refresh`` to disable both root-hints processing and periodic refresh of the cached root `NS` records.

-  String
-  Default: (empty)

- Old style setting: :ref:`setting-hint-file`

If set, the root-hints are read from this file. If empty, the default built-in root hints are used.

In some special cases, processing the root hints is not needed, for example when forwarding all queries to another recursor.
For these special cases, it is possible to disable the processing of root hints by setting the value to ``no`` or ``no-refresh``.
See :ref:`handling-of-root-hints` for more information on root hints handling.

.. _setting-yaml-recursor.ignore_unknown_settings:

``recursor.ignore_unknown_settings``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  Sequence of strings
-  Default: ``[]``

- Old style setting: :ref:`setting-ignore-unknown-settings`

Names of settings to be ignored while parsing configuration files, if the setting
name is unknown to PowerDNS.

Useful during upgrade testing.

.. _setting-yaml-recursor.include_dir:

``recursor.include_dir``
^^^^^^^^^^^^^^^^^^^^^^^^

-  String
-  Default: (empty)

- Old style setting: :ref:`setting-include-dir`

Directory to scan for additional config files. All files that end with .conf are loaded in order using ``POSIX`` as locale.

.. _setting-yaml-recursor.latency_statistic_size:

``recursor.latency_statistic_size``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  Integer
-  Default: ``10000``

- Old style setting: :ref:`setting-latency-statistic-size`

Indication of how many queries will be averaged to get the average latency reported by the 'qa-latency' metric.

.. _setting-yaml-recursor.lua_config_file:

``recursor.lua_config_file``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  String
-  Default: (empty)

- Old style setting: :ref:`setting-lua-config-file`

If set, and Lua support is compiled in, this will load an additional configuration file for newer features and more complicated setups.
See :doc:`lua-config/index` for the options that can be set in this file.

.. _setting-yaml-recursor.lua_dns_script:

``recursor.lua_dns_script``
^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  String
-  Default: (empty)

- Old style setting: :ref:`setting-lua-dns-script`

Path to a lua file to manipulate the Recursor's answers. See :doc:`lua-scripting/index` for more information.

.. _setting-yaml-recursor.lua_maintenance_interval:

``recursor.lua_maintenance_interval``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.2.0

-  Integer
-  Default: ``1``

- Old style setting: :ref:`setting-lua-maintenance-interval`

The interval between calls to the Lua user defined `maintenance()` function in seconds.
See :ref:`hooks-maintenance-callback`

.. _setting-yaml-recursor.max_generate_steps:

``recursor.max_generate_steps``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.3.0

-  Integer
-  Default: ``0``

- Old style setting: :ref:`setting-max-generate-steps`

Maximum number of steps for a '$GENERATE' directive when parsing a
zone file. This is a protection measure to prevent consuming a lot of
CPU and memory when untrusted zones are loaded. Default to 0 which
means unlimited.

.. _setting-yaml-recursor.max_include_depth:

``recursor.max_include_depth``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.6.0

-  Integer
-  Default: ``20``

- Old style setting: :ref:`setting-max-include-depth`

Maximum number of nested ``$INCLUDE`` directives while processing a zone file.
Zero mean no ``$INCLUDE`` directives will be accepted.

.. _setting-yaml-recursor.max_mthreads:

``recursor.max_mthreads``
^^^^^^^^^^^^^^^^^^^^^^^^^

-  Integer
-  Default: ``2048``

- Old style setting: :ref:`setting-max-mthreads`

Maximum number of simultaneous MTasker threads.

.. _setting-yaml-recursor.max_ns_address_qperq:

``recursor.max_ns_address_qperq``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.1.16
.. versionadded:: 4.2.2
.. versionadded:: 4.3.1

-  Integer
-  Default: ``10``

- Old style setting: :ref:`setting-max-ns-address-qperq`

The maximum number of outgoing queries with empty replies for
resolving nameserver names to addresses we allow during the resolution
of a single client query. If IPv6 is enabled, an A and a AAAA query
for a name counts as 1. If a zone publishes more than this number of
NS records, the limit is further reduced for that zone by lowering
it by the number of NS records found above the
:ref:`setting-yaml-recursor.max_ns_address_qperq` value. The limit wil not be reduced to a
number lower than 5.

.. _setting-yaml-recursor.max_ns_per_resolve:

``recursor.max_ns_per_resolve``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.8.0
.. versionadded:: 4.7.3
.. versionadded:: 4.6.4
.. versionadded:: 4.5.11

-  Integer
-  Default: ``13``

- Old style setting: :ref:`setting-max-ns-per-resolve`

The maximum number of NS records that will be considered to select a nameserver to contact to resolve a name.
If a zone has more than :ref:`setting-yaml-recursor.max_ns_per_resolve` NS records, a random sample of this size will be used.
If :ref:`setting-yaml-recursor.max_ns_per_resolve` is zero, no limit applies.

.. _setting-yaml-recursor.max_qperq:

``recursor.max_qperq``
^^^^^^^^^^^^^^^^^^^^^^

-  Integer
-  Default: ``60``

- Old style setting: :ref:`setting-max-qperq`

The maximum number of outgoing queries that will be sent out during the resolution of a single client query.
This is used to limit endlessly chasing CNAME redirections.
If qname-minimization is enabled, the number will be forced to be 100
at a minimum to allow for the extra queries qname-minimization generates when the cache is empty.

.. _setting-yaml-recursor.max_recursion_depth:

``recursor.max_recursion_depth``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionchanged:: 4.1.0

  Before 4.1.0, this settings was unlimited.
.. versionchanged:: 4.9.0

  Before 4.9.0 this setting's default was 40 and the limit on ``CNAME`` chains (fixed at 16) acted as a bound on he recursion depth.

-  Integer
-  Default: ``16``

- Old style setting: :ref:`setting-max-recursion-depth`

Total maximum number of internal recursion calls the server may use to answer a single query.
0 means unlimited.
The value of :ref:`setting-yaml-recursor.stack_size` should be increased together with this one to prevent the stack from overflowing.
If :ref:`setting-yaml-recursor.qname_minimization` is enabled, the fallback code in case of a failing resolve is allowed an additional `max-recursion-depth/2`.

.. _setting-yaml-recursor.max_total_msec:

``recursor.max_total_msec``
^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  Integer
-  Default: ``7000``

- Old style setting: :ref:`setting-max-total-msec`

Total maximum number of milliseconds of wallclock time the server may use to answer a single query.
0 means unlimited.

.. _setting-yaml-recursor.minimum_ttl_override:

``recursor.minimum_ttl_override``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionchanged:: 4.5.0

  Old versions used default 0.

-  Integer
-  Default: ``1``

- Old style setting: :ref:`setting-minimum-ttl-override`

This setting artificially raises all TTLs to be at least this long.
Setting this to a value greater than 1 technically is an RFC violation, but might improve performance a lot.
Using a value of 0 impacts performance of TTL 0 records greatly, since it forces the recursor to contact
authoritative servers each time a client requests them.
Can be set at runtime using ``rec_control set-minimum-ttl 3600``.

.. _setting-yaml-recursor.non_resolving_ns_max_fails:

``recursor.non_resolving_ns_max_fails``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.5.0

-  Integer
-  Default: ``5``

- Old style setting: :ref:`setting-non-resolving-ns-max-fails`

Number of failed address resolves of a nameserver name to start throttling it, 0 is disabled.
Nameservers matching :ref:`setting-yaml-outgoing.dont_throttle_names` will not be throttled.

.. _setting-yaml-recursor.non_resolving_ns_throttle_time:

``recursor.non_resolving_ns_throttle_time``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.5.0

-  Integer
-  Default: ``60``

- Old style setting: :ref:`setting-non-resolving-ns-throttle-time`

Number of seconds to throttle a nameserver with a name failing to resolve.

.. _setting-yaml-recursor.nothing_below_nxdomain:

``recursor.nothing_below_nxdomain``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.3.0

-  String
-  Default: ``dnssec``

- Old style setting: :ref:`setting-nothing-below-nxdomain`

- One of ``no``, ``dnssec``, ``yes``.

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

.. _setting-yaml-recursor.public_suffix_list_file:

``recursor.public_suffix_list_file``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.2.0

-  String
-  Default: (empty)

- Old style setting: :ref:`setting-public-suffix-list-file`

Path to the Public Suffix List file, if any. If set, PowerDNS will try to load the Public Suffix List from this file instead of using the built-in list. The PSL is used to group the queries by relevant domain names when displaying the top queries.

.. _setting-yaml-recursor.qname_minimization:

``recursor.qname_minimization``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.3.0

-  Boolean
-  Default: ``true``

- Old style setting: :ref:`setting-qname-minimization`

Enable Query Name Minimization. This implements a relaxed form of Query Name Mimimization as
described in :rfc:`7816`.

.. _setting-yaml-recursor.rng:

``recursor.rng``
^^^^^^^^^^^^^^^^

-  String
-  Default: ``auto``

- Old style setting: :ref:`setting-rng`

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

.. _setting-yaml-recursor.root_nx_trust:

``recursor.root_nx_trust``
^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionchanged:: 4.0.0

  Default is ``yes`` now, was ``no`` before 4.0.0

-  Boolean
-  Default: ``true``

- Old style setting: :ref:`setting-root-nx-trust`

If set, an NXDOMAIN from the root-servers will serve as a blanket NXDOMAIN for the entire TLD the query belonged to.
The effect of this is far fewer queries to the root-servers.

.. _setting-yaml-recursor.save_parent_ns_set:

``recursor.save_parent_ns_set``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.7.0

-  Boolean
-  Default: ``true``

- Old style setting: :ref:`setting-save-parent-ns-set`

If set, a parent (non-authoritative) ``NS`` set is saved if it contains more entries than a newly encountered child (authoritative) ``NS`` set for the same domain.
The saved parent ``NS`` set is tried if resolution using the child ``NS`` set fails.

.. _setting-yaml-recursor.security_poll_suffix:

``recursor.security_poll_suffix``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  String
-  Default: ``secpoll.powerdns.com.``

- Old style setting: :ref:`setting-security-poll-suffix`

Domain name from which to query security update notifications.
Setting this to an empty string disables secpoll.

.. _setting-yaml-recursor.serve_rfc1918:

``recursor.serve_rfc1918``
^^^^^^^^^^^^^^^^^^^^^^^^^^

-  Boolean
-  Default: ``true``

- Old style setting: :ref:`setting-serve-rfc1918`

This makes the server authoritatively aware of: ``10.in-addr.arpa``, ``168.192.in-addr.arpa``, ``16-31.172.in-addr.arpa``, which saves load on the AS112 servers.
Individual parts of these zones can still be loaded or forwarded.

.. _setting-yaml-recursor.serve_stale_extensions:

``recursor.serve_stale_extensions``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.8.0

-  Integer
-  Default: ``0``

- Old style setting: :ref:`setting-serve-stale-extensions`

Maximum number of times an expired record's TTL is extended by 30s when serving stale.
Extension only occurs if a record cannot be refreshed.
A value of 0 means the ``Serve Stale`` mechanism is not used.
To allow records becoming stale to be served for an hour, use a value of 120.
See :ref:`serve-stale` for a description of the Serve Stale mechanism.

.. _setting-yaml-recursor.server_down_max_fails:

``recursor.server_down_max_fails``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  Integer
-  Default: ``64``

- Old style setting: :ref:`setting-server-down-max-fails`

If a server has not responded in any way this many times in a row, no longer send it any queries for :ref:`setting-yaml-recursor.server_down_throttle_time` seconds.
Afterwards, we will try a new packet, and if that also gets no response at all, we again throttle for :ref:`setting-yaml-recursor.server_down_throttle_time` seconds.
Even a single response packet will drop the block.

.. _setting-yaml-recursor.server_down_throttle_time:

``recursor.server_down_throttle_time``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  Integer
-  Default: ``60``

- Old style setting: :ref:`setting-server-down-throttle-time`

Throttle a server that has failed to respond :ref:`setting-yaml-recursor.server_down_max_fails` times for this many seconds.

.. _setting-yaml-recursor.server_id:

``recursor.server_id``
^^^^^^^^^^^^^^^^^^^^^^

-  String
-  Default: ``*runtime determined*``

- Old style setting: :ref:`setting-server-id`

The reply given by The PowerDNS recursor to a query for 'id.server' with its hostname, useful for in clusters.
When a query contains the :rfc:`NSID EDNS0 Option <5001>`, this value is returned in the response as the NSID value.

This setting can be used to override the answer given to these queries.
Set to 'disabled' to disable NSID and 'id.server' answers.

Query example (where 192.0.2.14 is your server):

.. code-block:: sh

    dig @192.0.2.14 CHAOS TXT id.server.
    dig @192.0.2.14 example.com IN A +nsid

.. _setting-yaml-recursor.setgid:

``recursor.setgid``
^^^^^^^^^^^^^^^^^^^

-  String
-  Default: (empty)

- Old style setting: :ref:`setting-setgid`

PowerDNS can change its user and group id after binding to its socket.
Can be used for better :doc:`security <security>`.

.. _setting-yaml-recursor.setuid:

``recursor.setuid``
^^^^^^^^^^^^^^^^^^^

-  String
-  Default: (empty)

- Old style setting: :ref:`setting-setuid`

PowerDNS can change its user and group id after binding to its socket.
Can be used for better :doc:`security <security>`.

.. _setting-yaml-recursor.socket_dir:

``recursor.socket_dir``
^^^^^^^^^^^^^^^^^^^^^^^

-  String
-  Default: (empty)

- Old style setting: :ref:`setting-socket-dir`

Where to store the control socket and pidfile.
The default depends on ``LOCALSTATEDIR`` or the ``--with-socketdir`` setting when building (usually ``/var/run`` or ``/run``).

When using :ref:`setting-yaml-recursor.chroot` the default becomes ``/``.

.. _setting-yaml-recursor.socket_group:

``recursor.socket_group``
^^^^^^^^^^^^^^^^^^^^^^^^^

-  String
-  Default: (empty)

- Old style setting: :ref:`setting-socket-group`

Group and mode of the controlsocket.
Owner and group can be specified by name, mode is in octal.

.. _setting-yaml-recursor.socket_mode:

``recursor.socket_mode``
^^^^^^^^^^^^^^^^^^^^^^^^

-  String
-  Default: (empty)

- Old style setting: :ref:`setting-socket-mode`

Mode of the controlsocket.
Owner and group can be specified by name, mode is in octal.

.. _setting-yaml-recursor.socket_owner:

``recursor.socket_owner``
^^^^^^^^^^^^^^^^^^^^^^^^^

-  String
-  Default: (empty)

- Old style setting: :ref:`setting-socket-owner`

Owner of the controlsocket.
Owner and group can be specified by name, mode is in octal.

.. _setting-yaml-recursor.spoof_nearmiss_max:

``recursor.spoof_nearmiss_max``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionchanged:: 4.5.0

  Older versions used 20 as the default value.

-  Integer
-  Default: ``1``

- Old style setting: :ref:`setting-spoof-nearmiss-max`

If set to non-zero, PowerDNS will assume it is being spoofed after seeing this many answers with the wrong id.

.. _setting-yaml-recursor.stack_cache_size:

``recursor.stack_cache_size``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.9.0

-  Integer
-  Default: ``100``

- Old style setting: :ref:`setting-stack-cache-size`

Maximum number of mthread stacks that can be cached for later reuse, per thread. Caching these stacks reduces the CPU load at the cost of a slightly higher memory usage, each cached stack consuming `stack-size` bytes of memory.
It makes no sense to cache more stacks than the value of `max-mthreads`, since there will never be more stacks than that in use at a given time.

.. _setting-yaml-recursor.stack_size:

``recursor.stack_size``
^^^^^^^^^^^^^^^^^^^^^^^

-  Integer
-  Default: ``200000``

- Old style setting: :ref:`setting-stack-size`

Size in bytes of the stack of each mthread.

.. _setting-yaml-recursor.stats_api_disabled_list:

``recursor.stats_api_disabled_list``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.5.0

-  Sequence of strings
-  Default: cache-bytes, packetcache-bytes, special-memory-usage, ecs-v4-response-bits-\*, ecs-v6-response-bits-\*

- Old style setting: :ref:`setting-stats-api-disabled-list`

A sequence of statistic names, that are disabled when retrieving the complete list of statistics via the API for performance reasons.
These statistics can still be retrieved individually by specifically asking for it.

.. _setting-yaml-recursor.stats_carbon_disabled_list:

``recursor.stats_carbon_disabled_list``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.5.0

-  Sequence of strings
-  Default: cache-bytes, packetcache-bytes, special-memory-usage, ecs-v4-response-bits-\*, ecs-v6-response-bits-\*, cumul-answers-\*, cumul-auth4answers-\*, cumul-auth6answers-\*

- Old style setting: :ref:`setting-stats-carbon-disabled-list`

A sequence of statistic names, that are prevented from being exported via carbon for performance reasons.

.. _setting-yaml-recursor.stats_rec_control_disabled_list:

``recursor.stats_rec_control_disabled_list``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.5.0

-  Sequence of strings
-  Default: cache-bytes, packetcache-bytes, special-memory-usage, ecs-v4-response-bits-\*, ecs-v6-response-bits-\*, cumul-answers-\*, cumul-auth4answers-\*, cumul-auth6answers-\*

- Old style setting: :ref:`setting-stats-rec-control-disabled-list`

A sequence of statistic names, that are disabled when retrieving the complete list of statistics via `rec_control get-all`, for performance reasons.
These statistics can still be retrieved individually.

.. _setting-yaml-recursor.stats_ringbuffer_entries:

``recursor.stats_ringbuffer_entries``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  Integer
-  Default: ``10000``

- Old style setting: :ref:`setting-stats-ringbuffer-entries`

Number of entries in the remotes ringbuffer, which keeps statistics on who is querying your server.
Can be read out using ``rec_control top-remotes``.

.. _setting-yaml-recursor.stats_snmp_disabled_list:

``recursor.stats_snmp_disabled_list``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.5.0

-  Sequence of strings
-  Default: cache-bytes, packetcache-bytes, special-memory-usage, ecs-v4-response-bits-\*, ecs-v6-response-bits-\*

- Old style setting: :ref:`setting-stats-snmp-disabled-list`

A sequence of statistic names, that are prevented from being exported via SNMP, for performance reasons.

.. _setting-yaml-recursor.tcp_threads:

``recursor.tcp_threads``
^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 5.0.0

-  Integer
-  Default: ``1``

- Old style setting: :ref:`setting-tcp-threads`

Spawn this number of TCP processing threads on startup.

.. _setting-yaml-recursor.threads:

``recursor.threads``
^^^^^^^^^^^^^^^^^^^^

-  Integer
-  Default: ``2``

- Old style setting: :ref:`setting-threads`

Spawn this number of threads on startup.

.. _setting-yaml-recursor.version_string:

``recursor.version_string``
^^^^^^^^^^^^^^^^^^^^^^^^^^^

-  String
-  Default: ``*runtime determined*``

- Old style setting: :ref:`setting-version-string`

By default, PowerDNS replies to the 'version.bind' query with its version number.
Security conscious users may wish to override the reply PowerDNS issues.

.. _setting-yaml-recursor.write_pid:

``recursor.write_pid``
^^^^^^^^^^^^^^^^^^^^^^

-  Boolean
-  Default: ``true``

- Old style setting: :ref:`setting-write-pid`

If a PID file should be written to :ref:`setting-yaml-recursor.socket_dir`

.. _setting-yaml-snmp.agent:

``snmp.agent``
^^^^^^^^^^^^^^
.. versionadded:: 4.1.0

-  Boolean
-  Default: ``false``

- Old style setting: :ref:`setting-snmp-agent`

If set to true and PowerDNS has been compiled with SNMP support, it will register as an SNMP agent to provide statistics and be able to send traps.

.. _setting-yaml-snmp.daemon_socket:

``snmp.daemon_socket``
^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.5.0

-  String
-  Default: (empty)

- Old style setting: :ref:`setting-snmp-daemon-socket`

If not empty and ``snmp-agent`` is set to true, indicates how PowerDNS should contact the SNMP daemon to register as an SNMP agent.

.. _setting-yaml-webservice.address:

``webservice.address``
^^^^^^^^^^^^^^^^^^^^^^

-  String
-  Default: ``127.0.0.1``

- Old style setting: :ref:`setting-webserver-address`

IP address for the webserver to listen on.

.. _setting-yaml-webservice.allow_from:

``webservice.allow_from``
^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionchanged:: 4.1.0

  Default is now 127.0.0.1,::1, was 0.0.0.0/0,::/0 before.

-  Sequence of `Subnet`_ (IP addresses or subnets, negation supported)
-  Default: ``[127.0.0.1, ::1]``

- Old style setting: :ref:`setting-webserver-allow-from`

These IPs and subnets are allowed to access the webserver. Note that
specifying an IP address without a netmask uses an implicit netmask
of /32 or /128.

.. _setting-yaml-webservice.api_dir:

``webservice.api_dir``
^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.0.0

-  String
-  Default: (empty)

- Old style setting: :ref:`setting-api-config-dir`

Directory where the REST API stores its configuration and zones.
For configuration updates to work, :ref:`setting-yaml-recursor.include_dir` should have the same value.

.. _setting-yaml-webservice.api_key:

``webservice.api_key``
^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.0.0
.. versionchanged:: 4.6.0

  This setting now accepts a hashed and salted version.

-  String
-  Default: (empty)

- Old style setting: :ref:`setting-api-key`

Static pre-shared authentication key for access to the REST API. Since 4.6.0 the key can be hashed and salted using ``rec_control hash-password`` instead of being stored in the configuration in plaintext, but the plaintext version is still supported.

.. _setting-yaml-webservice.hash_plaintext_credentials:

``webservice.hash_plaintext_credentials``
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.6.0

-  Boolean
-  Default: ``false``

- Old style setting: :ref:`setting-webserver-hash-plaintext-credentials`

Whether passwords and API keys supplied in the configuration as plaintext should be hashed during startup, to prevent the plaintext versions from staying in memory. Doing so increases significantly the cost of verifying credentials and is thus disabled by default.
Note that this option only applies to credentials stored in the configuration as plaintext, but hashed credentials are supported without enabling this option.

.. _setting-yaml-webservice.loglevel:

``webservice.loglevel``
^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.2.0

-  String
-  Default: ``normal``

- Old style setting: :ref:`setting-webserver-loglevel`

One of ``one``, ``normal``, ``detailed``.
The amount of logging the webserver must do. 'none' means no useful webserver information will be logged.
When set to 'normal', the webserver will log a line per request that should be familiar::

  [webserver] e235780e-a5cf-415e-9326-9d33383e739e 127.0.0.1:55376 'GET /api/v1/servers/localhost/bla HTTP/1.1' 404 196

When set to 'detailed', all information about the request and response are logged::

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
  [webserver] e235780e-a5cf-415e-9326-9d33383e739e 127.0.0.1:55376 'GET /api/v1/servers/localhost/bla HTTP/1.1' 404 196

The value between the hooks is a UUID that is generated for each request. This can be used to find all lines related to a single request.

.. note::
  The webserver logs these line on the NOTICE level. The :ref:`setting-yaml-logging.loglevel` seting must be 5 or higher for these lines to end up in the log.

.. _setting-yaml-webservice.password:

``webservice.password``
^^^^^^^^^^^^^^^^^^^^^^^
.. versionchanged:: 4.6.0

  This setting now accepts a hashed and salted version.

-  String
-  Default: (empty)

- Old style setting: :ref:`setting-webserver-password`

Password required to access the webserver. Since 4.6.0 the password can be hashed and salted using ``rec_control hash-password`` instead of being present in the configuration in plaintext, but the plaintext version is still supported.

.. _setting-yaml-webservice.port:

``webservice.port``
^^^^^^^^^^^^^^^^^^^

-  Integer
-  Default: ``8082``

- Old style setting: :ref:`setting-webserver-port`

TCP port where the webserver should listen on.

.. _setting-yaml-webservice.webserver:

``webservice.webserver``
^^^^^^^^^^^^^^^^^^^^^^^^

-  Boolean
-  Default: ``false``

- Old style setting: :ref:`setting-webserver`

Start the webserver (for REST API).

