PowerDNS Recursor New Style (YAML) Settings
===========================================

Each setting can appear on the command line, prefixed by ``--`` and using the old style name, or in configuration files.
Settings on the command line are processed after the file-based settings are processed.

.. note::
   Starting with version 5.0.0, :program:`Recursor` supports a new YAML syntax for configuration files
   as described here.
   If both ``recursor.conf`` and ``recursor.yml`` files are found in the configuration directory the YAML file is used.
   A configuration using the old style syntax can be converted to a YAML configuration using the instructions in :doc:`appendices/yamlconversion`.

   Release 5.0.0 will install a default old-style ``recursor.conf`` file.

   Starting with version 5.1.0, in the absence of a ``recursor.yml`` file, an existing ``recursor.conf`` will be processed as YAML,
   if that fails, it will be processed as old-style configuration.
   Packages will stop installing a old-style ``recursor.conf`` file and start installing a default ``recursor.conf`` file containing YAML syntax.

   With the release of 5.2.0, the default will be to expect a YAML configuration file and reading of old-style ``recursor.conf`` files will have to be enabled specifically by providing a command line option ``--enable-old-settings``.

   In a future release support for the "old-style" ``recursor.conf`` settings file will be dropped.

.. note::
   Starting with version 5.1.0, the settings originally specified in a Lua config file can also be put in YAML form.
   The conversion printed by ``rec_control show-yaml`` will print these settings if a Lua config file is specified in the config file being converted.
   You have to choose however: either set Lua settings the old way in the Lua config file, or convert all to YAML.
   If you are using YAML settings of items originally specified in the Lua config file do not set :ref:`setting-yaml-recursor.lua_config_file` anymore. The :program:`Recursor` will check that you do not mix both configuration methods.

   When using YAML style for settings originally found in the Lua config file ``rec_control reload-lua-config`` will reload parts of the YAML settings. Refer to the specific setting to learn if it is subject to reloading. Starting with version 5.2.0, the command ``rec_control reload-yaml`` can be used (which is an alias for ``rec_control reload-lua-config``).

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
    source_address:
      - 0.0.0.0
      - '::'
  logging:
    loglevel: 6

Take care when listing IPv6 addresses, as characters used for these are special to YAML.
If in doubt, quote any string containing ``:``, ``!``, ``[`` or ``]`` and use (online) tools to check your YAML syntax.
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
     source_address: !override
       - 0.0.0.0
     dont_query: []

After merging, ``dnssec.log_bogus`` will be ``false``, the sequence of ``recursor.forward_zones`` will contain 2 zones and the ``outgoing`` addresses used will contain one entry, as the ``extra.yml`` entry has overwritten the existing one.

``outgoing.dont-query`` has a non-empty sequence as default value. The main ``recursor.yml`` did not set it, so before processing ``extra.yml`` it had the default value.
After processing ``extra.yml`` the value will be set to the empty sequence, as existing default values are overwritten by new values.

.. warning::
   The merging process does not process values deeper than the second level.
   For example if the main ``recursor.yml`` specified a forward zone

   .. code-block:: yaml

     recursor:
       forward_zones:
         - zone: example.net
           forwarders:
             - '::1'

   and another settings file contains

   .. code-block:: yaml

     recursor:
       forward_zones:
         - zone: example.net
           forwarders:
           - '::2'

   The result will *not* be a a single forward with two IP addresses, but two entries for ``example.net``.
   It depends on the specific setting how the sequence is processed and interpreted further.

Description of YAML syntax for structured types
-----------------------------------------------

Socket Address
^^^^^^^^^^^^^^
A socket address is a string containing either an IP address or and IP address:port combination
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

For example, ``allow-from`` takes a sequence of subnets:

.. code-block:: yaml

  incoming:
    allow_from:
      - '2001:DB8::/32'
      - 128.66.0.0/16
      - '!128.66.1.2'

In this case the address ``128.66.1.2`` is excluded from the addresses allowed access.

Forward Zone
^^^^^^^^^^^^
A forward zone is defined as:

.. code-block:: yaml

  zone: string
  forwarders:
    - Socket Address
    - ...
  recurse: Boolean, default false (only relevant in a forwarding file)
  notify_allowed: Boolean, default false

An example of a ``forward_zones_file`` contents, which consists of a sequence of `Forward Zone`_ entries:

.. code-block:: yaml

  - zone: example1.com
    forwarders:
      - 127.0.0.1
      - 127.0.0.1:5353
      - '[::1]:53'
  - zone: example2.com
    forwarders:
      - '::1'
    recurse: true
    notify_allowed: true

.. note::

  The ``recurse`` field is relevant only in a ``Forward Zone`` clause in a forwarding file.
  It has a fixed value in the context of :ref:`setting-yaml-recursor.forward_zones` and :ref:`setting-yaml-recursor.forward_zones_recurse`.

Starting with version 5.1.0, names can be used if
:ref:`setting-yaml-recursor.system_resolver_ttl` is set.
The names will be resolved using the system resolver and an automatic refresh of the forwarding zones will happen if a name starts resolving to a new address.
The refresh is done by performing the equivalent of ``rec_control reload-zones``.


Auth Zone
^^^^^^^^^
An auth zone is defined as:

.. code-block:: yaml

  zone: string
  file: string

An example of a ``auth_zones`` entry, consisting of a sequence of `Auth Zone`_:

.. code-block:: yaml

   recursor:
     auth_zones:
       - zone: example.com
         file: zones/example.com.zone
       - zone: example.net
         file: zones/example.net.zone


Description of YAML syntax corresponding to Lua config items
------------------------------------------------------------

The YAML settings below were introduced in version 5.1.0 and correspond to their
respective Lua settings. Refer to :doc:`lua-config/index`.

TrustAnchor
^^^^^^^^^^^
As of version 5.1.0, a trust anchor is defined as

.. code-block:: yaml

   name: string
   dsrecords: sequence of DS record strings in presentation format

An example of a ``trustanchors`` entry, which is a sequence of `TrustAnchor`_:

.. code-block:: yaml

   dnssec:
     trustanchors:
       - name: example.com
         dsrecords:
         - 10000 8 2 a06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d

NegativeTrustAnchor
^^^^^^^^^^^^^^^^^^^
As of version 5.1.0, a negative trust anchor is defined as

.. code-block:: yaml

   name: string
   reason: string

An example of a ``negative_trustanchors`` entry, which is a sequence of `NegativeTrustAnchor`_:

.. code-block:: yaml

   dnssec:
     negative_trustanchors:
       - name: example.com
         reason: an example

ProtobufServer
^^^^^^^^^^^^^^
As of version 5.1.0, a protobuf server is defined as

.. code-block:: yaml

    servers: [] Sequence of strings representing SocketAddress
    timeout: 2
    maxQueuedEntries: 100
    reconnectWaitTime: 1
    taggedOnly: false
    asyncConnect: false
    logQueries: true
    logResponses: true
    exportTypes: [A, AAAA, CNAME] Sequence of QType names
    logMappedFrom: false

An example of a ``protobuf_servers`` entry, which is a sequence of `ProtobufServer`_:

.. code-block:: yaml

  logging:
    protobuf_servers:
      - servers: [127.0.0.1:4578]
        exportTypes: [A, AAAA]
      - servers: ['[2001:DB8::1]':7891]
        logQueries: false
        logResponses: true
        exportTypes: [A]

DNSTapFrameStreamServers
^^^^^^^^^^^^^^^^^^^^^^^^
As of version 5.1.0, a dnstap framestream server is defined as

.. code-block:: yaml

  servers: [] Sequence of strings representing SocketAddress or a socket path
  logQueries: true
  logResponses: true
  bufferHint: 0
  flushTimeout: 0
  inputQueueSize: 0
  outputQueueSize: 0
  queueNotifyThreshold: 0
  reopenInterval: 0

An example of a ``dnstap_framestream_servers`` entry, which is a sequence of `DNSTapFrameStreamServers`_:

.. code-block:: yaml

  logging:
    dnstap_framestream_servers:
      - servers: [127.0.0.1:2024]
        logQueries: false
        logResponses: true

DNSTapNODFrameStreamServers
^^^^^^^^^^^^^^^^^^^^^^^^^^^
As of version 5.1.0, an NOD dnstap framestream server is defined as

.. code-block:: yaml

  servers: [] Sequence of strings representing SocketAddress or a socket path
  logNODs: true
  logUDRs: false
  bufferHint: 0
  flushTimeout: 0
  inputQueueSize: 0
  outputQueueSize: 0
  queueNotifyThreshold: 0
  reopenInterval: 0

An example of a ``dnstap_nod_framestream_servers`` entry, which is a sequence of `DNSTapNODFrameStreamServers`_:

.. code-block:: yaml

  logging:
    dnstap_nop_framestream_servers:
      - servers: [127.0.0.1:2024]
        logNODs: false
        logUDRs: true

SortList
^^^^^^^^
As of version 5.1.0, a sortlist entry is defined as

.. code-block:: yaml

   - key: Subnet
     subnets:
       - subnet: Subnet
         order: number

An example of a ``sortlists`` entry, which is a sequence of `SortList`_:

.. code-block:: yaml

   recursor:
     sortlists:
       - key: 198.18.0.0/8
         subnets:
           - subnet: 233.252.0.0/24
             order: 10
       - key: 198.18.1.0/8
         subnets:
           - subnet: 198.18.0.0/16
             order: 20
           - subnet: 203.0.113.0/24
             order: 20

RPZ
^^^
As of version 5.1.0, an RPZ entry is defined as

.. code-block:: yaml

    name: name or pathname
    addresses: [] Sequence of SocketAddress
    defcontent: string
    defpol:  Custom, Drop, NXDOMAIN, NODATA Truncate or NoAction
    defpolOverrideLocalData: true
    defttl: number
    extendedErrorCode: number
    extendedErrorExtra: string
    includeSOA: false
    ignoreDuplicates: false
    maxTTL: number
    policyName: string
    tags: Sequence of string
    overridesGettag: true
    zoneSizeHint: number
    tsig:
      name: string
      algo: string
      secret: base64string
    refresh: number
    maxReceivedMBytes: number
    localAddress: IP address
    axfrTimeout: number
    dumpFile: string
    seedFile: string

If ``addresses`` is empty, the ``name`` field specifies the path name of the RPZ, otherwise the ``name`` field defines the name of the RPZ.
Starting with version 5.2.0, names instead of IP addresess can be used for ``addresses`` if
:ref:`setting-yaml-recursor.system_resolver_ttl` is set.


An example of an ``rpzs`` entry, which is a sequence of `RPZ`_:

.. code-block:: yaml

  recursor:
    rpzs:
      - name: 'path/to/a/file'
      - name: 'remote.rpz'
        addresses: ['192.168.178.99']
        policyName: mypolicy

ZoneToCache
^^^^^^^^^^^
As of version 5.1.0, a ZoneToCache entry is defined as

.. code-block:: yaml

   zone: zonename
   method: One of axfr, url, file
   sources: [] Sequence of string, representing IP address, URL or path
   timeout: 20
   tsig:
     name: name of key
     algo: algorithm
     secret: Base64 encoded secret
   refreshPeriod: 86400
   retryOnErrorPeriod: 60
   maxReceivedMBytes: 0 Zero mean no restrcition
   localAddress: local IP address to  bind to.
   zonemd: One of ignore, validate, require
   dnssec: One of ignore, validate, require

An example of an ``zonetocaches`` entry, which is a sequence of `ZoneToCache`_:

.. code-block:: yaml

   recursor:
     zonetocaches:
       - zone: .
         method: url
         sources: ['https://www.example.com/path']
       - zone: example.com
         method: file
         sources: ['dir/example.com.zone']

AllowedAdditionalQType
^^^^^^^^^^^^^^^^^^^^^^
As of version 5.1.0, an allowed additional qtype entry is defined as:

.. code-block:: yaml

   qtype: string representing a QType
   targets: [] Sequence of string representing QType
   mode: One of Ignore, CacheOnly, CacheOnlyRequireAuth, ResolveImmediately, ResolveDeferred, default CacheOnlyRequireAuth

An example of an ``allowed_additional_qtypes`` entry, which is a sequence of `AllowedAdditionalQType`_:

.. code-block:: yaml

   recursor:
     allowed_additional_qtypes:
     - qtype: MX
       targets: [A, AAAA]
     - qtype: NAPTR
       targets: [A, AAAA, SRV]
       mode: ResolveDeferred

ProxyMapping
^^^^^^^^^^^^
As of version 5.1.0, a proxy mapping entry is defined as:

.. code-block:: yaml

   subnet: Subnet
   address: IPAddress
   domains: [] Sequence of string

An example of an ``proxymappings`` entry, which is a sequence of `ProxyMapping`_:

.. code-block:: yaml

   incoming:
     proxymappings:
       - subnet: 192.168.178.0/24
         address: 128.66.1.2
       - subnet: 192.168.179.0/24
         address: 128.66.1.3
         domains:
           - example.com
           - example.net

ForwardingCatalogZone
^^^^^^^^^^^^^^^^^^^^^
As of version 5.2.0, a forwarding catalog zone entry is defined as:

.. code-block:: yaml

     zone: Name of catalog zone
     notify_allowed: bool, default false
     xfr:
       addresses: [] Sequence of SocketAddress
       zoneSizeHint: number, default not set
       tsig:
         name: string
         algo: string
         secret: base64string
       refresh: number, default not set
       maxReceivedMBytes: number, default not set
       localAddress: IP address, default not set
       axfrTimeout: number, default 20
     groups:
     - name: optional group name
       forwarders: [] Sequence of SocketAddress
       recurse: bool, default false
       notify_allowed: bool, default false

While this setting has no equivalent old-style Lua configuration, it cannot appear together with :ref:`setting-lua-config-file` being set.
If you want to use catalog zones to define forwards, you need to convert existing Lua configuration to YAML format.

Names instead of IP addresess can be used for ``addresses`` if :ref:`setting-yaml-recursor.system_resolver_ttl` is set.
An example of a :ref:`setting-yaml-recursor.forwarding_catalog_zones` entry, which is a sequence of `ForwardingCatalogZone`_:

.. code-block:: yaml

   recursor:
     forwarding_catalog_zones:
     - zone: 'forward.example'
       xfr:
         addresses: [128.66.1.2]
       groups:
         - forwarders: [192.168.178.1] # default forwarder
         - name: mygroup
           forwarders: [192.168.179.2] # forwarder for catalog zone members in mygroup
           recurse: true
           notify_allowed: true
     - zone: 'forward2.example'
       xfr:
         addresses: [128.66.1.3]
       groups:
         - forwarders: [192.168.178.3] # only default forwarder for 2nd catalog zone

:program:`Recursor` will transfer the catalog zone from the authoritative server using IXFR (falling back to AXFR if needed) and add forwarding clauses for all members of the catalog zone.
The forwarding parameters will be taken from the default group entry (the one without a name) defined in the YAML settings.
For catalog zone members in a group, the forwarding parameters will be taken from the group entry with the corresponding name.

The forwarding definitions will be written into a file ``$api_dir/catzone.$zonename``. :ref:`setting-yaml-webservice.api_dir` must be defined, the directory must exist and be writable by the :program:`Recursor` process.

IncomingWSConfig
^^^^^^^^^^^^^^^^
As of version 5.3.0, an incoming web server configuration is defined as

.. code-block:: yaml

   addresses: [] Sequence of SocketAddress
   tls:
     certificates: file containing full certificate chain in PEM format
     key: file containing private key in PEM format


A :ref:`setting-yaml-webservice.listen` section contains a sequence of `IncomingWSConfig`_, for example:

.. code-block:: yaml

  webservice:
    listen:
      - addresses: [127.0.0.1:8083, '[::]:8083']
        tls:
          certificate: fullchain.pem
          key: keyfile.key
      - addresses: [127.0.0.1:8084, '[::]:8084']

If no ``tls`` section is present, plaintext ``http`` connections are accepted on the listed addresses.

If a ``tls`` section is present, clients are required to use ``https`` to contact any of the address-port combinations listen in addresses. At the moment it is not possible to list additional properties of the TLS listener and encrypted key files cannot be used.


The YAML settings
-----------------

The notation ``section.name`` means that an entry ``name`` can appear in the YAML section ``section``.
So the entry ``recordcache.max_ttl`` will end up in settings file as follows:

.. code-block:: yaml

   recordcache:
     ...
     max_ttl: 3600
     ...

