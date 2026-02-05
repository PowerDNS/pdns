# This file contains the table used to generate old and new-style settings code
#
# Example:
# {
# 'name' : 'allow_from',
# 'section' : 'incoming',
# 'oldname' : 'allow-from'
# 'type' : LType.ListSubnets,
# 'default' : '127.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 192.168.0.0/16, 172.16.0.0/12, ::1/128, fc00::/7, fe80::/10',
# 'help' : 'If set, only allow these comma separated netmasks to recurse',
# 'doc' : '''
#  '''
# }
#
# See generate.py for a description of the fields.
#
# Sections
# - incoming
# - outgoing
# - packetcache
# - recursor
# - recordcache
# - dnssec
# - webservice
# - carbon
# - ecs
# - logging
# - nod
# - snmp

[
    {
        'name' : 'aggressive_nsec_cache_size',
        'section' : 'dnssec',
        'type' : LType.Uint64,
        'default' : '100000',
        'help' : 'The number of records to cache in the aggressive cache. If set to a value greater than 0, and DNSSEC processing or validation is enabled, the recursor will cache NSEC and NSEC3 records to generate negative answers, as defined in rfc8198',
        'doc' : '''
The number of records to cache in the aggressive cache. If set to a value greater than 0, the recursor will cache NSEC and NSEC3 records to generate negative answers, as defined in :rfc:`8198`.
To use this, DNSSEC processing or validation must be enabled by setting :ref:`setting-dnssec` to ``process``, ``log-fail`` or ``validate``.
 ''',
        'versionadded': '4.5.0',
        'runtime': 'set-max-aggr-nsec-cache-size',
    },
    {
        'name' : 'aggressive_cache_min_nsec3_hit_ratio',
        'section' : 'dnssec',
        'type' : LType.Uint64,
        'default' : '2000',
        'help' : 'The minimum expected hit ratio to store NSEC3 records into the aggressive cache',
        'doc' : '''
The limit for which to put NSEC3 records into the aggressive cache.
A value of ``n`` means that an NSEC3 record is only put into the aggressive cache if the estimated probability of a random name hitting the NSEC3 record is higher than ``1/n``.
A higher ``n`` will cause more records to be put into the aggressive cache, e.g. a value of 4000 will cause records to be put in the aggressive cache even if the estimated probability of hitting them is twice as low as would be the case for ``n=2000``.
A value of 0 means no NSEC3 records will be put into the aggressive cache.

For large zones the effectiveness of the NSEC3 cache is reduced since each NSEC3 record only covers a randomly distributed subset of all possible names.
This setting avoids doing unnecessary work for such large zones.
 ''',
        'versionadded' : '4.9.0',
    },
    {
        'name' : 'allow_from',
        'section' : 'incoming',
        'type' : LType.ListSubnets,
        'default' : '127.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 192.168.0.0/16, 172.16.0.0/12, ::1/128, fc00::/7, fe80::/10',
        'help' : 'If set, only allow these comma separated netmasks to recurse',
        'doc' : '''
Netmasks (both IPv4 and IPv6) that are allowed to use the server.
The default allows access only from :rfc:`1918` private IP addresses.
An empty value means no checking is done, all clients are allowed.
Due to the aggressive nature of the internet these days, it is highly recommended to not open up the recursor for the entire internet.
Questions from IP addresses not listed here are ignored and do not get an answer.

When the Proxy Protocol is enabled (see :ref:`setting-proxy-protocol-from`), the recursor will check the address of the client IP advertised in the Proxy Protocol header instead of the one of the proxy.

Note that specifying an IP address without a netmask uses an implicit netmask of /32 or /128.
 ''',
        'runtime': ['reload-acls'],
    },
    {
        'name' : 'allow_from_file',
        'section' : 'incoming',
        'type' : LType.String,
        'default' : '',
        'help' : 'If set, load allowed netmasks from this file',
        'doc' : '''
Like :ref:`setting-allow-from`, except reading from file.
Overrides the :ref:`setting-allow-from` setting. To use this feature, supply one netmask per line, with optional comments preceded by a '#'.
 ''',
        'doc-new' : '''
Like :ref:`setting-allow-from`, except reading a sequence of `Subnet`_ from file.
Overrides the :ref:`setting-allow-from` setting. Example content of th specified file:

.. code-block:: yaml

 - 127.0.0.1
 - ::1

 ''',
        'runtime': ['reload-acls'],
    },
    {
        'name' : 'allow_notify_for',
        'section' : 'incoming',
        'type' : LType.ListStrings,
        'default' : '',
        'help' : 'If set, NOTIFY requests for these zones will be allowed',
        'doc' : '''
Domain names specified in this list are used to permit incoming
NOTIFY operations to wipe any cache entries that match the domain
name. If this list is empty, all NOTIFY operations will be ignored.
Matching is done using suffix matching, it is allowed to NOTIFY a subdomain of a listed domain.
 ''',
        'versionadded': '4.6.0',
        'runtime': ['reload-acls'],
    },
    {
        'name' : 'allow_notify_for_file',
        'section' : 'incoming',
        'type' : LType.String,
        'default' : '',
        'help' : 'If set, load NOTIFY-allowed zones from this file',
        'doc' : '''
Like :ref:`setting-allow-notify-for`, except reading from file. To use this
feature, supply one domain name per line, with optional comments
preceded by a '#'.

NOTIFY-allowed zones can also be specified using :ref:`setting-forward-zones-file`.
 ''',
        'doc-new' : '''
Like :ref:`setting-allow-notify-for`, except reading a sequence of names from file. Example contents of specified file:

.. code-block:: yaml

 - example.com
 - example.org

 ''',
        'versionadded': '4.6.0',
        'runtime': ['reload-acls'],
    },
    {
        'name' : 'allow_notify_from',
        'section' : 'incoming',
        'type' : LType.ListSubnets,
        'default' : '',
        'help' : 'If set, NOTIFY requests from these comma separated netmasks will be allowed',
        'doc' : '''
Netmasks (both IPv4 and IPv6) that are allowed to issue NOTIFY operations
to the server.  NOTIFY operations from IP addresses not listed here are
ignored and do not get an answer.

When the Proxy Protocol is enabled (see :ref:`setting-proxy-protocol-from`), the
recursor will check the address of the client IP advertised in the
Proxy Protocol header instead of the one of the proxy.

Note that specifying an IP address without a netmask uses an implicit
netmask of /32 or /128.

NOTIFY operations received from a client listed in one of these netmasks
will be accepted and used to wipe any cache entries whose zones match
the zone specified in the NOTIFY operation, but only if that zone (or
one of its parents) is included in :ref:`setting-allow-notify-for`,
:ref:`setting-allow-notify-for-file`, or :ref:`setting-forward-zones-file` with a '^' prefix.
 ''',
        'doc-new' : '''
Subnets (both IPv4 and IPv6) that are allowed to issue NOTIFY operations
to the server.  NOTIFY operations from IP addresses not listed here are
ignored and do not get an answer.

When the Proxy Protocol is enabled (see :ref:`setting-proxy-protocol-from`), the
recursor will check the address of the client IP advertised in the
Proxy Protocol header instead of the one of the proxy.

Note that specifying an IP address without a netmask uses an implicit
netmask of /32 or /128.

NOTIFY operations received from a client listed in one of these netmasks
will be accepted and used to initiate a freshness check for an RPZ zone or wipe any cache entries whose zones match
the zone specified in the NOTIFY operation, but only if that zone (or
one of its parents) is included in :ref:`setting-allow-notify-for`,
:ref:`setting-allow-notify-for-file`, or :ref:`setting-forward-zones-file` with a ``allow_notify`` set to ``true``.
 ''',
        'versionadded': '4.6.0',
        'runtime': ['reload-acls'],
    },
    {
        'name' : 'allow_notify_from_file',
        'section' : 'incoming',
        'type' : LType.String,
        'default' : '',
        'help' : 'If set, load NOTIFY-allowed netmasks from this file',
        'doc' : '''
Like :ref:`setting-allow-notify-from`, except reading from file. To use this
feature, supply one netmask per line, with optional comments preceded
by a '#'.
 ''',
        'doc-new' : '''
Like :ref:`setting-allow-notify-from`, except reading a sequence of `Subnet`_ from file.
 ''',
        'versionadded': '4.6.0',
        'runtime': ['reload-acls'],
    },
    {
        'name' : 'allow_no_rd',
        'section' : 'incoming',
        'type' : LType.Bool,
        'default' : 'false',
        'help' : 'Allow \'no recursion desired (RD=0)\' queries.',
        'doc' : '''
Allow ``no recursion desired (RD=0) queries`` to query cache contents.
If not set (the default), these queries are answered with rcode ``Refused``.
 ''',
    'versionadded': '5.0.0'
    },
    {
        'name' : 'any_to_tcp',
        'section' : 'recursor',
        'type' : LType.Bool,
        'default' : 'true',
        'help' : 'Answer ANY queries with tc=1, shunting to TCP',
        'doc' : '''
Answer questions for the ANY type on UDP with a truncated packet that refers the remote client to TCP.
Useful for mitigating ANY reflection attacks.
 ''',
    'versionchanged': ('5.4.0', 'Default is enabled now, was disabled before 5.4.0'),
    },
    {
        'name' : 'any_to_tcp',
        'oldname': 'out-any-to-tcp',
        'section' : 'outgoing',
        'type' : LType.Bool,
        'default' : 'true',
        'help' : 'Use TCP for ANY queries to authoritative servers',
        'doc' : '''
Send out requests with qtype `ANY` using TCP.
 ''',
    'versionadded': '5.4.0',
    },
    {
        'name' : 'allow_trust_anchor_query',
        'section' : 'recursor',
        'type' : LType.Bool,
        'default' : 'false',
        'help' : 'Allow queries for trustanchor.server CH TXT and negativetrustanchor.server CH TXT',
        'doc' : '''
Allow ``trustanchor.server CH TXT`` and ``negativetrustanchor.server CH TXT`` queries to view the configured :doc:`DNSSEC <dnssec>` (negative) trust anchors.
 ''',
    'versionadded': '4.3.0'
    },
    {
        'name' : 'api_dir',
        'section' : 'webservice',
        'oldname' : 'api-config-dir',
        'type' : LType.String,
        'default' : '',
        'help' : 'Directory where REST API stores config and zones',
        'doc' : '''
Directory where the REST API stores its configuration and zones.
For configuration updates to work, :ref:`setting-include-dir` should have the same value when using old-style settings.
When using YAML settings :ref:`setting-yaml-recursor.include_dir` and :ref:`setting-yaml-webservice.api_dir` must have a different value.
 ''',
    'versionadded': '4.0.0'
     },
    {
        'name' : 'api_key',
        'section' : 'webservice',
        'type' : LType.String,
        'default' : '',
        'help' : 'Static pre-shared authentication key for access to the REST API',
        'doc' : '''
Static pre-shared authentication key for access to the REST API. Since 4.6.0 the key can be hashed and salted using ``rec_control hash-password`` instead of being stored in the configuration in plaintext, but the plaintext version is still supported.
 ''',
        'versionadded': '4.0.0',
        'versionchanged': ('4.6.0', 'This setting now accepts a hashed and salted version.')
    },
    {
        'name' : 'auth_zones',
        'section' : 'recursor',
        'type' : LType.ListAuthZones,
        'default' : '',
        'help' : 'Zones for which we have authoritative data, comma separated domain=file pairs',
        'doc' : '''
Zones read from these files (in BIND format) are served authoritatively (but without the AA bit set in responses).
DNSSEC is not supported. Example:

.. code-block:: none

 auth-zones=example.org=/var/zones/example.org, powerdns.com=/var/zones/powerdns.com
 ''',
        'doc-new' : '''
Zones read from these files (in BIND format) are served authoritatively (but without the AA bit set in responses).
DNSSEC is not supported. Example:

.. code-block:: yaml

  recursor:
    auth_zones:
      - zone: example.org
        file: /var/zones/example.org
      - zone: powerdns.com
        file: /var/zones/powerdns.com
 ''',
        'runtime': ['reload-zones'],
    },
    {
        'name' : 'interval',
        'section' : 'carbon',
        'oldname' : 'carbon-interval',
        'type' : LType.Uint64,
        'default' : '30',
        'help' : 'Number of seconds between carbon (graphite) updates',
        'doc' : '''
If sending carbon updates, this is the interval between them in seconds.
See :doc:`metrics`.
 ''',
    },
    {
        'name' : 'ns',
        'section' : 'carbon',
        'oldname' : 'carbon-namespace',
        'type' : LType.String,
        'default' : 'pdns',
        'help' : 'If set overwrites the first part of the carbon string',
        'doc' : '''
Change the namespace or first string of the metric key. The default is pdns.
 ''',
    'versionadded': '4.2.0'
    },
    {
        'name' : 'ourname',
        'section' : 'carbon',
        'oldname' : 'carbon-ourname',
        'type' : LType.String,
        'default' : '',
        'help' : 'If set, overrides our reported hostname for carbon stats',
        'doc' : '''
If sending carbon updates, if set, this will override our hostname.
Be careful not to include any dots in this setting, unless you know what you are doing.
See :ref:`metricscarbon`.
 ''',
    },
    {
        'name' : 'instance',
        'section' : 'carbon',
        'oldname' : 'carbon-instance',
        'type' : LType.String,
        'default' : 'recursor',
        'help' : 'If set overwrites the instance name default',
        'doc' : '''
Change the instance or third string of the metric key. The default is recursor.
 ''',
    'versionadded': '4.2.0'
    },
    {
        'name' : 'server',
        'section' : 'carbon',
        'oldname' : 'carbon-server',
        'type' : LType.ListSocketAddresses,
        'default' : '',
        'help' : 'If set, send metrics in carbon (graphite) format to this server IP address',
        'doc' : '''
If set to an IP or IPv6 address, will send all available metrics to this server via the carbon protocol, which is used by graphite and metronome. Moreover you can specify more than one server using a comma delimited list, ex: carbon-server=10.10.10.10,10.10.10.20.
You may specify an alternate port by appending :port, for example: ``127.0.0.1:2004``.
See :doc:`metrics`.
 ''',
        'doc-new' : '''
Will send all available metrics to these servers via the carbon protocol, which is used by graphite and metronome.
See :doc:`metrics`.
 ''',
        'runtime': 'set-carbon-server',
    },
    {
        'name' : 'chroot',
        'section' : 'recursor',
        'type' : LType.String,
        'default' : '',
        'help' : 'switch to chroot jail',
        'doc' : '''
If set, chroot to this directory for more security.
This is not recommended; instead, we recommend containing PowerDNS using operating system features.
We ship systemd unit files with our packages to make this easy.

Make sure that ``/dev/log`` is available from within the chroot.
Logging will silently fail over time otherwise (on logrotate).

When using ``chroot``, all other paths (except for :ref:`setting-config-dir`) set in the configuration are relative to the new root.

When running on a system where systemd manages services, ``chroot`` does not work out of the box, as PowerDNS cannot use the ``NOTIFY_SOCKET``.
Either do not ``chroot`` on these systems or set the 'Type' of this service to 'simple' instead of 'notify' (refer to the systemd documentation on how to modify unit-files).
 ''',
    },
    {
        'name' : 'tcp_timeout',
        'section' : 'incoming',
        'oldname' : 'client-tcp-timeout',
        'type' : LType.Uint64,
        'default' : '2',
        'help' : 'Timeout in seconds when talking to TCP clients',
        'doc' : '''
Time to wait for data from TCP clients.
 ''',
    },
    {
        'name' : 'config',
        'section' : 'commands',
        'type' : LType.Command,
        'default' : 'no',
        'help' : 'Output blank configuration. You can use --config=check to test the config file and command line arguments.',
        'doc' : '''
EMPTY?  '''
    },
    {
        'name' : 'config_dir',
        'section' : 'recursor',
        'type' : LType.String,
        'default' : 'SYSCONFDIR',
        'docdefault': 'Determined by distribution',
        'help' : 'Location of configuration directory (recursor.conf or recursor.yml)',
        'doc' : '''
Location of configuration directory (where ``recursor.conf`` or ``recursor.yml`` is stored).
Usually ``/etc/powerdns``, but this depends on ``SYSCONFDIR`` during compile-time.
Use default or set on command line.
 ''',
    },
    {
        'name' : 'config_name',
        'section' : 'recursor',
        'type' : LType.String,
        'default' : '',
        'help' : 'Name of this virtual configuration - will rename the binary image',
        'doc' : '''
When running multiple recursors on the same server, read settings from :file:`recursor-{name}.conf`, this will also rename the binary image.
 ''',
    },
    {
        'name' : 'cpu_map',
        'section' : 'recursor',
        'type' : LType.String,
        'default' : '',
        'help' : 'Thread to CPU mapping, space separated thread-id=cpu1,cpu2..cpuN pairs',
        'doc' : '''
Set CPU affinity for threads, asking the scheduler to run those threads on a single CPU, or a set of CPUs.
This parameter accepts a space separated list of thread-id=cpu-id, or thread-id=cpu-id-1,cpu-id-2,...,cpu-id-N.
For example, to make the worker thread 0 run on CPU id 0 and the worker thread 1 on CPUs 1 and 2::

  cpu-map=0=0 1=1,2

The thread handling the control channel, the webserver and other internal stuff has been assigned id 0, the distributor
threads if any are assigned id 1 and counting, and the worker threads follow behind.
The number of distributor threads is determined by :ref:`setting-distributor-threads`, the number of worker threads is determined by the :ref:`setting-threads` setting.

This parameter is only available if the OS provides the ``pthread_setaffinity_np()`` function.

Note that, depending on the configuration, the Recursor can start more threads.
Typically these threads will sleep most of the time.
These threads cannot be specified in this setting as their thread-ids are left unspecified.
 ''',
        'doc-new' : '''
Set CPU affinity for threads, asking the scheduler to run those threads on a single CPU, or a set of CPUs.
This parameter accepts a space separated list of thread-id=cpu-id, or thread-id=cpu-id-1,cpu-id-2,...,cpu-id-N.
For example, to make the worker thread 0 run on CPU id 0 and the worker thread 1 on CPUs 1 and 2:

.. code-block:: yaml

  recursor:
    cpu_map: 0=0 1=1,2

The thread handling the control channel, the webserver and other internal stuff has been assigned id 0, the distributor
threads if any are assigned id 1 and counting, and the worker threads follow behind.
The number of distributor threads is determined by :ref:`setting-distributor-threads`, the number of worker threads is determined by the :ref:`setting-threads` setting.

This parameter is only available if the OS provides the ``pthread_setaffinity_np()`` function.

Note that, depending on the configuration, the Recursor can start more threads.
Typically these threads will sleep most of the time.
These threads cannot be specified in this setting as their thread-ids are left unspecified.
 ''',
    },
    {
        'name' : 'daemon',
        'section' : 'recursor',
        'type' : LType.Bool,
        'default' : 'false',
        'help' : 'Operate as a daemon',
        'doc' : '''
Operate in the background.
 ''',
        'versionchanged': ('4.0.0', 'Default is now ``no``, was ``yes`` before.')
    },
    {
        'name' : 'dont_throttle_names',
        'section' : 'outgoing',
        'type' : LType.ListStrings,
        'default' : '',
        'help' : 'Do not throttle nameservers with this name or suffix',
        'doc' : '''
When an authoritative server does not answer a query or sends a reply that the recursor does not like, it is throttled.
Any servers' name suffix-matching the supplied names will never be throttled.

.. warning::
  Most servers on the internet do not respond for a good reason (overloaded or unreachable), ``dont-throttle-names`` could make this load on the upstream server even higher, resulting in further service degradation.
 ''',
        'versionadded': '4.2.0',
        'runtime': ['add-dont-throttle-names', 'clear-dont-throttle-names'],
    },
    {
        'name' : 'dont_throttle_netmasks',
        'section' : 'outgoing',
        'type' : LType.ListSubnets,
        'default' : '',
        'help' : 'Do not throttle nameservers with this IP netmask',
        'doc' : '''
When an authoritative server does not answer a query or sends a reply that the recursor does not like, it is throttled.
Any servers matching the supplied netmasks will never be throttled.

This can come in handy on lossy networks when forwarding, where the same server is configured multiple times (e.g. with ``forward-zones-recurse=example.com=192.0.2.1;192.0.2.1``).
By default, the PowerDNS Recursor would throttle the 'first' server on a timeout and hence not retry the 'second' one.
In this case, ``dont-throttle-netmasks`` could be set to ``192.0.2.1``.

.. warning::
  Most servers on the internet do not respond for a good reason (overloaded or unreachable), ``dont-throttle-netmasks`` could make this load on the upstream server even higher, resulting in further service degradation.
 ''',
        'doc-new' : '''
When an authoritative server does not answer a query or sends a reply that the recursor does not like, it is throttled.
Any servers matching the supplied netmasks will never be throttled.

This can come in handy on lossy networks when forwarding, where the same server is configured multiple times (e.g. with ``forward_zones_recurse: [ {zone: example.com, forwarders: [ 192.0.2.1, 192.0.2.1 ] } ]``.
By default, the PowerDNS Recursor would throttle the 'first' server on a timeout and hence not retry the 'second' one.
In this case, :ref:`setting-dont-throttle-netmasks` could be set to include ``192.0.2.1``.

.. warning::
  Most servers on the internet do not respond for a good reason (overloaded or unreachable), ``dont-throttle-netmasks`` could make this load on the upstream server even higher, resulting in further service degradation.
 ''',
        'versionadded': '4.2.0',
        'runtime': ['rec_control add-dont-throttle-netmasks', 'rec_control clear-dont-throttle-netmask'],
    },
    {
        'name' : 'devonly_regression_test_mode',
        'section' : 'recursor',
        'type' : LType.Bool,
        'default' : 'false',
        'help' : 'internal use only',
        'doc' : 'SKIP',
    },
    {
        'name' : 'disable',
        'section' : 'packetcache',
        'oldname' : 'disable-packetcache',
        'type' : LType.Bool,
        'default' : 'false',
        'help' : 'Disable packetcache',
        'doc' : '''
Turn off the packet cache. Useful when running with Lua scripts that modify answers in such a way they cannot be cached, though individual answer caching can be controlled from Lua as well.
 ''',
    },
    {
        'name' : 'disable_syslog',
        'section' : 'logging',
        'type' : LType.Bool,
        'default' : 'false',
        'help' : 'Disable logging to syslog, useful when running inside a supervisor that logs stderr',
        'doc' : '''
Do not log to syslog, only to stderr.
Use this setting when running inside a supervisor that handles logging (like systemd).
**Note**: do not use this setting in combination with :ref:`setting-daemon` as all logging will disappear.
 ''',
    },
    {
        'name' : 'distribution_load_factor',
        'section' : 'incoming',
        'type' : LType.Double,
        'default' : '0.0',
        'help' : 'The load factor used when PowerDNS is distributing queries to worker threads',
        'doc' : '''
If :ref:`setting-pdns-distributes-queries` is set and this setting is set to another value
than 0, the distributor thread will use a bounded load-balancing algorithm while
distributing queries to worker threads, making sure that no thread is assigned
more queries than distribution-load-factor times the average number of queries
currently processed by all the workers.
For example, with a value of 1.25, no server should get more than 125 % of the
average load. This helps making sure that all the workers have roughly the same
share of queries, even if the incoming traffic is very skewed, with a larger
number of requests asking for the same qname.
 ''',
    'versionadded': '4.1.12'
    },
    {
        'name' : 'distribution_pipe_buffer_size',
        'section' : 'incoming',
        'type' : LType.Uint64,
        'default' : '0',
        'help' : 'Size in bytes of the internal buffer of the pipe used by the distributor to pass incoming queries to a worker thread',
        'doc' : '''
Size in bytes of the internal buffer of the pipe used by the distributor to pass incoming queries to a worker thread.
Requires support for `F_SETPIPE_SZ` which is present in Linux since 2.6.35. The actual size might be rounded up to
a multiple of a page size. 0 means that the OS default size is used.
A large buffer might allow the recursor to deal with very short-lived load spikes during which a worker thread gets
overloaded, but it will be at the cost of an increased latency.
 ''',
    'versionadded': '4.2.0'
    },
    {
        'name' : 'distributor_threads',
        'section' : 'incoming',
        'type' : LType.Uint64,
        'default' : '0',
        'docdefault' : '1 if :ref:`setting-pdns-distributes-queries` is set, 0 otherwise',
        'help' : 'Launch this number of distributor threads, distributing queries to other threads',
        'doc' : '''
If :ref:`setting-pdns-distributes-queries` is set, spawn this number of distributor threads on startup. Distributor threads
handle incoming queries and distribute them to other threads based on a hash of the query.
 ''',
    'versionadded': '4.2.0'
    },
    {
        'name' : 'dot_to_auth_names',
        'section' : 'outgoing',
        'type' : LType.ListStrings,
        'default' : '',
        'help' : 'Use DoT to authoritative servers with these names or suffixes',
        'doc' : '''
Force DoT to the listed authoritative nameservers. For this to work, DoT support has to be compiled in.
Currently, the certificate is not checked for validity in any way.
 ''',
    'versionadded': '4.6.0'
    },
    {
        'name' : 'dot_to_port_853',
        'section' : 'outgoing',
        'type' : LType.Bool,
        'default' : 'true',
        'help' : 'Force DoT connection to target port 853 if DoT compiled in',
        'doc' : '''
Enable DoT to forwarders that specify port 853.
 ''',
    'versionadded': '4.6.0'
    },
    {
        'name' : 'dns64_prefix',
        'section' : 'recursor',
        'type' : LType.String,
        'default' : '',
        'help' : 'DNS64 prefix',
        'doc' : '''
Enable DNS64 (:rfc:`6147`) support using the supplied /96 IPv6 prefix. This will generate 'fake' ``AAAA`` records for names
with only ``A`` records, as well as 'fake' ``PTR`` records to make sure that reverse lookup of DNS64-generated IPv6 addresses
generate the right name.
See :doc:`dns64` for more flexible but slower alternatives using Lua.
 ''',
    'versionadded': '4.4.0'
    },
    {
        'name' : 'validation',
        'section' : 'dnssec',
        'oldname' : 'dnssec',
        'type' : LType.String,
        'default' : 'process',
        'help' : 'DNSSEC mode: off/process-no-validate/process (default)/log-fail/validate',
        'doc' : '''
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
 ''',
        'versionadded': '4.0.0',
        'versionchanged': ('4.5.0',
   'The default changed from ``process-no-validate`` to ``process``')
    },
    {
        'name' : 'disabled_algorithms',
        'section' : 'dnssec',
        'oldname' : 'dnssec-disabled-algorithms',
        'type' : LType.ListStrings,
        'default' : '',
        'help' : 'List of DNSSEC algorithm numbers that are considered unsupported',
        'doc' : '''
A list of DNSSEC algorithm numbers that should be considered disabled.
These algorithms will not be used to validate DNSSEC signatures.
Zones (only) signed with these algorithms will be considered ``Insecure``.

If this setting is empty (the default), :program:`Recursor` will determine which algorithms to disable automatically.
This is done for specific algorithms only, currently algorithms 5 (``RSASHA1``) and 7 (``RSASHA1NSEC3SHA1``).

This is important on systems that have a default strict crypto policy, like RHEL9 derived systems.
On such systems not disabling some algorithms (or changing the security policy) will make affected zones to be considered ``Bogus`` as using these algorithms fails.
 ''',
    'versionadded': '4.9.0'
    },
    {
        'name' : 'log_bogus',
        'section' : 'dnssec',
        'oldname' : 'dnssec-log-bogus',
        'type' : LType.Bool,
        'default' : 'false',
        'help' : 'Log DNSSEC bogus validations',
        'doc' : '''
Log every DNSSEC validation failure.
**Note**: This is not logged per-query but every time records are validated as Bogus.
 ''',
        'runtime': 'set-dnssec-log-bogus',
    },
    {
        'name' : 'dont_query',
        'section' : 'outgoing',
        'type' : LType.ListSubnets,
        'default' : '127.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 169.254.0.0/16, 192.168.0.0/16, 172.16.0.0/12, ::1/128, fc00::/7, fe80::/10, 0.0.0.0/8, 192.0.0.0/24, 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 240.0.0.0/4, ::/96, ::ffff:0:0/96, 100::/64, 2001:db8::/32',
        'help' : 'If set, do not query these netmasks for DNS data',
        'doc' : '''
The DNS is a public database, but sometimes contains delegations to private IP addresses, like for example 127.0.0.1.
This can have odd effects, depending on your network, and may even be a security risk.
Therefore, the PowerDNS Recursor by default does not query private space IP addresses.
This setting can be used to expand or reduce the limitations.

Queries for names in forward zones and to addresses as configured in any of the settings :ref:`setting-forward-zones`, :ref:`setting-forward-zones-file` or :ref:`setting-forward-zones-recurse` are performed regardless of these limitations. However, if NS records are learned from :ref:`setting-forward-zones` and the IP addresses of the nameservers learned in that way are included in :ref:`setting-dont-query`, lookups relying on these nameservers will fail with SERVFAIL.
 ''',
    },
    {
        'name' : 'add_for',
        'section' : 'ecs',
        'oldname' : 'ecs-add-for',
        'type' : LType.ListSubnets,
        'default' : '0.0.0.0/0, ::/0, !127.0.0.0/8, !10.0.0.0/8, !100.64.0.0/10, !169.254.0.0/16, !192.168.0.0/16, !172.16.0.0/12, !::1/128, !fc00::/7, !fe80::/10',
        'help' : 'List of client netmasks for which EDNS Client Subnet will be added',
        'doc' : '''
List of requestor netmasks for which the requestor IP Address should be used as the :rfc:`EDNS Client Subnet <7871>` for outgoing queries. Outgoing queries for requestors that do not match this list will use the :ref:`setting-ecs-scope-zero-address` instead.
Valid incoming ECS values from :ref:`setting-use-incoming-edns-subnet` are not replaced.

Regardless of the value of this setting, ECS values are only sent for outgoing queries matching the conditions in the :ref:`setting-edns-subnet-allow-list` setting. This setting only controls the actual value being sent.

This defaults to not using the requestor address inside RFC1918 and similar 'private' IP address spaces.
 ''',
    'versionadded': '4.2.0'
    },
    {
        'name' : 'ipv4_bits',
        'section' : 'ecs',
        'oldname' : 'ecs-ipv4-bits',
        'type' : LType.Uint64,
        'default' : '24',
        'help' : 'Number of bits of IPv4 address to pass for EDNS Client Subnet',
        'doc' : '''
Number of bits of client IPv4 address to pass when sending EDNS Client Subnet address information.
 ''',
        'versionadded': '4.1.0',
    },
    {
        'name' : 'ipv4_cache_bits',
        'section' : 'ecs',
        'oldname' : 'ecs-ipv4-cache-bits',
        'type' : LType.Uint64,
        'default' : '24',
        'help' : 'Maximum number of bits of IPv4 mask to cache ECS response',
        'doc' : '''
Maximum number of bits of client IPv4 address used by the authoritative server (as indicated by the EDNS Client Subnet scope in the answer) for an answer to be inserted into the record cache. This condition applies in conjunction with ``ecs-cache-limit-ttl``.
That is, only if both the limits apply, the record will not be cached. This decision can be overridden by ``ecs-ipv4-never-cache`` and ``ecs-ipv6-never-cache``.
 ''',
    'versionadded': '4.1.12'
    },
    {
        'name' : 'ipv6_bits',
        'section' : 'ecs',
        'oldname' : 'ecs-ipv6-bits',
        'type' : LType.Uint64,
        'default' : '56',
        'help' : 'Number of bits of IPv6 address to pass for EDNS Client Subnet',
        'doc' : '''
Number of bits of client IPv6 address to pass when sending EDNS Client Subnet address information.
 ''',
    'versionadded': '4.1.0'
    },
    {
        'name' : 'ipv6_cache_bits',
        'section' : 'ecs',
        'oldname' : 'ecs-ipv6-cache-bits',
        'type' : LType.Uint64,
        'default' : '56',
        'help' : 'Maximum number of bits of IPv6 mask to cache ECS response',
        'doc' : '''
Maximum number of bits of client IPv6 address used by the authoritative server (as indicated by the EDNS Client Subnet scope in the answer) for an answer to be inserted into the record cache. This condition applies in conjunction with ``ecs-cache-limit-ttl``.
That is, only if both the limits apply, the record will not be cached. This decision can be overridden by ``ecs-ipv4-never-cache`` and ``ecs-ipv6-never-cache``.
 ''',
    'versionadded': '4.1.12'
    },
    {
        'name' : 'ipv4_never_cache',
        'section' : 'ecs',
        'oldname' : 'ecs-ipv4-never-cache',
        'type' : LType.Bool,
        'default' : 'false',
        'help' : 'If we should never cache IPv4 ECS responses',
        'doc' : '''
When set, never cache replies carrying EDNS IPv4 Client Subnet scope in the record cache.
In this case the decision made by ``ecs-ipv4-cache-bits`` and ``ecs-cache-limit-ttl`` is no longer relevant.
 ''',
    'versionadded': '4.5.0'
    },
    {
        'name' : 'ipv6_never_cache',
        'section' : 'ecs',
        'oldname' : 'ecs-ipv6-never-cache',
        'type' : LType.Bool,
        'default' : 'false',
        'help' : 'If we should never cache IPv6 ECS responses',
        'doc' : '''
When set, never cache replies carrying EDNS IPv6 Client Subnet scope in the record cache.
In this case the decision made by ``ecs-ipv6-cache-bits`` and ``ecs-cache-limit-ttl`` is no longer relevant.
 ''',
    'versionadded': '4.5.0'
    },
    {
        'name' : 'minimum_ttl_override',
        'section' : 'ecs',
        'oldname' : 'ecs-minimum-ttl-override',
        'type' : LType.Uint64,
        'default' : '1',
        'help' : 'The minimum TTL for records in ECS-specific answers',
        'doc' : '''
This setting artificially raises the TTLs of records in the ANSWER section of ECS-specific answers to be at least this long.
Setting this to a value greater than 1 technically is an RFC violation, but might improve performance a lot.
Using a value of 0 impacts performance of TTL 0 records greatly, since it forces the recursor to contact
authoritative servers every time a client requests them.
 ''',
        'versionchanged': ('4.5.0', 'Old versions used default 0.'),
        'runtime': 'set-ecs-minimum-ttl',
    },
    {
        'name' : 'cache_limit_ttl',
        'section' : 'ecs',
        'oldname' : 'ecs-cache-limit-ttl',
        'type' : LType.Uint64,
        'default' : '0',
        'help' : 'Minimum TTL to cache ECS response',
        'doc' : '''
The minimum TTL for an ECS-specific answer to be inserted into the record cache. This condition applies in conjunction with ``ecs-ipv4-cache-bits`` or ``ecs-ipv6-cache-bits``.
That is, only if both the limits apply, the record will not be cached. This decision can be overridden by ``ecs-ipv4-never-cache`` and ``ecs-ipv6-never-cache``.
 ''',
    'versionadded': '4.1.12'
    },
    {
        'name' : 'scope_zero_address',
        'section' : 'ecs',
        'oldname' : 'ecs-scope-zero-address',
        'type' : LType.String,
        'default' : '',
        'help' : 'Address to send to allow-listed authoritative servers for incoming queries with ECS prefix-length source of 0',
        'doc' : '''
The IP address sent via EDNS Client Subnet to authoritative servers listed in
:ref:`setting-edns-subnet-allow-list` when :ref:`setting-use-incoming-edns-subnet` is set and the query has
an ECS source prefix-length set to 0.
The default is to look for the first usable (not an ``any`` one) address in
:ref:`setting-query-local-address` (starting with IPv4). If no suitable address is
found, the recursor fallbacks to sending 127.0.0.1.
 ''',
    'versionadded': '4.1.0'
    },
    {
        'name' : 'edns_bufsize',
        'section' : 'outgoing',
        'oldname' : 'edns-outgoing-bufsize',
        'type' : LType.Uint64,
        'default' : '1232',
        'help' : 'Outgoing EDNS buffer size',
        'doc' : '''
.. note:: Why 1232?

  1232 is the largest number of payload bytes that can fit in the smallest IPv6 packet.
  IPv6 has a minimum MTU of 1280 bytes (:rfc:`RFC 8200, section 5 <8200#section-5>`), minus 40 bytes for the IPv6 header, minus 8 bytes for the UDP header gives 1232, the maximum payload size for the DNS response.

This is the value set for the EDNS0 buffer size in outgoing packets.
Lower this if you experience timeouts.
 ''',
     'versionchanged': ('4.2.0', 'Before 4.2.0, the default was 1680')
    },
    {
        'name' : 'edns_padding_from',
        'section' : 'incoming',
        'type' : LType.ListSubnets,
        'default' : '',
        'help' : 'List of netmasks (proxy IP in case of proxy-protocol presence, client IP otherwise) for which EDNS padding will be enabled in responses, provided that \'edns-padding-mode\' applies',
        'doc' : '''
List of netmasks (proxy IP in case of proxy-protocol presence, client IP otherwise) for which EDNS padding will be enabled in responses, provided that :ref:`setting-edns-padding-mode` applies.
 ''',
        'versionadded' : '4.5.0',
        'versionchanged' : ('5.0.5', 'YAML settings only: previously this was defined as a string instead of a sequence')
    },
    {
        'name' : 'edns_padding_mode',
        'section' : 'incoming',
        'type' : LType.String,
        'default' : 'padded-queries-only',
        'help' : 'Whether to add EDNS padding to all responses (\'always\') or only to responses for queries containing the EDNS padding option (\'padded-queries-only\', the default). In both modes, padding will only be added to responses for queries coming from \'setting-edns-padding-from\' sources',
        'doc' : '''
One of ``always``, ``padded-queries-only``.
Whether to add EDNS padding to all responses (``always``) or only to responses for queries containing the EDNS padding option (``padded-queries-only``, the default).
In both modes, padding will only be added to responses for queries coming from :ref:`setting-edns-padding-from` sources.
 ''',
    'versionadded': '4.5.0'
    },
    {
        'name' : 'edns_padding',
        'section' : 'outgoing',
        'oldname' : 'edns-padding-out',
        'type' : LType.Bool,
        'default' : 'true',
        'help' : 'Whether to add EDNS padding to outgoing DoT messages',
        'doc' : '''
Whether to add EDNS padding to outgoing DoT queries.
 ''',
    'versionadded': '4.8.0'
    },
    {
        'name' : 'edns_padding_tag',
        'section' : 'incoming',
        'type' : LType.Uint64,
        'default' : '7830',
        'help' : 'Packetcache tag associated to responses sent with EDNS padding, to prevent sending these to clients for which padding is not enabled.',
        'doc' : '''
The packetcache tag to use for padded responses, to prevent a client not allowed by the :ref:`setting-edns-padding-from` list to be served a cached answer generated for an allowed one. This
effectively divides the packet cache in two when :ref:`setting-edns-padding-from` is used. Note that this will not override a tag set from one of the ``Lua`` hooks.
 ''',
    'versionadded': '4.5.0'
    },
    {
        'name' : 'edns_subnet_allow_list',
        'section' : 'outgoing',
        'type' : LType.ListStrings,
        'default' : '',
        'help' : 'List of netmasks and domains that we should enable EDNS subnet for',
        'doc' : '''
List of netmasks and domains that :rfc:`EDNS Client Subnet <7871>` should be enabled for in outgoing queries.

For example, an EDNS Client Subnet option containing the address of the initial requestor (but see :ref:`setting-ecs-add-for`) will be added to an outgoing query sent to server 192.0.2.1 for domain X if 192.0.2.1 matches one of the supplied netmasks, or if X matches one of the supplied domains.
The initial requestor address will be truncated to 24 bits for IPv4 (see :ref:`setting-ecs-ipv4-bits`) and to 56 bits for IPv6 (see :ref:`setting-ecs-ipv6-bits`), as recommended in the privacy section of RFC 7871.


Note that this setting describes the destination of outgoing queries, not the sources of incoming queries, nor the subnets described in the EDNS Client Subnet option.

By default, this option is empty, meaning no EDNS Client Subnet information is sent.
 ''',
    'versionadded': '4.5.0'
    },
    {
        'name' : 'edns_subnet_harden',
        'section' : 'outgoing',
        'type' : LType.Bool,
        'default' : 'false',
        'help' : 'Do more strict checking or EDNS Client Subnet information returned by authoritative servers',
        'doc' : '''
Do more strict checking or EDNS Client Subnet information returned by authoritative servers.
Answers missing ECS information will be ignored and followed up by an ECS-less query.
 ''',
    'versionadded': ['5.2.4', '5.1.6', '5.0.12']
    },
    {
        'name' : 'enable_old_settings',
        'section' : 'recursor',
        'type' : LType.Bool,
        'default' : 'false',
        'help' : 'Enable (deprecated) parsing of old-style settings',
        'doc' : '''
Enable the deprecated parsing of old-style settings.
Only makes sense to set on the command line.
        ''',
        'skip-yaml': True,
        'versionadded': '5.2.0',
    },
    {
        'name' : 'entropy_source',
        'section' : 'recursor',
        'type' : LType.String,
        'default' : '/dev/urandom',
        'help' : '',
        'doc' : '''
 ''',
        'skip-yaml': True,
        'versionchanged': ('4.9.0', 'This setting is no longer used.'),
    },
    {
        'name' : 'etc_hosts_file',
        'section' : 'recursor',
        'type' : LType.String,
        'default' : '/etc/hosts',
        'help' : 'Path to \'hosts\' file',
        'doc' : '''
The path to the /etc/hosts file, or equivalent.
This file can be used to serve data authoritatively using :ref:`setting-export-etc-hosts`.
 ''',
    },
    {
        'name' : 'event_trace_enabled',
        'section' : 'recursor',
        'type' : LType.Uint64,
        'default' : '0',
        'help' : 'If set, event traces are collected and send out via protobuf logging (1), logfile (2), opentelemetry trace data (4) or a combination',
        'doc' : '''
Enable the recording and logging of ref:`event traces`. This is an experimental feature and subject to change.
Possible values are 0: (disabled), 1 (add information to protobuf logging messages), 2 (write to log), 4 (output OpenTelemetry Trace data in protobuf logging messages, since version 5.3.0). Values can be added to get multiple types of logging simultaneously.
For example, 6 means: write to log and output OpenTelemetry Trace data in the protobuf stream.
 ''',
        'versionadded': '4.6.0',
        'versionchanged': ('5.3.0', 'A value to generate OpenTelemetry Trace data was added'),
        'runtime': 'set-event-trace-enabled',
    },
    {
        'name' : 'export_etc_hosts',
        'section' : 'recursor',
        'type' : LType.Bool,
        'default' : 'false',
        'help' : 'If we should serve up contents from /etc/hosts',
        'doc' : '''
If set, this flag will export the host names and IP addresses mentioned in ``/etc/hosts``.
 ''',
    },
    {
        'name' : 'export_etc_hosts_search_suffix',
        'section' : 'recursor',
        'type' : LType.String,
        'default' : '',
        'help' : 'Also serve up the contents of /etc/hosts with this suffix',
        'doc' : '''
If set, all hostnames in the :ref:`setting-export-etc-hosts` file are loaded in canonical form, based on this suffix, unless the name contains a '.', in which case the name is unchanged.
So an entry called 'pc' with ``export-etc-hosts-search-suffix='home.com'`` will lead to the generation of 'pc.home.com' within the recursor.
An entry called 'server1.home' will be stored as 'server1.home', regardless of this setting.
 ''',
    },
    {
        'name' : 'extended_resolution_errors',
        'section' : 'recursor',
        'type' : LType.Bool,
        'default' : 'true',
        'help' : 'If set, send an EDNS Extended Error extension on resolution failures, like DNSSEC validation errors',
        'doc' : '''
If set, the recursor will add an EDNS Extended Error (:rfc:`8914`) to responses when resolution failed, like DNSSEC validation errors, explaining the reason it failed. This setting is not needed to allow setting custom error codes from Lua or from a RPZ hit.
 ''',
        'versionadded': '4.5.0',
        'versionchanged': ('5.0.0', 'Default changed to enabled, previously it was disabled.'),
    },
    {
        'name' : 'forward_zones',
        'section' : 'recursor',
        'type' : LType.ListForwardZones,
        'default' : '',
        'help' : 'Zones for which we forward queries, comma separated domain=ip pairs',
        'doc' : '''
Queries for zones listed here will be forwarded to the IP address listed. i.e.

.. code-block:: none

    forward-zones=example.org=203.0.113.210, powerdns.com=2001:DB8::BEEF:5

Multiple IP addresses can be specified and port numbers other than 53 can be configured:

.. code-block:: none

    forward-zones=example.org=203.0.113.210:5300;127.0.0.1, powerdns.com=127.0.0.1;198.51.100.10:530;[2001:DB8::1:3]:5300

Forwarded queries have the ``recursion desired (RD)`` bit set to ``0``, meaning that this setting is intended to forward queries to authoritative servers.
If an ``NS`` record set for a subzone of the forwarded zone is learned, that record set will be used to determine addresses for name servers of the subzone.
This allows e.g. a forward to a local authoritative server holding a copy of the root zone, delegations received from that server will work.

**Note**: When an ``NS`` record for a subzone is learned and the IP address for that nameserver is included in the IP ranges in :ref:`setting-dont-query`,
SERVFAIL is returned.

**IMPORTANT**: When using DNSSEC validation (which is default), forwards to non-delegated (e.g. internal) zones that have a DNSSEC signed parent zone will validate as Bogus.
To prevent this, add a Negative Trust Anchor (NTA) for this zone in the :ref:`setting-lua-config-file` with ``addNTA('your.zone', 'A comment')``.
If this forwarded zone is signed, instead of adding NTA, add the DS record to the :ref:`setting-lua-config-file`.
See the :doc:`dnssec` information.
 ''',
        'doc-new' : '''
Queries for zones listed here will be forwarded to the IP address listed. i.e.

.. code-block:: yaml

 recursor:
   forward_zones:
     - zone: example.org
       forwarders:
       - 203.0.113.210
     - zone: powerdns.com
       forwarders:
       - 2001:DB8::BEEF:5

Multiple IP addresses can be specified and port numbers other than 53 can be configured:

.. code-block:: yaml

  recursor:
    forward_zones:
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
To forward to a recursive resolver use :ref:`setting-yaml-recursor.forward_zones_recurse`.

.. warning::
  When using DNSSEC validation (which is default), forwards to non-delegated (e.g. internal) zones that have a DNSSEC signed parent zone will validate as ``Bogus``.
  To prevent this, add a Negative Trust Anchor (NTA) for this zone in the :ref:`setting-lua-config-file` with :func:`addNTA`.
  If this forwarded zone is signed, instead of adding NTA, add the DS record to the :ref:`setting-lua-config-file` using :func:`addTA`.
  See the :doc:`dnssec` information.
  When using trust anchors listed in a YAML settings file, use the :ref:`setting-yaml-dnssec.trustanchors` and :ref:`setting-yaml-dnssec.negative_trustanchors` clauses.

.. note::
  The ``recurse`` field of a `Forward Zone`_ is fixed to ``false`` in the context of :ref:`setting-yaml-recursor.forward_zones`.

.. note::
  When an ``NS`` record for a subzone is learned and the IP address for that nameserver is included in the IP ranges in :ref:`setting-dont-query`, SERVFAIL is returned.
 ''',
        'versionchanged' : ('5.2.0',  'Zones having ``notify_allowed`` set will be added to :ref:`setting-yaml-incoming.allow_notify_for`.'),
        'runtime': ['reload-zones'],
    },
    {
        'name' : 'forward_zones_file',
        'section' : 'recursor',
        'type' : LType.String,
        'default' : '',
        'help' : 'File with (+)domain=ip pairs for forwarding',
        'doc' : '''
Same as :ref:`setting-forward-zones`, parsed from a file. Only 1 zone is allowed per line, specified as follows:

.. code-block:: none

    example.org=203.0.113.210, 192.0.2.4:5300

Zones prefixed with a ``+`` are treated as with
:ref:`setting-forward-zones-recurse`.  Default behaviour without ``+`` is as with
:ref:`setting-forward-zones`.

The DNSSEC notes from :ref:`setting-forward-zones` apply here as well.
 ''',
    'doc-new' : '''
        Same as :ref:`setting-forward-zones`, parsed from a file as a sequence of `Forward Zone`_.
        The filename MUST end in ``.yml`` for the content to be parsed as YAML.

.. code-block:: yaml

  - zone: example1.com
    forwarders:
      - 127.0.0.1
      - 127.0.0.1:5353
      - '[::1]:53'
  - zone: example2.com
    forwarders:
      - ::1
    recurse: true
    notify_allowed: true

The DNSSEC notes from :ref:`setting-forward-zones` apply here as well.
 ''',
     'versionchanged': [('4.0.0', '(Old style settings only) Comments are allowed, everything behind ``#`` is ignored.'),
                        ('4.6.0', '(Old style settings only) Zones prefixed with a ``^`` are added to the :ref:`setting-allow-notify-for` list. Both prefix characters can be used if desired, in any order.')],
        'runtime': ['reload-zones'],
    },
    {
        'name' : 'forward_zones_recurse',
        'section' : 'recursor',
        'type' : LType.ListForwardZones,
        'default' : '',
        'help' : 'Zones for which we forward queries with recursion bit, comma separated domain=ip pairs',
        'doc' : '''
Like regular :ref:`setting-forward-zones`, but forwarded queries have the ``recursion desired (RD)`` bit set to ``1``, meaning that this setting is intended to forward queries to other recursive resolvers.
In contrast to regular forwarding, the rule that delegations of the forwarded subzones are respected is not active.
This is because we rely on the forwarder to resolve the query fully.

See :ref:`setting-forward-zones` for additional options (such as supplying multiple recursive servers) and an important note about DNSSEC.
 ''',
        'doc-new' : '''
Like regular :ref:`setting-forward-zones`, but forwarded queries have the ``recursion desired (RD)`` bit set to ``1``, meaning that this setting is intended to forward queries to other recursive resolvers.
In contrast to regular forwarding, the rule that delegations of the forwarded subzones are respected is not active.
This is because we rely on the forwarder to resolve the query fully.

.. note::
  The `recurse` field of a `Forward Zone`_ is fixed to ``true`` in the context of :ref:`setting-yaml-recursor.forward_zones_recurse`.

See :ref:`setting-forward-zones` for additional options (such as supplying multiple recursive servers) and an important note about DNSSEC.
 ''',
        'runtime': ['reload-zones'],
    },
    {
        'name' : 'gettag_needs_edns_options',
        'section' : 'incoming',
        'type' : LType.Bool,
        'default' : 'false',
        'help' : 'If EDNS Options should be extracted before calling the gettag() hook',
        'doc' : '''
If set, EDNS options in incoming queries are extracted and passed to the :func:`gettag` hook in the ``ednsoptions`` table.
 ''',
    'versionadded': '4.1.0'
    },
    {
        'name' : 'help',
        'section' : 'commands',
        'type' : LType.Command,
        'default' : 'no',
        'help' : 'Provide a helpful message',
        'doc' : '''
EMPTY?  '''
    },
    {
        'name' : 'hint_file',
        'section' : 'recursor',
        'type' : LType.String,
        'default' : '',
        'help' : 'If set, load root hints from this file',
        'doc' : '''
If set, the root-hints are read from this file. If empty, the default built-in root hints are used.

In some special cases, processing the root hints is not needed, for example when forwarding all queries to another recursor.
For these special cases, it is possible to disable the processing of root hints by setting the value to ``no`` or ``no-refresh``.
See :ref:`handling-of-root-hints` for more information on root hints handling.
 ''',
        'versionchanged': [('4.6.2', 'Introduced the value ``no`` to disable root-hints processing.'),
                           ('4.9.0', 'Introduced the value ``no-refresh`` to disable both root-hints processing and periodic refresh of the cached root `NS` records.')]
    },
    {
        'name' : 'ignore_unknown_settings',
        'section' : 'recursor',
        'type' : LType.ListStrings,
        'default' : '',
        'help' : 'Configuration settings to ignore if they are unknown',
        'doc' : '''
Names of settings to be ignored while parsing configuration files, if the setting
name is unknown to PowerDNS.

Useful during upgrade testing.
 ''',
    },
    {
        'name' : 'include_dir',
        'section' : 'recursor',
        'type' : LType.String,
        'default' : '',
        'help' : 'Include settings files from this directory.',
        'doc' : '''
Directory to scan for additional config files. All files that end with ``.conf`` are loaded in order using ``POSIX`` as locale.
 ''',
        'doc-new' : '''
Directory to scan for additional config files. All files that end with ``.yml`` are loaded in order using ``POSIX`` as locale.
 ''',
    },
    {
        'name' : 'latency_statistic_size',
        'section' : 'recursor',
        'type' : LType.Uint64,
        'default' : '10000',
        'help' : 'Number of latency values to calculate the qa-latency average',
        'doc' : '''
Indication of how many queries will be averaged to get the average latency reported by the 'qa-latency' metric.
 ''',
    },
    {
        'name' : 'listen',
        'section' : 'incoming',
        'oldname' : 'local-address',
        'type' : LType.ListSocketAddresses,
        'default' : '127.0.0.1, ::1',
        'help' : 'IP addresses to listen on, separated by spaces or commas. Also accepts ports.',
        'versionchanged': ('5.3.0', '::1 was added to the list'),
        'doc' : '''
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
 ''',
        'doc-new' : '''
Local IP addresses to which we bind. Each address specified can
include a port number; if no port is included then the
:ref:`setting-local-port` port will be used for that address. If a
port number is specified, it must be separated from the address with a
':'; for an IPv6 address the address must be enclosed in square
brackets.

Example:

.. code-block:: yaml

  incoming:
    listen:
      - 127.0.0.1
      - '[::1]:5353'
      - '::'
 ''',
    },
    {
        'name' : 'port',
        'section' : 'incoming',
        'oldname' : 'local-port',
        'type' : LType.Uint64,
        'default' : '53',
        'help' : 'port to listen on',
        'doc' : '''
Local port to bind to.
If an address in :ref:`setting-local-address` does not have an explicit port, this port is used.
 ''',
    },
    {
        'name' : 'timestamp',
        'section' : 'logging',
        'oldname' : 'log-timestamp',
        'type' : LType.Bool,
        'default' : 'true',
        'help' : 'Print timestamps in log lines, useful to disable when running with a tool that timestamps stderr already',
        'doc' : '''

 ''',
    },
    {
        'name' : 'non_local_bind',
        'section' : 'incoming',
        'type' : LType.Bool,
        'default' : 'false',
        'help' : 'Enable binding to non-local addresses by using FREEBIND / BINDANY socket options',
        'doc' : '''
Bind to addresses even if one or more of the :ref:`setting-local-address`'s do not exist on this server.
Setting this option will enable the needed socket options to allow binding to non-local addresses.
This feature is intended to facilitate ip-failover setups, but it may also mask configuration issues and for this reason it is disabled by default.
 ''',
    },
    {
        'name' : 'loglevel',
        'section' : 'logging',
        'type' : LType.Uint64,
        'default' : '6',
        'help' : 'Amount of logging. Higher is more. Do not set below 3',
        'doc' : '''
Amount of logging. The higher the number, the more lines logged.
Corresponds to ``syslog`` level values (e.g. 0 = ``emergency``, 1 = ``alert``, 2 = ``critical``, 3 = ``error``, 4 = ``warning``, 5 = ``notice``, 6 = ``info``, 7 = ``debug``).
Each level includes itself plus the lower levels before it.
Not recommended to set this below 3.
If :ref:`setting-quiet` is ``no/false``, :ref:`setting-loglevel` will be minimally set to ``6 (info)``.
 ''',
        'versionchanged': ('5.0.0', 'Previous version would not allow setting a level below ``3 (error)``.')
    },
    {
        'name' : 'common_errors',
        'section' : 'logging',
        'oldname' : 'log-common-errors',
        'type' : LType.Bool,
        'default' : 'false',
        'help' : 'If we should log rather common errors',
        'doc' : '''
Some DNS errors occur rather frequently and are no cause for alarm.
 ''',
    },
    {
        'name' : 'rpz_changes',
        'section' : 'logging',
        'oldname' : 'log-rpz-changes',
        'type' : LType.Bool,
        'default' : 'false',
        'help' : 'Log additions and removals to RPZ zones at Info level',
        'doc' : '''
Log additions and removals to RPZ zones at Info (6) level instead of Debug (7).
 ''',
    'versionadded': '4.1.0'
    },
    {
        'name' : 'facility',
        'section' : 'logging',
        'oldname' : 'logging-facility',
        'type' : LType.String,
        'default' : '',
        'help' : 'Facility to log messages as. 0 corresponds to local0',
        'doc' : '''
If set to a digit, logging is performed under this LOCAL facility.
See :ref:`logging`.
Do not pass names like 'local0'!
 ''',
    },
    {
        'name' : 'lowercase',
        'section' : 'outgoing',
        'oldname' : 'lowercase-outgoing',
        'type' : LType.Bool,
        'default' : 'false',
        'help' : 'Force outgoing questions to lowercase',
        'doc' : '''
Set to true to lowercase the outgoing queries.
When set to 'no' (the default) a query from a client using mixed case in the DNS labels (such as a user entering mixed-case names or `draft-vixie-dnsext-dns0x20-00 <http://tools.ietf.org/html/draft-vixie-dnsext-dns0x20-00>`_), PowerDNS preserves the case of the query.
Broken authoritative servers might give a wrong or broken answer on this encoding.
Setting ``lowercase-outgoing`` to 'yes' makes the PowerDNS Recursor lowercase all the labels in the query to the authoritative servers, but still return the proper case to the client requesting.
 ''',
    },
    {
        'name' : 'lua_config_file',
        'section' : 'recursor',
        'type' : LType.String,
        'default' : '',
        'help' : 'More powerful configuration options',
        'doc' : '''
If set, and Lua support is compiled in, this will load an additional configuration file for newer features and more complicated setups.
See :doc:`lua-config/index` for the options that can be set in this file.
 ''',
    },
    {
        'name' : 'lua_global_include_dir',
        'section' : 'recursor',
        'type' : LType.String,
        'default' : '',
        'help' : 'More powerful configuration options',
        'doc' : '''
 When creating a Lua context, all ``*.lua`` files in the directory are loaded into the Lua context.
 ''',
    },
    {
        'name' : 'lua_dns_script',
        'section' : 'recursor',
        'type' : LType.String,
        'default' : '',
        'help' : 'Filename containing an optional Lua script that will be used to modify dns answers',
        'doc' : '''
Path to a lua file to manipulate the Recursor's answers. See :doc:`lua-scripting/index` for more information.
 ''',
    },
    {
        'name' : 'lua_maintenance_interval',
        'section' : 'recursor',
        'type' : LType.Uint64,
        'default' : '1',
        'help' : 'Number of seconds between calls to the lua user defined maintenance() function',
        'doc' : '''
The interval between calls to the Lua user defined `maintenance()` function in seconds.
See :ref:`hooks-maintenance-callback`
 ''',
    'versionadded': '4.2.0'
    },
    {
        'name' : 'max_busy_dot_probes',
        'section' : 'outgoing',
        'type' : LType.Uint64,
        'default' : '0',
        'help' : 'Maximum number of concurrent DoT probes',
        'doc' : '''
Limit the maximum number of simultaneous DoT probes the Recursor will schedule.
The default value 0 means no DoT probes are scheduled.

DoT probes are used to check if an authoritative server's IP address supports DoT.
If the probe determines an IP address supports DoT, the Recursor will use DoT to contact it for subsequent queries until a failure occurs.
After a failure, the Recursor will stop using DoT for that specific IP address for a while.
The results of probes are remembered and can be viewed by the ``rec_control dump-dot-probe-map`` command.
If the maximum number of pending probes is reached, no probes will be scheduled, even if no DoT status is known for an address.
If the result of a probe is not yet available, the Recursor will contact the authoritative server in the regular way, unless an authoritative server is configured to be contacted over DoT always using :ref:`setting-dot-to-auth-names`.
In that case no probe will be scheduled.

.. note::
  DoT probing is an experimental feature.
  Please test thoroughly to determine if it is suitable in your specific production environment before enabling.
 ''',
    'versionadded': '4.7.0'
    },
    {
        'name' : 'max_cache_bogus_ttl',
        'section' : 'recordcache',
        'type' : LType.Uint64,
        'default' : '3600',
        'help' : 'maximum number of seconds to keep a Bogus (positive or negative) cached entry in memory',
        'doc' : '''
Maximum number of seconds to cache an item in the DNS cache (negative or positive) if its DNSSEC validation failed, no matter what the original TTL specified, to reduce the impact of a broken domain.
 ''',
    'versionadded': '4.2.0'
    },
    {
        'name' : 'max_entries',
        'section' : 'recordcache',
        'oldname' : 'max-cache-entries',
        'type' : LType.Uint64,
        'default' : '1000000',
        'help' : 'If set, maximum number of entries in the main cache',
        'doc' : '''
Maximum number of DNS record cache entries, shared by all threads since 4.4.0.
Each entry associates a name and type with a record set.
The size of the negative cache is 10% of this number.
 ''',
        'runtime': 'set-max-cache-entries',
    },
    {
        'name' : 'max_ttl',
        'section' : 'recordcache',
        'oldname' : 'max-cache-ttl',
        'type' : LType.Uint64,
        'default' : '86400',
        'help' : 'maximum number of seconds to keep a cached entry in memory',
        'doc' : '''
Maximum number of seconds to cache an item in the DNS cache, no matter what the original TTL specified.
This value also controls the refresh period of cached root data.
See :ref:`handling-of-root-hints` for more information on this.
 ''',
     'versionchanged': ('4.1.0', 'The minimum value of this setting is 15. i.e. setting this to lower than 15 will make this value 15.')
    },
    {
        'name' : 'max_entry_size',
        'section' : 'recordcache',
        'oldname': 'max-recordcache-entry-size',
        'type' : LType.Uint64,
        'default' : '8192',
        'help' : 'maximum storage size of a recordset stored in record cache',
        'doc' : '''
Maximum size of storage used by a single record cache entry. Entries larger than this number will not be stored.
Zero means no limit.
''',
    'versionadded': ['5.1.10', '5.2.8', '5.3.5'],
    },
    {
        'name' : 'max_concurrent_requests_per_tcp_connection',
        'section' : 'incoming',
        'type' : LType.Uint64,
        'default' : '10',
        'help' : 'Maximum number of requests handled concurrently per TCP connection',
        'doc' : '''
Maximum number of incoming requests handled concurrently per tcp
connection. This number must be larger than 0 and smaller than 65536
and also smaller than `max-mthreads`.
 ''',
    'versionadded': '4.3.0'
    },
    {
        'name': 'max_chain_length',
        'section': 'recursor',
        'type': LType.Uint64,
        'default': '0',
        'help': 'maximum number of queries that can be chained to an outgoing request, 0 is no limit',
        'doc': '''
The maximum number of queries that can be attached to an outgoing request chain. Attaching requests to a chain
saves on outgoing queries, but the processing of a chain when the reply to the outgoing query comes in
might result in a large outgoing traffic spike. Reducing the maximum chain length mitigates this.
If this value is zero, no maximum is enforced, though the maximum number of mthreads (:ref:`setting-max-mthreads`)
also limits the chain length.
''',
        'versionadded': '5.1.0'
    },
    {
        'name' : 'max_include_depth',
        'section' : 'recursor',
        'type' : LType.Uint64,
        'default' : '20',
        'help' : 'Maximum nested $INCLUDE depth when loading a zone from a file',
        'doc' : '''
Maximum number of nested ``$INCLUDE`` directives while processing a zone file.
Zero mean no ``$INCLUDE`` directives will be accepted.
 ''',
    'versionadded': '4.6.0'
    },
    {
        'name' : 'max_generate_steps',
        'section' : 'recursor',
        'type' : LType.Uint64,
        'default' : '0',
        'help' : 'Maximum number of $GENERATE steps when loading a zone from a file',
        'doc' : '''
Maximum number of steps for a '$GENERATE' directive when parsing a
zone file. This is a protection measure to prevent consuming a lot of
CPU and memory when untrusted zones are loaded. Default to 0 which
means unlimited.
 ''',
    'versionadded': '4.3.0'
    },
    {
        'name' : 'max_mthreads',
        'section' : 'recursor',
        'type' : LType.Uint64,
        'default' : '2048',
        'help' : 'Maximum number of simultaneous Mtasker threads',
        'doc' : '''
Maximum number of simultaneous MTasker threads, per worker thread.
 ''',
    },
    {
        'name' : 'max_entries',
        'section' : 'packetcache',
        'oldname' : 'max-packetcache-entries',
        'type' : LType.Uint64,
        'default' : '500000',
        'help' : 'maximum number of entries to keep in the packetcache',
        'doc' : '''
Maximum number of Packet Cache entries. Sharded and shared by all threads since 4.9.0.
''',
        'runtime': 'set-max-packetcache-entries',
    },
    {
        'name' : 'max_entry_size',
        'section' : 'packetcache',
        'oldname' : 'max-packetcache-entry-size',
        'type' : LType.Uint64,
        'default' : '8192',
        'help' : 'maximum size of a packet stored in the the packet cache',
        'doc' : '''
Maximum size of packets stored in the packet cache. Packets larger than this number will not be stored.
Zero means no limit.
''',
    'versionadded': ['5.1.10', '5.2.8', '5.3.5'],
    },
    {
        'name' : 'max_qperq',
        'section' : 'outgoing',
        'type' : LType.Uint64,
        'default' : '50',
        'help' : 'Maximum outgoing queries per query',
        'doc' : '''
The maximum number of outgoing queries that will be sent out during the resolution of a single client query.
This is used to avoid cycles resolving names.
 ''',
        'versionchanged': ('5.1.0', 'The default used to be 60, with an extra allowance if qname minimization was enabled. Having better algorithms allows for a lower default limit.'),
    },
    {
        'name' : 'max_cnames_followed',
        'section' : 'recursor',
        'type' : LType.Uint64,
        'default' : '10',
        'help' : 'Maximum number CNAME records followed',
        'doc' : '''
Maximum length of a CNAME chain. If a CNAME chain exceeds this length, a ``ServFail`` answer will be returned.
Previously, this limit was fixed at 10.
 ''',
    'versionadded': '5.1.0'
    },
    {
        'name' : 'limit_qtype_any',
        'section' : 'recordcache',
        'type' : LType.Bool,
        'default' : 'true',
        'help' : 'Limit answers to ANY queries in size',
        'doc' : '''
Limit answers to ANY queries constructed from the record cache in size.
Trying to retrieve more than :ref:`setting-max-rrset-size` records will result in a ``ServFail``',
 ''',
    'versionadded': ['4.9.9', '5.0.9', '5.1.2']
    },
    {
        'name' : 'max_rrset_size',
        'section' : 'recordcache',
        'type' : LType.Uint64,
        'default' : '256',
        'help' : 'Maximum size of RRSet in cache',
        'doc' : '''
Maximum size of RRSets in cache.
Trying to retrieve larger RRSets will result in a ``ServFail``.',
 ''',
    'versionadded': ['4.9.9', '5.0.9', '5.1.2']
    },
    {
        'name' : 'max_ns_address_qperq',
        'section' : 'outgoing',
        'type' : LType.Uint64,
        'default' : '10',
        'help' : 'Maximum outgoing NS address queries per query',
        'doc' : '''
The maximum number of outgoing queries with empty replies for
resolving nameserver names to addresses we allow during the resolution
of a single client query. If IPv6 is enabled, an A and a AAAA query
for a name counts as 1. If a zone publishes more than this number of
NS records, the limit is further reduced for that zone by lowering
it by the number of NS records found above the
:ref:`setting-max-ns-address-qperq` value. The limit will not be reduced to a
number lower than 5.
 ''',
    'versionadded' : ['4.1.16', '4.2.2', '4.3.1']
    },
    {
        'name' : 'max_ns_per_resolve',
        'section' : 'outgoing',
        'type' : LType.Uint64,
        'default' : '13',
        'help' : 'Maximum number of NS records to consider to resolve a name, 0 is no limit',
        'doc' : '''
The maximum number of NS records that will be considered to select a nameserver to contact to resolve a name.
If a zone has more than :ref:`setting-max-ns-per-resolve` NS records, a random sample of this size will be used.
If :ref:`setting-max-ns-per-resolve` is zero, no limit applies.
 ''',
    'versionadded': ['4.8.0', '4.7.3', '4.6.4', '4.5.11']
    },
    {
        'name' : 'max_negative_ttl',
        'section' : 'recordcache',
        'type' : LType.Uint64,
        'default' : '3600',
        'help' : 'maximum number of seconds to keep a negative cached entry in memory',
        'doc' : '''
A query for which there is authoritatively no answer is cached to quickly deny a record's existence later on, without putting a heavy load on the remote server.
In practice, caches can become saturated with hundreds of thousands of hosts which are tried only once.
This setting, which defaults to 3600 seconds, puts a maximum on the amount of time negative entries are cached.
 ''',
    },
    {
        'name' : 'max_recursion_depth',
        'section' : 'recursor',
        'type' : LType.Uint64,
        'default' : '16',
        'help' : 'Maximum number of internal recursion calls per query, 0 for unlimited',
        'doc' : '''
Total maximum number of internal recursion calls the server may use to answer a single query.
0 means unlimited.
The value of :ref:`setting-stack-size` should be increased together with this one to prevent the stack from overflowing.
If :ref:`setting-qname-minimization` is enabled, the fallback code in case of a failing resolve is allowed an additional `max-recursion-depth/2`.
 ''',
     'versionchanged': [('4.1.0', 'Before 4.1.0, this settings was unlimited.'),
                        ('4.9.0', "Before 4.9.0 this setting's default was 40 and the limit on ``CNAME`` chains (fixed at 16) acted as a bound on he recursion depth.")]
    },
    {
        'name' : 'max_tcp_clients',
        'section' : 'incoming',
        'type' : LType.Uint64,
        'default' : '1024',
        'help' : 'Maximum number of simultaneous TCP clients',
        'doc' : '''
Maximum number of simultaneous incoming TCP connections allowed.
 ''',
        'versionchanged': ('5.2.0', 'Before 5.2.0 the default was 128.'),
    },
    {
        'name' : 'max_tcp_per_client',
        'section' : 'incoming',
        'type' : LType.Uint64,
        'default' : '0',
        'help' : 'If set, maximum number of TCP sessions per client (IP address)',
        'doc' : '''
Maximum number of simultaneous incoming TCP connections allowed per client (remote IP address).
0 means unlimited.
 ''',
    },
    {
        'name' : 'max_tcp_queries_per_connection',
        'section' : 'incoming',
        'type' : LType.Uint64,
        'default' : '0',
        'help' : 'If set, maximum number of TCP queries in a TCP connection',
        'doc' : '''
Maximum number of DNS queries in a TCP connection.
0 means unlimited.
 ''',
    'versionadded': '4.1.0'
    },
    {
        'name' : 'max_total_msec',
        'section' : 'recursor',
        'type' : LType.Uint64,
        'default' : '7000',
        'help' : 'Maximum total wall-clock time per query in milliseconds, 0 for unlimited',
        'doc' : '''
Total maximum number of milliseconds of wallclock time the server may use to answer a single query.
0 means unlimited.
 ''',
    },
    {
        'name' : 'max_udp_queries_per_round',
        'section' : 'incoming',
        'type' : LType.Uint64,
        'default' : '10000',
        'help' : 'Maximum number of UDP queries processed per recvmsg() round, before returning back to normal processing',
        'doc' : '''
Under heavy load the recursor might be busy processing incoming UDP queries for a long while before there is no more of these, and might therefore
neglect scheduling new ``mthreads``, handling responses from authoritative servers or responding to :doc:`rec_control <manpages/rec_control.1>`
requests.
This setting caps the maximum number of incoming UDP DNS queries processed in a single round of looping on ``recvmsg()`` after being woken up by the multiplexer, before
returning back to normal processing and handling other events.
 ''',
    'versionadded': '4.1.4'
    },
    {
        'name' : 'minimum_ttl_override',
        'section' : 'recursor',
        'type' : LType.Uint64,
        'default' : '1',
        'help' : 'The minimum TTL',
        'doc' : '''
This setting artificially raises all TTLs to be at least this long.
Setting this to a value greater than 1 technically is an RFC violation, but might improve performance a lot.
Using a value of 0 impacts performance of TTL 0 records greatly, since it forces the recursor to contact
authoritative servers each time a client requests them.
 ''',
        'versionchanged': ('4.5.0', 'Old versions used default 0.'),
        'runtime': 'set-minimum-ttl',
    },
    {
        'name' : 'tracking',
        'section' : 'nod',
        'oldname' : 'new-domain-tracking',
        'type' : LType.Bool,
        'default' : 'false',
        'help' : 'Track newly observed domains (i.e. never seen before).',
        'doc' : '''
Whether to track newly observed domains, i.e. never seen before. This
is a probabilistic algorithm, using a stable bloom filter to store
records of previously seen domains. When enabled for the first time,
all domains will appear to be newly observed, so the feature is best
left enabled for e.g. a week or longer before using the results. Note
that this feature is optional and must be enabled at compile-time,
thus it may not be available in all pre-built packages.
If protobuf is enabled and configured, then the newly observed domain
status will appear as a flag in Response messages.
 ''',
    'versionadded': '4.2.0'
    },
    {
        'name' : 'log',
        'section' : 'nod',
        'oldname' : 'new-domain-log',
        'type' : LType.Bool,
        'default' : 'true',
        'help' : 'Log newly observed domains.',
        'doc' : '''
If a newly observed domain is detected, log that domain in the
recursor log file. The log line looks something like::

 Jul 18 11:31:25 Newly observed domain nod=sdfoijdfio.com
 ''',
    'versionadded': '4.2.0'
    },
    {
        'name' : 'lookup',
        'section' : 'nod',
        'oldname' : 'new-domain-lookup',
        'type' : LType.String,
        'default' : '',
        'help' : 'Perform a DNS lookup newly observed domains as a subdomain of the configured domain',
        'doc' : '''
If a domain is specified, then each time a newly observed domain is
detected, the recursor will perform an A record lookup of '<newly
observed domain>.<lookup domain>'. For example if 'new-domain-lookup'
is configured as 'nod.powerdns.com', and a new domain 'example.com' is
detected, then an A record lookup will be made for
'example.com.nod.powerdns.com'. This feature gives a way to share the
newly observed domain with partners, vendors or security teams. The
result of the DNS lookup will be ignored by the recursor.
 ''',
    'versionadded': '4.2.0'
    },
    {
        'name' : 'db_size',
        'section' : 'nod',
        'oldname' : 'new-domain-db-size',
        'type' : LType.Uint64,
        'default' : '67108864',
        'help' : 'Size of the DB used to track new domains in terms of number of cells. Defaults to 67108864',
        'doc' : '''
The default size of the stable bloom filter used to store previously
observed domains is 67108864. To change the number of cells, use this
setting. For each cell, the SBF uses 1 bit of memory, and one byte of
disk for the persistent file.
If there are already persistent files saved to disk, this setting will
have no effect unless you remove the existing files.
 ''',
    'versionadded': '4.2.0'
    },
    {
        'name' : 'history_dir',
        'section' : 'nod',
        'oldname' : 'new-domain-history-dir',
        'type' : LType.String,
        'default' : 'NODCACHEDIRNOD',
        'docdefault': 'Determined by distribution',
        'help' : 'Persist new domain tracking data here to persist between restarts',
        'doc' : '''
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
 ''',
    'versionadded': '4.2.0'
    },
    {
        'name' : 'db_snapshot_interval',
        'section' : 'nod',
        'oldname' : 'new-domain-db-snapshot-interval',
        'type' : LType.Uint64,
        'default' : '600',
        'help' : 'Interval (in seconds) to write the NOD and UDR DB snapshots',
        'doc' : '''
Interval (in seconds) to write the NOD and UDR DB snapshots.
Set to zero to disable snapshot writing.',
 ''',
    'versionadded': '5.1.0'
    },
    {
        'name' : 'ignore_list',
        'section' : 'nod',
        'oldname' : 'new-domain-ignore-list',
        'type' : LType.ListStrings,
        'default' : '',
        'help' : 'List of domains (and implicitly all subdomains) which will never be considered a new domain',
        'doc' : '''
This setting is a list of all domains (and implicitly all subdomains)
that will never be considered a new domain. For example, if the domain
'example.com' is in the list, then 'foo.bar.example.com' will never be
considered a new domain. One use-case for the ignore list is to never
reveal details of internal subdomains via the new-domain-lookup
feature.
 ''',
    'versionadded': '4.5.0'
    },
    {
        'name' : 'ignore_list_file',
        'section' : 'nod',
        'type' : LType.String,
        'oldname' : 'new-domain-ignore-list-file',
        'default' : '',
        'help' : 'File with a list of domains (and implicitly all subdomains) which will never be considered a new domain',
        'doc' : '''
Path to a file with a list of domains. File should have one domain per line,
with no extra characters or comments.
See :ref:`setting-new-domain-ignore-list`.
 ''',
    'versionadded': '5.1.0'
    },
    {
        'name' : 'pb_tag',
        'section' : 'nod',
        'oldname' : 'new-domain-pb-tag',
        'type' : LType.String,
        'default' : 'pdns-nod',
        'help' : 'If protobuf is configured, the tag to use for messages containing newly observed domains. Defaults to \'pdns-nod\'',
        'doc' : '''
If protobuf is configured, then this tag will be added to all protobuf response messages when
a new domain is observed.
 ''',
    'versionadded': '4.2.0'
    },
    {
        'name' : 'network_timeout',
        'section' : 'outgoing',
        'type' : LType.Uint64,
        'default' : '1500',
        'help' : 'Wait this number of milliseconds for network i/o',
        'doc' : '''
Number of milliseconds to wait for a remote authoritative server to respond.
If the number of concurrent requests is high, the :program:Recursor uses a lower value.
 ''',
    },
    {
        'name' : 'no_shuffle',
        'section' : 'recursor',
        'type' : LType.Bool,
        'default' : 'false',
        'help' : 'Don\'t change',
        'doc' : 'SKIP',
        'skip-yaml': True,
    },
    {
        'name' : 'non_resolving_ns_max_fails',
        'section' : 'outgoing',
        'type' : LType.Uint64,
        'default' : '5',
        'help' : 'Number of failed address resolves of a nameserver to start throttling it, 0 is disabled',
        'doc' : '''
Number of failed address resolves of a nameserver name to start throttling it, 0 is disabled.
Nameservers matching :ref:`setting-dont-throttle-names` will not be throttled.
 ''',
    'versionadded': '4.5.0'
    },
    {
        'name' : 'non_resolving_ns_throttle_time',
        'section' : 'outgoing',
        'type' : LType.Uint64,
        'default' : '60',
        'help' : 'Number of seconds to throttle a nameserver with a name failing to resolve',
        'doc' : '''
Number of seconds to throttle a nameserver with a name failing to resolve.
 ''',
    'versionadded': '4.5.0'
    },
    {
        'name' : 'nothing_below_nxdomain',
        'section' : 'recursor',
        'type' : LType.String,
        'default' : 'dnssec',
        'help' : 'When an NXDOMAIN exists in cache for a name with fewer labels than the qname, send NXDOMAIN without doing a lookup (see RFC 8020)',
        'doc' : '''
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
 ''',
    'versionadded': '4.3.0'
    },
    {
        'name' : 'nsec3_max_iterations',
        'section' : 'dnssec',
        'type' : LType.Uint64,
        'default' : '50',
        'help' : 'Maximum number of iterations allowed for an NSEC3 record',
        'doc' : '''
Maximum number of iterations allowed for an NSEC3 record.
If an answer containing an NSEC3 record with more iterations is received, its DNSSEC validation status is treated as ``Insecure``.
 ''',
        'versionadded': '4.1.0',
        'versionchanged': [('4.5.2', 'Default is now 150, was 2500 before.'),
                           ('5.0.0', 'Default is now 50, was 150 before.')]
    },
    {
        'name' : 'max_rrsigs_per_record',
        'section' : 'dnssec',
        'type' : LType.Uint64,
        'default' : '2',
        'help' : 'Maximum number of RRSIGs to consider when validating a given record',
        'doc' : '''
Maximum number of RRSIGs we are willing to cryptographically check when validating a given record. Expired or not yet incepted RRSIGs do not count toward to this limit.
 ''',
        'versionadded': ['5.0.2', '4.9.3', '4.8.6'],
    },
    {
        'name' : 'max_nsec3s_per_record',
        'section' : 'dnssec',
        'type' : LType.Uint64,
        'default' : '10',
        'help' : 'Maximum number of NSEC3s to consider when validating a given denial of existence',
        'doc' : '''
Maximum number of NSEC3s to consider when validating a given denial of existence.
 ''',
        'versionadded': ['5.0.2', '4.9.3', '4.8.6'],
    },
    {
        'name' : 'max_signature_validations_per_query',
        'section' : 'dnssec',
        'type' : LType.Uint64,
        'default' : '30',
        'help' : 'Maximum number of RRSIG signatures we are willing to validate per incoming query',
        'doc' : '''
Maximum number of RRSIG signatures we are willing to validate per incoming query.
 ''',
        'versionadded': ['5.0.2', '4.9.3', '4.8.6'],
    },
    {
        'name' : 'max_nsec3_hash_computations_per_query',
        'section' : 'dnssec',
        'type' : LType.Uint64,
        'default' : '600',
        'help' : 'Maximum number of NSEC3 hashes that we are willing to compute during DNSSEC validation, per incoming query',
        'doc' : '''
Maximum number of NSEC3 hashes that we are willing to compute during DNSSEC validation, per incoming query.
 ''',
        'versionadded': ['5.0.2', '4.9.3', '4.8.6'],
    },
    {
        'name' : 'aggressive_cache_max_nsec3_hash_cost',
        'section' : 'dnssec',
        'type' : LType.Uint64,
        'default' : '150',
        'help' : 'Maximum estimated NSEC3 cost for a given query to consider aggressive use of the NSEC3 cache',
        'doc' : '''
Maximum estimated NSEC3 cost for a given query to consider aggressive use of the NSEC3 cache. The cost is estimated based on a heuristic taking the zone's NSEC3 salt and iterations parameters into account, as well at the number of labels of the requested name. For example a query for a name like a.b.c.d.e.f.example.com. in an example.com zone. secured with NSEC3 and 10 iterations (NSEC3 iterations count of 9) and an empty salt will have an estimated worst-case cost of 10 (iterations) * 6 (number of labels) = 60. The aggressive NSEC cache is an optimization to reduce the number of queries to authoritative servers, which is especially useful when a zone is under pseudo-random subdomain attack, and we want to skip it the zone parameters make it expensive.
''',
        'versionadded': ['5.0.2', '4.9.3', '4.8.6'],
    },
    {
        'name' : 'max_ds_per_zone',
        'section' : 'dnssec',
        'type' : LType.Uint64,
        'default' : '8',
        'help' : 'Maximum number of DS records to consider per zone',
        'doc' : '''
Maximum number of DS records to consider when validating records inside a zone.
 ''',
        'versionadded': ['5.0.2', '4.9.3', '4.8.6'],
    },
    {
        'name' : 'max_dnskeys',
        'section' : 'dnssec',
        'type' : LType.Uint64,
        'default' : '2',
        'help' : 'Maximum number of DNSKEYs with the same algorithm and tag to consider when validating a given record',
        'doc' : '''
Maximum number of DNSKEYs with the same algorithm and tag to consider when validating a given record. Setting this value to 1 effectively denies DNSKEY tag collisions in a zone.
 ''',
        'versionadded': ['5.0.2', '4.9.3', '4.8.6'],
    },
    {
        'name' : 'ttl',
        'section' : 'packetcache',
        'oldname' : 'packetcache-ttl',
        'type' : LType.Uint64,
        'default' : '86400',
        'help' : 'maximum number of seconds to keep a cached entry in packetcache',
        'doc' : '''
Maximum number of seconds to cache an item in the packet cache, no matter what the original TTL specified.
 ''',
        'versionchanged': ('4.9.0', 'The default was changed from 3600 (1 hour) to 86400 (24 hours).')
    },
    {
        'name' : 'negative_ttl',
        'section' : 'packetcache',
        'oldname' : 'packetcache-negative-ttl',
        'type' : LType.Uint64,
        'default' : '60',
        'help' : 'maximum number of seconds to keep a cached NxDomain or NoData entry in packetcache',
        'doc' : '''
Maximum number of seconds to cache an ``NxDomain`` or ``NoData`` answer in the packetcache.
This setting's maximum is capped to :ref:`setting-packetcache-ttl`.
i.e. setting ``packetcache-ttl=15`` and keeping ``packetcache-negative-ttl`` at the default will lower ``packetcache-negative-ttl`` to ``15``.
 ''',
    'versionadded': '4.9.0'
    },
    {
        'name' : 'servfail_ttl',
        'section' : 'packetcache',
        'oldname' : 'packetcache-servfail-ttl',
        'type' : LType.Uint64,
        'default' : '60',
        'help' : 'maximum number of seconds to keep a cached servfail entry in packetcache',
        'doc' : '''
Maximum number of seconds to cache an answer indicating a failure to resolve in the packet cache.
Before version 4.6.0 only ``ServFail`` answers were considered as such. Starting with 4.6.0, all responses with a code other than ``NoError`` and ``NXDomain``, or without records in the answer and authority sections, are considered as a failure to resolve.
Since 4.9.0, negative answers are handled separately from resolving failures.
 ''',
        'doc-rst' : '''
        'versionchanged': ('4.0.0', "This setting's maximum is capped to :ref:`setting-packetcache-ttl`.
    i.e. setting ``packetcache-ttl=15`` and keeping ``packetcache-servfail-ttl`` at the default will lower ``packetcache-servfail-ttl`` to ``15``.")
 '''
    },
    {
        'name' : 'shards',
        'section' : 'packetcache',
        'oldname' : 'packetcache-shards',
        'type' : LType.Uint64,
        'default' : '1024',
        'help' : 'Number of shards in the packet cache',
        'doc' : '''
Sets the number of shards in the packet cache. If you have high contention as reported by ``packetcache-contented/packetcache-acquired``,
you can try to enlarge this value or run with fewer threads.
 ''',
    'versionadded': '4.9.0'
    },
    {
        'name' : 'pdns_distributes_queries',
        'section' : 'incoming',
        'type' : LType.Bool,
        'default' : 'false',
        'help' : 'If PowerDNS itself should distribute queries over threads',
        'doc' : '''
If set, PowerDNS will use distinct threads to listen to client sockets and distribute that work to worker-threads using a hash of the query.
This feature should maximize the cache hit ratio on versions before 4.9.0.
To use more than one thread set :ref:`setting-distributor-threads` in version 4.2.0 or newer.
Enabling should improve performance on systems where :ref:`setting-reuseport` does not have the effect of
balancing the queries evenly over multiple worker threads.
 ''',
     'versionchanged': ('4.9.0', 'Default changed to ``no``, previously it was ``yes``.')
    },
    {
        'name' : 'processes',
        'section' : 'recursor',
        'type' : LType.Uint64,
        'default' : '1',
        'help' : 'Launch this number of processes (EXPERIMENTAL, DO NOT CHANGE)',
        'doc' : '''SKIP''',
        'skip-yaml': True,
    },
    {
        'name' : 'protobuf_use_kernel_timestamp',
        'section' : 'logging',
        'type' : LType.Bool,
        'default' : 'false',
        'help' : 'Compute the latency of queries in protobuf messages by using the timestamp set by the kernel when the query was received (when available)',
        'doc' : '''
Whether to compute the latency of responses in protobuf messages using the timestamp set by the kernel when the query packet was received (when available), instead of computing it based on the moment we start processing the query.
 ''',
    'versionadded': '4.2.0'
    },
    {
        'name' : 'proxy_protocol_from',
        'section' : 'incoming',
        'type' : LType.ListSubnets,
        'default' : '',
        'help' : 'A Proxy Protocol header is required from these subnets',
        'doc' : '''
Ranges that are required to send a Proxy Protocol version 2 header in front of UDP and TCP queries, to pass the original source and destination addresses and ports to the recursor, as well as custom values.
Queries that are not prefixed with such a header will not be accepted from clients in these ranges. Queries prefixed by headers from clients that are not listed in these ranges will be dropped.

Note that once a Proxy Protocol header has been received, the source address from the proxy header instead of the address of the proxy will be checked against the :ref:`setting-allow-from` ACL.

The dnsdist docs have `more information about the PROXY protocol <https://dnsdist.org/advanced/passing-source-address.html#proxy-protocol>`_.
 ''',
        'versionadded' : '4.4.0',
        'versionchanged' : [('5.0.5', 'YAML settings only: previously this was defined as a string instead of a sequence'),
                            ('5.3.0', '``rec_control reload-acls`` reloads this setting')],
        'runtime': ['reload-acls (since 5.3.0)'],
    },
    {
        'name' : 'proxy_protocol_exceptions',
        'section' : 'incoming',
        'type' : LType.ListSocketAddresses,
        'default' : '',
        'help' : 'A Proxy Protocol header should not be used for these listen addresses.',
        'doc' : '''
If set, clients sending from an address in :ref:`setting-proxy-protocol-from` to an address:port listed here are excluded from using the Proxy Protocol.
If no port is specified, port 53 is assumed.
This is typically used to provide an easy to use address and port to send debug queries to.
 ''',
        'versionadded' : '5.1.0',
        'versionchanged' : ('5.3.0', '``rec_control reload-acls`` reloads this setting'),
        'runtime': ['reload-acls (since 5.3.0)'],
    },
    {
        'name' : 'proxy_protocol_maximum_size',
        'section' : 'incoming',
        'type' : LType.Uint64,
        'default' : '512',
        'help' : 'The maximum size of a proxy protocol payload, including the TLV values',
        'doc' : '''
The maximum size, in bytes, of a Proxy Protocol payload (header, addresses and ports, and TLV values). Queries with a larger payload will be dropped.
 ''',
    'versionadded': '4.4.0'
    },
    {
        'name' : 'public_suffix_list_file',
        'section' : 'recursor',
        'type' : LType.String,
        'default' : '',
        'help' : 'Path to the Public Suffix List file, if any',
        'doc' : '''
Path to the Public Suffix List file, if any. If set, PowerDNS will try to load the Public Suffix List from this file instead of using the built-in list. The PSL is used to group the queries by relevant domain names when displaying the top queries.
 ''',
    'versionadded': '4.2.0'
    },
    {
        'name' : 'qname_minimization',
        'section' : 'recursor',
        'type' : LType.Bool,
        'default' : 'true',
        'help' : 'Use Query Name Minimization',
        'doc' : '''
Enable Query Name Minimization. This implements a relaxed form of Query Name Mimimization as
described in :rfc:`9156`.
 ''',
    'versionadded': '4.3.0'
    },
    {
        'name' : 'qname_max_minimize_count',
        'section' : 'recursor',
        'type' : LType.Uint64,
        'default' : '10',
        'help' : 'RFC9156 max minimize count',
        'doc' : '''
``Max minimize count`` parameter, described in :rfc:`9156`. This is the maximum number of iterations
of the Query Name Minimization Algorithm.
 ''',
    'versionadded': '5.0.0'
    },
    {
        'name' : 'qname_minimize_one_label',
        'section' : 'recursor',
        'type' : LType.Uint64,
        'default' : '4',
        'help' : 'RFC9156 minimize one label parameter',
        'doc' : '''
``Minimize one label`` parameter, described in :rfc:`9156`.
The value for the number of iterations of the Query Name Minimization Algorithm that should only have one label appended.
This value has precedence over :ref:`setting-qname-max-minimize-count`.
 ''',
    'versionadded': '5.0.0'
    },
    {
        'name' : 'source_address',
        'section' : 'outgoing',
        'oldname' : 'query-local-address',
        'type' : LType.ListSubnets,
        'default' : '0.0.0.0',
        'help' : 'Source IP address for sending queries',
        'doc' : '''
.. note::
    While subnets and their negations are mentioned as accepted, the handling of subnets has not been implemented yet.
    Only individual IP addresses can be listed.

Send out local queries from this address, or addresses. By adding multiple
addresses, increased spoofing resilience is achieved. When no address of a certain
address family is configured, there are *no* queries sent with that address family.
In the default configuration this means that IPv6 is not used for outgoing queries.
 ''',
     'versionchanged': ('4.4.0', 'IPv6 addresses can be set with this option as well.')
    },
    {
        'name' : 'quiet',
        'section' : 'logging',
        'type' : LType.Bool,
        'default' : 'true',
        'help' : 'Suppress logging of questions and answers',
        'doc' : '''
Don't log queries.
 ''',
    },
    {
        'name' : 'locked_ttl_perc',
        'section' : 'recordcache',
        'oldname' : 'record-cache-locked-ttl-perc',
        'type' : LType.Uint64,
        'default' : '0',
        'help' : 'Replace records in record cache only after this % of original TTL has passed',
        'doc' : '''
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
- Record sets produced by :ref:`setting-refresh-on-ttl-perc` tasks will also replace existing record sets.
 ''',
    'versionadded': '4.8.0'
    },
    {
        'name' : 'shards',
        'section' : 'recordcache',
        'oldname' : 'record-cache-shards',
        'type' : LType.Uint64,
        'default' : '1024',
        'help' : 'Number of shards in the record cache',
        'doc' : '''
Sets the number of shards in the record cache. If you have high
contention as reported by
``record-cache-contented/record-cache-acquired``, you can try to
enlarge this value or run with fewer threads.
 ''',
    'versionadded': '4.4.0'
    },
    {
        'name' : 'refresh_on_ttl_perc',
        'section' : 'recordcache',
        'type' : LType.Uint64,
        'default' : '0',
        'help' : 'If a record is requested from the cache and only this % of original TTL remains, refetch',
        'doc' : '''
Sets the 'refresh almost expired' percentage of the record cache. Whenever a record is fetched from the packet or record cache
and only ``refresh-on-ttl-perc`` percent or less of its original TTL is left, a task is queued to refetch the name/type combination to
update the record cache. In most cases this causes future queries to always see a non-expired record cache entry.
A typical value is 10. If the value is zero, this functionality is disabled.
 ''',
    'versionadded': '4.5.0'
    },
    {
        'name' : 'reuseport',
        'section' : 'incoming',
        'type' : LType.Bool,
        'default' : 'true',
        'help' : 'Enable SO_REUSEPORT allowing multiple recursors processes to listen to 1 address',
        'doc' : '''
If ``SO_REUSEPORT`` support is available, allows multiple threads and processes to open listening sockets for the same port.

Since 4.1.0, when :ref:`setting-pdns-distributes-queries` is disabled and :ref:`setting-reuseport` is enabled, every worker-thread will open a separate listening socket to let the kernel distribute the incoming queries instead of running a distributor thread (which could otherwise be a bottleneck) and avoiding thundering herd issues, thus leading to much higher performance on multi-core boxes.
 ''',
     'versionchanged': ('4.9.0', 'The default is changed to ``yes``, previously it was ``no``. If ``SO_REUSEPORT`` support is not available, the setting defaults to ``no``.')
    },
    {
        'name' : 'rng',
        'section' : 'recursor',
        'type' : LType.String,
        'default' : 'auto',
        'help' : '',
        'doc' : '''
 ''',
        'skip-yaml': True,
        'versionchanged': ('4.9.0', 'This setting is no longer used.')
    },
    {
        'name' : 'root_nx_trust',
        'section' : 'recursor',
        'type' : LType.Bool,
        'default' : 'true',
        'help' : 'If set, believe that an NXDOMAIN from the root means the TLD does not exist',
        'doc' : '''
If set, an NXDOMAIN from the root-servers will serve as a blanket NXDOMAIN for the entire TLD the query belonged to.
The effect of this is far fewer queries to the root-servers.
 ''',
     'versionchanged': ('4.0.0', "Default is ``yes`` now, was ``no`` before 4.0.0")
    },
    {
        'name' : 'save_parent_ns_set',
        'section' : 'recursor',
        'type' : LType.Bool,
        'default' : 'true',
        'help' : 'Save parent NS set to be used if child NS set fails',
        'doc' : '''
If set, a parent (non-authoritative) ``NS`` set is saved if it contains more entries than a newly encountered child (authoritative) ``NS`` set for the same domain.
The saved parent ``NS`` set is tried if resolution using the child ``NS`` set fails.
 ''',
    'versionadded': '4.7.0'
    },
    {
        'name' : 'security_poll_suffix',
        'section' : 'recursor',
        'type' : LType.String,
        'default' : 'secpoll.powerdns.com.',
        'help' : 'Domain name from which to query security update notifications',
        'doc' : '''
Domain name from which to query security update notifications.
Setting this to an empty string disables secpoll.
 ''',
    },
    {
        'name' : 'serve_rfc1918',
        'section' : 'recursor',
        'type' : LType.Bool,
        'default' : 'true',
        'help' : 'If we should be authoritative for RFC 1918 private IP space',
        'doc' : '''
This makes the server authoritatively aware of: ``10.in-addr.arpa``, ``168.192.in-addr.arpa``, ``16-31.172.in-addr.arpa``, which saves load on the AS112 servers.
Individual parts of these zones can still be loaded or forwarded.
 ''',
        'runtime': ['reload-zones'],
    },
    {
        'name' : 'serve_rfc6303',
        'section' : 'recursor',
        'type' : LType.Bool,
        'default' : 'true',
        'help' : 'If we should be authoritative for RFC 6303 private IP space',
        'doc' : '''
This makes the server authoritatively aware of the zones in RFC 6303 not covered by RFC 1918.
Individual parts of these zones can still be loaded or forwarded.
:ref:`setting-serve-rfc1918` must be enabled for this option to take effect.
''',
        'versionadded': ['5.1.3', '5.2.0'],
        'runtime': ['reload-zones'],
    },
    {
        'name' : 'serve_stale_extensions',
        'section' : 'recordcache',
        'type' : LType.Uint64,
        'default' : '0',
        'help' : 'Number of times a record\'s ttl is extended by 30s to be served stale',
        'doc' : '''
Maximum number of times an expired record's TTL is extended by 30s when serving stale.
Extension only occurs if a record cannot be refreshed.
A value of 0 means the ``Serve Stale`` mechanism is not used.
To allow records becoming stale to be served for an hour, use a value of 120.
See :ref:`serve-stale` for a description of the Serve Stale mechanism.
 ''',
    'versionadded': '4.8.0'
    },
    {
        'name' : 'server_down_max_fails',
        'section' : 'outgoing',
        'type' : LType.Uint64,
        'default' : '64',
        'help' : 'Maximum number of consecutive timeouts (and unreachables) to mark a server as down ( 0 => disabled )',
        'doc' : '''
If a server has not responded in any way this many times in a row, no longer send it any queries for :ref:`setting-server-down-throttle-time` seconds.
Afterwards, we will try a new packet, and if that also gets no response at all, we again throttle for :ref:`setting-server-down-throttle-time` seconds.
Even a single response packet will drop the block.
 ''',
    },
    {
        'name' : 'server_down_throttle_time',
        'section' : 'outgoing',
        'type' : LType.Uint64,
        'default' : '60',
        'help' : 'Number of seconds to throttle all queries to a server after being marked as down',
        'doc' : '''
Throttle a server that has failed to respond :ref:`setting-server-down-max-fails` times for this many seconds.
 ''',
    },
    {
        'name' : 'bypass_server_throttling_probability',
        'section' : 'outgoing',
        'type' : LType.Uint64,
        'default' : '25',
        'help' : 'Determines the probability of a server marked down to be used anyway',
        'doc' : '''
This setting determines the probability of a server marked down to be used anyway.
A value of ``n`` means that the chance of a server marked down still being used after it wins speed selection is is ``1/n``.
If this setting is zero throttled servers will never be selected to be used anyway.
        ''',
        'versionadded': '5.0.0'
    },
    {
        'name' : 'server_id',
        'section' : 'recursor',
        'type' : LType.String,
        'default' : RUNTIME,
        'help' : 'Returned when queried for \'id.server\' TXT or NSID, defaults to hostname, set custom or \'disabled\'',
        'doc' : '''
The reply given by The PowerDNS recursor to a query for 'id.server' with its hostname, useful for in clusters.
When a query contains the :rfc:`NSID EDNS0 Option <5001>`, this value is returned in the response as the NSID value.

This setting can be used to override the answer given to these queries.
Set to 'disabled' to disable NSID and 'id.server' answers.

Query example (where 192.0.2.14 is your server):

.. code-block:: sh

    dig @192.0.2.14 CHAOS TXT id.server.
    dig @192.0.2.14 example.com IN A +nsid
 ''',
    },
    {
        'name' : 'setgid',
        'section' : 'recursor',
        'type' : LType.String,
        'default' : '',
        'help' : 'If set, change group id to this gid for more security',
        'doc' : '''
PowerDNS can change its user and group id after binding to its socket.
Can be used for better :doc:`security <security>`.
 '''
    },
    {
        'name' : 'setuid',
        'section' : 'recursor',
        'type' : LType.String,
        'default' : '',
        'help' : 'If set, change user id to this uid for more security',
        'doc' : '''
PowerDNS can change its user and group id after binding to its socket.
Can be used for better :doc:`security <security>`.
 '''
    },
    {
        'name' : 'signature_inception_skew',
        'section' : 'dnssec',
        'type' : LType.Uint64,
        'default' : '60',
        'help' : 'Allow the signature inception to be off by this number of seconds',
        'doc' : '''
Allow the signature inception to be off by this number of seconds. Negative values are not allowed.
 ''',
        'versionadded': '4.1.5',
        'versionchanged': ('4.2.0', 'Default is now 60, was 0 before.')
    },
    {
        'name' : 'single_socket',
        'section' : 'outgoing',
        'type' : LType.Bool,
        'default' : 'false',
        'help' : 'If set, only use a single socket for outgoing queries',
        'doc' : '''
Use only a single socket for outgoing queries.
 ''',
    },
    {
        'name' : 'agent',
        'section' : 'snmp',
        'oldname' : 'snmp-agent',
        'type' : LType.Bool,
        'default' : 'false',
        'help' : 'If set, register as an SNMP agent',
        'doc' : '''
If set to true and PowerDNS has been compiled with SNMP support, it will register as an SNMP agent to provide statistics and be able to send traps.
 ''',
    'versionadded': '4.1.0'
    },
    {
        'name' : 'daemon_socket',
        'section' : 'snmp',
        'oldname' : 'snmp-daemon-socket',
        'type' : LType.String,
        'default' : '',
        'help' : 'If set and snmp-agent is set, the socket to use to register to the SNMP daemon',
        'doc' : '''
If not empty and ``snmp-agent`` is set to true, indicates how PowerDNS should contact the SNMP daemon to register as an SNMP agent.
 ''',
    'versionadded': '4.5.0'
    },
    {
        'name' : 'soa_minimum_ttl',
        'section' : 'recursor',
        'type' : LType.Uint64,
        'default' : '0',
        'help' : 'Don\'t change',
        'doc' : '''SKIP''',
        'skip-yaml': True,
    },
    {
        'name' : 'socket_dir',
        'section' : 'recursor',
        'type' : LType.String,
        'default' : '',
        'help' : 'Where the controlsocket will live, /var/run/pdns-recursor when unset and not chrooted',
        'doc' : '''
Where to store the control socket and pidfile.
The default depends on ``LOCALSTATEDIR`` or the ``--with-socketdir`` setting when building (usually ``/var/run`` or ``/run``).

When using :ref:`setting-chroot` the default becomes ``/``.
The default value is overruled by the ``RUNTIME_DIRECTORY`` environment variable when that variable has a value (e.g. under systemd).
 ''',
    },
    {
        'name' : 'socket_group',
        'section' : 'recursor',
        'type' : LType.String,
        'default' : '',
        'help' : 'Group of socket',
        'doc' : '''
Group and mode of the controlsocket.
Owner and group can be specified by name, mode is in octal.
'''
    },
    {
        'name' : 'socket_mode',
        'section' : 'recursor',
        'type' : LType.String,
        'default' : '',
        'help' : 'Permissions for socket',
        'doc' : '''
Mode of the controlsocket.
Owner and group can be specified by name, mode is in octal.
 '''
    },
    {
        'name' : 'socket_owner',
        'section' : 'recursor',
        'type' : LType.String,
        'default' : '',
        'help' : 'Owner of socket',
        'doc' : '''
Owner of the controlsocket.
Owner and group can be specified by name, mode is in octal.
 '''
    },
    {
        'name' : 'spoof_nearmiss_max',
        'section' : 'recursor',
        'type' : LType.Uint64,
        'default' : '1',
        'help' : 'If non-zero, assume spoofing after this many near misses',
        'doc' : '''
If set to non-zero, PowerDNS will assume it is being subjected to a spoofing attack after seeing this many answers with the wrong id.
 ''',
     'versionchanged': ('4.5.0', 'Older versions used 20 as the default value.')
    },
    {
        'name' : 'stack_cache_size',
        'section' : 'recursor',
        'type' : LType.Uint64,
        'default' : '100',
        'help' : 'Size of the stack cache, per mthread',
        'doc' : '''
Maximum number of mthread stacks that can be cached for later reuse, per thread. Caching these stacks reduces the CPU load at the cost of a slightly higher memory usage, each cached stack consuming `stack-size` bytes of memory.
It makes no sense to cache more stacks than the value of `max-mthreads`, since there will never be more stacks than that in use at a given time.
 ''',
    'versionadded': '4.9.0'
    },
    {
        'name' : 'stack_size',
        'section' : 'recursor',
        'type' : LType.Uint64,
        'default' : '200000',
        'help' : 'stack size per mthread',
        'doc' : '''
Size in bytes of the stack of each mthread.
 ''',
    },
    {
        'name' : 'statistics_interval',
        'section' : 'logging',
        'type' : LType.Uint64,
        'default' : '1800',
        'help' : 'Number of seconds between printing of recursor statistics, 0 to disable',
        'doc' : '''
Interval between logging statistical summary on recursor performance.
Use 0 to disable.
 ''',
    'versionadded': '4.1.0'
    },
    {
        'name' : 'stats_api_disabled_list',
        'section' : 'recursor',
        'type' : LType.ListStrings,
        'default' : 'cache-bytes, packetcache-bytes, special-memory-usage, ecs-v4-response-bits-1, ecs-v4-response-bits-2, ecs-v4-response-bits-3, ecs-v4-response-bits-4, ecs-v4-response-bits-5, ecs-v4-response-bits-6, ecs-v4-response-bits-7, ecs-v4-response-bits-8, ecs-v4-response-bits-9, ecs-v4-response-bits-10, ecs-v4-response-bits-11, ecs-v4-response-bits-12, ecs-v4-response-bits-13, ecs-v4-response-bits-14, ecs-v4-response-bits-15, ecs-v4-response-bits-16, ecs-v4-response-bits-17, ecs-v4-response-bits-18, ecs-v4-response-bits-19, ecs-v4-response-bits-20, ecs-v4-response-bits-21, ecs-v4-response-bits-22, ecs-v4-response-bits-23, ecs-v4-response-bits-24, ecs-v4-response-bits-25, ecs-v4-response-bits-26, ecs-v4-response-bits-27, ecs-v4-response-bits-28, ecs-v4-response-bits-29, ecs-v4-response-bits-30, ecs-v4-response-bits-31, ecs-v4-response-bits-32, ecs-v6-response-bits-1, ecs-v6-response-bits-2, ecs-v6-response-bits-3, ecs-v6-response-bits-4, ecs-v6-response-bits-5, ecs-v6-response-bits-6, ecs-v6-response-bits-7, ecs-v6-response-bits-8, ecs-v6-response-bits-9, ecs-v6-response-bits-10, ecs-v6-response-bits-11, ecs-v6-response-bits-12, ecs-v6-response-bits-13, ecs-v6-response-bits-14, ecs-v6-response-bits-15, ecs-v6-response-bits-16, ecs-v6-response-bits-17, ecs-v6-response-bits-18, ecs-v6-response-bits-19, ecs-v6-response-bits-20, ecs-v6-response-bits-21, ecs-v6-response-bits-22, ecs-v6-response-bits-23, ecs-v6-response-bits-24, ecs-v6-response-bits-25, ecs-v6-response-bits-26, ecs-v6-response-bits-27, ecs-v6-response-bits-28, ecs-v6-response-bits-29, ecs-v6-response-bits-30, ecs-v6-response-bits-31, ecs-v6-response-bits-32, ecs-v6-response-bits-33, ecs-v6-response-bits-34, ecs-v6-response-bits-35, ecs-v6-response-bits-36, ecs-v6-response-bits-37, ecs-v6-response-bits-38, ecs-v6-response-bits-39, ecs-v6-response-bits-40, ecs-v6-response-bits-41, ecs-v6-response-bits-42, ecs-v6-response-bits-43, ecs-v6-response-bits-44, ecs-v6-response-bits-45, ecs-v6-response-bits-46, ecs-v6-response-bits-47, ecs-v6-response-bits-48, ecs-v6-response-bits-49, ecs-v6-response-bits-50, ecs-v6-response-bits-51, ecs-v6-response-bits-52, ecs-v6-response-bits-53, ecs-v6-response-bits-54, ecs-v6-response-bits-55, ecs-v6-response-bits-56, ecs-v6-response-bits-57, ecs-v6-response-bits-58, ecs-v6-response-bits-59, ecs-v6-response-bits-60, ecs-v6-response-bits-61, ecs-v6-response-bits-62, ecs-v6-response-bits-63, ecs-v6-response-bits-64, ecs-v6-response-bits-65, ecs-v6-response-bits-66, ecs-v6-response-bits-67, ecs-v6-response-bits-68, ecs-v6-response-bits-69, ecs-v6-response-bits-70, ecs-v6-response-bits-71, ecs-v6-response-bits-72, ecs-v6-response-bits-73, ecs-v6-response-bits-74, ecs-v6-response-bits-75, ecs-v6-response-bits-76, ecs-v6-response-bits-77, ecs-v6-response-bits-78, ecs-v6-response-bits-79, ecs-v6-response-bits-80, ecs-v6-response-bits-81, ecs-v6-response-bits-82, ecs-v6-response-bits-83, ecs-v6-response-bits-84, ecs-v6-response-bits-85, ecs-v6-response-bits-86, ecs-v6-response-bits-87, ecs-v6-response-bits-88, ecs-v6-response-bits-89, ecs-v6-response-bits-90, ecs-v6-response-bits-91, ecs-v6-response-bits-92, ecs-v6-response-bits-93, ecs-v6-response-bits-94, ecs-v6-response-bits-95, ecs-v6-response-bits-96, ecs-v6-response-bits-97, ecs-v6-response-bits-98, ecs-v6-response-bits-99, ecs-v6-response-bits-100, ecs-v6-response-bits-101, ecs-v6-response-bits-102, ecs-v6-response-bits-103, ecs-v6-response-bits-104, ecs-v6-response-bits-105, ecs-v6-response-bits-106, ecs-v6-response-bits-107, ecs-v6-response-bits-108, ecs-v6-response-bits-109, ecs-v6-response-bits-110, ecs-v6-response-bits-111, ecs-v6-response-bits-112, ecs-v6-response-bits-113, ecs-v6-response-bits-114, ecs-v6-response-bits-115, ecs-v6-response-bits-116, ecs-v6-response-bits-117, ecs-v6-response-bits-118, ecs-v6-response-bits-119, ecs-v6-response-bits-120, ecs-v6-response-bits-121, ecs-v6-response-bits-122, ecs-v6-response-bits-123, ecs-v6-response-bits-124, ecs-v6-response-bits-125, ecs-v6-response-bits-126, ecs-v6-response-bits-127, ecs-v6-response-bits-128',
        'docdefault': 'cache-bytes, packetcache-bytes, special-memory-usage, ecs-v4-response-bits-\\*, ecs-v6-response-bits-\\*',
        'help' : 'List of statistics that are disabled when retrieving the complete list of statistics via the API',
        'doc' : '''
A list of comma-separated statistic names, that are disabled when retrieving the complete list of statistics via the API for performance reasons.
These statistics can still be retrieved individually by specifically asking for it.
 ''',
        'doc-new' : '''
A sequence of statistic names, that are disabled when retrieving the complete list of statistics via the API for performance reasons.
These statistics can still be retrieved individually by specifically asking for it.
 ''',
    'versionadded': '4.5.0'
    },
    {
        'name' : 'stats_carbon_disabled_list',
        'section' : 'recursor',
        'type' : LType.ListStrings,
        'default' : 'cache-bytes, packetcache-bytes, special-memory-usage, ecs-v4-response-bits-1, ecs-v4-response-bits-2, ecs-v4-response-bits-3, ecs-v4-response-bits-4, ecs-v4-response-bits-5, ecs-v4-response-bits-6, ecs-v4-response-bits-7, ecs-v4-response-bits-8, ecs-v4-response-bits-9, ecs-v4-response-bits-10, ecs-v4-response-bits-11, ecs-v4-response-bits-12, ecs-v4-response-bits-13, ecs-v4-response-bits-14, ecs-v4-response-bits-15, ecs-v4-response-bits-16, ecs-v4-response-bits-17, ecs-v4-response-bits-18, ecs-v4-response-bits-19, ecs-v4-response-bits-20, ecs-v4-response-bits-21, ecs-v4-response-bits-22, ecs-v4-response-bits-23, ecs-v4-response-bits-24, ecs-v4-response-bits-25, ecs-v4-response-bits-26, ecs-v4-response-bits-27, ecs-v4-response-bits-28, ecs-v4-response-bits-29, ecs-v4-response-bits-30, ecs-v4-response-bits-31, ecs-v4-response-bits-32, ecs-v6-response-bits-1, ecs-v6-response-bits-2, ecs-v6-response-bits-3, ecs-v6-response-bits-4, ecs-v6-response-bits-5, ecs-v6-response-bits-6, ecs-v6-response-bits-7, ecs-v6-response-bits-8, ecs-v6-response-bits-9, ecs-v6-response-bits-10, ecs-v6-response-bits-11, ecs-v6-response-bits-12, ecs-v6-response-bits-13, ecs-v6-response-bits-14, ecs-v6-response-bits-15, ecs-v6-response-bits-16, ecs-v6-response-bits-17, ecs-v6-response-bits-18, ecs-v6-response-bits-19, ecs-v6-response-bits-20, ecs-v6-response-bits-21, ecs-v6-response-bits-22, ecs-v6-response-bits-23, ecs-v6-response-bits-24, ecs-v6-response-bits-25, ecs-v6-response-bits-26, ecs-v6-response-bits-27, ecs-v6-response-bits-28, ecs-v6-response-bits-29, ecs-v6-response-bits-30, ecs-v6-response-bits-31, ecs-v6-response-bits-32, ecs-v6-response-bits-33, ecs-v6-response-bits-34, ecs-v6-response-bits-35, ecs-v6-response-bits-36, ecs-v6-response-bits-37, ecs-v6-response-bits-38, ecs-v6-response-bits-39, ecs-v6-response-bits-40, ecs-v6-response-bits-41, ecs-v6-response-bits-42, ecs-v6-response-bits-43, ecs-v6-response-bits-44, ecs-v6-response-bits-45, ecs-v6-response-bits-46, ecs-v6-response-bits-47, ecs-v6-response-bits-48, ecs-v6-response-bits-49, ecs-v6-response-bits-50, ecs-v6-response-bits-51, ecs-v6-response-bits-52, ecs-v6-response-bits-53, ecs-v6-response-bits-54, ecs-v6-response-bits-55, ecs-v6-response-bits-56, ecs-v6-response-bits-57, ecs-v6-response-bits-58, ecs-v6-response-bits-59, ecs-v6-response-bits-60, ecs-v6-response-bits-61, ecs-v6-response-bits-62, ecs-v6-response-bits-63, ecs-v6-response-bits-64, ecs-v6-response-bits-65, ecs-v6-response-bits-66, ecs-v6-response-bits-67, ecs-v6-response-bits-68, ecs-v6-response-bits-69, ecs-v6-response-bits-70, ecs-v6-response-bits-71, ecs-v6-response-bits-72, ecs-v6-response-bits-73, ecs-v6-response-bits-74, ecs-v6-response-bits-75, ecs-v6-response-bits-76, ecs-v6-response-bits-77, ecs-v6-response-bits-78, ecs-v6-response-bits-79, ecs-v6-response-bits-80, ecs-v6-response-bits-81, ecs-v6-response-bits-82, ecs-v6-response-bits-83, ecs-v6-response-bits-84, ecs-v6-response-bits-85, ecs-v6-response-bits-86, ecs-v6-response-bits-87, ecs-v6-response-bits-88, ecs-v6-response-bits-89, ecs-v6-response-bits-90, ecs-v6-response-bits-91, ecs-v6-response-bits-92, ecs-v6-response-bits-93, ecs-v6-response-bits-94, ecs-v6-response-bits-95, ecs-v6-response-bits-96, ecs-v6-response-bits-97, ecs-v6-response-bits-98, ecs-v6-response-bits-99, ecs-v6-response-bits-100, ecs-v6-response-bits-101, ecs-v6-response-bits-102, ecs-v6-response-bits-103, ecs-v6-response-bits-104, ecs-v6-response-bits-105, ecs-v6-response-bits-106, ecs-v6-response-bits-107, ecs-v6-response-bits-108, ecs-v6-response-bits-109, ecs-v6-response-bits-110, ecs-v6-response-bits-111, ecs-v6-response-bits-112, ecs-v6-response-bits-113, ecs-v6-response-bits-114, ecs-v6-response-bits-115, ecs-v6-response-bits-116, ecs-v6-response-bits-117, ecs-v6-response-bits-118, ecs-v6-response-bits-119, ecs-v6-response-bits-120, ecs-v6-response-bits-121, ecs-v6-response-bits-122, ecs-v6-response-bits-123, ecs-v6-response-bits-124, ecs-v6-response-bits-125, ecs-v6-response-bits-126, ecs-v6-response-bits-127, ecs-v6-response-bits-128, cumul-clientanswers, cumul-authanswers, policy-hits, proxy-mapping-total, remote-logger-count',
        'docdefault': 'cache-bytes, packetcache-bytes, special-memory-usage, ecs-v4-response-bits-\\*, ecs-v6-response-bits-\\*, cumul-answers-\\*, cumul-auth4answers-\\*, cumul-auth6answers-\\*',
        'help' : 'List of statistics that are prevented from being exported via Carbon',
        'doc' : '''
A list of comma-separated statistic names, that are prevented from being exported via carbon for performance reasons.
 ''',
        'doc-new' : '''
A sequence of statistic names, that are prevented from being exported via carbon for performance reasons.
 ''',
    'versionadded': '4.5.0'
    },
    {
        'name' : 'stats_rec_control_disabled_list',
        'section' : 'recursor',
        'type' : LType.ListStrings,
        'default' : 'cache-bytes, packetcache-bytes, special-memory-usage, ecs-v4-response-bits-1, ecs-v4-response-bits-2, ecs-v4-response-bits-3, ecs-v4-response-bits-4, ecs-v4-response-bits-5, ecs-v4-response-bits-6, ecs-v4-response-bits-7, ecs-v4-response-bits-8, ecs-v4-response-bits-9, ecs-v4-response-bits-10, ecs-v4-response-bits-11, ecs-v4-response-bits-12, ecs-v4-response-bits-13, ecs-v4-response-bits-14, ecs-v4-response-bits-15, ecs-v4-response-bits-16, ecs-v4-response-bits-17, ecs-v4-response-bits-18, ecs-v4-response-bits-19, ecs-v4-response-bits-20, ecs-v4-response-bits-21, ecs-v4-response-bits-22, ecs-v4-response-bits-23, ecs-v4-response-bits-24, ecs-v4-response-bits-25, ecs-v4-response-bits-26, ecs-v4-response-bits-27, ecs-v4-response-bits-28, ecs-v4-response-bits-29, ecs-v4-response-bits-30, ecs-v4-response-bits-31, ecs-v4-response-bits-32, ecs-v6-response-bits-1, ecs-v6-response-bits-2, ecs-v6-response-bits-3, ecs-v6-response-bits-4, ecs-v6-response-bits-5, ecs-v6-response-bits-6, ecs-v6-response-bits-7, ecs-v6-response-bits-8, ecs-v6-response-bits-9, ecs-v6-response-bits-10, ecs-v6-response-bits-11, ecs-v6-response-bits-12, ecs-v6-response-bits-13, ecs-v6-response-bits-14, ecs-v6-response-bits-15, ecs-v6-response-bits-16, ecs-v6-response-bits-17, ecs-v6-response-bits-18, ecs-v6-response-bits-19, ecs-v6-response-bits-20, ecs-v6-response-bits-21, ecs-v6-response-bits-22, ecs-v6-response-bits-23, ecs-v6-response-bits-24, ecs-v6-response-bits-25, ecs-v6-response-bits-26, ecs-v6-response-bits-27, ecs-v6-response-bits-28, ecs-v6-response-bits-29, ecs-v6-response-bits-30, ecs-v6-response-bits-31, ecs-v6-response-bits-32, ecs-v6-response-bits-33, ecs-v6-response-bits-34, ecs-v6-response-bits-35, ecs-v6-response-bits-36, ecs-v6-response-bits-37, ecs-v6-response-bits-38, ecs-v6-response-bits-39, ecs-v6-response-bits-40, ecs-v6-response-bits-41, ecs-v6-response-bits-42, ecs-v6-response-bits-43, ecs-v6-response-bits-44, ecs-v6-response-bits-45, ecs-v6-response-bits-46, ecs-v6-response-bits-47, ecs-v6-response-bits-48, ecs-v6-response-bits-49, ecs-v6-response-bits-50, ecs-v6-response-bits-51, ecs-v6-response-bits-52, ecs-v6-response-bits-53, ecs-v6-response-bits-54, ecs-v6-response-bits-55, ecs-v6-response-bits-56, ecs-v6-response-bits-57, ecs-v6-response-bits-58, ecs-v6-response-bits-59, ecs-v6-response-bits-60, ecs-v6-response-bits-61, ecs-v6-response-bits-62, ecs-v6-response-bits-63, ecs-v6-response-bits-64, ecs-v6-response-bits-65, ecs-v6-response-bits-66, ecs-v6-response-bits-67, ecs-v6-response-bits-68, ecs-v6-response-bits-69, ecs-v6-response-bits-70, ecs-v6-response-bits-71, ecs-v6-response-bits-72, ecs-v6-response-bits-73, ecs-v6-response-bits-74, ecs-v6-response-bits-75, ecs-v6-response-bits-76, ecs-v6-response-bits-77, ecs-v6-response-bits-78, ecs-v6-response-bits-79, ecs-v6-response-bits-80, ecs-v6-response-bits-81, ecs-v6-response-bits-82, ecs-v6-response-bits-83, ecs-v6-response-bits-84, ecs-v6-response-bits-85, ecs-v6-response-bits-86, ecs-v6-response-bits-87, ecs-v6-response-bits-88, ecs-v6-response-bits-89, ecs-v6-response-bits-90, ecs-v6-response-bits-91, ecs-v6-response-bits-92, ecs-v6-response-bits-93, ecs-v6-response-bits-94, ecs-v6-response-bits-95, ecs-v6-response-bits-96, ecs-v6-response-bits-97, ecs-v6-response-bits-98, ecs-v6-response-bits-99, ecs-v6-response-bits-100, ecs-v6-response-bits-101, ecs-v6-response-bits-102, ecs-v6-response-bits-103, ecs-v6-response-bits-104, ecs-v6-response-bits-105, ecs-v6-response-bits-106, ecs-v6-response-bits-107, ecs-v6-response-bits-108, ecs-v6-response-bits-109, ecs-v6-response-bits-110, ecs-v6-response-bits-111, ecs-v6-response-bits-112, ecs-v6-response-bits-113, ecs-v6-response-bits-114, ecs-v6-response-bits-115, ecs-v6-response-bits-116, ecs-v6-response-bits-117, ecs-v6-response-bits-118, ecs-v6-response-bits-119, ecs-v6-response-bits-120, ecs-v6-response-bits-121, ecs-v6-response-bits-122, ecs-v6-response-bits-123, ecs-v6-response-bits-124, ecs-v6-response-bits-125, ecs-v6-response-bits-126, ecs-v6-response-bits-127, ecs-v6-response-bits-128, cumul-clientanswers, cumul-authanswers, policy-hits, proxy-mapping-total, remote-logger-count',
        'docdefault': 'cache-bytes, packetcache-bytes, special-memory-usage, ecs-v4-response-bits-\\*, ecs-v6-response-bits-\\*, cumul-answers-\\*, cumul-auth4answers-\\*, cumul-auth6answers-\\*',
        'help' : 'List of statistics that are prevented from being exported via rec_control get-all',
        'doc' : '''
A list of comma-separated statistic names, that are disabled when retrieving the complete list of statistics via `rec_control get-all`, for performance reasons.
These statistics can still be retrieved individually.
 ''',
        'doc-new' : '''
A sequence of statistic names, that are disabled when retrieving the complete list of statistics via `rec_control get-all`, for performance reasons.
These statistics can still be retrieved individually.
 ''',
    'versionadded': '4.5.0'
    },
    {
        'name' : 'stats_ringbuffer_entries',
        'section' : 'recursor',
        'type' : LType.Uint64,
        'default' : '10000',
        'help' : 'maximum number of packets to store statistics for',
        'doc' : '''
Number of entries in the remotes ringbuffer, which keeps statistics on who is querying your server.
Can be read out using ``rec_control top-remotes``.
 ''',
    },
    {
        'name' : 'stats_snmp_disabled_list',
        'section' : 'recursor',
        'type' : LType.ListStrings,
        'default' : 'cache-bytes, packetcache-bytes, special-memory-usage, ecs-v4-response-bits-1, ecs-v4-response-bits-2, ecs-v4-response-bits-3, ecs-v4-response-bits-4, ecs-v4-response-bits-5, ecs-v4-response-bits-6, ecs-v4-response-bits-7, ecs-v4-response-bits-8, ecs-v4-response-bits-9, ecs-v4-response-bits-10, ecs-v4-response-bits-11, ecs-v4-response-bits-12, ecs-v4-response-bits-13, ecs-v4-response-bits-14, ecs-v4-response-bits-15, ecs-v4-response-bits-16, ecs-v4-response-bits-17, ecs-v4-response-bits-18, ecs-v4-response-bits-19, ecs-v4-response-bits-20, ecs-v4-response-bits-21, ecs-v4-response-bits-22, ecs-v4-response-bits-23, ecs-v4-response-bits-24, ecs-v4-response-bits-25, ecs-v4-response-bits-26, ecs-v4-response-bits-27, ecs-v4-response-bits-28, ecs-v4-response-bits-29, ecs-v4-response-bits-30, ecs-v4-response-bits-31, ecs-v4-response-bits-32, ecs-v6-response-bits-1, ecs-v6-response-bits-2, ecs-v6-response-bits-3, ecs-v6-response-bits-4, ecs-v6-response-bits-5, ecs-v6-response-bits-6, ecs-v6-response-bits-7, ecs-v6-response-bits-8, ecs-v6-response-bits-9, ecs-v6-response-bits-10, ecs-v6-response-bits-11, ecs-v6-response-bits-12, ecs-v6-response-bits-13, ecs-v6-response-bits-14, ecs-v6-response-bits-15, ecs-v6-response-bits-16, ecs-v6-response-bits-17, ecs-v6-response-bits-18, ecs-v6-response-bits-19, ecs-v6-response-bits-20, ecs-v6-response-bits-21, ecs-v6-response-bits-22, ecs-v6-response-bits-23, ecs-v6-response-bits-24, ecs-v6-response-bits-25, ecs-v6-response-bits-26, ecs-v6-response-bits-27, ecs-v6-response-bits-28, ecs-v6-response-bits-29, ecs-v6-response-bits-30, ecs-v6-response-bits-31, ecs-v6-response-bits-32, ecs-v6-response-bits-33, ecs-v6-response-bits-34, ecs-v6-response-bits-35, ecs-v6-response-bits-36, ecs-v6-response-bits-37, ecs-v6-response-bits-38, ecs-v6-response-bits-39, ecs-v6-response-bits-40, ecs-v6-response-bits-41, ecs-v6-response-bits-42, ecs-v6-response-bits-43, ecs-v6-response-bits-44, ecs-v6-response-bits-45, ecs-v6-response-bits-46, ecs-v6-response-bits-47, ecs-v6-response-bits-48, ecs-v6-response-bits-49, ecs-v6-response-bits-50, ecs-v6-response-bits-51, ecs-v6-response-bits-52, ecs-v6-response-bits-53, ecs-v6-response-bits-54, ecs-v6-response-bits-55, ecs-v6-response-bits-56, ecs-v6-response-bits-57, ecs-v6-response-bits-58, ecs-v6-response-bits-59, ecs-v6-response-bits-60, ecs-v6-response-bits-61, ecs-v6-response-bits-62, ecs-v6-response-bits-63, ecs-v6-response-bits-64, ecs-v6-response-bits-65, ecs-v6-response-bits-66, ecs-v6-response-bits-67, ecs-v6-response-bits-68, ecs-v6-response-bits-69, ecs-v6-response-bits-70, ecs-v6-response-bits-71, ecs-v6-response-bits-72, ecs-v6-response-bits-73, ecs-v6-response-bits-74, ecs-v6-response-bits-75, ecs-v6-response-bits-76, ecs-v6-response-bits-77, ecs-v6-response-bits-78, ecs-v6-response-bits-79, ecs-v6-response-bits-80, ecs-v6-response-bits-81, ecs-v6-response-bits-82, ecs-v6-response-bits-83, ecs-v6-response-bits-84, ecs-v6-response-bits-85, ecs-v6-response-bits-86, ecs-v6-response-bits-87, ecs-v6-response-bits-88, ecs-v6-response-bits-89, ecs-v6-response-bits-90, ecs-v6-response-bits-91, ecs-v6-response-bits-92, ecs-v6-response-bits-93, ecs-v6-response-bits-94, ecs-v6-response-bits-95, ecs-v6-response-bits-96, ecs-v6-response-bits-97, ecs-v6-response-bits-98, ecs-v6-response-bits-99, ecs-v6-response-bits-100, ecs-v6-response-bits-101, ecs-v6-response-bits-102, ecs-v6-response-bits-103, ecs-v6-response-bits-104, ecs-v6-response-bits-105, ecs-v6-response-bits-106, ecs-v6-response-bits-107, ecs-v6-response-bits-108, ecs-v6-response-bits-109, ecs-v6-response-bits-110, ecs-v6-response-bits-111, ecs-v6-response-bits-112, ecs-v6-response-bits-113, ecs-v6-response-bits-114, ecs-v6-response-bits-115, ecs-v6-response-bits-116, ecs-v6-response-bits-117, ecs-v6-response-bits-118, ecs-v6-response-bits-119, ecs-v6-response-bits-120, ecs-v6-response-bits-121, ecs-v6-response-bits-122, ecs-v6-response-bits-123, ecs-v6-response-bits-124, ecs-v6-response-bits-125, ecs-v6-response-bits-126, ecs-v6-response-bits-127, ecs-v6-response-bits-128, cumul-clientanswers, cumul-authanswers, policy-hits, proxy-mapping-total, remote-logger-count',
        'docdefault': 'cache-bytes, packetcache-bytes, special-memory-usage, ecs-v4-response-bits-\\*, ecs-v6-response-bits-\\*',
        'help' : 'List of statistics that are prevented from being exported via SNMP',
        'doc' : '''
A list of comma-separated statistic names, that are prevented from being exported via SNMP, for performance reasons.
 ''',
        'doc-new' : '''
A sequence of statistic names, that are prevented from being exported via SNMP, for performance reasons.
 ''',
    'versionadded': '4.5.0'
    },
    {
        'name' : 'structured_logging',
        'section' : 'logging',
        'type' : LType.Bool,
        'default' : 'true',
        'help' : 'Prefer structured logging',
        'doc' : '''
Prefer structured logging when both an old style and a structured log messages is available.
 ''',
        'versionadded': '4.6.0',
        'versionchanged': [('5.0.0', 'Disabling structured logging is deprecated'),
                           ('5.1.0', 'Disabling structured logging is not supported')]
    },
    {
        'name' : 'structured_logging_backend',
        'section' : 'logging',
        'type' : LType.String,
        'default' : 'default',
        'help' : 'Structured logging backend',
        'doc' : '''
The backend used for structured logging output.
This setting must be set on the command line (``--structured-logging-backend=...``) to be effective.
Available backends are:

- ``default``: use the traditional logging system to output structured logging information.
- ``systemd-journal``: use systemd-journal.
  When using this backend, provide ``-o verbose`` or simular output option to ``journalctl`` to view the full information.
- ``json``: JSON objects are written to the standard error stream.

See :doc:`appendices/structuredlogging` for more details.
 ''',
        'versionadded': '4.8.0',
        'versionchanged': ('5.1.0', 'The JSON backend was added')
    },
    {
        'name' : 'tcp_fast_open',
        'section' : 'incoming',
        'type' : LType.Uint64,
        'default' : '0',
        'help' : 'Enable TCP Fast Open support on the listening sockets, using the supplied numerical value as the queue size',
        'doc' : '''
Enable TCP Fast Open support, if available, on the listening sockets.
The numerical value supplied is used as the queue size, 0 meaning disabled. See :ref:`tcp-fast-open-support`.
 ''',
    'versionadded': '4.1.0'
    },
    {
        'name' : 'tcp_fast_open_connect',
        'section' : 'outgoing',
        'type' : LType.Bool,
        'default' : 'false',
        'help' : 'Enable TCP Fast Open support on outgoing sockets',
        'doc' : '''
Enable TCP Fast Open Connect support, if available, on the outgoing connections to authoritative servers. See :ref:`tcp-fast-open-support`.
 ''',
    'versionadded': '4.5.0'
    },
    {
        'name' : 'tcp_max_idle_ms',
        'section' : 'outgoing',
        'oldname' : 'tcp-out-max-idle-ms',
        'type' : LType.Uint64,
        'default' : '10000',
        'help' : 'Time TCP/DoT connections are left idle in milliseconds or 0 if no limit',
        'doc' : '''
Time outgoing TCP/DoT connections are left idle in milliseconds or 0 if no limit. After having been idle for this time, the connection is eligible for closing.
 ''',
    'versionadded': '4.6.0'
    },
    {
        'name' : 'tcp_max_idle_per_auth',
        'section' : 'outgoing',
        'oldname' : 'tcp-out-max-idle-per-auth',
        'type' : LType.Uint64,
        'default' : '10',
        'help' : 'Maximum number of idle TCP/DoT connections to a specific IP per thread, 0 means do not keep idle connections open',
        'doc' : '''
Maximum number of idle outgoing TCP/DoT connections to a specific IP per thread, 0 means do not keep idle connections open.
 ''',
    'versionadded': '4.6.0'
    },
    {
        'name' : 'tcp_max_queries',
        'section' : 'outgoing',
        'oldname' : 'tcp-out-max-queries',
        'type' : LType.Uint64,
        'default' : '0',
        'help' : 'Maximum total number of queries per TCP/DoT connection, 0 means no limit',
        'doc' : '''
Maximum total number of queries per outgoing TCP/DoT connection, 0 means no limit. After this number of queries, the connection is
closed and a new one will be created if needed.
 ''',
    },
    {
        'name' : 'tcp_max_idle_per_thread',
        'section' : 'outgoing',
        'oldname' : 'tcp-out-max-idle-per-thread',
        'type' : LType.Uint64,
        'default' : '100',
        'help' : 'Maximum number of idle TCP/DoT connections per thread',
        'doc' : '''
Maximum number of idle outgoing TCP/DoT connections per thread, 0 means do not keep idle connections open.
 ''',
    'versionadded': '4.6.0'
    },
    {
        'name' : 'threads',
        'section' : 'recursor',
        'type' : LType.Uint64,
        'default' : '2',
        'help' : 'Launch this number of threads',
        'doc' : '''
Spawn this number of threads on startup.
 ''',
    },
    {
        'name' : 'tcp_threads',
        'section' : 'recursor',
        'type' : LType.Uint64,
        'default' : '1',
        'help' : 'Launch this number of threads listening for and processing TCP queries',
        'doc' : '''
Spawn this number of TCP processing threads on startup.
 ''',
        'versionadded': '5.0.0'
    },
    {
        'name' : 'trace',
        'section' : 'logging',
        'type' : LType.String,
        'default' : 'no',
        'help' : 'if we should output heaps of logging. set to \'fail\' to only log failing domains',
        'doc' : '''
One of ``no``, ``yes`` or ``fail``.
If turned on, output impressive heaps of logging.
May destroy performance under load.
To log only queries resulting in a ``ServFail`` answer from the resolving process, this value can be set to ``fail``, but note that the performance impact is still large.
Also note that queries that do produce a result but with a failing DNSSEC validation are not written to the log
 ''',
    },
    {
        'name' : 'udp_source_port_min',
        'section' : 'outgoing',
        'type' : LType.Uint64,
        'default' : '1024',
        'help' : 'Minimum UDP port to bind on',
        'doc' : '''
This option sets the low limit of UDP port number to bind on.

In combination with :ref:`setting-udp-source-port-max` it configures the UDP
port range to use. Port numbers are randomized within this range on
initialization, and exceptions can be configured with :ref:`setting-udp-source-port-avoid`
 ''',
    'versionadded': '4.2.0'
    },
    {
        'name' : 'udp_source_port_max',
        'section' : 'outgoing',
        'type' : LType.Uint64,
        'default' : '65535',
        'help' : 'Maximum UDP port to bind on',
        'doc' : '''
This option sets the maximum limit of UDP port number to bind on.

See :ref:`setting-udp-source-port-min`.
 ''',
    'versionadded': '4.2.0'
    },
    {
        'name' : 'udp_source_port_avoid',
        'section' : 'outgoing',
        'type' : LType.ListStrings,
        'default' : '4791,11211',
        'help' : 'List of comma separated UDP port numbers to avoid',
        'doc' : '''
A list of comma-separated UDP port numbers to avoid when binding.
Ex: `4791,5300,11211`

See :ref:`setting-udp-source-port-min`.
 ''',
        'doc-new' : '''
A sequence of UDP port numbers to avoid when binding. For example:

.. code-block:: yaml

 outgoing:
   udp_source_port_avoid:
     - 4791
     - 5300
     - 11211

See :ref:`setting-udp-source-port-min`.
 ''',
        'versionadded': '4.2.0',
        'versionchanged': ('5.2.0', 'port 4791 was added to the default list'),
    },
    {
        'name' : 'udp_truncation_threshold',
        'section' : 'incoming',
        'type' : LType.Uint64,
        'default' : '1232',
        'help' : 'Maximum UDP response size before we truncate',
        'doc' : '''
EDNS0 allows for large UDP response datagrams, which can potentially raise performance.
Large responses however also have downsides in terms of reflection attacks.
This setting limits the accepted size.
Maximum value is 65535, but values above 4096 should probably not be attempted.

To know why 1232, see the note at :ref:`setting-edns-outgoing-bufsize`.
 ''',
        'versionchanged': ('4.2.0', 'Before 4.2.0, the default was 1680.')
    },
    {
        'name' : 'unique_response_tracking',
        'section' : 'nod',
        'type' : LType.Bool,
        'default' : 'false',
        'help' : 'Track unique responses (tuple of query name, type and RR).',
        'doc' : '''
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
 ''',
    'versionadded': '4.2.0'
    },
    {
        'name' : 'unique_response_log',
        'section' : 'nod',
        'type' : LType.Bool,
        'default' : 'true',
        'help' : 'Log unique responses',
        'doc' : '''
Whether to log when a unique response is detected. The log line
looks something like:

Oct 24 12:11:27 Unique response observed: qname=foo.com qtype=A rrtype=AAAA rrname=foo.com rrcontent=1.2.3.4
 ''',
    'versionadded': '4.2.0'
    },
    {
        'name' : 'unique_response_db_size',
        'section' : 'nod',
        'type' : LType.Uint64,
        'default' : '67108864',
        'help' : 'Size of the DB used to track unique responses in terms of number of cells. Defaults to 67108864',
        'doc' : '''
The default size of the stable bloom filter used to store previously
observed responses is 67108864. To change the number of cells, use this
setting. For each cell, the SBF uses 1 bit of memory, and one byte of
disk for the persistent file.
If there are already persistent files saved to disk, this setting will
have no effect unless you remove the existing files.
 ''',
    'versionadded': '4.2.0'
    },
    {
        'name' : 'unique_response_history_dir',
        'section' : 'nod',
        'type' : LType.String,
        'default' : 'NODCACHEDIRUDR',
        'docdefault': 'Determined by distribution',
        'help' : 'Persist unique response tracking data here to persist between restarts',
        'doc' : '''
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
 ''',
    'versionadded': '4.2.0'
    },
    {
        'name' : 'unique_response_pb_tag',
        'section' : 'nod',
        'type' : LType.String,
        'default' : 'pdns-udr',
        'help' : 'If protobuf is configured, the tag to use for messages containing unique DNS responses. Defaults to \'pdns-udr\'',
        'doc' : '''
If protobuf is configured, then this tag will be added to all protobuf response messages when
a unique DNS response is observed.
 ''',
    'versionadded': '4.2.0'
    },
    {
        'name' : 'unique_response_ignore_list',
        'section' : 'nod',
        'type' : LType.ListStrings,
        'default' : '',
        'help' : 'List of domains (and implicitly all subdomains) which will never be considered for UDR',
        'doc' : '''
This setting is a list of all domains (and implicitly all subdomains)
that will never be considered for new unique domain responses.
For example, if the domain 'example.com' is in the list, then 'foo.bar.example.com'
will never be considered for a new unique domain response.
''',
        'versionadded': '5.1.0'
    },
    {
        'name' : 'unique_response_ignore_list_file',
        'section' : 'nod',
        'type' : LType.String,
        'default' : '',
        'help' : 'File with list of domains (and implicitly all subdomains) which will never be considered for UDR',
        'doc' : '''
Path to a file with a list of domains. File should have one domain per line,
with no extra characters or comments.
See :ref:`setting-unique-response-ignore-list`.
''',
        'versionadded': '5.1.0'
    },
    {
        'name' : 'use_incoming_edns_subnet',
        'section' : 'incoming',
        'type' : LType.Bool,
        'default' : 'false',
        'help' : 'Pass along received EDNS Client Subnet information',
        'doc' : '''
Whether to process and pass along a received EDNS Client Subnet to authoritative servers.
The ECS information will only be sent for netmasks and domains listed in :ref:`setting-edns-subnet-allow-list` and will be truncated if the received scope exceeds :ref:`setting-ecs-ipv4-bits` for IPv4 or :ref:`setting-ecs-ipv6-bits` for IPv6.
 ''',
    },
    {
        'name' : 'version',
        'section' : 'commands',
        'type' : LType.Command,
        'default' : 'no',
        'help' : 'Print version string',
        'doc' : '''
Print version of this binary. Useful for checking which version of the PowerDNS recursor is installed on a system.
 ''',
    },
    {
        'name' : 'version_string',
        'section' : 'recursor',
        'type' : LType.String,
        'default' : RUNTIME,
        'help' : 'string reported on version.pdns or version.bind',
        'doc' : '''
By default, PowerDNS replies to the 'version.bind' query with its version number.
Security conscious users may wish to override the reply PowerDNS issues.
 ''',
    },
    {
        'name' : 'webserver',
        'section' : 'webservice',
        'type' : LType.Bool,
        'default' : 'false',
        'help' : 'Start a webserver (for REST API)',
        'doc' : '''
Start the webserver (for REST API).
 ''',
    },
    {
        'name' : 'address',
        'section' : 'webservice',
        'oldname' : 'webserver-address',
        'type' : LType.String,
        'default' : '127.0.0.1',
        'help' : 'IP Address of webserver to listen on',
        'doc' : '''
IP address for the webserver to listen on.
''',
        'doc-new' : '''
IP address for the webserver to listen on.
This field is ignored if :ref:`setting-yaml-webservice.listen` is set.
''',
    },
    {
        'name' : 'listen',
        'section' : 'webservice',
        'type' : LType.ListIncomingWSConfigs,
        'default' : '',
        'help' : 'IP addresses and associated attributes for the webserver to listen on',
        'doc' : '''
IP addresses and associated attributes for the webserver to listen on.
If this setting has a non-default value, :ref:`setting-yaml-webservice.address` and :ref:`setting-yaml-webservice.port` will be ignored. Note multiple listen addresses can be configured and https is supported as well, in contrast to earlier (pre 5.3.0) versions.
 ''',
        'skip-old': 'No equivalent old-style setting',
        'versionadded': '5.3.0',
    },
    {
        'name' : 'allow_from',
        'section' : 'webservice',
        'oldname' : 'webserver-allow-from',
        'type' : LType.ListSubnets,
        'default' : '127.0.0.1, ::1',
        'help' : 'Webserver access is only allowed from these subnets',
        'doc' : '''
These IPs and subnets are allowed to access the webserver. Note that
specifying an IP address without a netmask uses an implicit netmask
of /32 or /128.
 ''',
        'versionchanged': ('4.1.0', 'Default is now 127.0.0.1,::1, was 0.0.0.0/0,::/0 before.')
    },
    {
        'name' : 'hash_plaintext_credentials',
        'section' : 'webservice',
        'oldname': 'webserver-hash-plaintext-credentials',
        'type' : LType.Bool,
        'default' : 'false',
        'help' : 'Whether to hash passwords and api keys supplied in plaintext, to prevent keeping the plaintext version in memory at runtime',
        'doc' : '''
Whether passwords and API keys supplied in the configuration as plaintext should be hashed during startup, to prevent the plaintext versions from staying in memory. Doing so increases significantly the cost of verifying credentials and is thus disabled by default.
Note that this option only applies to credentials stored in the configuration as plaintext, but hashed credentials are supported without enabling this option.
 ''',
    'versionadded': '4.6.0'
    },
    {
        'name' : 'loglevel',
        'section' : 'webservice',
        'oldname' : 'webserver-loglevel',
        'type' : LType.String,
        'default' : 'normal',
        'help' : 'Amount of logging in the webserver (none, normal, detailed)',
        'doc' : '''
One of ``none``, ``normal``, ``detailed``.
The amount of logging the webserver must do. ``none`` means no useful webserver information will be logged.
When set to ``normal``, the webserver will log a line per request::

   Feb 03 14:54:00 msg="Request" subsystem="webserver" level="0" prio="Notice" tid="0" ts="1738590840.208" HTTPVersion="HTTP/1.1" method="GET" remote="[::1]:49880" respsize="5418" status="200" uniqueid="a31a280d-29de-4db8-828f-edc862eb8653" urlpath="/"

When set to ``detailed``, all available information about the request and response is logged.

.. note::
  The webserver logs these line on the NOTICE level. The :ref:`setting-loglevel` setting must be 5 or higher for these lines to end up in the log.
 ''',
    'versionadded': '4.2.0'
    },
    {
        'name' : 'password',
        'section' : 'webservice',
        'oldname' : 'webserver-password',
        'type' : LType.String,
        'default' : '',
        'help' : 'Password required for accessing the webserver',
        'doc' : '''
Password required to access the webserver. Since 4.6.0 the password can be hashed and salted using ``rec_control hash-password`` instead of being present in the configuration in plaintext, but the plaintext version is still supported.
 ''',
        'versionchanged': ('4.6.0', 'This setting now accepts a hashed and salted version.')
    },
    {
        'name' : 'port',
        'section' : 'webservice',
        'type' : LType.Uint64,
        'oldname': 'webserver-port',
        'default' : '8082',
        'help' : 'Port of webserver to listen on',
        'doc' : '''
TCP port where the webserver should listen on.
 ''',
        'doc-new' : '''
TCP port where the webserver should listen on.
This field is ignored if :ref:`setting-yaml-webservice.listen` is set.
 ''',
    },
    {
        'name' : 'write_pid',
        'section' : 'recursor',
        'type' : LType.Bool,
        'default' : 'true',
        'help' : 'Write a PID file',
        'doc' : '''
If a PID file should be written to :ref:`setting-socket-dir`
 ''',
    },
    {
        'name' : 'x_dnssec_names',
        'section' : 'dnssec',
        'type' : LType.ListStrings,
        'default' : '',
        'help' : 'Collect DNSSEC statistics for names or suffixes in this list in separate x-dnssec counters',
        'doc' : '''
List of names whose DNSSEC validation metrics will be counted in a separate set of metrics that start
with ``x-dnssec-result-``.
The names are suffix-matched.
This can be used to not count known failing (test) name validations in the ordinary DNSSEC metrics.
 ''',
    'versionadded': '4.5.0'
    },
    {
        'name' : 'system_resolver_ttl',
        'section' : 'recursor',
        'type' : LType.Uint64,
        'default' : '0',
        'help' : 'Set TTL of system resolver feature, 0 (default) is disabled',
        'doc' : '''
Sets TTL in seconds of the system resolver feature.
If not equal to zero names can be used for forwarding targets.
The names will be resolved by the system resolver configured in the OS.

The TTL is used as a time to live to see if the names used in forwarding resolve to a different address than before.
If the TTL is expired, a re-resolve will be done by the next iteration of the check function;
if a change is detected, the recursor performs an equivalent of ``rec_control reload-zones``.

Make sure the recursor itself is not used by the system resolver! Default is 0 (not enabled).
A suggested value is 60.
''',
    'versionadded': '5.1.0'
    },
    {
        'name' : 'system_resolver_interval',
        'section' : 'recursor',
        'type' : LType.Uint64,
        'default' : '0',
        'help' : 'Set interval (in seconds) of the re-resolve checks of system resolver subsystem.',
        'doc' : '''
Sets the check interval (in seconds) of the system resolver feature.
All names known by the system resolver subsystem are periodically checked for changing values.

If the TTL of a name has expired, it is checked by re-resolving it.
if a change is detected, the recursor performs an equivalent of ``rec_control reload-zones``.

This settings sets the interval between the checks.
If set to zero (the default), the value :ref:`setting-system-resolver-ttl` is used.
''',
    'versionadded': '5.1.0'
    },
    {
        'name' : 'system_resolver_self_resolve_check',
        'section' : 'recursor',
        'type' : LType.Bool,
        'default' : 'true',
        'help' : 'Check for potential self-resolve, default enabled.',
        'doc' : '''
Warn on potential self-resolve.
If this check draws the wrong conclusion, you can disable it.
''',
        'versionadded': '5.1.0'
    },
    {
        'name' : 'trustanchors',
        'section' : 'dnssec',
        'type' : LType.ListTrustAnchors,
        'default' : '[{name: ., dsrecords: [\'20326 8 2 e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d\', \'38696 8 2 683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16\']}]',
        'docdefault' : '''

.. code-block:: yaml

   dnssec:
     - name: .
       dsrecords:
         - 20326 8 2 e06d44b80b8f1d39a95c0b0d7c65d08458e880409bbc683457104237c7f8ec8d
         - 38696 8 2 683d2d0acb8c9b712a1948b27f741219298d0a450d612c483af444a4c0fb2b16

''',
        'help' : 'Sequence of trust anchors',
        'doc' : '''
Sequence of trust anchors. If the sequence contains an entry for the root zone, the default root zone trust anchor is not included.
If a zone appears multiple times, the entries in ``dsrecords`` are merged.
        ''',
        'skip-old' : 'Equivalent Lua config in :doc:`lua-config/dnssec`',
        'versionadded': '5.1.0',
        'runtime': ['add-ta', 'clear-ta', 'reload-lua-config', 'reload-yaml'],
    },
    {
        'name' : 'negative_trustanchors',
        'section' : 'dnssec',
        'type' : LType.ListNegativeTrustAnchors,
        'default' : '',
        'help' : 'A sequence of negative trust anchors',
        'doc' : '''
Sequence of negative trust anchors.
        ''',
        'skip-old' : 'Equivalent Lua config in :doc:`lua-config/dnssec`',
        'versionadded': '5.1.0',
        'runtime': ['add-nta', 'clear-nta', 'reload-lua-config', 'reload-yaml'],
    },
    {
        'name' : 'trustanchorfile',
        'section' : 'dnssec',
        'type' : LType.String,
        'default' : '',
        'help' : 'A path to a zone file containing trust anchors',
        'doc' : '''
A path to a zone file to read trust anchors from.
This can be used to read distribution provided trust anchors, as for instance ``/usr/share/dns/root.key`` from Debian's ``dns-root-data`` package.
        ''',
        'skip-old' : 'Equivalent Lua config in :doc:`lua-config/dnssec`',
        'versionadded': '5.1.0',
        'runtime': ['reload-lua-config', 'reload-yaml'],
    },
    {
        'name' : 'trustanchorfile_interval',
        'section' : 'dnssec',
        'type' : LType.Uint64,
        'default' : '24',
        'help' : 'Interval (in hours) to read the trust anchors file',
        'doc' : '''
Interval (in hours) to re-read the ``trustanchorfile``.  Zero disables periodic re-reads.
        ''',
        'skip-old' : 'Equivalent Lua config in :doc:`lua-config/dnssec`',
        'versionadded': '5.1.0',
    },
    {
        'name' : 'protobuf_servers',
        'section' : 'logging',
        'type' : LType.ListProtobufServers,
        'default' : '',
        'help' : 'Sequence of protobuf servers',
        'doc' : '''
Sequence of outgoing protobuf servers. Currently the maximum size of this list is one.
        ''',
        'skip-old' : 'Equivalent Lua config in :doc:`lua-config/protobuf`',
        'versionadded': '5.1.0',
        'runtime': ['reload-lua-config', 'reload-yaml'],
    },
    {
        'name' : 'outgoing_protobuf_servers',
        'section' : 'logging',
        'type' : LType.ListProtobufServers,
        'default' : '',
        'help' : 'List of outgoing protobuf servers',
        'doc' : '''
Sequence of outgoing protobuf servers. Currently the maximum size of this list is one.
        ''',
        'skip-old' : 'Equivalent Lua config in :doc:`lua-config/protobuf`',
        'versionadded': '5.1.0',
        'runtime': ['reload-lua-config', 'reload-yaml'],
    },
    {
        'name' : 'protobuf_mask_v4',
        'section' : 'logging',
        'type' : LType.Uint64,
        'default' : '32',
        'help' : 'Network mask to apply for client IPv4 addresses in protobuf messages',
        'doc' : '''
Network mask to apply to the client IPv4 addresses, for anonymization purposes. The default of 32 means no anonymization.
        ''',
        'skip-old' : 'Equivalent Lua config in :doc:`lua-config/protobuf`',
        'versionadded': '5.1.0',
    },
    {
        'name' : 'protobuf_mask_v6',
        'section' : 'logging',
        'type' : LType.Uint64,
        'default' : '128',
        'help' : 'Network mask to apply for client IPv6 addresses in protobuf messages',
        'doc' : '''
Network mask to apply to the client IPv6 addresses, for anonymization purposes. The default of 128 means no anonymization.
        ''',
        'skip-old' : 'Equivalent Lua config in :doc:`lua-config/protobuf`',
        'versionadded': '5.1.0',
    },
    {
        'name' : 'dnstap_framestream_servers',
        'section' : 'logging',
        'type' : LType.ListDNSTapFrameStreamServers,
        'default' : '',
        'help' : 'Sequence of dnstap servers',
        'doc' : '''
Sequence of dnstap servers. Currently the maximum size of this list is one.
        ''',
        'skip-old' : 'Equivalent Lua config in :doc:`lua-config/protobuf`',
        'versionadded': '5.1.0',
        'runtime': ['reload-lua-config', 'reload-yaml'],
    },
    {
        'name' : 'dnstap_nod_framestream_servers',
        'section' : 'logging',
        'type' : LType.ListDNSTapNODFrameStreamServers,
        'default' : '',
        'help' : 'Sequence of NOD dnstap servers',
        'doc' : '''
Sequence of NOD dnstap servers. Currently the maximum size of this list is one.
        ''',
        'skip-old' : 'Equivalent Lua config in :doc:`lua-config/protobuf`',
        'versionadded': '5.1.0',
        'runtime': ['reload-lua-config', 'reload-yaml'],
    },
    {
        'name' : 'sortlists',
        'section' : 'recursor',
        'type' : LType.ListSortLists,
        'default' : '',
        'help' : 'Sequence of sort lists',
        'doc' : '''
Sequence of sort lists.
        ''',
        'skip-old' : 'Equivalent Lua config in :doc:`lua-config/sortlist`',
        'versionadded': '5.1.0',
    },
    {
        'name' : 'rpzs',
        'section' : 'recursor',
        'type' : LType.ListRPZs,
        'default' : '',
        'help' : 'Sequence of RPZ entries',
        'doc' : '''
Sequence of RPZ entries.
        ''',
        'skip-old' : 'Equivalent Lua config in :doc:`lua-config/rpz`',
        'versionadded': '5.1.0',
        'runtime': ['reload-lua-config', 'reload-yaml'],
    },
    {
        'name' : 'zonetocaches',
        'section' : 'recordcache',
        'type' : LType.ListZoneToCaches,
        'default' : '',
        'help' : 'Sequence of ZoneToCache entries ',
        'doc' : '''
Sequence of ZoneToCache entries
        ''',
        'skip-old' : 'Equivalent Lua config in :doc:`lua-config/ztc`',
        'versionadded': '5.1.0',
        'runtime': ['reload-lua-config', 'reload-yaml'],
    },
    {
        'name' : 'allowed_additional_qtypes',
        'section' : 'recursor',
        'type' : LType.ListAllowedAdditionalQTypes,
        'default' : '',
        'help' : 'Sequence of AllowedAdditionalQType',
        'doc' : '''
Sequence of AllowedAdditionalQType
        ''',
        'skip-old' : 'Equivalent Lua config in :doc:`lua-config/additionals`',
        'versionadded': '5.1.0',
        'runtime': ['reload-lua-config', 'reload-yaml'],
    },
    {
        'name' : 'proxymappings',
        'section' : 'incoming',
        'type' : LType.ListProxyMappings,
        'default' : '',
        'help' : 'Sequence of ProxyMapping',
        'doc' : '''
Sequence of ProxyMapping
        ''',
        'skip-old' : 'Equivalent Lua config in :doc:`lua-config/proxymapping`',
        'versionadded': '5.1.0',
        'runtime': ['reload-lua-config', 'reload-yaml'],
    },
    {
        'name' : 'lua_start_stop_script',
        'section' : 'recursor',
        'type' : LType.String,
        'default' : '',
        'help' : 'Lua script containing functions to run on startup and shutdown',
        'doc' : '''
Load this Lua script on startup and shutdown and run the Lua function ``on_recursor_start`` on startup and the Lua function ``on_recursor_stop`` on a ``nice`` shutdown (using ``rec_control quit-nicely`` of the :program:`Recursor` process.
        ''',
        'skip-old' : 'No equivalent old-style setting',
        'versionadded': '5.2.0',
    },
    {
        'name' : 'forwarding_catalog_zones',
        'section' : 'recursor',
        'type' : LType.ListForwardingCatalogZones,
        'default' : '',
        'help' : 'Sequence of ForwardingCatalogZone',
        'doc' : '''
Sequence of ForwardingCatalogZone. This setting cannot be combined with :ref:`setting-lua-config-file`.
        ''',
        'skip-old' : 'No equivalent old style setting',
        'versionadded': '5.2.0',
        'runtime': ['reload-lua-config', 'reload-yaml'],
    },
    {
        'name' : 'cookies',
        'section' : 'outgoing',
        'oldname': 'outgoing-cookies',
        'type': LType.Bool,
        'default': 'false',
        'help': 'Enable DNS cookies when contacting authoritative servers or forwarders',
        'doc': '''
Enable DNS cookies (:rfc:`7873`, :rfc:`9018`) when contacting authoritative servers or forwarders.
''',
        'versionadded': '5.4.0',
    },
    {
        'name' : 'cookies_unsupported',
        'section' : 'outgoing',
        'oldname': 'outgoing-cookies-unsupported',
        'type': LType.ListSocketAddresses,
        'default': '',
        'help': 'Addresses (with optional port) of authoritative servers that do not support cookies',
        'doc': '''
Addresses of servers that do not properly support DNS cookies (:rfc:`7873`, :rfc:`9018`). Recursor will not even try to probe these servers for cookie support. If no port is specified port 53 is used.
''',
        'versionadded': '5.4.0',
    },
    {
        'name' : 'tls_configurations',
        'section' : 'outgoing',
        'type' : LType.ListOutgoingTLSConfigurations,
        'default' : '',
        'help' : 'Sequence of OutgoingTLSConfiguration',
        'doc' : '''
Configurations used for outgoing DoT connections.
A DoT connection is matched against the subnets lists (using the remote IP) and if that does not provide a match, the nameserver name is matched against the suffixes lists. When a match is found, the corresponding DoT configuration is used.
        ''',
        'skip-old' : 'No equivalent old style setting',
        'versionadded': '5.4.0',
        'runtime': ['reload-lua-config', 'reload-yaml'],
    },
    {
        'name' : 'opentelemetry_trace_conditions',
        'section' : 'logging',
        'type' : LType.ListOpenTelemetryTraceConditions,
        'default' : '',
        'help' : 'Sequence of OpenTelemetryTraceCondition',
        'doc' : '''
        List of conditions specifying when to generate :ref:`opentelemetry_tracing`.
        ''',
        'skip-old' : 'No equivalent old style setting',
        'versionadded': '5.4.0',
        'runtime': ['reload-lua-config', 'reload-yaml'],
    },
]
