Operating PowerDNS Recursor
===========================

.. _logging:

Logging
-------

In a production environment, you will want to be able to monitor PowerDNS performance.
Furthermore, PowerDNS can perform a configurable amount of operational logging.

On modern Linux distributions, the PowerDNS recursor logs to stderr, which is consumed by ``systemd-journald``.
This means that looking into the logs that are produced, `journalctl <https://www.freedesktop.org/software/systemd/man/journalctl.html>`_ can be used::

    # journalctl -u pdns-recursor -n 100

Additionally, the Recursor *can* log to syslog on these systems.
Logging to syslog is disabled in the unit file to prevent double logging.
To enable this, create an drop in unit file at ``/etc/systemd/systemd/pdns-recursor.service.d/use-syslog.conf``::

    [Service]
    ExecStart=
    ExecStart=/usr/sbin/pdns_recursor --daemon=no --write-pid=no --enable-syslog

Logging to syslog
^^^^^^^^^^^^^^^^^
This chapter assumes familiarity with syslog, the unix logging device.
PowerDNS logs messages with different levels.
The more urgent the message, the lower the 'priority'.

By default, PowerDNS will only log messages with an urgency of 3 or lower, but this can be changed using the :ref:`setting-yaml-logging.loglevel` setting in the configuration file.
Setting it to 0 will eliminate all logging, 9 will log everything.

By default, logging is performed under the 'DAEMON' facility which is shared with lots of other programs.
If you regard nameserving as important, you may want to have it under a dedicated facility so PowerDNS can log to its own files, and not clutter generic files.

For this purpose, syslog knows about 'local' facilities, numbered from LOCAL0 to LOCAL7.
To move PowerDNS logging to LOCAL0, set :ref:`setting-yaml-logging.facility` to 0 in your configuration.

Furthermore, you may want to have separate files for the differing priorities - preventing lower priority messages from obscuring important ones.
A sample ``syslog.conf`` might be::

  local0.info                       -/var/log/pdns.info
  local0.warn                       -/var/log/pdns.warn
  local0.err                        /var/log/pdns.err

Where local0.err would store the really important messages.
For performance and disk space reasons, it is advised to audit your ``syslog.conf`` for statements also logging PowerDNS activities.
Many ``syslog.conf``\ s have a ``*.*`` statement to ``/var/log/syslog``, which you may want to remove.

For performance reasons, be especially certain that no large amounts of synchronous logging take place.
Under Linux, this is indicated by file names not starting with a ``-`` - indicating a synchronous log, which hurts performance.

Be aware that syslog by default logs messages at the configured priority and higher!
To log only info messages, use ``local0.=info``

Cache Management
----------------
Sometimes a domain fails to resolve due to an error on the domain owner's end, or records for your own domain have updated and you want your users to immediately see them without waiting for the TTL to expire.
The :doc:`rec_control <manpages/rec_control.1>` tool can be used to selectively wipe the cache.

To wipe all records for the exact name 'www.example.com'::

  rec_control wipe-cache www.example.com

Whole subtrees can we wiped as well, to wipe all cache entries for 'example.com' and everything below it, suffix the name with a '$'::

  rec_control wipe-cache example.com$

.. note::

  When wiping cache entries, matching entries in *all* caches (packet cache, recursor cache, negative cache) are removed.

When debugging resolving issues, it can be advantageous to have a dump of all the cache entries.
:doc:`rec_control <manpages/rec_control.1>` can write the caches of all threads to a file::

  rec_control dump-cache /tmp/cache

.. _tracing:

Tracing Queries
---------------
To investigate failures with resolving certain domain names, the PowerDNS :program:`Recursor` features a tracing infrastructure.
This infrastructure will log every step the :program:`Recursor` takes to resolve a name and will log all DNSSEC related information as well.

To enable tracing for all queries, enable the :ref:`setting-yaml-logging.trace` setting.
Trace information will be written to the log.

.. warning::

  Enabling tracing for all queries on a system with a high query rate can severely impact performance.

Tracing can also be enabled at runtime, without restarting the :program:`Recursor`, for specific domains.
These specific domains can be specified as a regular expression.
This can be done using :doc:`rec_control trace-regex <manpages/rec_control.1>`::

  rec_control trace-regex '.*\.example.com\.$'

Will enable tracing for any query *in* the example.com domain (but not example.com itself).

Since version 4.9.0 ``trace_regex`` takes an extra file argument.
Trace information will be written to the file and not to the log.
If the file argument is a hyphen (``-``), trace information will be written to the standard output stream.
For example::

  rec_control trace-regex 'example\.com\.$' - | grep asking

will show which authoritative servers were consulted.

Do not forget to disable tracing after diagnosis is done::

  rec_control trace-regex

Logging details of queries and answers
--------------------------------------

In some cases a tracing provides too much information, and we want to follow what the recursor is doing on a higher level.
By setting :ref:`setting-yaml-logging.quiet` to ``true`` the recursor will produce a log line for each client query received and answered.
Be aware that this causes overhead and should not be used in a high query-per-second production environment::

    Jul 09 09:08:31 msg="Question" subsystem="syncres" level="0" prio="Info" tid="4" ts="1720508911.919" ecs="" mtid="1" proto="udp" qname="www.example.com" qtype="A" remote="127.0.0.1:54573"

    Jul 09 09:08:32 msg="Answer" subsystem="syncres" level="0" prio="Info" tid="4" ts="1720508912.549" additional="1" answer-is-variable="0" answers="1" dotout="0" ecs="" into-packetcache="1" maxdepth="3" mtid="1" netms="617.317000" outqueries="13" proto="udp" qname="www.example.com" qtype="A" rcode="0" rd="1" remote="127.0.0.1:54573" tcpout="0" throttled="0" timeouts="0" totms="627.060000" validationState="Secure"

When ``quiet`` is set to ``false``, the following keys and values are logged for questions and answers not
answered from the packet cache.
Refer to :doc:`appendices/structuredlogging` for more details on the common keys used for structured logging messages.
Note that depending on record cache content a single client query can result into multiple queries to authoritative servers.
If the exact answer is available from the record cache no outgoing queries are needed.

+-------------------------------------------------------------------------------------------+
|                         **Keys common to Questions and Answers**                          |
+-----------------------+-----------------------------+-------------------------------------+
| **Key**               | **Description**             | **Remarks**                         |
+-----------------------+-----------------------------+-------------------------------------+
|``ecs``                |Client ECS info              |Filled in if enabled                 |
+-----------------------+-----------------------------+-------------------------------------+
|``proto``              |Protocol used by client      |``udp`` or ``tcp``                   |
+-----------------------+-----------------------------+-------------------------------------+
|``qname``              |Query name                   |                                     |
+-----------------------+-----------------------------+-------------------------------------+
|``qtype``              |Query type                   |                                     |
+-----------------------+-----------------------------+-------------------------------------+
|``remote``             |Client address               |IP:port combination                  |
+-----------------------+-----------------------------+-------------------------------------+
|                               **Keys specific to Answers**                                |
+-----------------------+-----------------------------+-------------------------------------+
|``additional``         |Number of additional records |                                     |
|                       |in answer                    |                                     |
+-----------------------+-----------------------------+-------------------------------------+
|``answer-is-variable`` |Is answer marked variable by |e.g. ECS dependent answers           |
|                       |recursor?                    |                                     |
+-----------------------+-----------------------------+-------------------------------------+
|``answers``            |Number of answer records in  |                                     |
|                       |answer                       |                                     |
+-----------------------+-----------------------------+-------------------------------------+
|``dotout``             |Number of outgoing DoT       |                                     |
|                       |queries sent to authoritative|                                     |
|                       |servers to resolve answer    |                                     |
+-----------------------+-----------------------------+-------------------------------------+
|``into-packetcache``   |Is the answer being stored   |Variable answers (as determined by   |
|                       |into the packetcache?        |the recursor or marked as such by Lua|
|                       |                             |code) will not be put into the packet|
|                       |                             |cache                                |
+-----------------------+-----------------------------+-------------------------------------+
|``maxdepth``           |Depth of recursion needed to |Some queries need resolving multiple |
|                       |resolve answer               |targets, e.g. to find the right      |
|                       |                             |delegation or answers containing     |
|                       |                             |CNAMEs                               |
+-----------------------+-----------------------------+-------------------------------------+
|``netms``              |Time spent waiting for       |                                     |
|                       |answers from authoritative   |                                     |
|                       |servers                      |                                     |
+-----------------------+-----------------------------+-------------------------------------+
|``outqueries``         |Total queries sent to        |A single client query can cause      |
|                       |authoritative servers        |multiple queries to authoritative    |
|                       |                             |servers, depending on record cache   |
|                       |                             |content and the query itself.        |
+-----------------------+-----------------------------+-------------------------------------+
|``rcode``              |Result code                  |If no rcode is available (e.g. in the|
|                       |                             |case of timeouts) this value can be  |
|                       |                             |negative                             |
+-----------------------+-----------------------------+-------------------------------------+
|``rd``                 |Did the client set the       |                                     |
|                       |Recursion Desired DNS Header |                                     |
|                       |flag?                        |                                     |
+-----------------------+-----------------------------+-------------------------------------+
|``tcpout``             |Number of outgoing TCP       |                                     |
|                       |queries sent to authoritative|                                     |
|                       |servers to resolve answer    |                                     |
|                       |                             |                                     |
+-----------------------+-----------------------------+-------------------------------------+
|``throttled``          |Number of potential outgoing |If a target is throttled, the        |
|                       |queries **not** sent out     |recursor will try another suitable   |
|                       |because the target was marked|authoritative server (if available)  |
|                       |as unreliable by previous    |                                     |
|                       |interactions                 |                                     |
|                       |                             |                                     |
+-----------------------+-----------------------------+-------------------------------------+
|``timeouts``           |Number of outgoing queries   |                                     |
|                       |that timed out               |                                     |
+-----------------------+-----------------------------+-------------------------------------+
|``totms``              |Total time spent resolving   |                                     |
+-----------------------+-----------------------------+-------------------------------------+
|``validationState``    |The DNSSEC status of the     |                                     |
|                       |answer                       |                                     |
+-----------------------+-----------------------------+-------------------------------------+
