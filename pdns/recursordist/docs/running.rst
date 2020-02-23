Operating the PowerDNS Recursor
===============================

.. _logging:

Logging
-------

In a production environment, you will want to be able to monitor PowerDNS performance.
Furthermore, PowerDNS can perform a configurable amount of operational logging.

On modern Linux distributions, the PowerDNS recursor logs to stdout, which is consumed by ``systemd-journald``.
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

By default, PowerDNS will only log messages with an urgency of 3 or lower, but this can be changed using the :ref:`setting-loglevel` setting in the configuration file.
Setting it to 0 will eliminate all logging, 9 will log everything.

By default, logging is performed under the 'DAEMON' facility which is shared with lots of other programs.
If you regard nameserving as important, you may want to have it under a dedicated facility so PowerDNS can log to its own files, and not clutter generic files.

For this purpose, syslog knows about 'local' facilities, numbered from LOCAL0 to LOCAL7.
To move PowerDNS logging to LOCAL0, add :ref:`logging-facility=0 <setting-logging-facility>` to your configuration.

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
Sometimes a domain fails to resolve due to an error on the domain owner's end, or records for your own domain have updated and you want your users to immediatly see them without waiting for the TTL to expire.
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

Tracing Queries
---------------
To investigate failures with resolving certain domain names, the PowerDNS Recursor features a "tracing" infrastructure.
This infrastructure will log every step the Recursor takes to resolve a name and will log all DNSSEC related information as well.

To enable tracing for all queries, enable the :ref:`setting-trace` setting.

.. warning::

  Enabling tracing for all queries on a system with a high query rate can severely impact performance.

Tracing can also be enabled at runtime, without restarting the Recursor, for specific domains.
These specific domains can be specified as a regular expression.
This can be done using :doc:`rec_control trace-regex <manpages/rec_control.1>`::

    rec_control trace-regex '.*\.example.com\.$'

Will enable tracing for any query *in* the example.com domain (but not example.com itself).
