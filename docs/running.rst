Running and Operating
=====================

PowerDNS is normally controlled via a SysV-style init.d script, often
located in ``/etc/init.d`` or ``/etc/rc.d/init.d``. For Linux
distributions with systemd, a service file is provided (either in the
package or in the contrib directory of the tarball).

Furthermore, PowerDNS can be run on the foreground for testing or in
other init- systems that supervise processes.

.. _running-guardian:

Guardian
--------

When the init-system of the Operating System does not properly
supervises processes, like SysV init, it is recommended to run PowerDNS
with the :ref:`setting-guardian` option set to 'yes'.

When launched with ``guardian=yes``, ``pdns_server`` wraps itself inside
a 'guardian'. This guardian monitors the performance of the inner
``pdns_server`` instance which shows up in the process list of your OS
as ``pdns_server-instance``. It is also this guardian that
:ref:`running-pdnscontrol` talks to. A **STOP** is interpreted
by the guardian, which causes the guardian to sever the connection to
the inner process and terminate it, after which it terminates itself.
Requests that require data from the actual nameserver are passed to the
inner process as well.

Logging to syslog on systemd-based operating systems
----------------------------------------------------

By default, logging to syslog is disabled in the the systemd unit file
to prevent the service logging twice, as the systemd journal picks up
the output from the process itself.

Removing the ``--disable-syslog`` option from the ``ExecStart`` line
using ``systemctl edit --full pdns`` enables logging to syslog.

.. _logging-to-syslog:

Logging to syslog
-----------------
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

Controlling A Running PowerDNS Server
-------------------------------------

As a DNS server is critical infrastructure, downtimes should be avoided
as much as possible. Even though PowerDNS (re)starts very fast, it
offers a way to control it while running.

.. _control-socket:

Control Socket
~~~~~~~~~~~~~~

The controlsocket is the means to contact a running PowerDNS process.
Over this socket, instructions can be sent using the ``pdns_control``
program. The control socket is called ``pdns.controlsocket`` and is
created inside the :ref:`setting-socket-dir`.

.. _running-pdnscontrol:

``pdns_control``
~~~~~~~~~~~~~~~~

To communicate with PowerDNS Authoritative Server over the
controlsocket, the ``pdns_control`` command is used. The syntax is
simple: ``pdns_control command arguments``. Currently this is most
useful for telling backends to rediscover domains or to force the
transmission of notifications. See :ref:`master-operation`.

For all supported ``pdns_control`` commands and options, see :doc:`the
manpage <../manpages/pdns_control.1>` and the output of
``pdns_control --help`` on your system.

The SysV init script
--------------------

This script supplied with the PowerDNS source accepts the following
commands:

-  ``monitor``: Monitor is a special way to view the daemon. It executes
   PowerDNS in the foreground with a lot of logging turned on, which
   helps in determining startup problems. Besides running in the
   foreground, the raw PowerDNS control socket is made available. All
   external communication with the daemon is normally sent over this
   socket. While useful, the control console is not an officially
   supported feature. Commands which work are: ``QUIT``, ``SHOW *``,
   ``SHOW varname``, ``RPING``.
-  ``start``: Start PowerDNS in the background. Launches the daemon but
   makes no special effort to determine success, as making database
   connections may take a while. Use ``status`` to query success. You
   can safely run ``start`` many times, it will not start additional
   PowerDNS instances.
-  ``restart``: Restarts PowerDNS if it was running, starts it
   otherwise.
-  ``status``: Query PowerDNS for status. This can be used to figure out
   if a launch was successful. The status found is prefixed by the PID
   of the main PowerDNS process.
-  ``stop``: Requests that PowerDNS stop. Again, does not confirm
   success. Success can be ascertained with the ``status`` command.
-  ``dump``: Dumps a lot of statistics of a running PowerDNS daemon. It
   is also possible to single out specific variable by using the
   ``show`` command.
-  ``show variable``: Show a single statistic, as present in the output
   of the ``dump``.
-  ``mrtg``: Dump statistics in mrtg format. See the performance
   :ref:`counters` documentation.

.. note::
  Packages provided by Operating System vendors might support
  different or less commands.

Running in the foreground
-------------------------

One can run PowerDNS in the foreground by invoking the ``pdns_server``
executable. Without any options, it will load the ``pdns.conf`` and run.
To make sure PowerDNS starts in the foreground, add the ``--daemon=no``
option.

All :doc:`settings <settings>` can be added on the commandline. e.g. to
test a new database config, you could start PowerDNS like this:

.. code-block:: shell

    pdns_server --no-config --daemon=no --local-port=5300 --launch=gmysql --gmysql-user=my_user --gmysql-password=mypassword

This starts PowerDNS without loading on-disk config, in the foreground,
on all network interfaces on port 5300 and starting the
:doc:`gmysql <backends/generic-mysql>` backend.
