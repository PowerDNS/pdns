Running and Operating
=====================

On Linux, PowerDNS is controlled by a systemd service called ``pdns.service``.
The service definition file should be installed by the binary package, and 
can also be found in the tarball (``pdns.service.in`` template file).

On Linux, optionally, you can configure pdns to listen for incoming connections
on the sockets managed by systemd via a systemd socket file. This requires you
to:
 - install a systemd socket file to configure systemd to listen for incoming
   connections before pdns is started. The ``pdns.socket`` example file illustrates
   how this can be done.
 - configure the pdns tcp and udp resolvers, and/or the api webserver to use these
   sockets by referencing them via the ``fd:FD`` and ``fdgram:FD`` syntax in the
   ``local-address`` and ``webserver-address`` options. Doing this assumes you 
   understand how systemd allocates file descriptors (sequentially starting at 3)
   for ``Listen*`` options in the socket file. More details can be found in the
   systemd manual for [sd_listen_fds](https://man7.org/linux/man-pages/man3/sd_listen_fds.3.html)

On non-Linux systems, a SysV-style init script can be used, and should be supplied by the operating system packages.

Furthermore, PowerDNS can be run on the foreground for testing or for use with other init-systems that supervise processes.

Also see :doc:`guides/virtual-instances`.

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

By default, logging to syslog is disabled in the systemd unit file
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
transmission of notifications. See :ref:`primary-operation`.

For all supported ``pdns_control`` commands and options, see :doc:`the
manpage <../manpages/pdns_control.1>` and the output of
``pdns_control --help`` on your system.

Backend manipulation
~~~~~~~~~~~~~~~~~~~~

``pdnsutil``
~~~~~~~~~~~~

To perform zone and record changes using inbuilt tools, the :doc:`pdnsutil <../manpages/pdnsutil.1>` command can be used. All available options are described in the online :doc:`manual page <../manpages/pdnsutil.1>` as well as in ``man pdnsutil``.

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
