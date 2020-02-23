Running and Configuring dnsdist
===============================

dnsdist is meant to run as a daemon.
As such, distribution native packages know how to stop/start themselves using operating system services.

It is configured with a configuration file called ``dnsdist.conf``
The default path to this file is determined by the ``SYSCONFDIR`` variable during compilation.
Most likely this path is ``/etc/dnsdist``,  ``/etc`` or ``/usr/local/etc/``, dnsdist will tell you on startup which file it reads.

dnsdist is designed to (re)start almost instantly.
But to prevent downtime when changing configuration, the console (see :ref:`Console`) can be used for live configuration.

Issuing :func:`delta` on the console will print the changes to the configuration that have been made since startup::

  > delta()
  -- Wed Feb 22 2017 11:31:44 CET
  addLocal('127.0.0.1:5301', false)
  -- Wed Feb 22 2017 12:03:48 CET
  addACL('2.0.0.0/8')
  -- Wed Feb 22 2017 12:03:50 CET
  addACL('2.0.0.0/8')
  -- Wed Feb 22 2017 12:03:51 CET
  addACL('2.0.0.0/8')
  -- Wed Feb 22 2017 12:05:51 CET
  addACL('2001:db8::1')

These commands can be copied to the configuration file, should they need to persist after a restart.

Running as unprivileged user
----------------------------

:program:`dnsdist` can drop privileges using the ``--uid`` and ``--gid`` command line switches to ensure it does not run with root privileges.
Note that :program:`dnsdist` drops its privileges **after** parsing its startup configuration and binding its listening and initial :func:`newServer` sockets as user `root`.
It is highly recommended to create a system user and group for :program:`dnsdist`.
Note that most packaged versions of :program:`dnsdist` already create this user.
