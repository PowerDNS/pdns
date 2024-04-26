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
  addACL('192.0.2.1/8')
  -- Wed Feb 22 2017 12:05:51 CET
  addACL('2001:db8::1')

These commands can be copied to the configuration file, should they need to persist after a restart.

Running as unprivileged user
----------------------------

:program:`dnsdist` can drop privileges using the ``--uid`` and ``--gid`` command line switches to ensure it does not run with root privileges.
Note that :program:`dnsdist` drops its privileges **after** parsing its startup configuration and binding its listening and initial :func:`newServer` sockets as user `root`.
It is highly recommended to create a system user and group for :program:`dnsdist`.
Note that most packaged versions of :program:`dnsdist` already create this user.

Understanding how queries are forwarded to backends
---------------------------------------------------

Initially dnsdist tried to forward a query to the backend using the same protocol than the client used to contact dnsdist: queries received over UDP were forwarded over UDP, and the same for TCP. When incoming DNSCrypt and DNS over TLS support were added, the same logic was applied, so DoT queries are forwarded over TCP. For DNS over HTTPS, UDP was selected instead for performance reason, breaking with the existing logic.

Before 1.7.0, which introduced TCP fallback, that meant that there was a potential issue with very large answers and DNS over HTTPS, requiring careful configuration of the path between dnsdist and the backend. More information about that is available in the :doc:`DNS over HTTPS section <guides/dns-over-https>`.

In addition to TCP fallback for DoH, 1.7.0 introduced three new notions:

 * TCP-only backends, for which queries will always forwarded over a TCP connection (see the `tcpOnly` parameter of :func:`newServer`)
 * DNS over HTTPS backends, for which queries are forwarded over a DNS over HTTPS connection (see the `dohPath` parameter of :func:`newServer`)
 * and DNS over TLS backends, for which queries are forwarded over a DNS over TLS connection (see the `tls` parameter of :func:`newServer`)

To sum it up:

+--------------+--------------------+---------------------------+----------------------+----------------------+
| Incoming     | Outgoing (regular) | Outgoing (TCP-only, 1.7+) | Outgoing (TLS, 1.7+) | Outgoing (DoH, 1.7+) |
+==============+====================+===========================+======================+======================+
| UDP          | UDP                | TCP                       | TLS                  | DoH                  |
+--------------+--------------------+---------------------------+----------------------+----------------------+
| TCP          | TCP                | TCP                       | TLS                  | DoH                  |
+--------------+--------------------+---------------------------+----------------------+----------------------+
| DNSCrypt UDP | UDP                | TCP                       | TLS                  | DoH                  |
+--------------+--------------------+---------------------------+----------------------+----------------------+
| DNSCrypt TCP | TCP                | TCP                       | TLS                  | DoH                  |
+--------------+--------------------+---------------------------+----------------------+----------------------+
| DoT          | TCP                | TCP                       | TLS                  | DoH                  |
+--------------+--------------------+---------------------------+----------------------+----------------------+
| DoH          | **UDP**            | TCP                       | TLS                  | DoH                  |
+--------------+--------------------+---------------------------+----------------------+----------------------+
| DoQ          | TCP                | TCP                       | TLS                  | DoH                  |
+--------------+--------------------+---------------------------+----------------------+----------------------+
| DoH3         | TCP                | TCP                       | TLS                  | DoH                  |
+--------------+--------------------+---------------------------+----------------------+----------------------+
