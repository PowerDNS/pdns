dnsdist
=======

Synopsis
--------

:program:`dnsdist` [OPTION]... [ADDRESS]...

Description
-----------

:program:`dnsdist` receives DNS queries and relays them to one or more
downstream servers. It subsequently sends back responses to the original
requestor.

:program:`dnsdist` operates over TCP and UDP, and strives to deliver very high
performance over both.

Currently, queries are sent to the downstream server with the least
outstanding queries. This effectively implies load balancing, making
sure that slower servers get less queries.

If a reply has not come in after a few seconds, it is removed from the
queue, but in the short term, timeouts do cause a server to get less
traffic.

IPv4 and IPv6 operation can be mixed and matched, in other words,
queries coming in over IPv6 could be forwarded to IPv4 and vice versa.

:program:`dnsdist` is scriptable in Lua, see the dnsdist documentation for more
information on this.

Scope
-----

:program:`dnsdist` does not 'think' about DNS queries, it restricts itself to
measuring response times and error codes and routing questions
accordingly. It comes with a very high performance packet-cache.

The goal for dnsdist is to remain simple. If more powerful loadbalancing
is required, dedicated hardware or software is recommended. Linux
Virtual Server for example is often mentioned.

Options
-------

.. option:: -a <NETMASK>, --acl <NETMASK>

   Add *netmask* to the ACL.

.. option:: -C <FILE>, --config <FILE>

   Load configuration from *FILE*.

.. option:: --check-config

   Test the configuration file (which may be set with **--config** or **-C**)
   for errors. dnsdist will show the errors and exit with a non-zero
   exit-code when errors are found.

.. option:: -c <ADDRESS>, --client <ADDRESS>

   Operate as a client, connect to dnsdist. This will read the dnsdist
   configuration for the **controlSocket** statement and connect to it.
   When *ADDRESS* (with an optional port number) is set, dnsdist will connect
   to that instead.

.. option:: -k <KEY>, --setkey <KEY>

   When operating as a client(**-c**, **--client**), use *KEY* as
   shared secret to connect to dnsdist. This should be the same key
   that is used on the server (set with **setKey()**). Note that this
   will leak the key into your shell's history and into the systems
   running process list. Only available when dnsdist is compiled with
   libsodium or libcrypto support.

.. option:: -e <COMMAND>, --execute <COMMAND>

   Connect to dnsdist and execute *COMMAND*.

.. option:: -h, --help

   Display a helpful message and exit.

.. option:: -l <ADDRESS>, --local <ADDRESS>

   Bind to *ADDRESS*, Supply as many addresses (using multiple
   **--local** statements) to listen on as required. Specify IPv4 as
   0.0.0.0:53 and IPv6 as [::]:53.

.. option:: --supervised

   Run in foreground, but do not spawn a console. Use this switch to
   run dnsdist inside a supervisor (use with e.g. systemd and
   daemontools).

.. option:: --disable-syslog

   Disable logging to syslog. Use this when running inside a supervisor
   that handles logging (like systemd).

.. option:: --log-timestamps

   Prepend timestamps to messages logged to standard out.

.. option:: --structured-logging <true|false>

   Whether to enable structured logging.

.. option:: --structured-logging-backend <BACKEND>

   The backend to use when structured logging is enabled.
   Supported values are 'default', 'json' and 'systemd-journal'.

.. option:: -u <UID>, --uid <UID>

   Change the process user to *UID* after binding sockets. *UID* can be
   a name or number.

.. option:: -g <GID>, --gid <GID>

   Change the process group to *GID* after binding sockets. *GID* Can
   be a name or number.

.. option:: -V, --version

   Show the dnsdist version and exit.

.. option:: -v, --verbose

   Be verbose.

.. option:: ADDRESS

   Any number of downstream DNS servers, in the same syntax as used
   with **--local**. If the port is not specified, 53 is used.

Bugs
----

Right now, the TCP support has some rather arbitrary limits.

Resources
---------

Website: https://dnsdist.org
