.. _Console:

Working with the dnsdist Console
================================

dnsdist can expose a commandline console over an encrypted tcp connection for controlling it, debugging DNS issues and retrieving statistics.

The console can be enabled with :func:`controlSocket`:

.. code-block:: lua

  controlSocket('192.0.2.53:5199')

To enable encryption, first generate a key with :func:`makeKey`::

  $ ./dnsdist -l 127.0.0.1:5300
  [..]
  > makeKey()
  setKey("ENCODED KEY")

Add the generated :func:`setKey` line to you dnsdist configuration file, along with a :func:`controlSocket`:

.. code-block:: lua

  controlSocket('192.0.2.53:5199') -- Listen on this IP and port for client connections
  setKey("ENCODED KEY")            -- Shared secret for the console

Now you can run ``dnsdist -c`` to connect to the console.
This makes dnsdist read its configuration file and use the :func:`controlSocket` and :func:`setKey` statements to set up its connection to the server.

If you want to connect over the network, create a configuration file with the same two statements and run ``dnsdist -C /path/to/configfile -c``.

Alternatively, you can specify the address and key on the client commandline::

  dnsdist -k "ENCODED KEY" -c 192.0.2.53:5199

.. warning::

  This will leak the key into your shell's history and is **not** recommended.
