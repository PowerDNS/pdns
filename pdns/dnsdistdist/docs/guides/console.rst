.. _Console:

Working with the dnsdist Console
================================

dnsdist can expose a commandline console over an encrypted tcp connection for controlling it, debugging DNS issues and retrieving statistics.

The console can be enabled with :func:`controlSocket`:

.. code-block:: lua

  controlSocket('192.0.2.53:5199')

Or in ``yaml``:

.. code-block:: yaml

  console:
    listen_address: "192.0.2.53:5199"


Enabling the console without encryption enabled is not recommended. Note that encryption requires building dnsdist with either libsodium or libcrypto support enabled.

Once you have a console-enabled dnsdist, the first step to enable encryption is to generate a key with :func:`makeKey`::

  $ ./dnsdist -l 127.0.0.1:5300 -C /dev/null
  [..]
  > makeKey()
  setKey("ENCODED KEY")

The example above tells :program:`dnsdist` not to load the default configuration file (``-C /dev/null``) to prevent it
from trying to listen on privileged ports, connect to backends, etc. It also instructs :program:`dnsdist` not to listen
on the default (privileged) port 53 of all available addresses but on an unprivileged and hopefully available
port 5300 on the local interface instead (``-l 127.0.0.1:5300``).

The key does not have a specific format, so base-64 encoding 32 random bytes works as well::

  $ dd if=/dev/random bs=1 count=32 status=none | base64

or using ``openssl``::

  $ openssl rand -base64 32

Then add the generated :func:`setKey` line to your dnsdist configuration file, along with a :func:`controlSocket`:

.. code-block:: lua

  controlSocket('192.0.2.53:5199') -- Listen on this IP and port for client connections
  setKey("ENCODED KEY")            -- Shared secret for the console

.. code-block:: yaml

  console:
    listen_address: "192.0.2.53:5199"
    key: "ENCODED KEY"

Now you can run ``dnsdist -c`` to connect to the console.
This makes dnsdist read its configuration file and use the :func:`controlSocket` and :func:`setKey` statements to set up its connection to the server.

If you want to connect over the network, create a configuration file with the same two statements and run ``dnsdist -C /path/to/configfile -c``.

Alternatively, you can specify the address and key on the client commandline::

  dnsdist -k "ENCODED KEY" -c 192.0.2.53:5199

.. warning::

  This will leak the key into your shell's history and is **not** recommended.

Since 1.3.0, dnsdist supports restricting which client can connect to the console with an ACL:

.. code-block:: lua

  controlSocket('192.0.2.53:5199')
  setConsoleACL('192.0.2.0/24')

.. code-block:: yaml

  console:
    listen_address: "192.0.2.53:5199"
    key: "ENCODED KEY"
    acl:
      - "192.0.2.0/24"


The default value is '127.0.0.1', restricting the use of the console to local users. Please make sure that encryption is enabled
before using :func:`addConsoleACL` or :func:`setConsoleACL` to allow connection from remote clients. Even if the console is
restricted to local users, the use of encryption is still strongly advised to prevent unauthorized local users from connecting to
the console.
