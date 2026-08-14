EDNS Cookies
============

The PowerDNS Authoritative Server supports :rfc:`Interoperable DNS Cookies <9018>`. It can generate new Cookies and validate Cookies sent by clients.
When Cookies are enabled and the client sends a bad (expired, non-validating, or only a client) Cookie, the server will respond with :rfc:`BADCOOKIE <7873>` and a new server cookie.

Configuration
-------------

The secrets for Cookies can be configured using :ref:`setting-edns-cookie-secret`.
The secret MUST be 32 hexadecimal characters, as the siphash algorithm's key used to create the cookie requires a 128-bit key.
e.g.

.. code-block::

  edns-cookie-secret=11223344556677889900aabbccddeeff

Since version 5.2.0, this setting accepts a comma-separated list of secrets.
This allows rolling the Cookie secret without invalidating existing Cookies.

.. code-block::

  edns-cookie-secret=11223344556677889900aabbccddeeff,ffeeddccbbaa0099887766554433221100

The first secret is used to create new Cookies, all secrets are used to validate Cookies.
When a valid Cookie signed with an old secret is received, the query is processed normally, but a new Cookie signed with the active secret is returned to the client with the response.

Run-time configuration
----------------------

The secrets for Cookies can also be managed at runtime (i.e. without restarting) using :doc:`pdns_control <../manpages/pdns_control.1>` using the ``cookie-secret`` command.

There's 3 different commands:

* ``cookie-secret list``
* ``cookie-secret add``
* ``cookie-secret delete``

Listing secrets
^^^^^^^^^^^^^^^

The ``list`` command lists all secrets in use.
The active secret is marked with a ``*``::

  $ pdns_control cookie-secret list
  fe049dc46c882d68e49625091dac9e24 *
  fce4f37674154e6d13059031ca56091b
  38684c618a30a1c4fdcb20bfed423a75
  5505bbea8c07a2c1515c9538095e4a9a

Adding secrets
^^^^^^^^^^^^^^

A new, active secret can be added by using ``add``.
This command accepts either the 32 hexadecimal characters of a secret, or the special word "random" to have the server generate a secret itself::

  $ pdns_control cookie-secret list
  fe049dc46c882d68e49625091dac9e24 *

  $ pdns_control cookie-secret add random
  COOKIE secret set to 3018b369915c0dcd1aab7ab2c4b74206

  $ pdns_control cookie-secret list
  3018b369915c0dcd1aab7ab2c4b74206 *
  fe049dc46c882d68e49625091dac9e24

  $ pdns_control cookie-secret add 45010811ae2902212b55f32383d5f29b
  COOKIE secret set to 45010811ae2902212b55f32383d5f29b

  $ pdns_control cookie-secret list
  45010811ae2902212b55f32383d5f29b *
  3018b369915c0dcd1aab7ab2c4b74206
  fe049dc46c882d68e49625091dac9e24

Removing inactive secrets
^^^^^^^^^^^^^^^^^^^^^^^^^

The ``delete`` command can remove inactive secrets.
This command accepts either the 32 hexadecimal characters of a secret, or the special word "last" to remove the secret at the bottom of ``list``, which is the oldest secret::

  $ pdns_control cookie-secret list
  b7fd1950874887bdbc06554815557a37 *
  45010811ae2902212b55f32383d5f29b
  3018b369915c0dcd1aab7ab2c4b74206
  fe049dc46c882d68e49625091dac9e24

  $ pdns_control cookie-secret delete last
  COOKIE secret fe049dc46c882d68e49625091dac9e24 removed

  $ pdns_control cookie-secret list
  b7fd1950874887bdbc06554815557a37 *
  45010811ae2902212b55f32383d5f29b
  3018b369915c0dcd1aab7ab2c4b74206

  $ pdns_control cookie-secret delete 45010811ae2902212b55f32383d5f29b
  COOKIE secret 45010811ae2902212b55f32383d5f29b removed

  $ pdns_control cookie-secret list
  b7fd1950874887bdbc06554815557a37 *
  3018b369915c0dcd1aab7ab2c4b74206

Rolling secrets
^^^^^^^^^^^^^^^

:rfc:`7873` demands that cookie secrets are updated at least every 36 days.
By default, the PowerDNS Authoritative Server does not roll secrets by itself.
However, the ``pdns_control`` commands allow automation of roll-overs.

This can be done using ``cron``, at the interval required::

  # Create a new Cookie secret at 2 at night, once a week
  0 2 */7 * * /usr/bin/pdns_control cookie-secret add random
  # Remove the old Cookie secret at 7 in the morning, once a week
  0 7 */7 * * /usr/bin/pdns_control cookie-secret delete last

Or, using systemd timers, create a service (at e.g. ``/etc/systemd/system/pdns-cookie-roll-new.service``)::

  [Unit]
  Description=Create new EDNS Cookie secret
  Requisite=pdns.service
  After=pdns.service

  [Service]
  Type=oneshot
  ExecStart=/usr/bin/pdns_control cookie-secret add random

And ``/etc/systemd/system/pdns-cookie-roll-remove.service``::

  [Unit]
  Description=Remove old EDNS Cookie secret
  Requisite=pdns.service
  After=pdns.service

  [Service]
  Type=oneshot
  ExecStart=/usr/bin/pdns_control cookie-secret delete last

And then create a timer (at e.g. ``/etc/systemd/system/pdns-cookie-roll-new.timer``)::

  [Unit]
  Description=Create new EDNS Cookie secret in PowerDNS every week

  [Timer]
  # Every Monday night at 2
  OnCalendar=Mon *-*-* 2:00:00

  [Install]
  WantedBy=timers.target

And to remove the old secret (at e.g. ``/etc/systemd/system/pdns-cookie-roll-remove.timer``)::

  [Unit]
  Description=Remove old EDNS Cookie secret from PowerDNS

  [Timer]
  # Every Monday at noon
  OnCalendar=Mon *-*-* 12:00:00

  [Install]
  WantedBy=timers.target

.. note::
   When rolling keys this way, keep in mind that when PowerDNS is restarted it will read the secrets from the configuration file.
   Hence, other plumbing might be required to keep the configuration file up to date with the new cookies.
