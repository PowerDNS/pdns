Running multiple instances
==========================

Sometimes, it can be advantageous to run multiple instances of :program:`dnsdist`.
Usecases can be:

 * Multiple inbound IP addresses with different rulesets
 * Taking advantage of more processes, using SO_REUSEPORT

:program:`dnsdist` supports loading a different configuration file with the ``--config`` command line switch.

By default, ``SYSCONFDIR/dnsdist.conf`` is loaded. ``SYSCONFDIR`` is usually ``/etc`` or ``/etc/dnsdist``.

Using systemd
-------------
.. versionadded:: 1.3.0

On systems with systemd, instance services can be used.
To create a dnsdist service named ``foo``, create a ``dnsdist-foo.conf`` in ``SYSCONFDIR``, then run ``systemctl enable dnsdist@foo.service`` and ``systemctl start dnsdist@foo.service``.
