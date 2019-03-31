Running Virtual Instances
=========================

It may be advantageous to run multiple separate PowerDNS installations
on a single host, for example to make sure that different customers
cannot affect each others zones. PowerDNS fully supports running
multiple instances on one host.

To generate additional PowerDNS instances, create a ``pdns-NAME.conf``
in your configuration directory (usually ``/etc/powerdns``), where
``NAME`` is the name of your virtual configuration.

Following one of the following instructions, PowerDNS will read its
configuration from the ``pdns-NAME.conf`` instead of ``pdns.conf``.

Starting virtual instances with Sysv init-scripts
-------------------------------------------------

Symlink the init.d script ``pdns`` to ``pdns-NAME``, where ``NAME`` is
the name of your virtual configuration.

.. warning::
  ``NAME`` must not contain a '-' as this will confuse the script.

Internally, the init script calls the binary with the
:ref:`setting-config-name` option set to ``name``,
setting in motion the loading of separate configuration files.

When you launch a virtual instance of PowerDNS, the pid-file is saved
inside :ref:`setting-socket-dir` as ``pdns-name.pid``.

.. warning::
  Be aware however that the init.d ``force-stop`` will kill all PowerDNS instances!

Starting virtual instances with systemd
---------------------------------------

With systemd it is as simple as calling the correct service instance.
Assuming your instance is called ``myinstance`` and
``pdns-myinstance.conf`` exists in the configuration directory, the
following command will start the service:

.. code-block:: shell

    systemctl start pdns@myinstance.service

Similarly you can enable it at boot:

.. code-block:: shell

    systemctl enable pdns@myinstance.service


