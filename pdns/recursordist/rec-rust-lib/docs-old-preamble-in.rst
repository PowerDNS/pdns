PowerDNS Recursor Settings
==========================
Each setting can appear on the command line, prefixed by ``--``, or in the configuration file.
The command line overrides the configuration file.

.. note::
   Starting with version 5.0.0, :program:`Recursor` supports a new YAML syntax for configuration files.
   A configuration using the old style syntax can be converted to a YAML configuration using the instructions in :doc:`appendices/yamlconversion`.
   Starting with version 5.2.0, parsing of old-style settings must be explicitly enabled using a command line argument ``--enable-old-settings``.
   In a future release support for the old-style settings described here will be dropped.
   See :doc:`yamlsettings` for details.

.. note::
   Settings marked as ``Boolean`` can either be set to an empty value, which means **on**, or to ``no`` or ``off`` which means **off**.
   Anything else means **on**.

   For example:

   - ``serve-rfc1918`` on its own means: do serve those zones.
   - ``serve-rfc1918 = off`` or ``serve-rfc1918 = no`` means: do not serve those zones.
   - Anything else means: do serve those zones.

You can use ``+=`` syntax to set some variables incrementally, but this
requires you to have at least one non-incremental setting for the
variable to act as base setting. This is mostly useful for
:ref:`setting-include-dir` directive. An example::

  forward-zones = foo.example.com=192.168.100.1;
  forward-zones += bar.example.com=[1234::abcde]:5353;

When a list of **Netmasks** is mentioned, a list of subnets can be specified.
A subnet that is not followed by ``/`` will be interpreted as a ``/32`` or ``/128`` subnet (a single address), depending on address family.
For most settings, it is possible to exclude ranges by prefixing an item with the negation character ``!``.
For example::

  allow-from = 2001:DB8::/32, 128.66.0.0/16, !128.66.1.2

In this case the address ``128.66.1.2`` is excluded from the addresses allowed access.

The Settings
------------
