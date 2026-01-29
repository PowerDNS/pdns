Zones
=====

Zone
----

A Zone object represents a forward or authoritative DNS Zone.

A Resource Record Set (below as "RRset") are all records for a given name and type.

Comments are per-RRset.

.. json:schema:: Zone

To properly process new zones, the following conditions must
be true:

* ``forward-zones``, ``forward-zones-recurse`` and/or ``auth-zones``
  settings must be set (possibly to the empty string) in a
  configuration file. These settings must not be overridden on the
  command line. Setting these options on the command line will
  override what has been set in the dynamically generated
  configuration files.

* For configuration changes to work :ref:`setting-include-dir` and :ref:`setting-api-config-dir` should have the same value for old-style settings.
  When using YAML settings :ref:`setting-yaml-recursor.include_dir` and :ref:`setting-yaml-webservice.api_dir` must have a different value.

.. include:: ../common/api/zone.rst
