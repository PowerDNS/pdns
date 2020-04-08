Zones
=====

Zone
----

A Zone object represents an authoritative DNS Zone.

A Resource Record Set (below as "RRset") are all records for a given name and type.

Comments are per-RRset.

.. json:object:: Zone

  Represents a configured zone in the PowerDNS server.

  :property string id: Opaque zone id (string), assigned by the server, should not be interpreted by the application. Guaranteed to be safe for embedding in URLs.
  :property string name: Name of the zone (e.g. "example.com.") MUST have a trailing dot
  :property string type: Set to "Zone"
  :property string url: API endpoint for this zone
  :property string kind: Zone kind, one of "Native", "Forwarded".
  :property [RRSet] rrsets: RRSets in this zone
  :property [str] servers: For zones of type "Forwarded", addresses to send the queries to
  :property bool recursion_desired: For zones of type "Forwarded", Whether or not the RD bit should be set in the query

To properly process new zones, the following conditions must
be true:

* ``forward-zones``, ``forward-zones-recurse`` and/or ``auth-zones``
  settings must be set (possibly to the empty string) in a
  configuration file. These settings must not be overridden on the
  command line. Setting these options on the command line will
  override what has been set in the dynamically generated
  configuration files.
* ``include-dir`` must refer to the same directory as
  ``api-config-dir`` for the dynamic reloading to work.

.. include:: ../common/api/zone.rst
