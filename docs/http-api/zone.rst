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
  :property string kind: Zone kind, one of "Native", "Master", "Slave"
  :property [RRSet] rrsets: RRSets in this zone
  :property integer serial: The SOA serial number
  :property integer notified_serial: The SOA serial notifications have been sent out for
  :property [str] masters: List of IP addresses configured as a master for this zone ("Slave" type zones only)
  :property bool dnssec: Whether or not this zone is DNSSEC signed (inferred from presigned being true XOR presence of at least one cryptokey with active being true)
  :property string nsec3param: The NSEC3PARAM record (not implemented)
  :property bool nsec3narrow: Whether or not the zone uses NSEC3 narrow (not implemented)
  :property bool presigned: Whether or not the zone is pre-signed (not implemented)
  :property string soa_edit: The :ref:`metadata-soa-edit` metadata item
  :property string soa_edit_api: The :ref:`metadata-soa-edit-api` metadata item
  :property string zone: MAY contain a BIND-style zone file when creating a zone
  :property str account: MAY be set. Its value is defined by local policy
  :property [str] nameservers: MAY be sent in client bodies during creation, and MUST NOT be sent by the server. Simple list of strings of nameserver names, including the trailing dot. Not required for slave zones.

.. note::

  Switching ``dnssec`` to ``true`` (from ``false``) sets up DNSSEC signing
  based on the other flags, this includes running the equivalent of
  ``secure-zone`` and ``rectify-zone``. This also applies to newly created
  zones. If ``presigned`` is ``true``, no DNSSEC changes will be made to
  the zone or cryptokeys.

  ``dnssec``, ``nsec3narrow``, ``nsec3param``, ``presigned`` are not yet implemented.

.. note::

  ``notified_serial``, ``serial`` MUST NOT be sent in client bodies.

Changes made through the Zones API will always yield valid zone data,
and the zone will be properly "rectified". If changes are made through other means
(e.g. direct database access), this is not guaranteed to be true and clients SHOULD
trigger rectify.

.. note::

  Rectification is not yet implemented.

Backends might implement additional features (by coincidence or not).
These things are not supported through the API.

When creating a slave zone, it is recommended to not set any of
``nameservers``, ``records`` or ``zone``.

.. include:: ../common/api/zone.rst
