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
  :property string nsec3param: The NSEC3PARAM record
  :property bool nsec3narrow: Whether or not the zone uses NSEC3 narrow
  :property bool presigned: Whether or not the zone is pre-signed
  :property string soa_edit: The :ref:`metadata-soa-edit` metadata item
  :property string soa_edit_api: The :ref:`metadata-soa-edit-api` metadata item
  :property bool api_rectify: Whether or not the zone will be rectified on data changes via the API
  :property string zone: MAY contain a BIND-style zone file when creating a zone
  :property str account: MAY be set. Its value is defined by local policy
  :property [str] nameservers: MAY be sent in client bodies during creation, and MUST NOT be sent by the server. Simple list of strings of nameserver names, including the trailing dot. Not required for slave zones.

.. note::

  Switching ``dnssec`` to ``true`` (from ``false``) sets up DNSSEC signing
  based on the other flags, this includes running the equivalent of
  ``secure-zone`` and ``rectify-zone`` (if ``api_rectify`` is set to ``true``).
  This also applies to newly created zones. If ``presigned`` is ``true``,
  no DNSSEC changes will be made to the zone or cryptokeys.

.. note::

  ``notified_serial``, ``serial`` MUST NOT be sent in client bodies.

Changes made through the Zones API will always yield valid zone data, as the API will reject records with wrong data.

DNSSEC-enabled zones should be :ref:`rectified <rules-for-filling-out-dnssec-fields>` after changing the zone data.
This can be done by the API automatically after a change when the :ref:`metadata-api-rectify` metadata is set.
When creating or updating a zone, the "api_rectify" field of the :json:object:`ZOne` can be set to `true` to enable this behaviour.

Backends might implement additional features (by coincidence or not).
These things are not supported through the API.

When creating a slave zone, it is recommended to not set any of
``nameservers``, ``rrsets`` or ``zone``.

.. include:: ../common/api/zone.rst
