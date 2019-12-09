Zones
=====

Manipulating zones is the primary use of the API.

Zone Endpoints
--------------

.. openapi:: swagger/authoritative-api-swagger.yaml
  :paths: /servers/{server_id}/zones /servers/{server_id}/zones/{zone_id} /servers/{server_id}/zones/{zone_id}/axfr-retrieve /servers/{server_id}/zones/{zone_id}/notify /servers/{server_id}/zones/{zone_id}/export /servers/{server_id}/zones/{zone_id}/rectify

Objects
-------

A Zone object represents an authoritative DNS Zone.

A Resource Record Set (below as "RRset") are all records for a given name and type.

Comments are per-RRset.

.. openapi:: swagger/authoritative-api-swagger.yaml
  :definitions: Zone RRSet Record Comment

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
