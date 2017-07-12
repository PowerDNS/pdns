  :property integer serial: The SOA serial number
  :property integer notified_serial: The SOA serial notifications have been sent out for
  :property [str] masters: List of IP addresses configured as a master for this zone ("Slave" type zones only)
  :property bool dnssec: Whether or not this zone is DNSSEC signed (inferred from presigned being true XOR presence of at least one cryptokey with active being true)
  :property string nsec3param: The NSEC3PARAM record (not implemented)
  :property bool nsec3narrow: Whether or not the zone uses NSEC3 narrow (not implemented)
  :property bool presigned: Whether or not the zone is pre-signed (not implemented)
  :property string soa_edit: The SOA-EDIT metadata item. MAY be set to change the ``SOA-EDIT`` zone setting.
  :property string soa_edit_api: The SOA-EDIT-API metadata item



Switching ``dnssec`` to ``true`` (from ``false``) sets up DNSSEC signing
based on the other flags, this includes running the equivalent of
``secure-zone`` and ``rectify-zone``. This also applies to newly created
zones. If ``presigned`` is ``true``, no DNSSEC changes will be made to
the zone or cryptokeys. .

**TODO**: ``dnssec``, ``nsec3narrow``, ``nsec3param``, ``presigned`` are
not yet implemented.

-  ``soa_edit_api`` MAY be set. If it is set, on changes to the contents
   of a zone made through the API, the SOA record will be edited
   according to the SOA-EDIT-API rules. (Which are the same as the
   SOA-EDIT-DNSUPDATE rules.) If not set during zone creation, a
   SOA-EDIT-API metadata record is created and set to ``DEFAULT``. (If
   this record is removed from the backend, the default behaviour is to
   not do any SOA editing based on this setting. This is different from
   setting ``DEFAULT``).

-  ``account`` MAY be set. Its value is defined by local policy.

-  ``notified_serial``, ``serial`` MUST NOT be sent in client bodies.

-  ``nameservers`` MAY be sent in client bodies during creation, and
   MUST NOT be sent by the server. Simple list of strings of nameserver
   names, including the trailing dot. Note: Before 4.0.0, names were
   taken without the trailing dot. . Not
   required for slave zones.

-  ``rrsets``: list of DNS records and comments in the zone.

Please see the description for ``PATCH`` for details on the fields in
``RRset``, ``Record`` and ``Comment``.

Turning on DNSSEC with custom keys: just create the zone with ``dnssec``
set to ``false``, and add keys using the cryptokeys REST interface. Have
at least one of them ``active`` set to ``true``. **TODO**: not yet
implemented.

Changes made through the Zones API will always yield valid zone data,
and the zone will be properly "rectified" (**TODO**: not yet
implemented). If changes are made through other means (e.g. direct
database access), this is not guaranteed to be true and clients SHOULD
trigger rectify.

Backends might implement additional features (by coincidence or not).
These things are not supported through the API.

When creating a slave zone, it is recommended to not set any of
``nameservers``, ``records``.

