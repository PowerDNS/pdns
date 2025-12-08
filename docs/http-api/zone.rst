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
  ``pdnsutil zone secure`` and ``pdnsutil zone rectify`` (if ``api_rectify``
  is set to ``true``).
  This also applies to newly created zones. If ``presigned`` is ``true``,
  no DNSSEC changes will be made to the zone or cryptokeys.

.. note::

  ``notified_serial``, ``serial`` MUST NOT be sent in client bodies.

Changes made through the Zones API will always yield valid zone data, as the API will reject records with wrong data.

DNSSEC-enabled zones should be :ref:`rectified <rules-for-filling-out-dnssec-fields>` after changing the zone data.
This can be done by the API automatically after a change when the :ref:`metadata-api-rectify` metadata is set.
When creating or updating a zone, the "api_rectify" field of the :json:object:`Zone` can be set to `true` to enable this behaviour.

Backends might implement additional features (by coincidence or not).
These things are not supported through the API.

When creating a secondary zone, it is recommended to not set any of
``nameservers``, ``rrsets`` or ``zone``.

Examples
--------

Listing all zones
^^^^^^^^^^^^^^^^^

.. code-block:: http

  GET /api/v1/servers/localhost/zones HTTP/1.1
  X-API-Key: secret

Will yield a response similar to this (several headers omitted):

.. code-block:: http
  
  HTTP/1.1 200 OK
  Content-Type: application/json

  [{"account": "", "dnssec": false, "edited_serial": 2022040504, "id": "example.org.", "kind": "Native", "last_check": 0, "masters": [], "name": "example.org.", "notified_serial": 0, "serial": 2022040504, "url": "/api/v1/servers/localhost/zones/example.org."}]

Creating new zone
^^^^^^^^^^^^^^^^^

.. code-block:: http

  POST /api/v1/servers/localhost/zones HTTP/1.1
  X-API-Key: secret
  Content-Type: application/json

  {"name": "example.org.", "kind": "Native", "masters": [], "nameservers": ["ns1.example.org.", "ns2.example.org."]}

Will yield a response similar to this (several headers omitted):

.. code-block:: http
  
  HTTP/1.1 200 OK
  Content-Type: application/json

  {"account": "", "api_rectify": false, "dnssec": false, "edited_serial": 2022040501, "id": "example.org.", "kind": "Native", "last_check": 0, "master_tsig_key_ids": [], "masters": [], "name": "example.org.", "notified_serial": 0, "nsec3narrow": false, "nsec3param": "", "rrsets": [{"comments": [], "name": "example.org.", "records": [{"content": "a.misconfigured.dns.server.invalid. hostmaster.example.org. 2022040501 10800 3600 604800 3600", "disabled": false}], "ttl": 3600, "type": "SOA"}, {"comments": [], "name": "example.org.", "records": [{"content": "ns1.example.org.", "disabled": false}, {"content": "ns2.example.org.", "disabled": false}], "ttl": 3600, "type": "NS"}], "serial": 2022040501, "slave_tsig_key_ids": [], "soa_edit": "", "soa_edit_api": "DEFAULT", "url": "/api/v1/servers/localhost/zones/example.org."}

Listing a zone
^^^^^^^^^^^^^^

.. code-block:: http

  GET /api/v1/servers/localhost/zones/example.org. HTTP/1.1
  X-API-Key: secret

Will yield a response similar to this (several headers omitted):

.. code-block:: http
  
  HTTP/1.1 200 OK
  Content-Type: application/json

  {"account": "", "api_rectify": false, "dnssec": false, "edited_serial": 2022040501, "id": "example.org.", "kind": "Native", "last_check": 0, "master_tsig_key_ids": [], "masters": [], "name": "example.org.", "notified_serial": 0, "nsec3narrow": false, "nsec3param": "", "rrsets": [{"comments": [], "name": "example.org.", "records": [{"content": "a.misconfigured.dns.server.invalid. hostmaster.example.org. 2022040501 10800 3600 604800 3600", "disabled": false}], "ttl": 3600, "type": "SOA"}, {"comments": [], "name": "example.org.", "records": [{"content": "ns1.example.org.", "disabled": false}, {"content": "ns2.example.org.", "disabled": false}], "ttl": 3600, "type": "NS"}], "serial": 2022040501, "slave_tsig_key_ids": [], "soa_edit": "", "soa_edit_api": "DEFAULT", "url": "/api/v1/servers/localhost/zones/example.org."}

Deleting a zone
^^^^^^^^^^^^^^^

.. code-block:: http

  DELETE /api/v1/servers/localhost/zones/example.org. HTTP/1.1
  X-API-Key: secret

Will yield a response similar to this (several headers omitted):

.. code-block:: http
  
  HTTP/1.1 204 No Content
  
Creating new RRset
^^^^^^^^^^^^^^^^^^

.. code-block:: http

  PATCH /api/v1/servers/localhost/zones/example.org. HTTP/1.1
  X-API-Key: secret
  Content-Type: application/json

  {"rrsets": [{"name": "test.example.org.", "type": "A", "ttl": 3600, "changetype": "REPLACE", "records": [{"content": "192.168.0.5", "disabled": false}]}]}

Will yield a response similar to this (several headers omitted):

.. code-block:: http
  
  HTTP/1.1 204 No Content

Adding a single record to a RRset
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. note:: added in versions 4.9.12 and 5.0.2

.. code-block:: http

  PATCH /api/v1/servers/localhost/zones/example.org. HTTP/1.1
  X-API-Key: secret
  Content-Type: application/json

  {"rrsets": [{"name": "test.example.org.", "type": "TXT", "changetype": "EXTEND", "records": [{"content": "the contents of the records to add", "disabled": false}]}]}

Will yield a response similar to this (several headers omitted):

.. code-block:: http
  
  HTTP/1.1 204 No Content

If a record with the same exact content already exists in the RRSet, no action is performed and no error is returned.

Deleting a RRset
^^^^^^^^^^^^^^^^^^

.. code-block:: http

  PATCH /api/v1/servers/localhost/zones/example.org. HTTP/1.1
  X-API-Key: secret
  Content-Type: application/json

  {"rrsets": [{"name": "test.example.org.", "type": "A", "changetype": "DELETE"}]}

Will yield a response similar to this (several headers omitted):

.. code-block:: http
  
  HTTP/1.1 204 No Content

If no record with the same exact content exists in the RRSet, no action is performed and no error is returned.

Deleting a single record from a RRset
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. note:: added in versions 4.9.12 and 5.0.2

.. code-block:: http

  PATCH /api/v1/servers/localhost/zones/example.org. HTTP/1.1
  X-API-Key: secret
  Content-Type: application/json

  {"rrsets": [{"name": "test.example.org.", "type": "TXT", "changetype": "PRUNE", "records": [{"content": "the contents of the records to delete"}]}]}

Will yield a response similar to this (several headers omitted):

.. code-block:: http
  
  HTTP/1.1 204 No Content

Rectifying a zone
^^^^^^^^^^^^^^^^^

.. code-block:: http

  PUT /api/v1/servers/localhost/zones/example.org./rectify HTTP/1.1
  X-API-Key: secret

Will yield a response similar to this (several headers omitted):

.. code-block:: http
  
  HTTP/1.1 200 OK
  Content-Type: application/json

  {"result": "Rectified"}
  
