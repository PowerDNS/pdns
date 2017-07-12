Zones endpoint ``/api/v1/servers/:server_id/zones``
===================================================
.. http:get:: /api/v1/servers/:server_id/zones

  Get all zones from the server.

  :query server_id: The name of the server

.. http:post:: /api/v1/servers/:server_id/zones

  Creates a new domain.

  :query server_id: The name of the server

  **Authoritative Server only:**

  -  ``dnssec``, ``nsec3narrow``, ``presigned``, ``nsec3param``, ``active-keys`` are OPTIONAL.
  -  ``dnssec``, ``nsec3narrow``, ``presigned`` default to ``false``.

  The server MUST create a SOA record.
  The created SOA record SHOULD have serial set to the value given as ``serial`` (or 0 if missing), use the nameserver name, email, TTL values as specified in the PowerDNS configuration (``default-soa-name``, ``default-soa-mail``, etc).
  These default values can be overridden by supplying a custom SOA record in the records list.
  If ``soa_edit_api`` is set, the SOA record is edited according to the SOA-EDIT-API rules before storing it (also applies to custom SOA records).

  **TODO**: ``dnssec``, ``nsec3narrow``, ``nsec3param``, ``presigned`` are not yet implemented.

.. http:get:: /api/v1/servers/:server_id/zones/:zone_id

  Returns zone information.

  :query server_id: The name of the server
  :query zone_id: The id number of the :json:object:`Zone`

.. http:delete:: /api/v1/servers/:server_id/zones/:zone_id

  Deletes this zone, all attached metadata and rrsets.

  :query server_id: The name of the server
  :query zone_id: The id number of the :json:object:`Zone`

.. http:patch:: /api/v1/servers/:server_id/zones/:zone_id

  .. note::

    Authoritative only.

  Modifies present RRsets and comments. Returns ``204 No Content`` on success.

  :query server_id: The name of the server
  :query zone_id: The id number of the :json:object:`Zone`

  Example client body for PATCH:

  .. code-block:: json

    { "rrsets":
      [
        {
          "name": "www.example.com.",
          "type": "A",
          "ttl": 3600,
          "changetype": "REPLACE",
          "records":
            [
              {
                "content": "192.0.2.15",
                "disabled": false,
                "set-ptr": false
              }
            ],
        }
      ]
    }


.. http:put:: /api/v1/servers/:server_id/zones/:zone_id

  .. note::

    Authoritative only.

  Modifies basic zone data (metadata).

  :query server_id: The name of the server
  :query zone_id: The id number of the :json:object:`Zone`

  Allowed fields in client body: all except ``id`` and ``url``.
  Returns ``204 No Content`` on success.

  Changing ``name`` renames the zone, as expected.

.. http:put:: /api/v1/servers/:server_id/zones/:zone_id/notify

  .. note::

    Authoritative only.

  Send a DNS NOTIFY to all slaves.

  :query server_id: The name of the server
  :query zone_id: The id number of the :json:object:`Zone`

  Fails when zone kind is not ``Master`` or ``Slave``, or ``master`` and ``slave`` are disabled in the configuration.
  Only works for ``Slave`` if renotify is on.

  Clients MUST NOT send a body.

.. http:put:: /api/v1/servers/:server_id/zones/:zone_id/axfr-retrieve

  .. note::

    Authoritative only.

  Retrieves the zone from the master.

  :query server_id: The name of the server
  :query zone_id: The id number of the :json:object:`Zone`

  Fails when zone kind is not ``Slave``, or ``slave`` is disabled in PowerDNS configuration.


.. http:get:: /api/v1/servers/:server_id/zones/:zone_id/export

  .. note::

    Authoritative only.

  Returns the zone in AXFR format.

  :query server_id: The name of the server
  :query zone_id: The id number of the :json:object:`Zone`

.. http:get:: /api/v1/servers/:server_id/zones/:zone_id/check

  .. note::

    Not yet implemented

  Verify zone contents/configuration.

  Return format:

  .. code-block: json

    {
      "zone": "<zone_name>",
      "errors": ["error message1"],
      "warnings": ["warning message1"]
    }

