Zones endpoint
==============
.. http:get:: /api/v1/servers/:server_id/zones

  Get all zones from the server.

  :param server_id: The name of the server

.. http:post:: /api/v1/servers/:server_id/zones

  Creates a new domain, returns the :json:object:`Zone` on creation.

  :param server_id: The name of the server
  :query rrsets: "true" (default) or "false", whether to include the "rrsets" in the response :json:object:`Zone` object.
  :statuscode 201: The zone was successfully created

  A :json:object:`Zone` MUST be sent in the request body.

  -  ``dnssec``, ``nsec3narrow``, ``presigned``, ``nsec3param``, ``api_rectify``, ``active-keys`` are OPTIONAL.
  -  ``dnssec``, ``nsec3narrow``, ``presigned``, ``api_rectify`` default to ``false``.

  The server MUST create a SOA record.
  The created SOA record SHOULD have serial set to the value given as ``serial`` (or 0 if missing), use the nameserver name, email, TTL values as specified in the PowerDNS configuration (``default-soa-name``, ``default-soa-mail``, etc).
  These default values can be overridden by supplying a custom SOA record in the records list.
  If ``soa_edit_api`` is set, the SOA record is edited according to the SOA-EDIT-API rules before storing it (also applies to custom SOA records).

.. http:get:: /api/v1/servers/:server_id/zones/:zone_id

  Returns zone information.

  :param server_id: The name of the server
  :param zone_id: The id number of the :json:object:`Zone`
  :query rrsets: "true" (default) or "false", whether to include the "rrsets" in the response :json:object:`Zone` object.

.. http:delete:: /api/v1/servers/:server_id/zones/:zone_id

  Deletes this zone, all attached metadata and rrsets.

  :param server_id: The name of the server
  :param zone_id: The id number of the :json:object:`Zone`

.. http:patch:: /api/v1/servers/:server_id/zones/:zone_id

  Modifies present RRsets and comments. Returns ``204 No Content`` on success.

  The new and old zone serials will be returned in `X-PDNS-New-Serial` and `X-PDNS-Old-Serial` headers (auth 4.1+).

  :param server_id: The name of the server
  :param zone_id: The id number of the :json:object:`Zone`

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

  Modifies basic zone data (metadata).

  :param server_id: The name of the server
  :param zone_id: The id number of the :json:object:`Zone`

  Allowed fields in client body: all except ``id``, ``url`` and ``name``.
  Returns ``204 No Content`` on success.

.. http:put:: /api/v1/servers/:server_id/zones/:zone_id/notify

  Send a DNS NOTIFY to all slaves.

  :param server_id: The name of the server
  :param zone_id: The id number of the :json:object:`Zone`

  Fails when zone kind is not ``Master`` or ``Slave``, or ``master`` and ``slave`` are disabled in the configuration.
  Only works for ``Slave`` if renotify is on.

  Clients MUST NOT send a body.

.. http:put:: /api/v1/servers/:server_id/zones/:zone_id/axfr-retrieve

  Retrieves the zone from the master.

  :param server_id: The name of the server
  :param zone_id: The id number of the :json:object:`Zone`

  Fails when zone kind is not ``Slave``, or ``slave`` is disabled in PowerDNS configuration.


.. http:get:: /api/v1/servers/:server_id/zones/:zone_id/export

  Returns the zone in AXFR format.

  :param server_id: The name of the server
  :param zone_id: The id number of the :json:object:`Zone`

.. http:get:: /api/v1/servers/:server_id/zones/:zone_id/check

  Verify zone contents/configuration.

  Return format:

  .. code-block: json

    {
      "zone": "<zone_name>",
      "errors": ["error message1"],
      "warnings": ["warning message1"]
    }

  :param server_id: The name of the server
  :param zone_id: The id number of the :json:object:`Zone`

.. http:put:: /api/v1/servers/:server_id/zones/:zone_id/rectify

  Rectify the zone data. This does not take into account the :ref:`metadata-api-rectify` metadata.

  :param server_id: The name of the server
  :param zone_id: The id number of the :json:object:`Zone`

  Fails on slave zones and zones that do not have DNSSEC.
