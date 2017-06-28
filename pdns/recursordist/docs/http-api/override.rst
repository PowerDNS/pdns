Data Overrides
==============

.. note::

  Overrides are not yet implemented!

.. json:object: Override

  ``created`` is filled by the Server.

  ::

    {
      "type": "Override",
      "id": <int>,
      "override": "ignore-dnssec",
      "domain": "nl",
      "until": <timestamp>,
      "created": <timestamp>
    }


    {
      "type": "Override",
      "id": <int>,
      "override": "replace",
      "domain": "www.cnn.com.",
      "rrtype": "AAAA",
      "values": ["203.0.113.4", "203.0.113..2"],
      "until": <timestamp>,
      "created": <timestamp>
    }

  **TODO**: what about validation here?

  ::

    {
      "type": "Override",
      "id": <int>,
      "override": "purge",
      "domain": "example.net.",
      "created": <timestamp>
    }

  Clears recursively all cached data ("plain" DNS + DNSSEC)

  **TODO**: should this be stored? (for history)

.. http:get:: /api/v1/servers/:server_id/overrides

  Collection access.

.. http:post:: /api/v1/servers/:server_id/overrides

  Override edits

.. http:get:: /api/v1/servers/:server_id/overrides/:override_id

.. http:put:: /api/v1/servers/:server_id/overrides/:override_id

.. http:delete:: /api/v1/servers/:server_id/overrides/:override_id

