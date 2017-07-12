Cache manipulation endpoint
===========================

.. http:put:: /api/v1/servers/:server_id/cache/flush?domain=:domain

  Flush the positive, negative and packet cache for a given domain name.

  :query server_id: The name of the server
  :query domain: The domainname to flush for

  **Example Response:**

  .. code-block:: json

    {
      "count": 10,
      "result": "Flushed cache."
    }

