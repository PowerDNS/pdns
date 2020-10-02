Cache manipulation endpoint
===========================

.. http:put:: /api/v1/servers/:server_id/cache/flush?domain=:domain

  Flush the positive, negative and packet cache for a given domain name.

  :query server_id: The name of the server
  :query domain: The domainname to flush for

  .. versionadded:: 4.1.3

  :query subtree: If set to `true`, also flush the whole subtree (default = `false`)

  .. versionadded:: 4.4.0

  :query type: If set the recursor only flushes records of the specified type name.

  **Example Response:**

  .. code-block:: json

    {
      "count": 10,
      "result": "Flushed cache."
    }

