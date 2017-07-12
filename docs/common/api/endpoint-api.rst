API root endpoints
==================

.. http:get:: /api

  Version discovery endpoint.

  **Example response:**

  .. sourcecode:: json

    [
      {
        "url": "/api/v1",
        "version": 1
      }
    ]

.. http:get:: /api/v1

  APIv1 root endpoint.
  Gives some information about the current API.

  Not yet implemented:

  -  ``api_features``
  -  ``servers_modifiable``
  -  ``oauth``

  **Example response**:

  .. sourcecode:: json

    {
      "server_url": "/api/v1/servers{/server}",
      "api_features": []
    }

