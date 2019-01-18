Servers
=======

The server endpoint is the 'basis' for all other API operations.
In the PowerDNS Authoritative Server, the ``server_id`` is always ``localhost``.
However, the API is written in a way that a proxy could be in front of many servers, each with their own ``server_id``.

Endpoints
---------

.. openapi:: swagger/authoritative-api-swagger.yaml
  :paths: /servers /servers/{server_id}

Objects
-------
.. openapi:: swagger/authoritative-api-swagger.yaml
  :definitions: Server
