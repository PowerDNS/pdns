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

Examples
--------

Listing all servers
^^^^^^^^^^^^^^^^^^^

.. code-block:: http

  GET /api/v1/servers HTTP/1.1
  X-API-Key: secret

Will yield a response similar to this (several headers omitted):

.. code-block:: http
  
  HTTP/1.1 200 OK
  Content-Type: application/json
  
  [{"autoprimaries_url": "/api/v1/servers/localhost/autoprimaries{/autoprimary}", "config_url": "/api/v1/servers/localhost/config{/config_setting}", "daemon_type": "authoritative", "id": "localhost", "type": "Server", "url": "/api/v1/servers/localhost", "version": "4.6.1", "zones_url": "/api/v1/servers/localhost/zones{/zone}"}]

Listing a server
^^^^^^^^^^^^^^^^

.. code-block:: http

  GET /api/v1/servers/localhost HTTP/1.1
  X-API-Key: secret

Will yield a response similar to this (several headers omitted):

.. code-block:: http
  
  HTTP/1.1 200 OK
  Content-Type: application/json
  
  {"autoprimaries_url": "/api/v1/servers/localhost/autoprimaries{/autoprimary}", "config_url": "/api/v1/servers/localhost/config{/config_setting}", "daemon_type": "authoritative", "id": "localhost", "type": "Server", "url": "/api/v1/servers/localhost", "version": "4.6.1", "zones_url": "/api/v1/servers/localhost/zones{/zone}"}
