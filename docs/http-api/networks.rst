Networks
========

These endpoints allow configuration of networks, used by :doc:`../views`.

Networks Endpoints
------------------

.. openapi:: swagger/authoritative-api-swagger.yaml
  :paths: /servers/{server_id}/networks /servers/{server_id}/networks/{ip}/{prefixlen}

Examples
--------

Listing all networks
^^^^^^^^^^^^^^^^^^^^

.. code-block:: http

  GET /api/v1/servers/localhost/networks HTTP/1.1
  X-API-Key: secret

Will yield a response similar to this (several headers omitted):

.. code-block:: http
  
  HTTP/1.1 200 OK
  Content-Type: application/json

  {"networks": [{"network":"192.168.0.0/16","view":"trusted"},{"network":"0.0.0.0/0","view":"untrusted"}]}

Listing the view of a given network
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: http

  GET /api/v1/servers/localhost/networks/192.168.0.0/16 HTTP/1.1
  X-API-Key: secret

Will yield a response similar to this (several headers omitted):

.. code-block:: http
  
  HTTP/1.1 200 OK
  Content-Type: application/json

  {"networks": [{"network":"192.168.0.0/16","view":"trusted"}]}

Setting up a network
^^^^^^^^^^^^^^^^^^^^

.. code-block:: http

  PUT /api/v1/servers/localhost/networks/192.168.0.0/16 HTTP/1.1
  X-API-Key: secret
  Content-Type: application/json

  {"view": "trusted"}

Will yield a response similar to this (several headers omitted):

.. code-block:: http
  
  HTTP/1.1 204 No Content


