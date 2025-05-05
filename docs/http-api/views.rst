Views
=====

These endpoints allow configuration of per-zone :doc:`../views`.

Views Endpoints
---------------

.. openapi:: swagger/authoritative-api-swagger.yaml
  :paths: /servers/{server_id}/views /servers/{server_id}/views/{view} /servers/{server_id}/views/{view}/{id}

Examples
--------

Listing all views
^^^^^^^^^^^^^^^^^^

.. code-block:: http

  GET /api/v1/servers/localhost/views HTTP/1.1
  X-API-Key: secret

Will yield a response similar to this (several headers omitted):

.. code-block:: http
  
  HTTP/1.1 200 OK
  Content-Type: application/json

  {"views":["trusted","untrusted"]}

Listing the zones of a view
^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: http

  GET /api/v1/servers/localhost/views/trusted HTTP/1.1
  X-API-Key: secret

Will yield a response similar to this (several headers omitted):

.. code-block:: http
  
  HTTP/1.1 200 OK
  Content-Type: application/json

  {"zones":["example.com..trusted","otherdomain.com..untrusted"]}

Creating or adding to a view
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: http

  POST /api/v1/servers/localhost/views/trusted HTTP/1.1
  X-API-Key: secret
  Content-Type: application/json

  {"name":"example.org..trusted"}

Will yield a response similar to this (several headers omitted):

.. code-block:: http
  
  HTTP/1.1 204 No Content

Deleting a view
^^^^^^^^^^^^^^^

.. code-block:: http

  DELETE /api/v1/servers/localhost/views/trusted HTTP/1.1
  X-API-Key: secret

Will yield a response similar to this (several headers omitted):

.. code-block:: http
  
  HTTP/1.1 204 No Content

