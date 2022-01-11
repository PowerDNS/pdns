Autoprimaries
=============

This API is used to manage :ref:`autoprimaries <autoprimary-operation>`.

Autoprimary endpoints
---------------------

.. openapi:: swagger/authoritative-api-swagger.yaml
  :paths: /servers/{server_id}/autoprimaries /servers/{server_id}/autoprimaries/{ip}/{nameserver}

Objects
-------

An autoprimary object represents a single autoprimary server.

.. openapi:: swagger/authoritative-api-swagger.yaml
  :definitions: Autoprimary

Examples
--------

Listing autoprimaries
^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: http

  GET /servers/localhost/autoprimaries HTTP/1.1
  X-Api-Key: secret
  Content-Type: application/json

Will yield a response similar to this (several headers omitted):

.. code-block:: http

  HTTP/1.1 200 Ok
  Content-Type: application/json

  [{"ip":"192.0.2.1","nameserver":"ns.example.com","account":""},{"ip":"192.0.2.50","nameserver":"ns.example.org","account":"example"}]

Creating an autoprimary
^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: http

  POST /servers/localhost/autoprimaries HTTP/1.1
  X-Api-Key: secret
  Content-Type: application/json 

  {"ip":"192.0.2.1","nameserver":"ns.example.com","account":""}

Will yield a response similar to this (several headers omitted):

.. code-block:: http

  HTTP/1.1 201 Created

Deleting an autoprimary
^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: http

  DELETE /servers/localhost/autoprimaries/192.0.2.1/ns.example.com HTTP/1.1
  X-Api-Key: secret
  Content-Type: application/json

Will yield a response similar to this (several headers omitted):

.. code-block:: http

  HTTP/1.1 204 No Content
