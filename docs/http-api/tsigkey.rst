TSIGKeys
========
.. versionadded:: 4.2.0

TSIGKeys can be manipulated via the API.

Examples
--------

Generating a new TSIG key
^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: http

  POST /servers/localhost/tsigkeys HTTP/1.1
  X-Api-Key: secret
  Content-Type: application/json

  {"name": "mytsigkey", "algorithm": "hmac-sha256"}

Will yield a response similar to this (several headers ommitted):

.. code-block:: http

  HTTP/1.1 201 Created
  Content-Type: application/json

  {"algorithm": "hmac-sha256", "id": "mytsigkey.", "key": "ayZmdUpT5xh7H21p3UUHJWZgF2F2jNncqx5SQkRIWbqReuwieiVBG8jtEieb/njCbjrLtQkjVsgoiKCtsqNsdQ==", "name": "mytsigkey", "type": "TSIGKey"}

Modifying the key material
^^^^^^^^^^^^^^^^^^^^^^^^^^

.. code-block:: http

  PUT /servers/localhost/tsigkeys/mytsigkey. HTTP/1.1
  X-Api-Key: secret
  Content-Type: application/json

  {"name": "mytsigkey", "key": "GQNyFy1QagMUarHmiSgsIJajghdTGJGVcN5TRVwgbclzxGyhQR1uYLCOyJ/uj9uj12jyeLwzJuW12wCI9PYv7Q=="}

.. code-block:: http

  HTTP/1.1 200 Ok
  Content-Type: application/json

  {"algorithm": "hmac-sha256", "id": "mytsigkey.", "key": "GQNyFy1QagMUarHmiSgsIJajghdTGJGVcN5TRVwgbclzxGyhQR1uYLCOyJ/uj9uj12jyeLwzJuW12wCI9PYv7Q==", "name": "mytsigkey", "type": "TSIGKey"}


TSIGKey Endpoints
-----------------

.. openapi:: swagger/authoritative-api-swagger.yaml
  :paths: /servers/{server_id}/tsigkeys /servers/{server_id}/tsigkeys/{tsigkey_id}

Objects
-------

.. openapi:: swagger/authoritative-api-swagger.yaml
  :definitions: TSIGKey
