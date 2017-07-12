Data format
===========

The API accepts and emits JSON.
The ``Accept:`` header determines the output format. An unknown value or
``*/*`` will cause a ``400 Bad Request``.

All text is UTF-8 and HTTP headers will reflect this.

Data types:

-  empty fields: ``null`` but present
-  Regex: implementation defined
-  Dates: ISO 8601

General Collections Interface
-----------------------------

Collections generally support ``GET`` and ``POST`` with these meanings:

GET
^^^

Retrieve a list of all entries.

The special ``type`` and ``url`` fields are included in the response
objects:

-  ``type``: name of the resource type
-  ``url``: url to the object

Response format:

::

    [
      obj1
      [, further objs]
    ]

Example:

.. code-block:: json

    [
      {
        "type": "AType",
        "id": "anid",
        "url": "/atype/anid",
        "a_field": "a_value"
      },
      {
        "type": "AType",
        "id": "anotherid",
        "url": "/atype/anotherid",
        "a_field": "another_value"
      }
    ]

POST
^^^^

Create a new entry. The client has to supply the entry in the request body, in JSON format.
``application/x-www-form-urlencoded`` data MUST NOT be sent.

Clients SHOULD not send the 'url' field.

Client body:

::

    obj1

Example:

.. code-block:: json

    {
      "type": "AType",
      "id": "anewid",
      "a_field": "anew_value"
    }

REST
----

-  GET: List/Retrieve. Success reply: ``200 OK``
-  POST: Create. Success reply: ``201 Created``, with new object as body.
-  PUT: Update. Success reply: ``200 OK``, with modified object as body. For some operations, ``204 No Content`` is returned instead (and the modified object is not given in the body).
-  DELETE: Delete. Success reply: ``200 OK``, no body.

not-so-REST
-----------

For interactions that do not directly map onto CRUD, we use these:

-  GET: Query. Success reply: ``200 OK``
-  PUT: Action/Execute. Success reply: ``200 OK``

Action/Execute methods return a JSON body of this format:

.. code-block:: json

    {
      "message": "result message"
    }

Authentication
--------------

The PowerDNS daemons accept a static API Key, configured with the :ref:`setting-api-key` option, which has to be sent in the ``X-API-Key`` header.

Errors
------

Response code ``4xx`` or ``5xx``, depending on the situation. Never return ``2xx`` for an error!

-  Invalid JSON body from client: ``400 Bad Request``
-  JSON body from client not a hash: ``400 Bad Request``
-  Input validation failed: ``422 Unprocessable Entity``

Error responses have a JSON body of this format:

.. code-block:: json

    {
      "error": "short error message",
      "errors": [
        {  },
      ]
    }

Where ``errors`` is optional, and the contents are error-specific.

Common Error Causes
^^^^^^^^^^^^^^^^^^^

400 Bad Request
~~~~~~~~~~~~~~~

1. The client body was not a JSON document, or it could not be parsed, or the root element of the JSON document was not a hash.
2. The client did not send an ``Accept:`` header, or it was set to ``*/*``.
3. For requests that operate on a zone, the ``zone_id`` URL part was invalid.
   To get a valid ``zone_id``, list the zones with the ``/api/v1/servers/:server_id/zones`` endpoint.
