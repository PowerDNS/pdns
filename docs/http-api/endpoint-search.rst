Data Search Endpoint
====================

.. http:get:: /api/v1/servers/:server_id/search-data?q=:search_term&max=:max_results

  Search the data inside PowerDNS for ``search_term`` and return at most
  ``max_results``. This includes zones, records and comments. The ``*``
  character can be used in ``search_term`` as a wildcard character and the
  ``?`` character can be used as a wildcard for a single character.

  :param server_id: The name of the server
  :query string search_term: The term to search for
  :query int max_results: Maximum number of entries to return

  Response body is an array of one or more of the following objects:

  .. code-block:: http

    HTTP/1.1 200 OK
    Content-Type: application/json

    [
      {
        "name": "example.com.",
        "object_type": "zone",
        "zone_id": "example.com."
      }
    ]


  For a record:

  .. code-block:: http

    HTTP/1.1 200 OK
    Content-Type: application/json

    [
      {
        "content": "192.0.2.1",
        "disabled": false,
        "name": "www.example.com",
        "object_type": "record",
        "ttl": 1200,
        "type": "A",
        "zone": "example.com.",
        "zone_id": "example.com."
      }
    ]

  For a comment:

  .. code-block:: http

    HTTP/1.1 200 OK
    Content-Type: application/json

    [
      {
        "object_type": "comment",
        "name": "www.example.com",
        "content": "An awesome comment",
        "zone": "example.com.",
        "zone_id": "example.com."
      }
    ]
