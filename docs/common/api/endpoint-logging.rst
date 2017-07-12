Log endpoint
============

.. http:get:: /api/v1/servers/:server_id/search-log?q=:search_term

  Query the log, filtered by ``search_term``.
  Returns a single JSON object with a single array of strings.

  :param server_id: The name of the server
  :param search_term: The string to search for
