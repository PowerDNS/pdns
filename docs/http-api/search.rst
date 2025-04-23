Searching
=========

The API allows searching for data in :json:object:`Zone`\ s, :json:object:`Comment`\ s and :json:object:`RRSet`\ s.

.. note::

  Not all backends support searching in records or comments.


Endpoints
---------

.. openapi:: swagger/authoritative-api-swagger.yaml
  :paths: /servers/{server_id}/search-data

Objects
-------
.. openapi:: swagger/authoritative-api-swagger.yaml
  :definitions: SearchResult
