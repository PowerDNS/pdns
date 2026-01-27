Searching
=========

The API allows searching for data in :json:schema:`Zones <Zone>`, :json:schema:`Comments <Comment>` and :json:schema:`RRSets <RRSet>`.

.. note::

  Not all backends support searching in records or comments.


Endpoints
---------

.. openapi:: swagger/authoritative-api-swagger.yaml
  :paths: /servers/{server_id}/search-data

Objects
-------
.. json:schema:: SearchResult
