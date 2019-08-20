Statistics
==========

Endpoints
---------

.. openapi:: swagger/authoritative-api-swagger.yaml
  :paths: /servers/{server_id}/statistics

Objects
-------

The Statistics endpoint returns an array of objects that can be StatisticItem, MapStatisticItem or RingStatisticItem :

.. openapi:: swagger/authoritative-api-swagger.yaml
  :definitions: StatisticItem

.. openapi:: swagger/authoritative-api-swagger.yaml
  :definitions: MapStatisticItem

.. openapi:: swagger/authoritative-api-swagger.yaml
  :definitions: RingStatisticItem

Both MapStatisticItem and RingStatisticItem objects contains an array of SimpleStatisticItem

.. openapi:: swagger/authoritative-api-swagger.yaml
  :definitions: SimpleStatisticItem