Statistics
==========

Endpoints
---------

.. openapi:: swagger/authoritative-api-swagger.yaml
  :paths: /servers/{server_id}/statistics
  :examples:

Objects
-------

The Statistics endpoint returns an array of objects that can be StatisticItem, MapStatisticItem or RingStatisticItem :

.. json:schema:: StatisticItem
.. json:schema:: MapStatisticItem
.. json:schema:: RingStatisticItem

Both MapStatisticItem and RingStatisticItem objects contains an array of SimpleStatisticItem

.. json:schema:: SimpleStatisticItem
