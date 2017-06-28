Zones endpoint
==============

.. http:get:: /api/v1/servers/:server_id/zones

  Get all zones from the server.

  :query server_id: The name of the server

.. http:post:: /api/v1/servers/:server_id/zones

  Creates a new domain. The client body must contain a :json:object:`Zone`.

  :query server_id: The name of the server

.. http:get:: /api/v1/servers/:server_id/zones/:zone_id

  Returns zone information.

  :query server_id: The name of the server
  :query zone_id: The id number of the :json:object:`Zone`

.. http:delete:: /api/v1/servers/:server_id/zones/:zone_id

  Deletes this zone, all attached metadata and rrsets.

  :query server_id: The name of the server
  :query zone_id: The id number of the :json:object:`Zone`
