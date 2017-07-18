Zone Metadata endpoints
=======================

.. versionadded:: 4.1.0

.. http:get:: /api/v1/servers/:server_id/zones/:zone_id/metadata

  Get all the :json:object:`MetaData` associated with the zone.

  :param server_id: The name of the server
  :param zone_id: The id number of the :json:object:`Zone`

.. http:post:: /api/v1/servers/:server_id/zones/:zone_id/metadata

  Creates a set of metadata entries of given kind for the zone.
  Existing metadata entries for the zone with the same kind are not overwritten.

  :param server_id: The name of the server
  :param zone_id: The id number of the :json:object:`Zone`

.. http:get:: /api/v1/servers/:server_id/zones/:zone_name/metadata/:metadata_kind

  Get the content of a single kind of :doc:`domain metadata <../domainmetadata>` as a list of :json:object:`MetaData` objects.

  :param server_id: The name of the server
  :param zone_id: The id number of the :json:object:`Zone`
  :param metadata_kind: The name of the metadata to retrieve

.. http:put:: /api/v1/servers/:server_id/zones/:zone_name/metadata/:metadata_kind

  Modify the content of a single kind of :doc:`domain metadata <../domainmetadata>`.

  :param server_id: The name of the server
  :param zone_id: The id number of the :json:object:`Zone`
  :param metadata_kind: The name of the metadata to edit
  :reqjson MetaData data: The list of :json:object:`MetaData` to set.

.. http:delete:: /api/v1/servers/:server_id/zones/:zone_name/metadata/:metadata_kind

  Delete all items of a single kind of :doc:`domain metadata <../domainmetadata>`.

  :param server_id: The name of the server
  :param zone_id: The id number of the :json:object:`Zone`
  :param metadata_kind: The name of the metadata to delete
