Configuration endpoint
======================

.. http:get:: /api/v1/servers/:server_id/config

  Returns all :json:object:`ConfigSetting` for a single server

  :param server_id: The name of the server

.. http:post:: /api/v1/servers/:server_id/config

  .. note::
    Not implemented

  Creates a new config setting.
  This is useful for creating configuration for new backends.

  :param server_id: The name of the server

.. http:get:: /api/v1/servers/:server_id/config/:config_setting_name

  Retrieve a single setting

  :param server_id: The name of the server
  :param config_setting_name: The name of the setting to retrieve
