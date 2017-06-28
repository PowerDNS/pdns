Configuration endpoint
======================

.. http:get:: /api/v1/servers/:server_id/config

  Returns all :json:object:`ConfigSetting` for a single server

  :query server_id: The name of the server

.. http:post:: /api/v1/servers/:server_id/config

  .. note::
    Not implemented

  Creates a new config setting.
  This is useful for creating configuration for new backends.

  :query server_id: The name of the server


.. http:get:: /api/v1/servers/:server_id/config/:config_setting_name

  Retrieve a single setting

  :query server_id: The name of the server
  :query config_setting_name: The name of the setting to retrieve

  .. note::
    only the :ref:`setting-allow-from` configuration setting can be retrieved

.. http:put:: /api/v1/servers/:server_id/config/:config_setting_name

  Change a single setting

  :query server_id: The name of the server
  :query config_setting_name: The name of the setting to change

  .. note::
    only the :ref:`setting-allow-from` configuration setting can be changed

  **Example request**

  .. sourcecode:: http

    PUT /api/v1/servers/localhost/config/allow-from HTTP/1.1
    Host: localhost:8082
    User-Agent: curl/7.54.1
    Accept: application/json
    X-Api-Key: secret
    Content-Type: application/json
    Content-Length: 48

    { "name": "allow-from", "value": ["127.0.0.0/8"] }

  **Example response**

  .. sourcecode:: http

    HTTP/1.1 200 OK
    Access-Control-Allow-Origin: *
    Connection: close
    Content-Length: 48
    Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'
    Content-Type: application/json
    Server: PowerDNS/0.0.g00799130f
    X-Content-Type-Options: nosniff
    X-Frame-Options: deny
    X-Permitted-Cross-Domain-Policies: none
    X-Xss-Protection: 1; mode=block

    {"name": "allow-from", "value": ["127.0.0.0/8"]}



