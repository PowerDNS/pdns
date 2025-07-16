.. include:: ../common/api/endpoint-servers-config.rst

.. http:put:: /api/v1/servers/:server_id/config/:config_setting_name

  Change a single setting

  .. note::
    Only :ref:`setting-yaml-incoming.allow_from` and :ref:`setting-yaml-incoming.allow_notify_from` can be set.

  .. note::
    For configuration changes to work :ref:`setting-include-dir` and :ref:`setting-api-config-dir` should have the same value for old-style settings.
    When using YAML settings :ref:`setting-yaml-recursor.include_dir` and :ref:`setting-yaml-webservice.api_dir` must have a different value.

  :param server_id: The name of the server
  :param config_setting_name: The name of the setting to change

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



