Cryptokeys
==========
.. versionadded:: 4.1.0

Allows for modifying DNSSEC key material via the API.

Endpoints
---------
.. openapi:: swagger/authoritative-api-swagger.yaml
  :paths: /servers/{server_id}/zones/{zone_id}/cryptokeys /servers/{server_id}/zones/{zone_id}/cryptokeys/{cryptokey_id}

Objects
-------
.. openapi:: swagger/authoritative-api-swagger.yaml
  :definitions: Cryptokey
