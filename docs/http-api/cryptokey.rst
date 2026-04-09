Cryptokeys
==========
Allows for modifying DNSSEC key material via the API.

Endpoints
---------
.. openapi:: openapi/authoritative-api-openapi.yaml
  :paths: /servers/{server_id}/zones/{zone_id}/cryptokeys /servers/{server_id}/zones/{zone_id}/cryptokeys/{cryptokey_id}
  :examples:

Objects
-------
.. json:schema:: Cryptokey
