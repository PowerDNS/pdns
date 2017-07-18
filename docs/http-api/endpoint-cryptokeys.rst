CryptoKeys endpoint
===================

.. versionadded:: 4.1.0

These endpoints allow for the manipulation of DNSSEC crypto material.

.. http:get:: /api/v1/servers/:server_id/zones/:zone_id/cryptokeys

  Get all :json:object:`CryptoKeys <CryptoKey>` for a zone, except the privatekey

  :param server_id: The name of the server
  :param zone_id: The id value of the :json:object:`Zone`

.. http:post:: /api/v1/servers/:server_id/zones/:zone_id/cryptokeys

  This method adds a new key to a zone.
  The key can either be generated or imported by supplying the ``content`` parameter.

  :param server_id: The name of the server
  :param zone_id: The id value of the :json:object:`Zone`
  :reqjson string content: The private key to use (The format used is compatible with BIND and NSD/LDNS)
  :reqjson string keytype: Either "ksk" or "zsk"
  :reqjson bool active: If not set the key will not be active by default
  :reqjson int bits: Number of bits in the key (if ``content`` is not set)
  :reqjson int,string algo: The DNSSEC algorithm (if ``content`` is not set), see :ref:`dnssec-supported-algos`
  :statuscode 201: Everything was fine, returns all public data as a :json:object:`CryptoKey`.
  :statuscode 422: Returned when something is wrong with the content of the request.
                   Contains an error message
  :resjson string error: Has the error message

.. http:get:: /api/v1/servers/:server_id/zones/:zone_name/cryptokeys/:cryptokey_id

  Returns all data about the :json:object:`CryptoKey`, including the ``privatekey``.

  :param string server_id: The name of the server
  :param string zone_id: The id value of the :json:object:`Zone`
  :param string cryptokey_id: The id value of the :json:object:`CryptoKey`

.. http:put:: /api/v1/servers/:server_id/zones/:zone_name/cryptokeys/:cryptokey_id

  This method (de)activates a key from ``zone_name`` specified by ``cryptokey_id``.

  :param string server_id: The name of the server
  :param string zone_id: The id value of the :json:object:`Zone`
  :param string cryptokey_id: The id value of the :json:object:`CryptoKey`
  :reqjson bool active: The new 'active' status of the key
  :statuscode 204: Everything was fine, the key with ``cryptokey_id`` is de/activated.
  :statuscode 422: Returned when something is wrong with the content of the request.
                   Contains an error message
  :resjson string error: Has the error message

.. http:delete:: /api/v1/servers/:server_id/zones/:zone_name/cryptokeys/:cryptokey_id

  This method deletes a key from ``zone_name`` specified by ``cryptokey_id``.

  :param string server_id: The name of the server
  :param string zone_id: The id value of the :json:object:`Zone`
  :param string cryptokey_id: The id value of the :json:object:`CryptoKey`
  :statuscode 200: Everything was fine, the key with ``cryptokey_id`` is gone
  :statuscode 422: Returned when the key could not be removed.
                   Contains an error message
  :resjson string error: Has the error message
