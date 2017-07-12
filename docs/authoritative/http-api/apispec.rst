URL: /api/v0/servers/:server\_id/zones/:zone\_name/metadata
-----------------------------------------------------------

Collection access.

Allowed methods: ``GET``, ``POST``

GET
^^^

Returns all metadata entries for the zone.

POST
^^^^

Creates a set of metadata entries of given kind for the zone.

-  existing metadata entries for the zone with the same kind are not
   overwritten.

URL: /api/v1/servers/:server\_id/zones/:zone\_name/metadata/:metadata\_kind
---------------------------------------------------------------------------

Allowed methods: ``GET``, ``PUT``, ``DELETE``

GET
^^^

Returns all metadata entries of a given kind for the zone.

DELETE
^^^^^^

Deletes all metadata entries of a given kind for the zone.

PUT
^^^

Modifies the metadata entries of a given kind for the zone.

This returns ``200 OK`` on success.

Cryptokeys
==========

cryptokey\_resource
-------------------

::

    {
      "type": "Cryptokey",
      "id": <int>,
      "active": <bool>,
      "keytype": <keytype>,
      "dnskey": <string>,
      "privatekey": <string>,
      "ds": [ <ds>,
              <ds>,
              .... ]
    }

Parameters:
'''''''''''

``id``: read-only.

``keytype``: ``<keytype>`` is one of the following: ``ksk``, ``zsk``,
``csk``.

``dnskey``: the DNSKEY for this key

``ds``: an array with all DSes for this key

``privatekey``: private key data (in ISC format).

URL: /api/v1/servers/:server\_id/zones/:zone\_name/cryptokeys
-------------------------------------------------------------

Allowed methods: ``GET``, ``POST``

GET
^^^

Returns all public data about cryptokeys, but not ``privatekey``.

POST
^^^^

This method adds a new key to a zone. The key can either be generated or
imported by supplying the content parameter.

Parameters:
'''''''''''

-  ``content`` : "<key>" ``<string>`` (The format used is compatible
   with BIND and NSD/LDNS)
-  ``keytype`` : "ksk\|zsk" ``<string>``
-  ``active``: "true\|false" ``<value>`` (If not set the key will not be
   active by default)

If ``content`` == ``null``, the server generates a new key. In this
case, the following additional fields MAY be supplied:

-  ``bits``: number of bits ``<int>``
-  ``algo``: ``<algo>`` (Default: 13/ECDSA)

Where ``<algo>`` is one of the supported key algorithms in lowercase OR
the numeric id, see
```the list`` <../authoritative/dnssec.md#supported-algorithms>`__.

Response:
'''''''''

-  ``422 Unprocessable Entity``:

   -  keytype is not ksk\|zsk:

      -  ``{"error" : "Invalid keytype 'keytype'"}``

   -  The "algo" is not supported:

      -  ``{"error" : "Unknown algorithm: 'algo'"}``

   -  Algo <= 10 and the ``bits`` parameter is not set:

      -  ``{"error" : "Creating an algorithm 'algo' key requires the size (in bits) to be passed."}``

   -  The provided bit size is not supported by the selected algorithm:

      -  ``{"error" : "The algorithm does not support the given bit size."}``

   -  The ``bits`` parameter is not a positive integer value:

      -  ``{"error" : "'bits' must be a positive integer value"}``

   -  If the server can not guess the key size:

      -  ``{"error" : "Can not guess key size for algorithm"}``

   -  The key-creation failed:

      -  ``{"error" : "Adding key failed, perhaps DNSSEC not enabled in configuration?"}``

   -  The key in ``content`` has the wrong format:

      -  ``{"error" : "Key could not be parsed. Make sure your key format is correct."}``

-  ``201 Created``:

   -  Everything was fine:

      -  Returns all public data about the new cryptokey. Look at
         cryptokey\_resource.

URL: /api/v1/servers/:server\_id/zones/:zone\_name/cryptokeys/:cryptokey\_id
----------------------------------------------------------------------------

Allowed methods: ``GET``, ``PUT``, ``DELETE``

GET
^^^

Returns all public data about cryptokeys, including ``privatekey``.

PUT
^^^

This method de/activates a key from ``zone_name`` specified by
``cryptokey_id``.

Parameters:
'''''''''''

-  ``active``: "true\|false" ``<value>``

Responses:
''''''''''

-  ``204 No Content``: The key with ``cryptokey_id`` is de/activated.
-  ``422 Unprocessable Entity``:   The backend returns false on
   de/activation. An error occurred.
     ``{"error": "Could not de/activate Key: :cryptokey_id in Zone: :zone_name"}``

DELETE
^^^^^^

This method deletes a key from ``zone_name`` specified by
``cryptokey_id``.

Responses:
''''''''''

-  ``200 OK``: The Key is gone.
-  ``422 Unprocessable Entity``:   The backend failed to remove the key.
     ``{"error": Could not DELETE :cryptokey_id"}``

Data searching
==============

URL: /api/v1/servers/localhost/search-data?q=:search\_term&max=:max\_results
----------------------------------------------------------------------------

**Note**: Authoritative only.

Allowed methods: ``GET``

GET
^^^

Search the data inside PowerDNS for :search\_term and return at most
:max\_results. This includes zones, records and comments. The ``*``
character can be used in :search\_term as a wildcard character and the
``?`` character can be used as a wildcard for a single character.

Response body is an array of one or more of the following objects:

For a zone:

::

    {
      "name": "<zonename>",
      "object_type": "zone",
      "zone_id": "<zoneid>"
    }

For a record:

::

    {
      "content": "<content>",
      "disabled": <bool>,
      "name": "<name>",
      "object_type": "record",
      "ttl": <ttl>,
      "type": "<type>",
      "zone": "<zonename>,
      "zone_id": "<zoneid>"
    }

For a comment:

::

    {
      "object_type": "comment",
      "name": "<name>",
      "content": "<content>"
      "zone": "<zonename>,
      "zone_id": "<zoneid>"
    }


