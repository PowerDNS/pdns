API Spec
========

This API runs over HTTP, preferably HTTPS.

Design Goals
------------

* Discovery endpoint
* Unified API Scheme for Daemons & Console.
  Think of the Console Server as a proxy for all your PowerDNS deployments.
* Have API documentation (this!) for other consumers

Data format
-----------

Input data format: JSON.

Output data formats: JSON.

The `Accept:` header determines the output format. An unknown value or
`*/*` will cause a `400 Bad Request`.

All text is UTF-8 and HTTP headers will reflect this.

Data types:

  * empty fields: `null` but present
  * Regex: implementation defined
  * Dates: ISO 8601


REST
----

* GET: List/Retrieve. Success reply: `200 OK`
* POST: Create. Success reply: `201 Created`, with new object as body.
* PUT: Update. Success reply: `200 OK`, with modified object as body. For some operations, `204 No Content` is returned instead (and the modified object is not given in the body).
* DELETE: Delete. Success reply: `200 OK`, no body.

not-so-REST
-----------

For interactions that do not directly map onto CRUD, we use these:

* GET: Query. Success reply: `200 OK`
* PUT: Action/Execute. Success reply: `200 OK`

Action/Execute methods return a JSON body of this format:

    {
      "message": "result message"
    }


Authentication
--------------

The PowerDNS daemons accept a static API Key, configured with the
[`api-key`]('../authoritative/settings.md#api-key')
option, which has to be sent in the `X-API-Key` header.

Note: Authoritative Server 3.4.0 and Recursor 3.6.0 and 3.6.1 use HTTP
Basic Authentication instead.


Errors
------

Response code `4xx` or `5xx`, depending on the situation. Never return `2xx`
for an error!

* Invalid JSON body from client: `400 Bad Request`
* JSON body from client not a hash: `400 Bad Request`
* Input validation failed: `422 Unprocessable Entity`

Error responses have a JSON body of this format:

    {
      "error": "short error message",
      "errors": [
        { ... },
      ]
    }

Where `errors` is optional, and the contents are error-specific.


Common Error Causes
-------------------

##### 400 Bad Request

1. The client body was not a JSON document, or it could not be parsed, or the root element of the JSON document was not a hash.
2. The client did not send an `Accept:` header, or it was set to `*/*`.
3. For requests that operate on a zone, the `zone_id` URL part was invalid. To get a valid `zone_id`, list the zones with the `/api/v1/servers/:server_id/zones` endpoint.


URL: /api
---------

Version discovery endpoint.

Allowed methods: `GET`

    [
      {
        "url": "/api/v1",
        "version": 1
      }
    ]


URL: /api/v1
------------

Allowed methods: `GET`

    {
      "server_url": "/api/v1/servers{/server}",
      "api_features": []
    }

**TODO**:

* Not yet implemented.
* `api_features`
  * `servers_modifiable`
  * `oauth`


General Collections Interface
=============================

Collections generally support `GET` and `POST` with these meanings:

GET
---

Retrieve a list of all entries.

The special `type` and `url` fields are included in the response objects:

  * `type`: name of the resource type
  * `url`: url to the object


Response format:

    [
      obj1
      [, further objs]
    ]

Example:

    [
      {
        "type": "AType",
        "id": "anid",
        "url": "/atype/anid",
        "a_field": "a_value"
      },
      {
        "type": "AType",
        "id": "anotherid",
        "url": "/atype/anotherid",
        "a_field": "another_value"
      }
    ]


POST
----

Create a new entry. The client has to supply the entry in the request body,
in JSON format. `application/x-www-form-urlencoded` data MUST NOT be sent.

Clients SHOULD not send the 'url' field.

Client body:

    obj1

Example:

    {
      "type": "AType",
      "id": "anewid",
      "a_field": "anew_value"
    }




Servers
=======

**TODO**: further routes


server_resource
---------------

Example with server `"localhost"`, which is the only server returned by
pdns\_server or pdns\_recursor.

pdnsmgrd and pdnscontrol MUST NOT return “localhost”, but SHOULD return
other servers.

    {
      "type": "Server",
      "id": "localhost",
      "url": "/api/v1/servers/localhost",
      "daemon_type": "recursor",
      "version": "VERSION",
      "config_url": "/api/v1/servers/localhost/config{/config_setting}",
      "zones_url": "/api/v1/servers/localhost/zones{/zone}",
    }

Note: On a pdns\_server or pdns\_recursor, the servers collection is read-only,
and the only allowed returned server is read-only as well.
On a pdnscontrol server, the servers collection is read-write, and the
returned server resources are read-write as well. Write permissions may
depend on the credentials you have supplied.

* daemon_type
  May be one of `authoritative`, `recursor`.


URL: /api/v1/servers
--------------------

Collection access.

Allowed REST methods:

* pdns\_server: `GET`
* pdns\_recursor: `GET`
* pdnsmgrd: `GET`
* pdnscontrol: `GET`, `PUT`, `POST`, `DELETE`


URL: /api/v1/servers/:server\_id
--------------------------------

Returns a single server_resource.



Config
======


config\_setting\_resource
-------------------------

    {
       "type": "ConfigSetting",
       "name": "config_setting_name",
       "value": "config_setting_value"
    }


URL: /api/v1/servers/:server\_id/config
---------------------------------------

Collection access.

Allowed REST methods: `GET`, `POST`

#### POST

Creates a new config setting. This is useful for creating configuration for new backends.

**TODO**: Not yet implemented.


URL: /api/v1/servers/:server\_id/config/:config\_setting\_name
--------------------------------------------------------------

Allowed REST methods: `GET`, `PUT`

**NOTE**: only the Recursors `allow_from` configuration setting can be retrieved or modified.


Zones
=====

Authoritative DNS Zones.

A Resource Record Set (below as "RRset") are all records for a given name and type.

Comments are per-RRset.


zone_collection
---------------

    {
      "id": "<id>",
      "name": "<string>",
      "type": "Zone",
      "url": "/api/v1/servers/:server_id/zones/:id",
      "kind": "<kind>",
      "serial": <int>,
      "notified_serial": <int>,
      "masters": ["<ip>", ...],
      "dnssec": <bool>,
      "nsec3param": "<nsec3param record>",
      "nsec3narrow": <bool>,
      "presigned": <bool>,
      "soa_edit": "<string>",
      "soa_edit_api": "<string>",
      "account": "<string>",
      "nameservers": ["<string>", ...],
      "servers": ["<string>", ...],
      "recursion_desired": <bool>,
      "rrsets": [<RRset>, ...],
    }


Where `RRset` is defined as:

    {
      "name": "<string>",
      "type": "<type>",
      "ttl": <int>,
      "records": [<Record>, ...],
      "comments": [<Comment>, ...]
    }


Where `Record` is defined as:

    {
      "content": "<string>",
      "disabled": <bool>
    }


Where `Comment` is defined as:

    {
      "content": "<string>",
      "account": "<string>",
      "modified_at": <int>
    }


##### Parameters:

* `id`
  Opaque zone id (string), assigned by the Server. Do not interpret.
  Guaranteed to be safe for embedding in URLs.

* `name`
  Zone name, always including the trailing dot. Example: `example.org.`
  Note: Before 4.0.0, zone names were taken/given without the trailing dot.

* `kind`
  Authoritative: `<kind>`: `Native`, `Master` or `Slave`
  Recursor: `<kind>`: `Native`, or `Forwarded`

* `dnssec`
  inferred from `presigned` being `true` XOR presence of at
  least one cryptokey with `active` being `true`.

  Switching `dnssec` to `true` (from `false`) sets up DNSSEC signing
  based on the other flags, this includes running the equivalent of
  `secure-zone` and `rectify-zone`. This also applies to newly created
  zones.
  If `presigned` is `true`, no DNSSEC changes will be made to the zone
  or cryptokeys.
  **Note**: Authoritative only.

  **TODO**: `dnssec`, `nsec3narrow`, `nsec3param`, `presigned` are not yet implemented.

* `soa_edit` MAY be set to change the `SOA-EDIT` zone setting. See
  [the `SOA-EDIT` documentation](../authoritative/domainmetadata.md#soa-edit)
  for more information.
  **Note**: Authoritative only.

* `soa_edit_api` MAY be set. If it is set, on changes to the contents of
  a zone made through the API, the SOA record will be edited according to
  the SOA-EDIT-API rules. (Which are the same as the SOA-EDIT-DNSUPDATE rules.)
  If not set during zone creation, a SOA-EDIT-API metadata record is created
  and set to `DEFAULT`. (If this record is removed from the backend, the
  default behaviour is to not do any SOA editing based on this setting. This
  is different from setting `DEFAULT`.)
  **Note**: Authoritative only.

* `account` MAY be set. Its value is defined by local policy.
  **Note**: Authoritative only.

* `notified_serial`, `serial` MUST NOT be sent in client bodies.
  **Note**: Authoritative only.

* `nameservers` MAY be sent in client bodies during creation, and MUST
  NOT be sent by the server. Simple list of strings of nameserver names,
  including the trailing dot. Note: Before 4.0.0, names were taken without
  the trailing dot.
  **Note**: Authoritative only. Not required for slave zones.

* `servers`: list of forwarded-to servers, including port.
  **Note**: Recursor only.

* `recursion_desired`: for `Forwarded` zones, if the RD bit should
  be set.
  **Note**: Authoritative only.

* `rrsets`: list of DNS records and comments in the zone.
  **Note**: Modifications are supported on Authoritative only.

Please see the description for `PATCH` for details on the fields in
`RRset`, `Record` and `Comment`.

##### Notes:

Turning on DNSSEC with custom keys: just create the zone with `dnssec`
set to `false`, and add keys using the cryptokeys REST interface. Have
at least one of them `active` set to `true`. **TODO**: not yet
implemented.

Changes made through the Zones API will always yield valid zone data,
and the zone will be properly "rectified" (**TODO**: not yet
implemented). If changes are made through other means (e.g. direct
database access), this is not guaranteed to be true and clients SHOULD
trigger rectify.

Backends might implement additional features (by coincidence or not).
These things are not supported through the API.

When creating a slave zone, it is recommended to not set any of
`nameservers`, `records`.


URL: /api/v1/servers/:server\_id/zones
--------------------------------------

Allowed REST methods: `GET`, `POST`

#### POST
Creates a new domain.

* `dnssec`, `nsec3narrow`, `presigned`, `nsec3param`, `active-keys` are OPTIONAL.
* `dnssec`, `nsec3narrow`, `presigned` default to `false`.
* The server MUST create a SOA record. The created SOA record SHOULD have
serial set to the value given as `serial` (or 0 if missing), use the
nameserver name, email, TTL values as specified in the PowerDNS configuration
(`default-soa-name`, `default-soa-mail`, etc).
These default values can be overridden by supplying a custom SOA record in
the records list.
If `soa_edit_api` is set, the SOA record is edited according to the SOA-EDIT-API
rules before storing it. (Also applies to custom SOA records.)

**TODO**: `dnssec`, `nsec3narrow`, `nsec3param`, `presigned` are not yet implemented.

URL: /api/v1/servers/:server\_id/zones/:zone\_id
------------------------------------------------

Allowed methods: `GET`, `PUT`, `DELETE`, `PATCH`.

#### GET
Returns zone information.

#### DELETE
Deletes this zone, all attached metadata and rrsets.

#### PATCH

Modifies present RRsets and comments.
Returns `204 No Content` on success.

**Note**: Authoritative only.

Client body for PATCH:

    { "rrsets":
      [
        {
          "name": <string>,
          "type": <string>,
          "ttl": <int>,
          "changetype": <changetype>,
          "records":
            [
              {
                "content": <string>,
                "disabled": <bool>,
                "set-ptr": <bool>
              }, ...
            ],
          "comments":
            [
              {
                "account": <string>,
                "content": <string>,
                "modified_at": <int>
              }, ...
            ]
        },
        { ... }
      ]
    }


* `name`
  Full name of the RRset to modify. (Example: `foo.example.org.`)

* `type`
  Type of the RRset to modify. (Example: `AAAA`)

* `ttl`
  DNS TTL to apply to records replaced, in seconds. MUST NOT be included when `changetype` is set to `DELETE`.

* `changetype`
  Must be `REPLACE` or `DELETE`.
  With `DELETE`, all existing RRs matching `name` and `type` will be deleted, including all comments.
  With `REPLACE`: when `records` is present, all existing RRs matching `name` and `type` will be deleted, and then new records given in `records` will be created.
  If no records are left, any existing comments will be deleted as well.
  When `comments` is present, all existing comments for the RRs matching `name` and `type` will be deleted, and then new comments given in `comments` will be created.

* `records`
  List of new records (replacing the old ones). Must be empty when `changetype` is set to `DELETE`.
  An empty list results in deletion of all records (and comments).
  A record consists of these fields:
  * `content`: the record content. Must confirm to the DNS content rules for the specified `type`. (PowerDNS hint: includes the backend's `priority` field.)
  * `disabled`: if this record will be hidden from DNS. (true: hidden, false: visible (the default)).
  * `set-ptr`: If set to true, the server will find the matching reverse zone and create a `PTR` there. Existing `PTR` records are replaced. If no matching reverse Zone, an error is thrown. Only valid in client bodies, only valid for `A` and `AAAA` types. Not returned by the server. Only valid for the Authoritative server.

* `comments`
  List of new comments (replacing the old ones). Must be empty when `changetype` is set to `DELETE`.
  An empty list results in deletion of all comments.
  `modified_at` is optional and defaults to the current server time.
  `account` is a field with user-defined meaning.

#### PUT

Modifies basic zone data (metadata).

Allowed fields in client body: all except `id` and `url`.
Returns `204 No Content` on success.

Changing `name` renames the zone, as expected.


URL: /api/v1/servers/:server\_id/zones/:zone\_id/notify
-------------------------------------------------------

Allowed methods: `PUT`

Send a DNS NOTIFY to all slaves.

Fails when zone kind is not `Master` or `Slave`, or `master` and `slave` are
disabled in pdns configuration. Only works for `Slave` if renotify is on.

Not supported for recursors.

Clients MUST NOT send a body.


URL: /api/v1/servers/:server\_id/zones/:zone\_id/axfr-retrieve
--------------------------------------------------------------

Allowed methods: `PUT`

Retrieves the zone from the master.

Fails when zone kind is not `Slave`, or `slave` is disabled in PowerDNS.
configuration.

Not supported for recursors.

**Note**: Added in 3.4.2


URL: /api/v1/servers/:server\_id/zones/:zone\_id/export
-------------------------------------------------------

Allowed methods: `GET`

Returns the zone in AXFR format.

Not supported for recursors.


URL: /api/v1/servers/:server\_id/zones/:zone\_id/check
------------------------------------------------------

Allowed methods: `GET`

Verify zone contents/configuration.

Return format:

    {
      "zone": "<zone_name>",
      "errors": ["error message1", ...],
      "warnings": ["warning message1", ...]
    }

**TODO**: Not yet implemented.

Zone Metadata
=============

zone\_metadata\_resource
------------------------

    {
      "type": "Metadata",
      "kind": <metadata_kind>,
      "metadata": [
        "value1",
        ...
      ]
    }

##### Parameters:

`kind`: valid values for `<metadata_kind>` are specified in
[the `domainmetadata` documentation](../authoritative/domainmetadata.md).

`metadata`: an array with all values for this metadata kind.

Clients MUST NOT modify `NSEC3PARAM`, `NSEC3NARROW`, `PRESIGNED` and
`LUA-AXFR-SCRIPT` through this interface. The server rejects updates to
these metadata. Modifications to custom metadata kinds are rejected
through this interface.


URL: /api/v1/servers/:server\_id/zones/:zone\_name/metadata
-----------------------------------------------------------

Collection access.

Allowed methods: `GET`, `POST`

#### GET

Returns all metadata entries for the zone.


#### POST

Creates a set of metadata entries of given kind for the zone.

* existing metadata entries for the zone with the same kind are not overwritten.


URL: /api/v1/servers/:server\_id/zones/:zone\_name/metadata/:metadata\_kind
---------------------------------------------------------------------------

Allowed methods: `GET`, `PUT`, `DELETE`

#### GET

Returns all metadata entries of a given kind for the zone.


#### DELETE

Deletes all metadata entries of a given kind for the zone.


#### PUT

Modifies the metadata entries of a given kind for the zone.

This returns `200 OK` on success.


Cryptokeys
==========

cryptokey\_resource
-------------------

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


##### Parameters:

`id`: read-only.

`keytype`: `<keytype>` is one of the following: `ksk`, `zsk`, `csk`.

`dnskey`: the DNSKEY for this key

`ds`: an array with all DSes for this key

`privatekey`: private key data (in ISC format).


URL: /api/v1/servers/:server\_id/zones/:zone\_name/cryptokeys
-------------------------------------------------------------

Allowed methods: `GET`, `POST`

#### GET

Returns all public data about cryptokeys, but not `privatekey`.

#### POST

This method adds a new key to a zone. The key can either be generated or imported by supplying the content parameter.

##### Parameters:

* `content` : "\<key\>" `<string>` (The format used is compatible with BIND and NSD/LDNS)
* `keytype` : "ksk|zsk" `<string>`
* `active`: "true|false" `<value>` (If not set the key will not be active by default)

If `content` == `null`, the server generates a new key. In this case, the
following additional fields MAY be supplied:

* `bits`: number of bits `<int>`
* `algo`: `<algo>` (Default: 13/ECDSA)

Where `<algo>` is one of the supported key algorithms in lowercase OR the
numeric id, see [`the list`](../authoritative/dnssec.md#supported-algorithms).

##### Response:
* `422 Unprocessable Entity`:
    * keytype is not ksk|zsk:
        * `{"error" : "Invalid keytype 'keytype'"}`
    * The "algo" is not supported:
        * `{"error" : "Unknown algorithm: 'algo'"}`
    * Algo <= 10 and the `bits` parameter is not set:
        * `{"error" : "Creating an algorithm 'algo' key requires the size (in bits) to be passed."}`
    * The provided bit size is not supported by the selected algorithm:
        * `{"error" : "The algorithm does not support the given bit size."}`
    * The `bits` parameter is not a positive integer value:
        * `{"error" : "'bits' must be a positive integer value"}`
    * If the server can not guess the key size:
        * `{"error" : "Can not guess key size for algorithm"}`
    * The key-creation failed:
        * `{"error" : "Adding key failed, perhaps DNSSEC not enabled in configuration?"}`
    * The key in `content` has the wrong format:
        * `{"error" : "Key could not be parsed. Make sure your key format is correct."}`
* `201 Created`:
    * Everything was fine:
        * Returns all public data about the new cryptokey. Look at cryptokey\_resource.

URL: /api/v1/servers/:server\_id/zones/:zone\_name/cryptokeys/:cryptokey\_id
----------------------------------------------------------------------------

Allowed methods: `GET`, `PUT`, `DELETE`

#### GET

Returns all public data about cryptokeys, including `privatekey`.

#### PUT

This method de/activates a key from `zone_name` specified by `cryptokey_id`.

##### Parameters:

* `active`: "true|false" `<value>`

##### Responses:
* `204 No Content`: The key with `cryptokey_id` is de/activated.
* `422 Unprocessable Entity`:
    &nbsp;&nbsp;The backend returns false on de/activation. An error occurred.
    &nbsp;&nbsp;`{"error": "Could not de/activate Key: :cryptokey_id in Zone: :zone_name"}`

#### DELETE

This method deletes a key from `zone_name` specified by `cryptokey_id`.

##### Responses:

* `200 OK`: The Key is gone.
* `422 Unprocessable Entity`:
    &nbsp;&nbsp;The backend failed to remove the key.
    &nbsp;&nbsp;`{"error": Could not DELETE :cryptokey_id"}`

Data searching
==============

URL: /api/v1/servers/localhost/search-data?q=:search\_term&max=:max\_results
---------------------------------------------------------------------------

**Note**: Authoritative only.

Allowed methods: `GET`

#### GET

Search the data inside PowerDNS for :search\_term and return at most
:max\_results. This includes zones, records and comments.
The `*` character can be used in :search\_term as a wildcard character and the `?` character can be used as a wildcard for a single character.

Response body is an array of one or more of the following objects:

For a zone:

    {
      "name": "<zonename>",
      "object_type": "zone",
      "zone_id": "<zoneid>"
    }

For a record:

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

    {
      "object_type": "comment",
      "name": "<name>",
      "content": "<content>"
      "zone": "<zonename>,
      "zone_id": "<zoneid>"
    }

Cache Access
============

**TODO**: Not yet implemented: Peek at the cache, clear the cache, possibly read cache?

URL: /api/v1/servers/:server\_id/cache/flush?domain=:domain
--------------------------------------------

Allowed methods: `PUT` (Execute)

#### PUT (Execute)

Flush the cache for a given domain name `:domain`. Response body:

    {
      "count": 10,
      "result": "Flushed cache."
    }

Implementation detail: On Authoritative servers, this clears the packet cache.
On Recursors, this clears the positive, negative and packet cache.


Logging & Statistics
====================

URL: /api/v1/servers/:server\_id/search-log?q=:search\_term
-----------------------------------------------------------

Allowed methods: `GET` (Query)

#### GET (Query)

Query the log, filtered by `:search_term` (query parameter). Response body:

    [
      "<log_line>",
      ...
    ]

URL: /api/v1/servers/:server\_id/statistics
-------------------------------------------

Allowed methods: `GET` (Query)

#### GET (Query)

Query PowerDNS internal statistics. Response body:

    [
      {
        "type": "StatisticItem",
        "name": "<name>",
        "value": "<value>"
      },
      ...
    ]

The statistic entries are dependent on the daemon type.
Values are returned as strings.


URL: /api/v1/servers/:server\_id/trace
--------------------------------------

**TODO**: Not yet implemented.

#### PUT (Configure)

Configure query tracing.

Client body:

    {
      "domains": "<regex_string>"
    }

Set `domains` to `null` to turn off tracing.

#### GET (Query)

Retrieve query tracing log and current config. Response body:

    {
      "domains": "<Regex>",
      log: [
        "<log_line>",
        ...
      ]
    }


URL: /api/v1/servers/:server\_id/failures
-----------------------------------------

**TODO**: Not yet implemented.

#### PUT

Configure query failure logging.

Client body:

    {
      "top-domains": <int>,
      "domains": "<Regex>",
    }

##### Parameters:

`top-domains` are the number of top resolved domains that are
automatically monitored for failures.

`domains` is a Regex of domains that are additionally monitored for
resolve failures.


#### GET

Retrieve query failure logging and current config.

Response body:

    {
      "top-domains": <int>,
      "domains": "<Regex>",
      "log": [
        {
          "first_occurred": <timestamp>,
          "domain": "<full domain>",
          "qtype": "<qtype>",
          "failure": <failure_code>,
          "failed_parent": "<full parent domain>",
          "details": "<log message>",
          "queried_servers": [
             {
               "name": <name>,
               "address": <address>
             }, ...
          ]
        },
        ...
      ]
    }

##### Parameters:

`failed_parent` is generally OPTIONAL.

Where `<failure_code>` is one of these:

  + `dnssec-validation-failed`

    DNSSEC Validation failed for this domain.

  + `dnssec-parent-validation-failed`

    DNSSEC Validation failed for one of the parent domains. Response
    MUST contain failed\_parent.

  + `nxdomain`

    This domain was not present on the authoritative nameservers.

  + `nodata`
  + `all-servers-unreachable`

    All auth nameservers that have been tried did not respond.

  + `parent-unresolvable`

    Response MUST contain `failed_parent`.

  + `refused`

    All auth nameservers that have been tried responded with REFUSED.

  + `servfail`

    All auth nameservers that have been tried responded with SERVFAIL.

  + **TODO**: further failures

Data Overrides
==============

**TODO**: Not yet implemented.

override\_type
--------------

`created` is filled by the Server.


    {
      "type": "Override",
      "id": <int>,
      "override": "ignore-dnssec",
      "domain": "nl",
      "until": <timestamp>,
      "created": <timestamp>
    }


    {
      "type": "Override",
      "id": <int>,
      "override": "replace",
      "domain": "www.cnn.com.",
      "rrtype": "AAAA",
      "values": ["203.0.113.4", "203.0.113..2"],
      "until": <timestamp>,
      "created": <timestamp>
    }

**TODO**: what about validation here?

    {
      "type": "Override",
      "id": <int>,
      "override": "purge",
      "domain": "example.net.",
      "created": <timestamp>
    }

Clears recursively all cached data ("plain" DNS + DNSSEC)

**TODO**: should this be stored? (for history)

URL: /api/v1/servers/:server\_id/overrides
------------------------------------------

**TODO**: Not yet implemented.

Collection access.

Allowed Methods: `GET`, `POST`

URL: /api/v1/servers/:server\_id/overrides/:override\_id
--------------------------------------------------------

**TODO**: Not yet implemented.

Allowed methods: `GET`, `PUT`, `DELETE`
