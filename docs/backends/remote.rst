Remote Backend
==============

* Native: Yes
* Master: Yes\*
* Slave: Yes\*
* Superslave: Yes\*
* Autoserial: Yes\*
* DNSSEC: Yes\*
* Multiple instances: Yes

\* If provided by the responder (your script).

This backend provides Unix socket, Pipe, HTTP and ZeroMQ remoting for
powerdns. You should think this as normal RPC thin client, which
converts native C++ calls into JSON/RPC and passes them to you via
connector.

Important notices
-----------------

Please do not use remotebackend shipped before version 3.3. This version
has severe bug that can crash the entire process.

There is a breaking change on v4.0 and later. Before version 4.0, the
DNS names passed in queries were without trailing dot, after version 4.0
the DNS names are sent with trailing dot. F.ex. example.org is now sent
as example.org.

In some (broken) network setups, the IP addresses provided in the
request (when this is an IPv6 address) may be suffixed with a ``%`` and
the name of the network interface (e.g. ``%eth1``). Keep this in mind
when checking the IP addresses.

Compiling
---------

To compile this backend, you need to configure
``--with-modules="remote"``.

For versions prior to 3.4.0, if you want to use http connector, you need
libcurl and use ``--enable-remotebackend-http``.

If you want to use ZeroMQ connector, you need libzmq-dev or libzmq3-dev
and use ``--enable-remotebackend-zeromq``.

Usage
-----

The only configuration options for backend are remote-connection-string
and remote-dnssec.

.. code-block:: ini

    remote-connection-string=<type>:<param>=<value>,<param>=<value>...

You can pass as many parameters as you want. For unix and pipe
connectors, these are passed along to the remote end as initialization.
See :ref:`remote-api`. Initialize is not called for http connector.

Unix connector
^^^^^^^^^^^^^^

parameters: path, timeout (default 2000ms)

.. code-block:: ini

    remote-connection-string=unix:path=/path/to/socket

Pipe connector
^^^^^^^^^^^^^^

parameters: command,timeout (default 2000ms)

.. code-block:: ini

    remote-connection-string=pipe:command=/path/to/executable,timeout=2000

HTTP connector
^^^^^^^^^^^^^^

parameters: url, url-suffix, post, post_json, timeout (default 2000ms)

.. code-block:: ini

    remote-connection-string=http:url=http://localhost:63636/dns,url-suffix=.php

HTTP connector tries to do RESTful requests to your server. See
examples. You can also use post to change behaviour so that it will send
POST request to url/method + url_suffix with
parameters=json-formatted-parameters. If you use post and post_json, it
will POST url with text/javascript containing JSON formatted RPC
request, just like for pipe and unix. You can use '1', 'yes', 'on' or
'true' to turn these features on.

URL should not end with /, and url-suffix is optional, but if you define
it, it's up to you to write the ".php" or ".json". Lack of dot causes
lack of dot in URL. Timeout is divided by 1000 because libcurl only
supports seconds, but this is given in milliseconds for consistency with
other connectors.

HTTPS is not supported, `stunnel <https://www.stunnel.org>`__ is the
suggested workaround. HTTP Authentication is not supported.

ZeroMQ connector
^^^^^^^^^^^^^^^^

parameters: endpoint, timeout (default 2000ms)

.. code-block:: ini

    remote-connection-string=zeromq:endpoint=ipc:///tmp/tmp.sock

0MQ connector implements a REQ/REP RPC model. Please see
http://zeromq.org/ for more information.

.. _remote-api:

API
---

Queries
^^^^^^^

Unix, Pipe and ZeroMQ connectors send JSON formatted strings to the
remote end. Each JSON query has two sections, 'method' and 'parameters'.

HTTP connector calls methods based on URL and has parameters in the
query string. Most calls are GET; see the methods listing for details.
You can change this with post and post_json attributes.

Replies
^^^^^^^

You **must** always reply with JSON hash with at least one key,
'result'. This must be boolean false if the query failed. Otherwise it
must conform to the expected result. For HTTP connector, to signal bare
success, you can just reply with HTTP 200 OK, and omit any output. This
will result in same outcome as sending {"result":true}.

You can optionally add an array of strings to the 'log' array; each line
in this array will be logged in PowerDNS at loglevel ``info`` (6).

Methods
^^^^^^^

``initialize``
~~~~~~~~~~~~~~

Called to initialize the backend. This is not called for HTTP connector.
You should do your initializations here.

-  Mandatory: Yes (except HTTP connector)
-  Parameters: all parameters in connection string
-  Reply: true on success / false on failure

Example JSON/RPC
~~~~~~~~~~~~~~~~

Query:

.. code-block:: json

    {"method":"initialize", "parameters":{"command":"/path/to/something", "timeout":"2000", "something":"else"}}

Response:

.. code-block:: json

    {"result":true}

.. _remote-lookup:

``lookup``
~~~~~~~~~~

This method is used to do the basic query. You can omit auth, but if you
are using DNSSEC this can lead into trouble.

-  Mandatory: Yes
-  Parameters: qtype, qname, zone_id
-  Optional parameters: remote, local, real-remote
-  Reply: array of ``qtype,qname,content,ttl,domain_id,scopeMask,auth``
-  Optional values: domain_id, scopeMask and auth
-  Note: priority field is required before 4.0, after 4.0 priority is
   added to content. This applies to any resource record which uses
   priority, for example SRV or MX.

Example JSON/RPC
''''''''''''''''

Query:

.. code-block:: json

    {"method":"lookup", "parameters":{"qtype":"ANY", "qname":"www.example.com.", "remote":"192.0.2.24", "local":"192.0.2.1", "real-remote":"192.0.2.24", "zone-id":-1}}

Response:

.. code-block:: json

    {"result":[{"qtype":"A", "qname":"www.example.com", "content":"203.0.113.2", "ttl": 60}]}

Example HTTP/RPC
''''''''''''''''

Query:

.. code-block:: http

    GET /dnsapi/lookup/www.example.com./ANY HTTP/1.1
    X-RemoteBackend-remote: 192.0.2.24
    X-RemoteBackend-local: 192.0.2.1
    X-RemoteBackend-real-remote: 192.0.2.24
    X-RemoteBackend-zone-id: -1

Response:

.. code-block:: http

    HTTP/1.1 200 OK
    Content-Type: text/javascript; charset=utf-8

    {"result":[{"qtype":"A", "qname":"www.example.com", "content":"203.0.113.2", "ttl": 60}]}

``list``
~~~~~~~~

Lists all records for the zonename. If you are running dnssec, you
should take care of setting auth to appropriate value, otherwise things
can go wrong.

-  Mandatory: No (Gives AXFR support)
-  Parameters: zonename, domain_id
-  Optional parameters: domain_id
-  Reply: array of ``qtype,qname,content,ttl,domain_id,scopeMask,auth``
-  Optional values: domain_id, scopeMask and auth

Example JSON/RPC
''''''''''''''''

Query:

.. code-block:: json

    {"method":"list", "parameters":{"zonename":"example.com.","domain_id":-1}}

Response (split into lines for ease of reading)

.. code-block:: json

    {"result":[
      {"qtype":"SOA", "qname":"example.com", "content":"dns1.icann.org. hostmaster.icann.org. 2012081600 7200 3600 1209600 3600", "ttl": 3600},
      {"qtype":"NS", "qname":"example.com", "content":"ns1.example.com", "ttl": 60},
      {"qtype":"MX", "qname":"example.com", "content":"10 mx1.example.com.", "ttl": 60},
      {"qtype":"A", "qname":"www.example.com", "content":"203.0.113.2", "ttl": 60},
      {"qtype":"A", "qname":"ns1.example.com", "content":"192.0.2.2", "ttl": 60},
      {"qtype":"A", "qname":"mx1.example.com", "content":"192.0.2.3", "ttl": 60} 
    ]}

Example HTTP/RPC
''''''''''''''''

Query:

.. code-block:: http

    GET /dnsapi/list/-1/example.com HTTP/1.1
    X-RemoteBackend-domain-id: -1

Response:

.. code-block:: http

    HTTP/1.1 200 OK
    Content-Type: text/javascript; charset=utf-8

    {"result":[{"qtype":"SOA", "qname":"example.com", "content":"dns1.icann.org. hostmaster.icann.org. 2012081600 7200 3600 1209600 3600", "ttl": 3600},{"qtype":"NS", "qname":"example.com", "content":"ns1.example.com", "ttl": 60},{"qtype":"MX", "qname":"example.com", "content":"10 mx1.example.com.", "ttl": 60},{"qtype":"A", "qname":"www.example.com", "content":"203.0.113.2", "ttl": 60},{"qtype":"A", "qname":"ns1.example.com", "content":"192.0.2.2", "ttl": 60},{"qtype":"A", "qname":"mx1.example.com", "content":"192.0.2.3", "ttl": 60}]}

``getBeforeAndAfterNamesAbsolute``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Asks the names before and after qname. qname is given without dots or
domain part. The query will be hashed when using NSEC3. Care must be
taken to handle wrap-around when qname is first or last in the ordered
list. Do not return nil for either one.

-  Mandatory: for NSEC/NSEC3 non-narrow
-  Parameters: id, qname
-  Reply: before, after

Example JSON/RPC
''''''''''''''''

Query:

.. code-block:: json

    {"method":"getbeforeandafternamesabsolute", "params":{"id":0,"qname":"www.example.com"}}

Response:

.. code-block:: json

    {"result":{"before":"ns1","after":""}}

Example HTTP/RPC
''''''''''''''''

Query:

::

    /dnsapi/getbeforeandafternamesabsolute/0/www.example.com

Response:

.. code-block:: json

    {"result":{"before":"ns1","after":""}}

``getAllDomainMetadata``
~~~~~~~~~~~~~~~~~~~~~~~~

Returns the value(s) for variable kind for zone name. You **must**
always return something, if there are no values, you shall return empty
set or false.

*  Mandatory: No
*  Parameters: name
*  Reply: hash of key to array of strings

Example JSON/RPC
''''''''''''''''

Query:

.. code-block:: json

    {"method":"getalldomainmetadata", "parameters":{"name":"example.com"}}

Response:

.. code-block:: json

    {"result":{"PRESIGNED":["0"]}}

Example HTTP/RPC
''''''''''''''''

Query:

.. code-block:: http

    GET /dnsapi/getalldomainmetadata/example.com HTTP/1.1

Response:

.. code-block:: http

    HTTP/1.1 200 OK
    Content-Type: text/javascript; charset=utf-8

    {"result":{"PRESIGNED":["0"]}}

``getDomainMetadata``
~~~~~~~~~~~~~~~~~~~~~

Returns the value(s) for variable kind for zone name. Most commonly it's
one of NSEC3PARAM, PRESIGNED, SOA-EDIT. Can be others, too. You **must**
always return something, if there are no values, you shall return empty
array or false.

-  Mandatory: No
-  Parameters: name, kind
-  Reply: array of strings

Example JSON/RPC
''''''''''''''''

Query:

.. code-block:: json

    {"method":"getdomainmetadata", "parameters":{"name":"example.com.","kind":"PRESIGNED"}}

Response:

.. code-block:: json

    {"result":["0"]}

Example HTTP/RPC
''''''''''''''''

Query:

.. code-block:: http

    GET /dnsapi/getdomainmetadata/example.com./PRESIGNED HTTP/1.1

Response:

.. code-block:: http

    HTTP/1.1 200 OK
    Content-Type: text/javascript; charset=utf-8

    {"result":["0"]}

``setDomainMetadata``
~~~~~~~~~~~~~~~~~~~~~

Replaces the value(s) on domain name for variable kind to string(s) on
array value. The old value is discarded. Value can be an empty array,
which can be interpreted as deletion request.

-  Mandatory: No
-  Parameters: name, kind, value
-  Reply: true on success, false on failure

Example JSON/RPC
''''''''''''''''

Query:

.. code-block:: json

    {"method":"setdomainmetadata","parameters":{"name":"example.com","kind":"PRESIGNED","value":["YES"]}}

Response:

.. code-block:: json

    {"result":true}

Example HTTP/RPC
''''''''''''''''

Query:

.. code-block:: http

    PATCH /dnsapi/setdomainmetadata/example.com/PRESIGNED HTTP/1.1
    Content-Type: application/x-www-form-urlencoded 
    Content-Length: 12

    value[]=YES&

Response:

.. code-block:: http

    HTTP/1.1 200 OK
    Content-Type: text/javascript; charset=utf-8

    {"result":true}

.. _remote-getdomainkeys:

``getDomainKeys``
~~~~~~~~~~~~~~~~~

Retrieves any keys of kind. The id, flags are unsigned integers, and
active is boolean. Content must be valid key record in format that
PowerDNS understands. You are encouraged to implement :ref:`the section
called "addDomainKey" <remote-adddomainkey>`, as you can use
:doc:`../manpages/pdnsutil.1` to provision keys.

-  Mandatory: for DNSSEC
-  Parameters: name, kind
-  Reply: array of ``id, flags, active, content``

Example JSON/RPC
''''''''''''''''

Query:

.. code-block:: json

    {"method":"getdomainkeys","parameters":{"name":"example.com."}}

Response:

.. code-block:: json

    {"result":[{"id":1,"flags":256,"active":true,"content":"Private-key-format: v1.2
    Algorithm: 8 (RSASHA256)
    Modulus: r+vmQll38ndQqNSCx9eqRBUbSOLcH4PZFX824sGhY2NSQChqt1G4ZfndzRwgjXMUwiE7GkkqU2Vbt/g4iP67V/+MYecMV9YHkCRnEzb47nBXvs9JCf8AHMCnma567GQjPECh4HevPE9wmcOfpy/u7UN1oHKSKRWuZJadUwcjbp8=
    PublicExponent: AQAB
    PrivateExponent: CYC93UtVnOM6wrFJZ+qA9+Yx+p5yk0CSi0Q7c+/6EVMuABQ5gNyTuu0j65lU3X81bwUk2wHPx6smfgoVDRAW5jjO4jgIFV6nE4inzk5YQKycQSL8YG3Nm9GciLFya1KUXs81sHsQpkvK7MNaSbvkaHZQ6iv16bZ4t73Wascwa/E=
    Prime1: 6a165cIC0nNsGlTW/s2jRu7idq5+U203iE1HzSIddmWgx5KIKE/s3I+pwfmXYRUmq+4H9ASd/Yot1lSYW98szw==
    Prime2: wLoCPKxxnuxDx6/9IKOYz8t9ZNLY74iCeQ85koqvTctkFmB9jpOUHTU9BhecaFY2euP9CuHV7z3PLtCoO8s1MQ==
    Exponent1: CuzJaiR/7UboLvL4ekEy+QYCIHpX/Z6FkiHK0ZRevEJUGgCHzRqvgEBXN3Jr2WYbwL4IMShmGoxzSCn8VY9BkQ==
    Exponent2: LDR9/tyu0vzuLwc20B22FzNdd5rFF2wAQTQ0yF/3Baj5NAi9w84l0u07KgKQZX4g0N8qUyypnU5YDyzc6ZoagQ==
    Coefficient: 6S0vhIQITWzqfQSLj+wwRzs6qCvJckHb1+SD1XpwYjSgMTEUlZhf96m8WiaE1/fIt4Zl2PC3fF7YIBoFLln22w=="}]}

Example HTTP/RPC
''''''''''''''''

Query:

.. code-block:: http

    GET /dnsapi/getdomainkeys/example.com/0 HTTP/1.1

Response:

.. code-block:: http

    HTTP/1.1 200 OK
    Content-Type: text/javascript; charset=utf-8

    {"result":[{"id":1,"flags":256,"active":true,"content":"Private-key-format: v1.2
    Algorithm: 8 (RSASHA256)
    Modulus: r+vmQll38ndQqNSCx9eqRBUbSOLcH4PZFX824sGhY2NSQChqt1G4ZfndzRwgjXMUwiE7GkkqU2Vbt/g4iP67V/+MYecMV9YHkCRnEzb47nBXvs9JCf8AHMCnma567GQjPECh4HevPE9wmcOfpy/u7UN1oHKSKRWuZJadUwcjbp8=
    PublicExponent: AQAB
    PrivateExponent: CYC93UtVnOM6wrFJZ+qA9+Yx+p5yk0CSi0Q7c+/6EVMuABQ5gNyTuu0j65lU3X81bwUk2wHPx6smfgoVDRAW5jjO4jgIFV6nE4inzk5YQKycQSL8YG3Nm9GciLFya1KUXs81sHsQpkvK7MNaSbvkaHZQ6iv16bZ4t73Wascwa/E=
    Prime1: 6a165cIC0nNsGlTW/s2jRu7idq5+U203iE1HzSIddmWgx5KIKE/s3I+pwfmXYRUmq+4H9ASd/Yot1lSYW98szw==
    Prime2: wLoCPKxxnuxDx6/9IKOYz8t9ZNLY74iCeQ85koqvTctkFmB9jpOUHTU9BhecaFY2euP9CuHV7z3PLtCoO8s1MQ==
    Exponent1: CuzJaiR/7UboLvL4ekEy+QYCIHpX/Z6FkiHK0ZRevEJUGgCHzRqvgEBXN3Jr2WYbwL4IMShmGoxzSCn8VY9BkQ==
    Exponent2: LDR9/tyu0vzuLwc20B22FzNdd5rFF2wAQTQ0yF/3Baj5NAi9w84l0u07KgKQZX4g0N8qUyypnU5YDyzc6ZoagQ==
    Coefficient: 6S0vhIQITWzqfQSLj+wwRzs6qCvJckHb1+SD1XpwYjSgMTEUlZhf96m8WiaE1/fIt4Zl2PC3fF7YIBoFLln22w=="}]}

.. _remote-adddomainkey:

``addDomainKey``
~~~~~~~~~~~~~~~~

Adds key into local storage. See :ref:`remote-getdomainkeys` for more information.

-  Mandatory: No
-  Parameters: name, key=\ ``<flags,active,content>``, id
-  Reply: true for success, false for failure

Example JSON/RPC
''''''''''''''''

Query:

.. code-block:: json

    {"method":"adddomainkey", "parameters":{"key":{"id":1,"flags":256,"active":true,"content":"Private-key-format: v1.2
    Algorithm: 8 (RSASHA256)
    Modulus: r+vmQll38ndQqNSCx9eqRBUbSOLcH4PZFX824sGhY2NSQChqt1G4ZfndzRwgjXMUwiE7GkkqU2Vbt/g4iP67V/+MYecMV9YHkCRnEzb47nBXvs9JCf8AHMCnma567GQjPECh4HevPE9wmcOfpy/u7UN1oHKSKRWuZJadUwcjbp8=
    PublicExponent: AQAB
    PrivateExponent: CYC93UtVnOM6wrFJZ+qA9+Yx+p5yk0CSi0Q7c+/6EVMuABQ5gNyTuu0j65lU3X81bwUk2wHPx6smfgoVDRAW5jjO4jgIFV6nE4inzk5YQKycQSL8YG3Nm9GciLFya1KUXs81sHsQpkvK7MNaSbvkaHZQ6iv16bZ4t73Wascwa/E=
    Prime1: 6a165cIC0nNsGlTW/s2jRu7idq5+U203iE1HzSIddmWgx5KIKE/s3I+pwfmXYRUmq+4H9ASd/Yot1lSYW98szw==
    Prime2: wLoCPKxxnuxDx6/9IKOYz8t9ZNLY74iCeQ85koqvTctkFmB9jpOUHTU9BhecaFY2euP9CuHV7z3PLtCoO8s1MQ==
    Exponent1: CuzJaiR/7UboLvL4ekEy+QYCIHpX/Z6FkiHK0ZRevEJUGgCHzRqvgEBXN3Jr2WYbwL4IMShmGoxzSCn8VY9BkQ==
    Exponent2: LDR9/tyu0vzuLwc20B22FzNdd5rFF2wAQTQ0yF/3Baj5NAi9w84l0u07KgKQZX4g0N8qUyypnU5YDyzc6ZoagQ==
    Coefficient: 6S0vhIQITWzqfQSLj+wwRzs6qCvJckHb1+SD1XpwYjSgMTEUlZhf96m8WiaE1/fIt4Zl2PC3fF7YIBoFLln22w=="}}}

Response:

.. code-block:: json

    {"result":true}

Example HTTP/RPC
''''''''''''''''

Query:

.. code-block:: http

    PUT /dnsapi/adddomainkey/example.com HTTP/1.1
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 965

    flags=256&active=1&content=Private-key-format: v1.2
    Algorithm: 8 (RSASHA256)
    Modulus: r+vmQll38ndQqNSCx9eqRBUbSOLcH4PZFX824sGhY2NSQChqt1G4ZfndzRwgjXMUwiE7GkkqU2Vbt/g4iP67V/+MYecMV9YHkCRnEzb47nBXvs9JCf8AHMCnma567GQjPECh4HevPE9wmcOfpy/u7UN1oHKSKRWuZJadUwcjbp8=
    PublicExponent: AQAB
    PrivateExponent: CYC93UtVnOM6wrFJZ+qA9+Yx+p5yk0CSi0Q7c+/6EVMuABQ5gNyTuu0j65lU3X81bwUk2wHPx6smfgoVDRAW5jjO4jgIFV6nE4inzk5YQKycQSL8YG3Nm9GciLFya1KUXs81sHsQpkvK7MNaSbvkaHZQ6iv16bZ4t73Wascwa/E=
    Prime1: 6a165cIC0nNsGlTW/s2jRu7idq5+U203iE1HzSIddmWgx5KIKE/s3I+pwfmXYRUmq+4H9ASd/Yot1lSYW98szw==
    Prime2: wLoCPKxxnuxDx6/9IKOYz8t9ZNLY74iCeQ85koqvTctkFmB9jpOUHTU9BhecaFY2euP9CuHV7z3PLtCoO8s1MQ==
    Exponent1: CuzJaiR/7UboLvL4ekEy+QYCIHpX/Z6FkiHK0ZRevEJUGgCHzRqvgEBXN3Jr2WYbwL4IMShmGoxzSCn8VY9BkQ==
    Exponent2: LDR9/tyu0vzuLwc20B22FzNdd5rFF2wAQTQ0yF/3Baj5NAi9w84l0u07KgKQZX4g0N8qUyypnU5YDyzc6ZoagQ==
    Coefficient: 6S0vhIQITWzqfQSLj+wwRzs6qCvJckHb1+SD1XpwYjSgMTEUlZhf96m8WiaE1/fIt4Zl2PC3fF7YIBoFLln22w==

Response:

.. code-block:: http

    HTTP/1.1 200 OK
    Content-Type: text/javascript; charset=utf-8

    {"result":true}

``removeDomainKey``
~~~~~~~~~~~~~~~~~~~

Removes key id from domain name.

-  Mandatory: No
-  Parameters: name, id
-  Reply: true for success, false for failure

Example JSON/RPC
''''''''''''''''

Query:

.. code-block:: json

    {"method":"removedomainkey","parameters":{"name":"example.com","id":1}}

Response:

.. code-block:: json

    {"result":true}

Example HTTP/RPC
''''''''''''''''

Query:

.. code-block:: http

    DELETE /dnsapi/removedomainkey/example.com/1 HTTP/1.1

Response:

.. code-block:: http

    HTTP/1.1 200 OK
    Content-Type: text/javascript; charset=utf-8

    {"result":true}

``activateDomainKey``
~~~~~~~~~~~~~~~~~~~~~

Activates key id for domain name.

-  Mandatory: No
-  Parameters: name, id
-  Reply: true for success, false for failure

Example JSON/RPC
''''''''''''''''

Query:

.. code-block:: json

    {"method":"activatedomainkey","parameters":{"name":"example.com","id":1}}

Response:

.. code-block:: json

    {"result":true}

Example HTTP/RPC
''''''''''''''''

Query:

.. code-block:: http

    POST /dnsapi/activatedomainkey/example.com/1 HTTP/1.1

Response:

.. code-block:: http

    HTTP/1.1 200 OK
    Content-Type: text/javascript; utf-8

    {"result": true}

``deactivateDomainKey``
~~~~~~~~~~~~~~~~~~~~~~~

Deactivates key id for domain name.

-  Mandatory: No
-  Parameters: name, id
-  Reply: true for success, false for failure

Example JSON/RPC
''''''''''''''''

Query:

.. code-block:: json

    {"method":"deactivatedomainkey","parameters":{"name":"example.com","id":1}}

Response:

.. code-block:: json

    {"result": true}

Example HTTP/RPC
''''''''''''''''

Query:

.. code-block:: http

    POST /dnsapi/deactivatedomainkey/example.com/1 HTTP/1.1

Response:

.. code-block:: http

    HTTP/1.1 200 OK
    Content-Type: text/javascript; utf-8

    {"result": true}

``getTSIGKey``
~~~~~~~~~~~~~~

Retrieves the key needed to sign AXFR.

-  Mandatory: No
-  Parameters: name
-  Reply: algorithm, content

Example JSON/RPC
''''''''''''''''

Query:

.. code-block:: json

    {"method":"gettsigkey","parameters":{"name":"example.com."}}

Response:

.. code-block:: json

    {"result":{"algorithm":"hmac-md5","content":"kp4/24gyYsEzbuTVJRUMoqGFmN3LYgVDzJ/3oRSP7ys="}}

Example HTTP/RPC
''''''''''''''''

Query:

.. code-block:: http

    GET /dnsapi/gettsigkey/example.com. HTTP/1.1

Response:

.. code-block:: http

    HTTP/1.1 200 OK
    Content-Type: text/javascript; charset=utf-8

    {"result":{"algorithm":"hmac-md5","content":"kp4/24gyYsEzbuTVJRUMoqGFmN3LYgVDzJ/3oRSP7ys="}}

``getDomainInfo``
~~~~~~~~~~~~~~~~~

Retrieves information about given domain from the backend. If your
return value has no zone attribute, the backend will signal error.
Everything else will default to something. Default values: serial:0,
kind:NATIVE, id:-1, notified_serial:-1, last_check:0, masters: [].
Masters, if present, must be array of strings.

-  Mandatory: No
-  Parameters: name
-  Reply: zone
-  Optional values: serial, kind, id, notified_serial, last_check,
   masters

Example JSON/RPC
''''''''''''''''

Query:

.. code-block:: json

    {"method":"getdomaininfo","parameters":{"name":"example.com"}}

Response:

.. code-block:: json

    {"result":{"id":1,"zone":"example.com","kind":"NATIVE","serial":2002010100}}

Example HTTP/RPC
''''''''''''''''

Query:

.. code-block:: http

    GET /dnsapi/getdomaininfo/example.com HTTP/1.1

Response:

.. code-block:: http

    HTTP/1.1 200 OK
    content-Type: text/javascript: charset=utf-8

    {"result":{id:1,"zone":"example.com","kind":"NATIVE","serial":2002010100}}

``setNotified``
~~~~~~~~~~~~~~~

Updates last notified serial for the domain id. Any errors are ignored.

-  Mandatory: No
-  Parameters: id, serial
-  Reply: true for success, false for failure

Example JSON/RPC
''''''''''''''''

Query:

.. code-block:: json

    {"method":"setnotified","parameters":{"id":1,"serial":2002010100}}

Response:

.. code-block:: json

    {"result":true}

Example HTTP/RPC
''''''''''''''''

Query:

.. code-block:: http

    PATCH /dnsapi/setnotified/1 HTTP/1.1
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 17

    serial=2002010100

Response:

.. code-block:: http

    HTTP/1.1 200 OK
    Content-Type: text/javascript; charset=utf-8

    {"result":true}

``isMaster``
~~~~~~~~~~~~

Determines whether given IP is master for given domain name.

-  Mandatory: No
-  Parameters: name,ip
-  Reply: true for success, false for failure.

Example JSON/RPC
''''''''''''''''

Query:

.. code-block:: json

    {"method":"isMaster","parameters":{"name":"example.com","ip":"198.51.100.0.1"}}

Response:

.. code-block:: json

    {"result":true}

Example HTTP/RPC
''''''''''''''''

Query:

.. code-block:: http

    GET /dnsapi/isMaster/example.com/198.51.100.0.1 HTTP/1.1

Response:

.. code-block:: http

    HTTP/1.1 200 OK
    Content-Type: text/javascript; charset=utf-8

    {"result":true}

``superMasterBackend``
~~~~~~~~~~~~~~~~~~~~~~

Creates new domain with given record(s) as master servers. IP address is
the address where notify is received from. nsset is array of NS resource
records.

-  Mandatory: No
-  Parameters: ip,domain,nsset,account
-  Reply: true for success, false for failure. can also return
   account=>name of account< and nameserver.

Example JSON/RPC
''''''''''''''''

Query:

.. code-block:: json

    {"method":"superMasterBackend","parameters":{"ip":"198.51.100.0.1","domain":"example.com","nsset":[{"qtype":"NS","qname":"example.com","qclass":1,"content":"ns1.example.com","ttl":300,"auth":true},{"qtype":"NS","qname":"example.com","qclass":1,"content":"ns2.example.com","ttl":300,"auth":true}]}}

Response:

.. code-block:: json

    {"result":true}

Alternative response:

.. code-block:: json

    {"result":{"account":"my account","nameserver":"ns2.example.com"}}

Example HTTP/RPC
''''''''''''''''

Query:

.. code-block:: http

    POST /dnsapi/supermasterbackend/198.51.100.0.1/example.com HTTP/1.1
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 317

    nsset[1][qtype]=NS&nsset[1][qname]=example.com&nsset[1][qclass]=1&nsset[1][content]=ns1.example.com&nsset[1][ttl]=300&nsset[1][auth]=true&nsset[2][qtype]=NS&nsset[2][qname]=example.com&nsset[2][qclass]=1&nsset[2][content]=ns2.example.com&nsset[2][ttl]=300&nsset[2][auth]=true

Response:

.. code-block:: http

    HTTP/1.1 200 OK
    Content-Type: text/javascript; charset=utf-8

    {"result":true}

Alternative response

.. code-block:: http

    HTTP/1.1 200 OK
    Content-Type: text/javascript; charset=utf-8

    {"result":{"account":"my account"}}

``createSlaveDomain``
~~~~~~~~~~~~~~~~~~~~~

Creates new domain. This method is called when NOTIFY is received and
you are superslaving.

Mandatory: No Parameters: ip, domain Optional parameters: nameserver,
account Reply: true for success, false for failure

Example JSON/RPC
''''''''''''''''

Query:

.. code-block:: json

    {"method":"createSlaveDomain","parameters":{"ip":"198.51.100.0.1","domain":"pirate.example.net"}}

Response:

.. code-block:: json

    {"result":true}

Example HTTP/RPC
''''''''''''''''

Query:

.. code-block:: http

    POST /dnsapi/createslavedomain/198.51.100.0.1/pirate.example.net HTTP/1.1
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 0

Response:

.. code-block:: http

    HTTP/1.1 200 OK
    Content-Type: text/javascript; charset=utf-8

    {"result":true}

``replaceRRSet``
~~~~~~~~~~~~~~~~

This method replaces a given resource record with new set. The new qtype
can be different from the old.

-  Mandatory: No
-  Parameters: domain_id, qname, qtype, rrset
-  Reply: true for success, false for failure

Example JSON/RPC
''''''''''''''''

Query:

.. code-block:: json

    {"method":"replaceRRSet","parameters":{"domain_id":2,"qname":"replace.example.com","qtype":"A","trxid":1370416133,"rrset":[{"qtype":"A","qname":"replace.example.com","qclass":1,"content":"1.1.1.1","ttl":300,"auth":true}]}}

Response:

.. code-block:: json

    {"result":true}

Example HTTP/RPC
''''''''''''''''

Query:

.. code-block:: http

    PATCH /dnsapi/replacerrset/2/replace.example.com/A HTTP/1.1
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 135

    trxid=1370416133&rrset[qtype]=A&rrset[qname]=replace.example.com&rrset[qclass]=1&rrset[content]=1.1.1.1&rrset[auth]=1

Response:

.. code-block:: http

    HTTP/1.1 200 OK
    Content-Type: text/javascript; charset=utf-8

    {"result":true}

``feedRecord``
~~~~~~~~~~~~~~

Asks to feed new record into system. If startTransaction was called,
trxId identifies a transaction. It is not always called by PowerDNS.

-  Mandatory: No
-  Parameters: rr, trxid
-  Reply: true for success, false for failure

Example JSON/RPC
''''''''''''''''

Query:

.. code-block:: json

    {"method":"feedRecord","parameters":{"rr":{"qtype":"A","qname":"replace.example.com","qclass":1,"content":"127.0.0.1","ttl":300,"auth":true},"trxid":1370416133}}

Response:

.. code-block:: json

    {"result":true}

Example HTTP/RPC
''''''''''''''''

Query:

.. code-block:: http

    PATCH /dnsapi/feedrecord/1370416133 HTTP/1.1
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 117

    rr[qtype]=A&rr[qname]=replace.example.com&rr[qclass]=1&rr[content]=127.0.0.1&rr[ttl]=300&rr[auth]=true

Response:

.. code-block:: http

    HTTP/1.1 200 OK
    Content-Type: text/javascript; charset=utf-8

    {"result":true}

.. _remote-feedents:

``feedEnts``
~~~~~~~~~~~~

This method is used by pdnsutil rectify-zone to populate missing
non-terminals. This is used when you have, say, record like
_sip._upd.example.com, but no _udp.example.com. PowerDNS requires
that there exists a non-terminal in between, and this instructs you to
add one. If startTransaction is called, trxid identifies a transaction.

-  Mandatory: No
-  Parameters: nonterm, trxid
-  Reply: true for success, false for failure

Example JSON/RPC
''''''''''''''''

Query:

.. code-block:: json

    {"method":"feedEnts","parameters":{"domain_id":2,"trxid":1370416133,"nonterm":["_sip._udp","_udp"]}}

Response:

.. code-block:: json

    {"result":true}

Example HTTP/RPC
''''''''''''''''

Query:

.. code-block:: http

    PATCH /dnsapi/feedents/2 HTTP/1.1
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 50

    trxid=1370416133&nonterm[]=_udp&nonterm[]=_sip.udp

Response:

.. code-block:: http

    HTTP/1.1 200 OK
    Content-Type: text/javascript; charset=utf-8

    {"result":true}

``feedEnts3``
~~~~~~~~~~~~~

Same as :ref:`remote-feedents`, but provides NSEC3 hashing
parameters. Note that salt is BYTE value, and can be non-readable text.

-  Mandatory: No
-  Parameters: trxid, domain_id, domain, times, salt, narrow, nonterm
-  Reply: true for success, false for failure

Example JSON/RPC
''''''''''''''''

Query:

.. code-block:: json

    {"method":"feedEnts3","parameters":{"domain_id":2,"domain":"example.com","times":1,"salt":"9642","narrow":false,"trxid":1370416356,"nonterm":["_sip._udp","_udp"]}}

Response:

.. code-block:: json

    {"result":true}

Example HTTP/RPC
''''''''''''''''

Query:

.. code-block:: http

    PATCH /dnsapi/2/example.com HTTP/1.1
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 78

    trxid=1370416356&times=1&salt=9642&narrow=0&nonterm[]=_sip._udp&nonterm[]=_udp

Response:

.. code-block:: http

    HTTP/1.1 200 OK
    Content-Type: text/javascript; charset=utf-8

    {"result":true}

``startTransaction``
~~~~~~~~~~~~~~~~~~~~

Starts a new transaction. Transaction ID is chosen for you. Used to
identify f.ex. AXFR transfer.

-  Mandatory: No
-  Parameters: domain_id, domain, trxid
-  Reply: true for success, false for failure

Example JSON/RPC
''''''''''''''''

Query:

.. code-block:: json

    {"method":"startTransaction","parameters":{"trxid":1234,"domain_id":1,"domain":"example.com"}}

Response:

.. code-block:: json

    {"result":true}

Example HTTP/RPC
''''''''''''''''

Query:

.. code-block:: http

    POST /dnsapi/starttransaction/1/example.com HTTP/1.1
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 10

    trxid=1234

Response:

.. code-block:: http

    HTTP/1.1 200 OK
    Content-Type: text/javascript; charset=utf-8

    {"result":true}

``commitTransaction``
~~~~~~~~~~~~~~~~~~~~~

Signals successful transfer and asks to commit data into permanent
storage.

-  Mandatory: No
-  Parameters: trxid
-  Reply: true for success, false for failure

Example JSON/RPC
''''''''''''''''

Query:

.. code-block:: json

    {"method":"commitTransaction","parameters":{"trxid":1234}}

Response:

.. code-block:: json

    {"result":true}

Example HTTP/RPC
''''''''''''''''

Query:

.. code-block:: http

    POST /dnsapi/committransaction/1234 HTTP/1.1
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 0

Response:

.. code-block:: http

    HTTP/1.1 200 OK
    Content-Type: text/javascript; charset=utf-8

    {"result":true}

``abortTransaction``
~~~~~~~~~~~~~~~~~~~~

Signals failed transaction, and that you should rollback any changes.

-  Mandatory: No
-  Parameters: trxid
-  Reply: true for success, false for failure

Example JSON/RPC
''''''''''''''''

Query:

.. code-block:: json

    {"method":"abortTransaction","parameters":{"trxid":1234}}

Response:

.. code-block:: json

    {"result":true}

Example HTTP/RPC
''''''''''''''''

Query:

.. code-block:: http

    POST /dnsapi/aborttransaction/1234 HTTP/1.1
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 0

Response:

.. code-block:: http

    HTTP/1.1 200 OK
    Content-Type: text/javascript; charset=utf-8

    {"result":true}

``calculateSOASerial``
~~~~~~~~~~~~~~~~~~~~~~

Asks you to calculate a new serial based on the given data and update
the serial.

-  Mandatory: No
-  Parameters: domain,sd
-  Reply: true for success, false for failure

Example JSON/RPC
''''''''''''''''

Query:

.. code-block:: json

    {"method":"calculateSOASerial","parameters":{"domain":"unit.test","sd":{"qname":"unit.test","nameserver":"ns.unit.test","hostmaster":"hostmaster.unit.test","ttl":300,"serial":1,"refresh":2,"retry":3,"expire":4,"default_ttl":5,"domain_id":-1,"scopeMask":0}}}

Response:

.. code-block:: json

    {"result":2013060501}

Example HTTP/RPC
''''''''''''''''

Query:

.. code-block:: http

    POST /dnsapi/calculatesoaserial/unit.test HTTP/1.1
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 198

    sd[qname]=unit.test&sd[nameserver]=ns.unit.test&sd[hostmaster]=hostmaster.unit.test&sd[ttl]=300&sd[serial]=1&sd[refresh]=2&sd[retry]=3&sd[expire]=4&sd[default_ttl]=5&sd[domain_id]=-1&sd[scopemask]=0

Response:

.. code-block:: http

    HTTP/1.1 200 OK
    Content-Type: text/javascript; charset=utf-8

    {"result":2013060501}

``directBackendCmd``
~~~~~~~~~~~~~~~~~~~~

Can be used to send arbitrary commands to your backend using
:doc:`../dnssec/pdnsutil`.

-  Mandatory: no
-  Parameters: query
-  Reply: anything but boolean false for success, false for failure

Example JSON/RPC
''''''''''''''''

Query:

.. code-block:: json

    {"method":"directBackendCmd","parameters":{"query":"PING"}}

Response:

.. code-block:: json

    {"result":"PONG"}

Example HTTP/RPC
''''''''''''''''

Query:

.. code-block:: http

    POST /dnsapi/directBackendCmd HTTP/1.1
    Content-Type: application/x-www-form-urlencoded
    Content-Length: 10

    query=PING

Response:

.. code-block:: http

    HTTP/1.1 200 OK
    Content-Type: text/javascript; charset=utf-8

    {"result":"PONG"}

``getAllDomains``
~~~~~~~~~~~~~~~~~

Get DomainInfo records for all domains in your backend.

-  Mandatory: no
-  Parameters: include_disabled
-  Reply: array of DomainInfo

Example JSON/RPC
''''''''''''''''

Query:

.. code-block:: json

    {"method": "getAllDomains", "parameters": {"include_disabled": true}}

Response:

.. code-block:: json

    {"result":[{"id":1,"zone":"unit.test.","masters":["10.0.0.1"],"notified_serial":2,"serial":2,"last_check":1464693331,"kind":"native"}]}

Example HTTP/RPC
''''''''''''''''

Query:

.. code-block:: http

    GET /dnsapi/getAllDomains?includeDisabled=true HTTP/1.1

Response:

.. code-block:: http

    HTTP/1.1 200 OK
    Content-Type: text/javascript; charset=utf-8
    Content-Length: 135
    {"result":[{"id":1,"zone":"unit.test.","masters":["10.0.0.1"],"notified_serial":2,"serial":2,"last_check":1464693331,"kind":"native"}]}

``searchRecords``
~~~~~~~~~~~~~~~~~

Can be used to search records from the backend. This is used by web api.

-  Mandatory: no
-  Parameters: pattern, maxResults
-  Reply: same as :ref:`remote-lookup` or false to indicate failed
   search

Example JSON/RPC
''''''''''''''''

Query:

.. code-block:: json

    {"method":"searchRecords","parameters":{"pattern":"www.example*","maxResults":100}}

Response:

.. code-block:: json

    {"result":[{"qtype":"A", "qname":"www.example.com", "content":"203.0.113.2", "ttl": 60}]}

Example HTTP/RPC
''''''''''''''''

Query:

.. code-block:: http

    GET /dnsapi/searchRecords?q=www.example*&maxResults=100 HTTP/1.1

Response:

.. code-block:: http

    HTTP/1.1 200 OK
    Content-Type: text/javascript; charset=utf-8

    {"result":[{"qtype":"A", "qname":"www.example.com", "content":"203.0.113.2", "ttl": 60}]}


``getUpdatedMasters``
~~~~~~~~~~~~~~~~~~~~~

Used to find out any updates to master domains. This is used to trigger notifications in master mode.

-  Mandatory: no
-  Parameters: none
-  Reply: array of DomainInfo

Example JSON/RPC
''''''''''''''''

Query:

.. code-block:: json

    {"method": "getUpdatedMasters", "parameters": {}}

Response:

.. code-block:: json

    {"result":[{"id":1,"zone":"unit.test.","masters":["10.0.0.1"],"notified_serial":2,"serial":2,"last_check":1464693331,"kind":"master"}]}

Example HTTP/RPC
''''''''''''''''

Query:

.. code-block:: http

    GET /dnsapi/getUpdatedMasters HTTP/1.1

Response:

.. code-block:: http

    HTTP/1.1 200 OK
    Content-Type: text/javascript; charset=utf-8
    Content-Length: 135
    {"result":[{"id":1,"zone":"unit.test.","masters":["10.0.0.1"],"notified_serial":2,"serial":2,"last_check":1464693331,"kind":"master"}]}



Examples
--------

Scenario: SOA lookup via pipe, unix or zeromq connector
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Query:

.. code-block:: json

    { 
      "method": "lookup",
      "parameters": {
         "qname": "example.com", 
         "qtype": "SOA",
         "zone_id": "-1"
      }
    }

Reply:

.. code-block:: json

    {
      "result": 
       [ 
         { "qtype": "SOA",
           "qname": "example.com", 
           "content": "dns1.icann.org. hostmaster.icann.org. 2012080849 7200 3600 1209600 3600",
           "ttl": 3600,
           "domain_id": -1
         }
       ]
    }

Scenario: SOA lookup with HTTP connector
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Query:

::

    /dns/lookup/example.com/SOA

Reply:

.. code-block:: json

    {
      "result":
       [
         { "qtype": "SOA",
           "qname": "example.com",
           "content": "dns1.icann.org. hostmaster.icann.org. 2012080849 7200 3600 1209600 3600",
           "ttl": 3600,
           "domain_id": -1
         }
       ]
    }
