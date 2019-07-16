Built-in Webserver and HTTP API
===============================

The PowerDNS Authoritative Server features a built-in webserver that exposes a JSON/REST API.
This API allows for controlling several functions, reading statistics and modifying zone content, metadata and DNSSEC key material.

Webserver
---------

To launch the internal webserver, add a :ref:`setting-webserver` to the configuration file.
This will instruct PowerDNS to start a webserver on localhost at port 8081, without password protection.
By default the webserver listens on localhost, meaning only local users (on the same host) will be able to access the webserver. Since the default ACL before 4.1.0 allows access from everywhere if :ref:`setting-webserver-address` is set to a different value, we strongly advise the use of a password protection.
The webserver lists a lot of potentially sensitive information about the PowerDNS process, including frequent queries, frequently failing queries, lists of remote hosts sending queries, hosts sending corrupt queries etc.
The webserver does not allow remote management of the daemon, but allows control over the size of the queries and response rings that may be used to monitor activities.
The following webserver related configuration items are available:

* :ref:`setting-webserver`: If set to anything but 'no', a webserver is launched.
* :ref:`setting-webserver-address`: Address to bind the webserver to. Defaults to 127.0.0.1, which implies that only the local computer is able to connect to the nameserver! To allow remote hosts to connect, change to 0.0.0.0 or the physical IP address of your nameserver.
* :ref:`setting-webserver-password`: If set, viewers will have to enter this plaintext password in order to gain access to the statistics, in addition to entering the configured API key on the index page.
* :ref:`setting-webserver-port`: Port to bind the webserver to.
* :ref:`setting-webserver-allow-from`: Netmasks that are allowed to connect to the webserver
* :ref:`setting-webserver-max-bodysize`: Maximum request/response body size in megabytes

Enabling the API
----------------

To enable the API, the webserver and the HTTP API need to be enabled.
Add these lines to the ``pdns.conf``::

  api=yes
  api-key=changeme

.. versionchanged:: 4.1.0

  Setting :ref:`setting-api` also implicitly enables the webserver.

And restart, the following examples should start working::

  curl -v -H 'X-API-Key: changeme' http://127.0.0.1:8081/api/v1/servers/localhost | jq .
  curl -v -H 'X-API-Key: changeme' http://127.0.0.1:8081/api/v1/servers/localhost/zones | jq .

Working with the API
--------------------

This chapter describes the PowerDNS Authoritative API.
When creating an API wrapper (for instance when fronting multiple API's), it is recommended to stick to this API specification.
The API is described in the `OpenAPI format <https://www.openapis.org/>`_, also known as "Swagger", and this description is `available <https://raw.githubusercontent.com/PowerDNS/pdns/master/docs/http-api/swagger/authoritative-api-swagger.yaml>`_.

Authentication
~~~~~~~~~~~~~~

The PowerDNS daemons accept a static API Key, configured with the :ref:`setting-api-key` option, which has to be sent in the ``X-API-Key`` header.

Errors
~~~~~~

Response code ``4xx`` or ``5xx``, depending on the situation.

-  Invalid JSON body from client: ``400 Bad Request``
-  Input validation failed: ``422 Unprocessable Entity``
-  JSON body from client not a hash: ``400 Bad Request``

Error responses have a JSON body of this format:

.. openapi:: swagger/authoritative-api-swagger.yaml
  :definitions: Error

Data format
~~~~~~~~~~~

The API accepts and emits :rfc:`JSON <7159>`.
The ``Accept:`` header determines the output format.
An unknown value or ``*/*`` will cause a ``400 Bad Request``.

All text is UTF-8 and HTTP headers will reflect this.

Data types:

-  empty fields: ``null`` but present
-  Regex: implementation defined
-  Dates: ISO 8601

Endpoints and Objects in the API
--------------------------------

The API has the basepath ``/api/v1`` and all URLs in this documentation are relative to this basepath.

The API exposes several endpoints and objects:

.. toctree::
  :maxdepth: 1

  server
  zone
  cryptokey
  metadata
  tsigkey
  search
  statistics
  cache
