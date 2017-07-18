Built-in Webserver and HTTP API
===============================

The PowerDNS Authoritative Server features a built-in built-in webserver that exposes a JSON/REST API.
This API allows for controlling several functions and reading statistics.

Webserver
---------

To launch the internal webserver, add a :ref:`setting-webserver` to the configuration file.
This will instruct PowerDNS to start a webserver on localhost at port 8081, without password protection.
Only local users (on the same host) will be able to access the webserver by default, but we still strongly advise the use of a password protection.
The webserver lists a lot of information about the PowerDNS process, including frequent queries, frequently failing queries, lists of remote hosts sending queries, hosts sending corrupt queries etc.
The webserver does not allow remote management.
The following webserver related configuration items are available:

* :ref:`setting-webserver`: If set to anything but 'no', a webserver is launched.
* :ref:`setting-webserver-address`: Address to bind the webserver to. Defaults to 127.0.0.1, which implies that only the local computer is able to connect to the nameserver! To allow remote hosts to connect, change to 0.0.0.0 or the physical IP address of your nameserver.
* :ref:`setting-webserver-password`: If set, viewers will have to enter this plaintext password in order to gain access to the statistics.
* :ref:`setting-webserver-port`: Port to bind the webserver to.
* :ref:`setting-webserver-allow-from`: Netmasks that are allowed to connect to the webserver

Enabling the API
----------------

To enable the API, the webserver and the HTTP API need to be enbaled.
Add these lines to the ``pdns.conf``::

    webserver=yes
    webserver-port=8082
    api-key=changeme

And restart, the following examples should start working::

    curl -v -H 'X-API-Key: changeme' http://127.0.0.1:8082/api/v1/servers/localhost | jq .
    curl -v -H 'X-API-Key: changeme' http://127.0.0.1:8082/api/v1/servers/localhost/zones | jq .

JSON Objects
------------

The following documents describe the JSON objects available in the API:

.. toctree::
    :maxdepth: 1

    ../common/api/dataformat
    ../common/api/server
    ../common/api/zone
    ../common/api/configsetting
    ../common/api/statisticitem
    cryptokeyitem
    zonemetadata

URL Endpoints
-------------

All API endpoints for the PowerDNS Recursor are documented here:

.. toctree::
  :maxdepth: 1

  ../common/api/endpoint-api
  ../common/api/endpoint-servers
  ../common/api/endpoint-servers-config
  ../common/api/endpoint-statistics
  ../common/api/endpoint-logging
  endpoint-search
  endpoint-zones
  endpoint-zone-metadata
  endpoint-cryptokeys
