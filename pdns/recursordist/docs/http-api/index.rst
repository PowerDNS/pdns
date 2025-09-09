Built-in Webserver and HTTP API
===============================

The PowerDNS Recursor features a built-in built-in webserver that exposes a JSON/REST API.
This API allows for controlling several functions and reading statistics.

The following documents contain the information for the PowerDNS API:

.. toctree::
    :maxdepth: 1

    ../common/api/dataformat
    ../common/api/server
    zone
    ../common/api/configsetting
    ../common/api/statisticitem


Webserver
---------

To launch the internal webserver, set :ref:`setting-yaml-webservice.webserver` to ``true`` the configuration file.
This will instruct PowerDNS to start a webserver on localhost at port 8081, without password protection.
By default the webserver listens on localhost, meaning only local users (on the same host) will be able to access the webserver. Since the default ACL before 4.1.0 allows access from everywhere if :ref:`setting-yaml-webservice.address` is set to a different value, we strongly advise the use of a password protection.
The webserver lists a lot of potentially sensitive information about the PowerDNS process, including frequent queries, frequently failing queries, lists of remote hosts sending queries, hosts sending corrupt queries etc.
The webserver does not allow remote management.
The following webserver related configuration items are available:

* :ref:`setting-yaml-webservice.webserver`: If set to ``yes`` a webserver is launched.
* :ref:`setting-yaml-webservice.address`: Address to bind the webserver to. Defaults to 127.0.0.1, which implies that only the local computer is able to connect to the nameserver! To allow remote hosts to connect, change to 0.0.0.0 or the physical IP address of your nameserver.
* :ref:`setting-yaml-webservice.password`: If set, viewers will have to enter this password in order to gain access to the statistics.
* :ref:`setting-yaml-webservice.port`: Port to bind the webserver to.
* :ref:`setting-yaml-webservice.allow_from`: Netmasks that are allowed to connect to the webserver

.. warning::

   Not setting a password will allow password-less access to the frontpage showing statistics, the :doc:`endpoint-jsonstat`, the :doc:`../common/api/endpoint-statistics` and the ``localhost`` specific endpoint of the :doc:`../common/api/endpoint-servers`.

Enabling the API
----------------

To enable the API, the webserver and the HTTP API need to be enabled.
Add these lines to the configuration file:

.. code-block:: yaml

   webservice:
     webserver: true
     port: 8082
     api_key: changeme

And restart ``pdns_recursor``, the following examples should start working::

    curl -v -H 'X-API-Key: changeme' http://127.0.0.1:8082/api/v1/servers/localhost | jq .
    curl -v -H 'X-API-Key: changeme' http://127.0.0.1:8082/api/v1/servers/localhost/zones | jq .

A few examples for zone manipulation follow, first one is to create a forwarding zone::

  curl --no-progress-meter -H 'X-API-Key: changeme' -H 'Content-type: application/json' -X POST --data-binary @- http://localhost:8082/api/v1/servers/localhost/zones << EOF | jq
  {
    "name": "example.com.",
    "type": "Zone",
    "kind": "Forwarded",
    "servers": ["192.168.178.1", "192.168.178.2:5353"],
    "recursion_desired" : false
  }
  EOF

Example output of the above command::

  {
    "id": "example.com.",
    "kind": "Forwarded",
    "name": "example.com.",
    "records": [],
    "recursion_desired": false,
    "servers": [
      "192.168.178.1:53",
      "192.168.178.2:5353"
    ],
    "url": "/api/v1/servers/localhost/zones/example.com."
  }

To delete the forwarding zone added above::

  curl --no-progress-meter -H 'X-API-Key: changeme' -X DELETE http://localhost:8082/api/v1/servers/localhost/zones/example.com.

URL Endpoints
-------------

All API endpoints for the PowerDNS Recursor are documented here:

.. toctree::
  :maxdepth: 1

  prometheus
  ../common/api/endpoint-api
  ../common/api/endpoint-servers
  endpoint-servers-config
  ../common/api/endpoint-statistics.rst
  endpoint-zones
  endpoint-trace
  endpoint-cache
  endpoint-failure
  endpoint-rpz-stats
  endpoint-jsonstat
