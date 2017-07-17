Built-in webserver
==================

To visually interact with dnsdist, try add :func:`webserver` to the configuration:

.. code-block:: lua

  webserver("127.0.0.1:8083", "supersecretpassword", "supersecretAPIkey")

Now point your browser at http://127.0.0.1:8083 and log in with any username, and that password. Enjoy!

Security of the Webserver
-------------------------

The built-in webserver serves its content from inside the binary, this means it will not and connot read from disk.

By default, our web server sends some security-related headers::

   X-Content-Type-Options: nosniff
   X-Frame-Options: deny
   X-Permitted-Cross-Domain-Policies: none
   X-XSS-Protection: 1; mode=block
   Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'

You can override those headers, or add custom headers by using the last parameter to :func:`webserver`.
For example, to remove the X-Frame-Options header and add a X-Custom one:

.. code-block:: lua

  webserver("127.0.0.1:8080", "supersecret", "apikey", {["X-Frame-Options"]= "", ["X-Custom"]="custom"}

dnsdist API
-----------

To access the API, the `apikey` must be set in the :func:`webserver` function.
Use the API, this key will need to be sent to dnsdist in the ``X-API-Key`` request header.
An HTTP 401 response is returned when a wrong or no API key is received.
A 404 response is generated is the requested endpoint does not exist.
And a 405 response is returned when the HTTP methos is not allowed.

URL Endpoints
~~~~~~~~~~~~~

.. http:get:: /jsonstat

  Get statistics from dnsdist in JSON format.
  The ``Accept`` request header is ignored.
  This endpoint accepts a ``command`` query for different statistics:

  * ``stats``: Get all :doc:`../statistics` as a JSON dict
  * ``dynblocklist``: Get all current :doc:`dynamic blocks <dynblocks>`, keyed by netmask
  * ``ebpfblocklist``: Idem, but for :doc:`eBPF <../advanced/ebpf>` blocks

  **Example request**:

   .. sourcecode:: http

      GET /jsonstat?command=stats HTTP/1.1
      Host: example.com
      Accept: application/json, text/javascript

  **Example response**:
   .. sourcecode:: http

      HTTP/1.1 200 OK
      Transfer-Encoding: chunked
      Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'
      Content-Type: application/json
      X-Content-Type-Options: nosniff
      X-Frame-Options: deny
      X-Permitted-Cross-Domain-Policies: none
      X-Xss-Protection: 1; mode=block

      {"acl-drops": 0, "block-filter": 0, "cache-hits": 0, "cache-misses": 0, "cpu-sys-msec": 633, "cpu-user-msec": 499, "downstream-send-errors": 0, "downstream-timeouts": 0, "dyn-block-nmg-size": 1, "dyn-blocked": 3, "empty-queries": 0, "fd-usage": 17, "latency-avg100": 7651.3982737482893, "latency-avg1000": 860.05142763680249, "latency-avg10000": 87.032142373878372, "latency-avg1000000": 0.87146026426551759, "latency-slow": 0, "latency0-1": 0, "latency1-10": 0, "latency10-50": 22, "latency100-1000": 1, "latency50-100": 0, "no-policy": 0, "noncompliant-queries": 0, "noncompliant-responses": 0, "over-capacity-drops": 0, "packetcache-hits": 0, "packetcache-misses": 0, "queries": 26, "rdqueries": 26, "real-memory-usage": 6078464, "responses": 23, "rule-drop": 0, "rule-nxdomain": 0, "rule-refused": 0, "self-answered": 0, "server-policy": "leastOutstanding", "servfail-responses": 0, "too-old-drops": 0, "trunc-failures": 0, "uptime": 412}

  **Example request**:

   .. sourcecode:: http

      GET /jsonstat?command=dynblocklist HTTP/1.1
      Host: example.com
      Accept: application/json, text/javascript

  **Example response**:
   .. sourcecode:: http

      HTTP/1.1 200 OK
      Transfer-Encoding: chunked
      Content-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'
      Content-Type: application/json
      X-Content-Type-Options: nosniff
      X-Frame-Options: deny
      X-Permitted-Cross-Domain-Policies: none
      X-Xss-Protection: 1; mode=block

      {"127.0.0.1/32": {"blocks": 3, "reason": "Exceeded query rate", "seconds": 10}}

  :query command: one of ``stats``, ``dynblocklist`` or ``ebpfblocklist``

.. http:get:: /api/v1/servers/localhost

  Get a quick overview of several parameters.

  :>json string acl: A string of comma-separated netmasks currently allowed by the :ref:`ACL <ACL>`.
  :>json string daemon_type: The type of daemon, always "dnsdist"
  :>json list frontends: A list of :json:object:`Frontend` objects
  :>json list response-rules: A list of :json:object:`ResponseRule` objects
  :>json list rules: A list of :json:object:`Rule` objects
  :>json list servers: A list of :json:object:`Server` objects
  :>json string version: The running version of dnsdist

.. http:get:: /api/v1/servers/localhost/statistics

  Returns a list of all statistics as :json:object:`StatisticItem`.

.. http:get:: /api/v1/servers/localhost/config

  Returns a list of :json:object:`ConfigSetting` objects.

.. http:get:: /api/v1/servers/localhost/config/allow-from

  Gets you the ``allow-from`` :json:object:`ConfigSetting`, who's value is a list of strings of all the netmasks in the :ref:`ACL <ACL>`.

.. http:put:: /api/v1/servers/localhost/config/allow-from

  Allows you to add to the ACL. TODO **how**

JSON Objects
~~~~~~~~~~~~

.. json:object:: ConfigSetting

  An object representing a global configuration element.
  The following configuration are returned:

  - ``acl`` The currently configured :ref:`ACLs <ACL>`
  - ``control-socket`` The currently configured :ref:`console address <Console>`
  - ``ecs-override``
  - ``ecs-source-prefix-v4`` The currently configured :func:`setECSSourcePrefixV4`
  - ``ecs-source-prefix-v6`` The currently configured :func:`setECSSourcePrefixV6`
  - ``fixup-case``
  - ``max-outstanding``
  - ``server-policy`` The currently set :doc:`serverselection`
  - ``stale-cache-entries-ttl``
  - ``tcp-recv-timeout``
  - ``tcp-send-timeout``
  - ``truncate-tc``
  - ``verbose``
  - ``verbose-health-checks``

  :property string name: The name of the setting
  :property string type: "ConfigSetting"
  :property string value: The value for this setting

.. json:object:: Frontend

  A description of a bind dnsdist is listening on.

  :property string address: IP and port that is listened on
  :property integer id: Internal identifier
  :property integer queries: The number of received queries on this bind
  :property boolean udp: true if this is a UDP bind
  :property boolean tcp: true if this is a TCP bind

.. json:object:: Rule

  This represents a policy that is applied to queries

  :property string action: The action taken when the rule matches (e.g. "to pool abuse")
  :property dict action-stats: TODO
  :property integer id: The identifier (or order) of this rule
  :property integer matches: How many times this rule was hit
  :property string rule: The matchers for the packet (e.g. "qname==bad-domain1.example., bad-domain2.example.")

.. json:object:: ResponseRule

  This represents a policy that is applied to responses

  TODO

.. json:object:: Server

  This object represents a backend server.

  :property string address: The remote IP and port
  :property integer id: Internal identifier
  :property integer latency: The current latency of this backend server
  :property string name: The name of this server
  :property integer order: Order number
  :property integer outstanding: Number of currently outstanding queries
  :property [string] pools: The pools this server belongs to
  :property integer qps: The current number of queries per second to this server
  :property integer qpsLimit: The configured maximum number of queries per second
  :property integer queries: Total number of queries sent to this backend
  :property integer reuseds: TODO
  :property string state: The state of the server (e.g. "DOWN" or "up")
  :property integer weight: The weight assigned to this server

.. json:object:: StatisticItem

  This represents a statistics element.

  :property string name: The name of this statistic. See :doc:`../statistics`
  :property string type: "StatisticItem"
  :property integer value: The value for this item

