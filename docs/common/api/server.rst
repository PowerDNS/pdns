Server
======
.. json:object:: Server

  An object representing a single PowerDNS server.
  In the built-in API, only one Server exists (called "localhost").

  A proxy that allows control of multiple servers MUST NOT return ``localhost``, but SHOULD return
  other servers.

  :property string type: Set to "Server"
  :property string id: The id of the server, "localhost"
  :property string daemon_type: "recursor" for the PowerDNS Recursor and "authoritative" for the Authoritative Server
  :property string version: The version of the server software
  :property string url: The API endpoint for this server
  :property string config_url: The API endpoint for this server's configuration
  :property string zones_url: The API endpoint for this server's zones

  **Example**:

  .. code-block:: json

    {
      "type": "Server",
      "id": "localhost",
      "url": "/api/v1/servers/localhost",
      "daemon_type": "recursor",
      "version": "4.1.0",
      "config_url": "/api/v1/servers/localhost/config{/config_setting}",
      "zones_url": "/api/v1/servers/localhost/zones{/zone}",
    }

  Note: the servers collection is read-only, and the only allowed returned server is read-only as well. A control proxy could return modifiable resources.
