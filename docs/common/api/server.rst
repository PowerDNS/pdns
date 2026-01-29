Server
======

An object representing a single PowerDNS server.
In the built-in API, only one Server exists (called "localhost").

A proxy that allows control of multiple servers MUST NOT return ``localhost``, but SHOULD return
other servers.

.. json:schema:: Server

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

.. note::
  The servers collection is read-only, and the only allowed returned server is read-only as well. A control proxy could return modifiable resources.
