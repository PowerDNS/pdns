RPZ Statistics endpoint
=======================

.. versionadded:: 4.1.2

.. http:get:: /api/v1/servers/:server_id/rpzstatistics

  Query PowerDNS for :doc:`Response Policy Zones <../lua-config/rpz>` statistics.

  Statistics are mapped per configured RPZ zone.
  The statistics are:

  last_update
    UNIX timestamp when the latest update was received
  records
    Number of records in the RPZ
  serial
    Current SOA serial of the RPZ zone
  transfers_failed
    Number of times a transfer failed
  transfers_full
    Number of times an AXFR succeeded
  transfers_success
    Number of times an AXFR or IXFR succeeded

  **Example response:**

  .. code-block:: json

    {
      "myRPZ": {
        "last_update": 1521798212,
        "records": 1343149,
        "serial": 5489,
        "transfers_failed": 0,
        "transfers_full": 3,
        "transfers_success": 478
      }
    }

