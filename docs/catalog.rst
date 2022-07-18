Catalog Zones (RFC  TBD)
========================

Starting with the PowerDNS Authoritative Server 4.7.0, catalog zone support is available.

Supported catalog versions
--------------------------

+-----------------+----------+----------+
| Catalog version | Producer | Consumer |
+=================+==========+==========+
| 1 (ISC)         | No       | Yes      |
+-----------------+----------+----------+
| 2 (RFC TBD)     | Yes      | Yes      |
+-----------------+----------+----------+

All the important features of catalog zones version "2" are supported.
There are however a few properties where support is limited:

-  There is no support for group templates on consumers;
-  There is no support for custom extensions;

The implementation requires the backend to support a number of new operations.
Currently, the following backends have been modified to support catalog zones:

- :doc:`gmysql <backends/generic-mysql>`
- :doc:`gpgsql <backends/generic-postgresql>`
- :doc:`gsqlite3 <backends/generic-sqlite3>`
- :doc:`godbc <backends/generic-odbc>`
- :doc:`lmdb <backends/lmdb>`

.. _catalog-configuration-options:

Configuration options
---------------------

None really.

.. _catalog-metadata:

Per zone settings
-----------------

It is highly recommended to protect catalog zones with :doc:`TSIG <../tsig>`

CATALOG-HASH
~~~~~~~~~~~~

Producer zones store the member state as a hash in this metadata setting.
This setting is managed by the authoritative server.
Modifying or deleting this value will result in a serial increase of the producer zone and the update or recreation of this value.

Setting up catalog zones
------------------------

.. note::
  Catalog zone specification and operation is described in `DNS Catalog Zones <https://datatracker.ietf.org/doc/draft-ietf-dnsop-dns-catalog-zones)>`__.

Setting up a producer zone
~~~~~~~~~~~~~~~~~~~~~~~~~~

Setting up a producer zone is not very different from a regular primary zone.
A producer zone is a minimal zone of type PRODUCER with only SOA and NS records at apex.
All the records in a producer zone are ignored while generating a catalog.

An initial producer zone may look like this:

::

  $TTL 3600
  $ORIGIN catalog.invalid.
  @               IN      SOA     ns1.zone.invalid. hostmaster.zone.invalid. (  1
                          1H ; refresh
                          10M ; retry
                          1W ; expire
                          1800 ; default_ttl
                          )

  @               IN      NS      ns1.zone.invalid.

An interesting detail is the serial.
Since the serial of a producer zone is automatically updated, it is important for the initial serial to be equal or lower than epoch.
This serial is increased to EPOCH after each relevant member update.

Create a producer zone:

.. code-block:: shell

  pdnsutil load-zone catalog.invalid zones/catalog.invalid ZONEFILE
  pdnsutil set-kind catalog.invalid producer

Creating producer zones is supported in the :doc:`API <http-api/zone>`.

Assigning members to a producer zone
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

After the producer zone is created it is necessary to assign member zones to it.
In the example below ``example.com`` is the member and ``catalog.invalid`` is the catalog.

.. code-block:: shell

  pdnsutil set-catalog example.com catalog.invalid

Setting catalog values is supported in the :doc:`API <http-api/zone>`.

Each member zone may have one or more additional properties.
PowerDNS supports the flowing properties:

- coo - A single DNSName
- group - Multiple string values for group are allowed

.. code-block:: shell

  pdnsutil set-option example.com producer coo other-catalog.invalid
  pdnsutil set-option example.com producer group pdns-group-x pdns-group-y

There is also an option to set a specific <unique-N> value for a zone. This is done by setting a the ``unique`` value.
This is used to signal a state reset to the consumer.
The value for ``unique`` is a single DNS label.

.. code-block:: shell

  pdnsutil --config-dir=. --config-name=gmysql set-option test.com producer unique 123

Setting options is not yet supported in the API.

Setting up a consumer zone
~~~~~~~~~~~~~~~~~~~~~~~~~~

Setting up a consumer zone on a secondary server is almost identical to a normal secondary zone.
The only difference is the type, which is now set to CONSUMER.

.. code-block:: shell

  pdnsutil create-secondary-zone catalog.invalid 127.0.0.1
  pdnsutil set-kind catalog.invalid consumer

Creating producer zones is supported in the :doc:`API <http-api/zone>`.
