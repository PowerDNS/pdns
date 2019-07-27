GeoIP backend
=============

* Native: Yes
* Master: No
* Slave: No
* Superslave: No
* DNSSEC: Yes
* Disabled data: No
* Comments: No
* Module name: geoip
* Launch name: ``geoip``

This backend (which is a.k.a. the YAML backend) allows visitors to be sent to a server closer to them, with
no appreciable delay, as would otherwise be incurred with a protocol
level redirect. Additionally, the Geo Backend can be used to provide
service over several clusters, any of which can be taken out of use
easily, for example for maintenance purposes. This backend can utilize
EDNS Client Subnet extension for decision making, if provided in query
and you have turned on
:ref:`setting-edns-subnet-processing`.

Prerequisites
--------------

To compile the backend, you need libyaml-cpp 0.5 or later and libgeoip.

You must have a geoip database available. As of this writing, on debian/ubuntu
systems, you can use ``apt-get install geoip-database`` to get one, and the
backend is configured to use the location where these files are
installed as source. On other systems you might need to alter the
``database-file`` and ``database-file6`` attribute. If you don't need ipv4 or
ipv6 support, set the respective setting to "". Leaving it unset leaves
it pointing to a default location, preventing the software from starting
up.

Since v4.2.0 libgeoip is optional. You can use also libmaxminddb, but
that is optional too. If no geo backend is provided, no geoip database
based expansions can be used. Other expansions will work.

Configuration Parameters
------------------------

These are the configuration file parameters that are available for the
GeoIP backend. ``geoip-zones-files`` is the only thing you must set, if the
defaults suit you.

.. _setting-geoip-database-files:

``geoip-database-files``
~~~~~~~~~~~~~~~~~~~~~~~~

.. versionchanged:: 4.2.0
  The syntax of the argument has been changed.

.. versionchanged:: 4.2.0
  Support for MMDB has been added.

Comma, tab or space separated list of files to open. You can use
`geoip-cvs-to-dat <https://github.com/dankamongmen/sprezzos-world/blob/master/packaging/geoip/debian/src/geoip-csv-to-dat.cpp>`__.
to generate your own.

For MMDB files, see `MaxMind's getting started guide <https://github.com/maxmind/getting-started-with-mmdb>`__.

Since v4.2.0, database type is determined by file suffix, or you can use the new syntax.
New syntax is ``[driver:]path[;options]``.

Drivers and options
^^^^^^^^^^^^^^^^^^^

:dat: legacy libGeoIP database. Options:

  :mode: The caching mode for data, one of ``standard``, ``memory``, ``index``, or ``mmap``.

:mmdb: driver for libmaxminddb databases. Options:

  :mode: The caching mode for data, only ``mmap`` is supported
  :language: The language to use, ``en`` by default

``geoip-database-cache``
~~~~~~~~~~~~~~~~~~~~~~~~

.. deprecated:: 4.2.0

  This setting is removed

Specifies the kind of caching that is done on the database. This is one
of "standard", "memory", "index" or "mmap". These options map to the
caching options described
`here <https://github.com/maxmind/geoip-api-c/blob/master/README.md#memory-caching-and-other-options>`__

.. _setting-geoip-zones-file:

``geoip-zones-file``
~~~~~~~~~~~~~~~~~~~~

Specifies the full path of the zone configuration file to use. The file is re-opened with a ``pdns_control reload``.

.. _setting-geoip-dnssec-keydir:

``geoip-dnssec-keydir``
~~~~~~~~~~~~~~~~~~~~~~~

Specifies the full path of a directory that will contain DNSSEC keys.
This option enables DNSSEC on the backend. Keys can be created/managed
with ``pdnsutil``, and the backend stores these keys in files with key
flags and active/disabled state encoded in the key filenames.

Zonefile format
---------------

Zone configuration files use YAML syntax. Here is simple example. Note
that the ``‐`` before certain keys is part of the syntax.

.. code-block:: yaml

    domains:
    - domain: geo.example.com
      ttl: 30
      records:
        geo.example.com:
          - soa: ns1.example.com hostmaster.example.com 2014090125 7200 3600 1209600 3600
          - ns:
               content: ns1.example.com
               ttl: 600
          - ns: ns2.example.com
          - mx: 10 mx.example.com
        fin.eu.service.geo.example.com:
          - a: 192.0.2.2
          - txt: hello world
          - aaaa: 2001:DB8::12:34DE:3
    # this will result first record being handed out 30% of time
        swe.eu.service.geo.example.com:
          - a:
               content: 192.0.2.3
               weight: 50
          - a: 192.0.2.4
      services:
    # syntax 1
        service.geo.example.com: '%co.%cn.service.geo.example.com'
    # syntax 2
        service.geo.example.com: [ '%co.%cn.service.geo.example.com', '%cn.service.geo.example.com']
    # alternative syntax
      services:
        service.geo.example.com:
          default: [ '%co.%cn.service.geo.example.com', '%cn.service.geo.example.com' ]
          10.0.0.0/8: 'internal.service.geo.example.com'

Keys explained
~~~~~~~~~~~~~~

:domains: Mandatory root key. All configuration is below this

  :domain: Defines a domain. You need ttl, records, services under this.
  :ttl: TTL value for all records, if no TTL is specified in specific record.
  :records: Records for this domain.
            Each subkey must be a fully qualified name, under which an array of records follows.
            Every record is then keyed by its type (e.g. ``a``, ``txt``) and a type may exist more than once.
            The content for this record may then be configured as the value.
            However, a record can alternatively have one or more subkeys:

            :content: The content of the record.
            :ttl: The TTL for this record.
            :weight: The weight for this specific content

  :services: Defines one or more services for querying.
             Each service name may have one or more placeholders.

.. note::

  For each **domain**, one record of the domain name **MUST** exist with a ``soa`` record.

Placeholders
~~~~~~~~~~~~

Services, domains and record content can contain any number of placeholders that are replaced based on the information in the database and the query.

Following placeholders are supported, and support subnet caching with EDNS:

:%%:   literal ``%``
:%co:  With legacy GeoIP database only expands to three letter country name,
       with MMDB and others this will expand into ISO3166 country code.
:%cc:  ISO3166 country code.
:%cn:  ISO3166 continent code.
:%af:  v4 or v6.
:%re:  Region code
:%na:  AS organization name (spaces are converted to _)
:%as:  AS number
:%ci:  City name
:%loc: LOC record style expansion of location
:%lat: Decimal degree latitude
:%lon: Decimal degree longitude

These placeholders disable caching for the record completely:

:%yy: Year
:%mos: Month name
:%mo: Month
:%wds: Weekday name
:%wd: Weekday
:%dd: Year day
:%hh: Hour
:%ip: Client IP address
:%ip4: Client IPv4 address
:%ip6: Client IPv6 address

.. versionadded:: 4.2.0

  These placeholders have been added in version 4.2.0:

  - %lat, %lon, %loc to expand for geographic location, if available in backend. %loc in particular can be safely used with LOC record type.
  - %ip4 and %ip6 that will expand to the IP address when AFI matches, and empty otherwise. Can be particularly used with A and AAAA record types.

.. versionadded:: 4.1.0

  These placeholders have been added in version 4.1.0:

  - %cc = 2 letter country code

Using the ``weight`` attribute
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can use record attributes to define positive and non-zero weight.
If this is given, only one record per type is chosen randomly based on the weight.

Probability is calculated by summing up the weights and dividing each weight with the sum.

Responses to queries
~~~~~~~~~~~~~~~~~~~~

If the record which a service points to exists under "records" then it is returned as a direct answer.
If it does not exist under "records" then it is returned as a CNAME.

You can mix service and static records to produce the sum of these records, including apex record.
For instance, this configuration will send the correct response for both A and SOA queries:

.. code-block:: yaml

  domains:
  - domain: example.com
  - ttl: 300
  - records:
    geo.example.com:
      - soa: ns1.example.com hostmaster.example.com 2014090125 7200 3600 1209600 3600
      - ns: ns1.example.com
      - a: 192.0.2.1
    swe.eu.example.com:
      - a: 192.0.2.2
  - services:
    geo.example.com: ['%co.%cn.example.com']

If your services match wildcard records in your zone file then these will be returned as CNAMEs.
This will only be an issue if you are trying to use a service record at the apex of your domain where you need other record types to be present (such as NS and SOA records).
Per :rfc:`2181`, CNAME records cannot appear in the same label as NS or SOA records.

.. versionchanged:: 4.2.0

  Before, a record expanded to an empty value would cause a SERVFAIL response.
  Since 4.2.0 such expansions for non-TXT record types are not included in response.

Caching and the GeoIP Backend
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The :ref:`packet-cache` and :ref:`query-cache` will cache the records with EDNS Client Subnet information, when provided in the response.
Use of certain placeholders (described above) can disable record caching for certain resource records.

That means, if you have a record like this:

.. code-block:: yaml

  something.example.com:
    - a: 1.2.3.4
    - txt: "your ip is %ip"

then caching will not happen for any records of something.example.com.

If you need to use TXT for debugging, make sure you use a dedicated name for it.
