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

This backend allows visitors to be sent to a server closer to them, with
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

You must have geoip database available. As of writing, on debian/ubuntu
systems, you can use apt-get install geoip-database to get one, and the
backend is configured to use the location where these files are
installed as source. On other systems you might need to alter the
database-file and database-file6 attribute. If you don't need ipv4 or
ipv6 support, set the respective setting to "". Leaving it unset leaves
it pointing to default location, preventing the software from starting
up.

Since v4.2.0 libgeoip is optional. You can use also libmaxminddb, but
that is optional too. If no geo backend is provided, no geoip database
based expansions can be used. Other expansions will work.

Configuration Parameters
------------------------

These are the configuration file parameters that are available for the
GeoIP backend. geoip-zones-files is the only thing you must set, if the
defaults suite you.

.. _setting-geoip-database-files:

``geoip-database-files``
~~~~~~~~~~~~~~~~~~~~~~~~

.. deprecated:: 4.2.0
  This setting has been removed

Comma, tab or space separated list of files to open. You can use
`geoip-cvs-to-dat <https://github.com/dankamongmen/sprezzos-world/blob/master/packaging/geoip/debian/src/geoip-csv-to-dat.cpp>`__
to generate your own.

For MMDB files, see `https://github.com/maxmind/getting-started-with-mmdb <https://github.com/maxmind/getting-started-with-mmdb>`

Since v4.2.0, database type is determined by file suffix, or you can use new syntax.
New syntax is ``[driver:]path[;options]``.

Currently supported options for dat driver (legacy libGeoIP):
  - mode=standard, memory, index or mmap

Currently supported options for mmdb driver (libmaxminddb):
  - mode=mmap
  - language=en (which language to use)

.. warning::
  This option has been changed since v4.2.0

.. _setting-geoip-database-cache:

``geoip-database-cache`` (before v4.2.0)
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

Specifies the full path of the zone configuration file to use.

.. _setting-geoip-dnssec-keydir:

``geoip-dnssec-keydir``
~~~~~~~~~~~~~~~~~~~~~~~

Specifies the full path of a directory that will contain DNSSEC keys.
This option enables DNSSEC on the backend. Keys can be created/managed
with ``pdnsutil``, and the backend stores these keys in files with key
flags and active/disabled state encoded in the key filenames.

Zonefile format
---------------

Zone configuration file uses YAML syntax. Here is simple example. Note
that the ‐ before certain keys is part of the syntax.

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

-  **domains**: Mandatory root key. All configuration is below this
-  **domain**: Defines a domain. You need ttl, records, services under
   this.
-  **ttl**: TTL value for all records
-  **records**: Put fully qualified name as subkey, under which you must
   define at least soa: key. Note that this is an array of records, so ‐
   is needed for the values.
-  **services**: Defines one or more services for querying.
-  From 4.2.0, you can also use %lat, %lon, %loc to expand for geographic
   location, if available in backend. %loc in particular can be safely
   used with LOC record type.
-  From 4.2.0, you can also use %ip4 and %ip6 that will expand to the
   IP address when AFI matches, and empty otherwise. Can be particularly
   used with A and AAAA record types.
-  From 4.1.0, you can also use %cc = 2 letter country code
-  From 4.0.0, you can also use %as = ASn, %ip = Remote IP
-  From 4.0.0, you can also use additional specifiers. These are %hh =
   hour, %dd = day, %mo = month, %mos = month as short string, %wd =
   weekday (as number), %wds weekday as short string.
-  From 4.0.0, scopeMask is set to most specific value, in case of
   date/time modifiers it will be 32 or 128, but with the others it is
   set to what geoip says it used for matching.
-  From 4.0.0, You can add per-network overrides for format, they will
   be formatted with the same placeholders as default. Default is
   short-hand for adding 0.0.0.0/0 and ::/0. Default is default when
   only string is given for service name.
-  From 4.0.0, You can use array to specify return values, works only if
   you have those records specified. It matches the format results to
   your records, and if it finds match that is used. Otherwise the last
   is returned.
-  From 4.0.0, You can apply all the attributes for the content of
   static records too.
-  From 4.0.0, You can use record attributes to set TTL.
-  From 4.0.0, You can use record attributes to define weight. If this
   is given, only one record is chosen randomly based on the weight.
   **DO NOT** mix record types for these. It will not work. PROBABILITY
   is calculated by summing up the weights and dividing each weight with
   the sum. **WARNING**: If you use ip or time/date specifiers, caching
   will be disabled for that RR completely. That means, if you have a

something.example.com: - a: 1.2.3.4 - txt: "your ip is %ip"

then caching will not happen for any records of something.example.com.
If you need to use TXT for debugging, make sure you use dedicated name
for it.

Since v4.1.0 you can mix service and static records to produce the sum
of these records, including apex record.

Format explained
~~~~~~~~~~~~~~~~

Following placeholders are supported, and support subnet caching with EDNS.
- %%: %
- %co: With legacy GeoIP database only expands to three letter country name,
       with MMDB and others this will expand into ISO3166 country code.
- %cc: ISO3166 country code.
- %cn: ISO3166 continent code.
- %af: v4 or v6.
- %re: Region code
- %na: AS organization name (spaces are converted to _)
- %as: AS number
- %ci: City name
- %loc: LOC record style expansion of location
- %lat: Decimal degree latitude
- %lon: Decimal degree longitude

Following placeholders disable caching completely.
- %yy: Year
- %mos: Month name
- %mo: Month
- %wds: Weekday name
- %wd: Weekday
- %dd: Year day
- %hh: Hour
- %ip: IP address
- %ip4: IPv4 address
- %ip6: IPv6 address

.. warning::
  Before 4.2.0 if record expanded to empty value it could cause SERVFAIL. Since 4.2.0 such expansions for non-TXT record types are not included in response.

.. warning::
  If the record which a service points to exists under "records" then it is returned as a direct answer. If it does not exist under "records" then it is returned as a CNAME.

.. warning::
  If your services match wildcard records in your zone file
  then these will be returned as CNAMEs. This will only be an issue if you
  are trying to use a service record at the apex of your domain where you
  need other record types to be present (such as NS and SOA records.) Per
  :rfc:`2181`, CNAME records cannot appear in the same label as NS or SOA
  records.
