TinyDNS Backend
===============

* Native: Yes
* Primary: Yes
* Secondary: No
* Producer: No
* Consumer: No
* Autosecondary: No
* DNS Update: No
* DNSSEC: No
* Disabled data: No
* Comments: No
* API: Read-only
* Multiple Instances: Yes
* Zone caching: Yes
* Module name: tinydns
* Launch: ``tinydns``

The TinyDNS backend allows you to use
`djbdns's <https://cr.yp.to/djbdns.html>`__ ``data.cdb`` file format as
the storage of your DNS records. The ``data.cdb`` file is created using
`tinydns-data <https://cr.yp.to/djbdns/tinydns-data.html>`__. The backend
is designed to be able to use the ``data.cdb`` files without any
changes.

Configuration Parameters
------------------------

These are the configuration file parameters that are available for the
TinyDNS backend. It is recommended to set the ``tinydns-dbfile``.

.. _setting-tinydns-dbfile:

``tinydns-dbfile``
~~~~~~~~~~~~~~~~~~

-  String
-  Default: data.cdb

Specifies the name of the data file to use.

.. _setting-tinydns-tai-adjust:

``tinydns-tai-adjust``
~~~~~~~~~~~~~~~~~~~~~~

-  Integer
-  Default: 11

This adjusts the `TAI <https://cr.yp.to/libtai/tai64.html>`__ value if
timestamps are used. These seconds will be added to the start point (1970)
and will allow you to adjust for leap seconds. The current default is 11.
The last update was on `January 1st,
2017 <https://hpiers.obspm.fr/iers/bul/bulc/bulletinc.dat>`__.

.. _setting-tinydns-notify-on-startup:

``tinydns-notify-on-startup``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Boolean
-  Default: no

Tell the TinyDNSBackend to notify all the slave nameservers on startup.
This might cause broadcast storms.

.. _setting-tinydns-ignore-bogus-records:

``tinydns-ignore-bogus-records``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

-  Boolean
-  Default: no

The ``tinydns-data`` program can create data.cdb files that have
bad/corrupt RDATA. PowerDNS will crash when it tries to read that
bad/corrupt data. This option (change to yes), allows you to ignore that
bad RDATA to make PowerDNS operate when bad data is in your CDB file. Be
aware that the records are then ignored, where tinydns would still send
out the bogus data. The option is primarily useful in master mode, as
that reads all the packets in the zone to find all the SOA records.

.. _setting-tinydns-locations:

``tinydns-locations``
~~~~~~~~~~~~~~~~~~~~~

-  Boolean
-  Default: yes

Enable or Disable location support in the backend. Changing the value to
'no' will make the backend ignore the locations. This then returns all
records. When the setting is changed to 'no' an AXFR will also return
all the records. With the setting on 'yes' an AXFR will only return
records without a location.

Location and Timestamp support
------------------------------

Both timestamp and location are supported in the backend.
Locations support can be changed using the :ref:`setting-tinydns-locations` setting.
Timestamp and location only work as expected when :ref:`setting-cache-ttl` and :ref:`setting-query-cache-ttl` are set to 0 (which disables these caches).
Timestamp can operate with :ref:`setting-cache-ttl` if cache is needed, but the
TTL returned for the timestamped racked will not be totally correct. The
record will expire once the cache is expired and the backend is queried
again. Please note that :ref:`setting-cache-ttl` is a
performance related setting. See :doc:`../performance`. Location support only exists for IPv4!

Master mode
-----------

The TinyDNSBackend supports master mode. This allows it to notify slave
nameservers of updates to a zone. You simply need to rewrite the
``data.cdb`` file with an updated/increased serial and PowerDNS will
notify the slave nameservers of that domain. The :ref:`setting-tinydns-notify-on-startup`
configuration setting tells the backend if it should notify all the
slave nameservers just after startup.

The CDB datafile does not allow PowerDNS to easily query for newly added
domains or updated serial numbers. The CDB datafile requires us to do a
full scan of all the records. When running with verbose logging, this
could lead to a lot of output. The scanning of the CDB file may also
take a while on systems with large files. The scan happens at an
interval set by the :ref:`setting-xfr-cycle-interval`. It
might be useful to raise this value to limit the amount of scans on the
CDB file.

The TinyDNSBackend also keeps a list of all the zones. This is needed to
detect an updated serial and to give every zone a unique id. The list is
updated when a zone is added, but not when a zone is removed. This leads
to some memory loss.

Useful implementation Notes
---------------------------

This backend might solve some issues you have with the current tinydns
noted on `Jonathan de Boyne
Pollard's <http://jdebp.uk/about-the-author.html>`__
`djbdns known problems
page <http://jdebp.uk/FGA/djbdns-problems.html>`__.

The ``data.cdb`` file format support all types of records. They are
sometimes difficult to create because you need to specify the actual
content of the rdata. `Tinydns.org <http://tinydns.org/>`__ provides a
number of links to tools/cgi-scripts that allow you to create records.
`Anders Brownworth <https://andersbrownworth.com/>`__ also provides a number of
useful record building scripts on his
`djbdnsRecordBuilder <https://andersbrownworth.com/projects/sysadmin/djbdnsRecordBuilder/>`__.

PowerDNS and TinyDNS handle wildcards differently. Looking up
foo.www.example.com with the below records on TinyDNS will return
198.51.100.1, PowerDNS will return NXDOMAIN. According to :rfc:`4592` \*.example.com should only
match subdomains in under example.com, not \*.\*.example.com. This
compatibility issue is `noted on the axfr-get page for the djbdns
suite <https://cr.yp.to/djbdns/axfr-get.html>`__.

::

    *.example.com     A 198.51.100.1
    www.example.com   A 198.51.100.1

Compiling the TinyDNS backend requires you to have
`tinycdb <http://www.corpit.ru/mjt/tinycdb.html>`__ version 0.77.
