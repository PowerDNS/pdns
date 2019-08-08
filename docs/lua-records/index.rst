Lua Records
===========

To facilitate dynamic behaviour, such as Global Server Load Balancing,
PowerDNS Authoritative Server version 4.2 and later support dynamic DNS
records.

These records contain small snippets of configuration that enable dynamic
behaviour based on requester IP address, requester's EDNS Client Subnet,
server availability or other factors.

Capabilities range from very simple to highly advanced multi-pool
geographically & weighed load balanced IP address selection.

Although users need not be aware, PowerDNS dynamic DNS records are actually
tiny (or larger) `Lua <https://www.lua.org>`_ statements.

.. note::
  This is a PowerDNS specific feature, and is not (yet) standardized by the
  IETF or other standards bodies. We are committed however to
  interoperability, and strive to turn this functionality into a broadly
  supported standard.

To enable this feature, either set 'enable-lua-records' in the configuration,
or set the 'ENABLE-LUA-RECORDS' per-zone metadata item to 1.

In addition, to benefit from the geographical features, make sure the PowerDNS
launch statement includes the ``geoip`` backend.

Examples
--------

Before delving into the details, some examples may be of use to explain what
dynamic records can do.

Here is a very basic example::

     www    IN    LUA    A    "ifportup(443, {'192.0.2.1', '192.0.2.2'})"

This turns the 'www' name within a zone into a special record that will
randomly return 192.0.2.1 or 192.0.2.2, as long as both of these IP
addresses listen on port 443.

If either IP address stops listening, only the other address will be
returned. If all IP addresses are down, all candidates are returned.

Because DNS queries require rapid answers, server availability is not checked
synchronously. In the background, a process periodically determines if IP
addresses mentioned in availability rules are, in fact, available.

Another example::

    www    IN    LUA    A    "pickclosest({'192.0.2.1','192.0.2.2','198.51.100.1'})"

This uses the GeoIP backend to find indications of the geographical location of
the requester and the listed IP addresses. It will return with one of the closest
addresses.

``pickclosest`` and ifportup can be combined as follows::

  www    IN    LUA    A    ("ifportup(443, {'192.0.2.1', '192.0.2.2', '198.51.100.1'}"
                            ", {selector='pickclosest'})                             ")

This will pick from the viable IP addresses the one deemed closest to the user.

Using LUA Records with Generic SQL backends
-------------------------------------------

It's possible to use Lua records with the Generic SQL backends such as gmysql and gpgsql.

Be aware that due to the fact that Lua records uses both double and single quotes, you will
need to appropriately escape them in INSERT/UPDATE queries.

Here is an example from the previous section (``pickclosest``) which should work 
for both **MySQL** and **PostgreSQL**::

    -- Create the zone example.com
    INSERT INTO domains (id, name, type) VALUES (1, 'example.com', 'NATIVE');

    -- Enable Lua records for the zone (if not enabled globally)
    INSERT INTO domainmetadata (domain_id, kind, content) 
    VALUES (1, 'ENABLE-LUA-RECORDS', 1);

    -- Create a pickClosest() Lua A record.
    -- Double single quotes are used to escape single quotes in both MySQL and PostgreSQL
    INSERT INTO records (domain_id, name, type, content, ttl)
    VALUES (
      1, 
      'www.example.com',
      'LUA', 
      'A "pickclosest({''192.0.2.1'',''192.0.2.2'',''198.51.100.1''})"',
      600
    );

The above queries create a zone ``example.com``, enable Lua records for the zone using ``ENABLE-LUA-RECORDS``,
and finally insert a LUA A record for the ``www`` subdomain using the previous pickclosest example.

See `Details & Security`_ for more information about enabling Lua records, and the risks involved.

Record format
-------------
.. note::
  The fine authors of the Lua programming language insist that it is Lua and
  not LUA. Lua means 'moon' in Portuguese, and it is not an abbreviation.
  Sadly, it is DNS convention for record types to be all uppercase. Sorry.

The LUA record consists of an initial query type, which is the selector on
which the snippet will trigger. Optionally this query type itself can be LUA
again for configuration scripts. The query type is then followed by the
actual Lua snippet.

LUA records can have TTL settings, and these will be honoured. In addition,
LUA records output can be DNSSEC signed like any other record, but see below
for further details.

More powerful example
---------------------

A more powerful example::

    west    IN    LUA    A    ( "ifurlup('https://www.lua.org/',                  "
                                "{{'192.0.2.1', '192.0.2.2'}, {'198.51.100.1'}},  "
                                "{stringmatch='Programming in Lua'})              " )

In this case, IP addresses are tested to see if they will serve
https for 'www.lua.org', and if that page contains the string 'Programming
in Lua'.

Two sets of IP addresses are supplied.  If an IP address from the first set
is available, it will be returned. If no addresses work in the first set,
the second set is tried.

This configuration makes sense in the following context::

    www    IN    LUA    CNAME   ( ";if(continent('EU')) then return 'west.powerdns.org' "
                                  "else return 'usa.powerdns.org' end" )


This sends queries that are geolocated to Europe to 'west.powerdns.org', and
the rest to 'usa.powerdns.org'. The configuration for that name would then
be::

    usa    IN    LUA    A    ( "ifurlup('https://www.lua.org/',           "
                               "{{'198.51.100.1'}, {'192.0.2.1', '192.0.2.2'}},  "
                               "{stringmatch='Programming in Lua'})              " )

Note that the sets of IP addresses have reversed order - visitors geolocated
outside of Europe will hit 198.51.100.1 as long as it is available, and the
192.0.2.1 and 192.0.2.2 servers as backup.

Advanced topics
---------------
By default, LUA records are executed with 'return ' prefixed to them. This saves
a lot of typing for common cases. To run actual Lua scripts, start a record with a ';'
which indicates no 'return ' should be prepended.

To keep records more concise and readable, configuration can be stored in
separate records. The full example from above can also be written as::

    config    IN    LUA    LUA ("settings={stringmatch='Programming in Lua'}  "
                                "EUips={'192.0.2.1', '192.0.2.2'}             "
                                "USAips={'198.51.100.1'}                      ")

    www       IN    LUA    CNAME ( ";if(continent('EU')) then return 'west.powerdns.org' "
                                   "else return 'usa.powerdns.org' end" )

    usa       IN    LUA    A    ( ";include('config')                               "
                                  "return ifurlup('https://www.lua.org/',        "
                                  "{USAips, EUips}, settings)                    " )

    west      IN    LUA    A    ( ";include('config')                               "
                                  "return ifurlup('https://www.lua.org/',        "
                                  "{EUips, USAips}, settings)                    " )

Details & Security
------------------
LUA records are synthesized on query. They can also be transferred via AXFR
to other PowerDNS servers.

LUA records themselves can not be queried however, as this would allow third parties to see load balancing internals
they do not need to see.

A non-supporting DNS server will also serve a zone with LUA records, but
they will not function, and will in fact leak the content of the LUA records.

.. note::
  Under NO circumstances serve LUA records from zones from untrusted sources!
  LUA records will be able to bring down your system and possible take over
  control of it. Use TSIG on AXFR even from trusted sources!

LUA records can be DNSSEC signed, but because they are dynamic, it is not
possible to combine pre-signed DNSSEC zone and LUA records. In other words,
the signing key must be available on the server creating answers based on
LUA records.

Note that to protect operators, support for LUA records must be enabled
explicitly, either globally (``enable-lua-records``) or per zone
(``ENABLE-LUA-RECORDS`` = 1).

.. _lua-records-shared-state:

Shared Lua state model
----------------------

The default mode of operation for LUA records is to create a fresh Lua state for every query that hits a LUA record.
This way, different LUA records cannot accidentally interfere with each other, by leaving around global objects, or perhaps even deleting relevant functions.
However, creating a Lua state (and registering all our functions for it, see Reference below) takes measurable time.
For users that are confident they can write Lua scripts that will not interfere with eachother, a mode is supported where Lua states are created on the first query, and then reused forever.
Note that the state is per-thread, so while data sharing between LUA invocations is possible (useful for caching and reducing the cost of ``require``), there is not a single shared Lua environment.
In non-scientific testing this has yielded up to 10x QPS increases.

To use this mode, set ``enable-lua-records=shared``.
Note that this enables LUA records for all zones.

Reference
---------

.. toctree::
  :maxdepth: 2

  functions
  reference/index
