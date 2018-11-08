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

To enable this feature, either set 'enable-lua-record' in the configuration,
or set the 'ENABLE-LUA-RECORD' per-zone metadata item to 1.  

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
                            ", {selector='pickclosest'})                                 ")

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
    VALUES (1, 'ENABLE-LUA-RECORD', 1);

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

The above queries create a zone ``example.com``, enable Lua records for the zone using ``ENABLE-LUA-RECORD``,
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
LUA record output can be DNSSEC signed like any other record, but see below
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



Preset variables
----------------

LUA rules run within the same environment as described in
:doc:`modes-of-operation`.

The Lua snippets can query the following variables:

``who``
~~~~~~~
IP address of requesting resolver


``ecswho``
~~~~~~~~~~~
The EDNS Client Subnet, should one have been set on the query. Unset
otherwise.

``bestwho``
~~~~~~~~~~~~
In absence of ECS, this is set to the IP address of requesting resolver.
Otherwise set to the network part of the EDNS Client Subnet supplied by the
resolver.

Functions available
-------------------

Record creation functions
~~~~~~~~~~~~~~~~~~~~~~~~~

.. function:: ifportup(portnum, addresses[, options])

  Simplistic test to see if an IP address listens on a certain port. This will
  attempt a TCP connection on port ``portnum`` and consider it UP if the
  connection establishes, no data will be sent or read on that connection. Note
  that both IPv4 and IPv6 addresses can be tested, but that it is an error to
  list IPv4 addresses on an AAAA record, or IPv6 addresses on an A record.

  Will return a single IP address from the set of available IP addresses. If
  no IP address is available, will return a random element of the set of
  addresses supplied for testing.

  :param int portnum: The port number to test connections to.
  :param {str} addresses: The list of IP addresses to check connectivity for.
  :param options: Table of options for this specific check, see below.

  Various options can be set in the ``options`` parameter:

  - ``selector``: used to pick the IP address from list of viable candidates. Choices include 'pickclosest', 'random', 'hashed'.
  - ``source``: Source IP address to check from


.. function:: ifurlup(url, addresses[, options])

  More sophisticated test that attempts an actual http(s) connection to
  ``url``. In addition, multiple groups of IP addresses can be supplied. The
  first set with a working (available) IP address is used.

  If all addresses are down, as usual, a random element from all sets is
  returned.

  :param string url: The url to retrieve.
  :param addresses: List of lists of IP addresses to check the URL on.
  :param options: Table of options for this specific check, see below.

  Various options can be set in the ``options`` parameter:

  - ``selector``: used to pick the IP address from list of viable candidates. Choices include 'pickclosest', 'random', 'hashed'.
  - ``source``: Source IP address to check from
  - ``stringmatch``: check ``url`` for this string, only declare 'up' if found

  An example of IP address sets:

  .. code-block:: lua

    ifurlup("example.com", { {"192.0.2.20", "203.0.113.4"}, {"203.0.113.2"} })

.. function:: pickrandom(addresses)

  Returns a random IP address from the list supplied.

  :param addresses: A list of strings with the possible IP addresses.

.. function:: pickclosest(addresses)

  Returns IP address deemed closest to the ``bestwho`` IP address.

  :param addresses: A list of strings with the possible IP addresses.

.. function:: latlon()

  Returns text listing fractional latitude/longitude associated with the ``bestwho`` IP address.

.. function:: latlonloc()

  Returns text in LOC record format listing latitude/longitude associated with the ``bestwho`` IP address.

.. function:: closestMagic()

  Suitable for use as a wildcard LUA A record. Will parse the query name which should be in format::

    192-0-2-1.192-0-2-2.198-51-100-1.magic.v4.powerdns.org

  It will then resolve to an A record with the IP address closest to ``bestwho`` from the list
  of supplied addresses.

  In the ``magic.v4.powerdns.org`` this looks like::

    *.magic.v4.powerdns.org    IN    LUA    A    "closestMagic()"


  In another zone, a record is then present like this::

    www-balanced.powerdns.org    IN    CNAME    192-0-2-1.192-0-2-2.198-51-100-1.magic.v4.powerdns.org

  This effectively opens up your server to being a 'geographical load balancer as a service'.

  Performs no uptime checking.

.. function:: view(pairs)

  Shorthand function to implement 'views' for all record types.

  :param pairs: A list of netmask/result pairs.

  An example::

      view.v4.powerdns.org    IN    LUA    A ("view({                                  "
                                              "{ {'192.168.0.0/16'}, {'192.168.1.54'}},"
                                              "{ {'0.0.0.0/0'}, {'192.0.2.1'}}         "
                                              " }) " )

  This will return IP address 192.168.1.54 for queries coming from
  192.168.0.0/16, and 192.0.2.1 for all other queries.

  This function also works for CNAME or TXT records.

.. function:: pickwhashed(weightparams)

  Based on the hash of ``bestwho``, returns an IP address from the list
  supplied, as weighted by the various ``weight`` parameters.
  Performs no uptime checking.

  :param weightparams: table of weight, IP addresses.

  Because of the hash, the same client keeps getting the same answer, but
  given sufficient clients, the load is still spread according to the weight
  factors.

  An example::

    mydomain.example.com    IN    LUA    A ("pickwhashed({                             "
                                            "        {15,  "192.0.2.1"},               "
                                            "        {100, "198.51.100.5"}             "
                                            "})                                        ")


.. function:: pickwrandom(weightparams)

  Returns a random IP address from the list supplied, as weighted by the
  various ``weight`` parameters. Performs no uptime checking.

  :param weightparams: table of weight, IP addresses.

  See :func:`pickwhashed` for an example.

Reverse DNS functions
~~~~~~~~~~~~~~~~~~~~~~~~~

.. warning::
  The reverse DNS functions are under active development. **They may**
  **not be safe for production use.** The syntax of these functions may change at any
  time.

.. function:: createReverse(format)

  Used for generating default hostnames from IPv4 wildcard reverse DNS records, e.g. ``*.0.0.127.in-addr.arpa`` 
  
  See :func:`createReverse6` for IPv6 records (ip6.arpa)

  See :func:`createForward` for creating the A records on a wildcard record such as ``*.static.example.com``
  
  Returns a formatted hostname based on the format string passed.

  :param format: A hostname string to format, for example ``%1%.%2%.%3%.%4%.static.example.com``.
  
  **Formatting options:**

    - ``%1%`` to ``%4%`` are individual octets
        - Example record query: ``1.0.0.127.in-addr.arpa`` 
        - ``%1%`` = 127
        - ``%2%`` = 0
        - ``%3%`` = 0
        - ``%4%`` = 1
    - ``%5%`` joins the four decimal octets together with dashes
        - Example: ``%5%.static.example.com`` is equivalent to ``%1%-%2%-%3%-%4%.static.example.com``
    - ``%6%`` converts each octet from decimal to hexadecimal and joins them together
        - Example: A query for ``15.0.0.127.in-addr.arpa`` 
        - ``%6`` would be ``7f00000f`` (127 is 7f, and 15 is 0f in hexadecimal)

  **NOTE:** At the current time, only forward dotted format works with :func:`createForward` (i.e. ``127.0.0.1.static.example.com``)
  
  Example records::
  
    *.0.0.127.in-addr.arpa IN    LUA    PTR "createReverse('%1%.%2%.%3%.%4%.static.example.com')"
    *.1.0.127.in-addr.arpa IN    LUA    PTR "createReverse('%5%.static.example.com')"
    *.2.0.127.in-addr.arpa IN    LUA    PTR "createReverse('%6%.static.example.com')"
 
  When queried::
  
    # -x is syntactic sugar to request the PTR record for an IPv4/v6 address such as 127.0.0.5
    # Equivalent to dig PTR 5.0.0.127.in-addr.arpa
    $ dig +short -x 127.0.0.5 @ns1.example.com
    127.0.0.5.static.example.com.
    $ dig +short -x 127.0.1.5 @ns1.example.com
    127-0-0-5.static.example.com.
    $ dig +short -x 127.0.2.5 @ns1.example.com
    7f000205.static.example.com.

.. function:: createForward()
  
  Used to generate the reverse DNS domains made from :func:`createReverse`
  
  Generates an A record for a dotted or hexadecimal IPv4 domain (e.g. 127.0.0.1.static.example.com)
  
  It does not take any parameters, it simply interprets the zone record to find the IP address.
  
  An example record for zone ``static.example.com``::
    
    *.static.example.com    IN    LUA    A "createForward()"
  
  **NOTE:** At the current time, only forward dotted format works for this function (i.e. ``127.0.0.1.static.example.com``)
  
  When queried::
  
    $ dig +short A 127.0.0.5.static.example.com @ns1.example.com
    127.0.0.5
  
.. function:: createReverse6(format)

  Used for generating default hostnames from IPv6 wildcard reverse DNS records, e.g. ``*.1.0.0.2.ip6.arpa``
  
  **For simplicity purposes, only small sections of IPv6 rDNS domains are used in most parts of this guide,**
  **as a full ip6.arpa record is around 80 characters long**
  
  See :func:`createReverse` for IPv4 records (in-addr.arpa)

  See :func:`createForward6` for creating the AAAA records on a wildcard record such as ``*.static.example.com``
  
  Returns a formatted hostname based on the format string passed.

  :param format: A hostname string to format, for example ``%33%.static6.example.com``.
  
  Formatting options:
   
    - ``%1%`` to ``%32%`` are individual characters (nibbles)
        - **Example PTR record query:** ``a.0.0.0.1.0.0.2.ip6.arpa``
        - ``%1%`` = 2
        - ``%2%`` = 0
        - ``%3%`` = 0
        - ``%4%`` = 1
    - ``%33%`` converts the compressed address format into a dashed format, e.g. ``2001:a::1`` to ``2001-a--1``
    - ``%34%`` to ``%41%`` represent the 8 uncompressed 2-byte chunks
        - **Example:** PTR query for ``2001:a:b::123``
        - ``%34%`` - returns ``2001`` (chunk 1)
        - ``%35%`` - returns ``000a`` (chunk 2)
        - ``%41%`` - returns ``0123`` (chunk 8)
  
  **NOTE:** At the current time, only dashed compressed format works for this function (i.e. ``2001-a-b--1.static6.example.com``)
  
  Example records::
  
    *.1.0.0.2.ip6.arpa IN    LUA    PTR "createReverse('%33%.static6.example.com')"
    *.2.0.0.2.ip6.arpa IN    LUA    PTR "createReverse('%34%.%35%.static6.example.com')"
 
  When queried::
  
    # -x is syntactic sugar to request the PTR record for an IPv4/v6 address such as 2001::1
    # Equivalent to dig PTR 1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.b.0.0.0.a.0.0.0.1.0.0.2.ip6.arpa
    # readable version:     1.0.0.0 .0.0.0.0 .0.0.0.0 .0.0.0.0 .0.0.0.0 .b.0.0.0 .a.0.0.0 .1.0.0.2 .ip6.arpa
    
    $ dig +short -x 2001:a:b::1 @ns1.example.com
    2001-a-b--1.static6.example.com.
    
    $ dig +short -x 2002:a:b::1 @ns1.example.com
    2002.000a.static6.example.com

.. function:: createForward6()
  
  Used to generate the reverse DNS domains made from :func:`createReverse6`
  
  Generates an AAAA record for a dashed compressed IPv6 domain (e.g. ``2001-a-b--1.static6.example.com``)
  
  It does not take any parameters, it simply interprets the zone record to find the IP address.
  
  An example record for zone ``static.example.com``::
    
    *.static6.example.com    IN    LUA    AAAA "createForward6()"
  
  **NOTE:** At the current time, only dashed compressed format works for this function (i.e. ``2001-a-b--1.static6.example.com``)
  
  When queried::
  
    $ dig +short AAAA 2001-a-b--1.static6.example.com @ns1.example.com
    2001:a:b::1


Helper functions
~~~~~~~~~~~~~~~~

.. function:: asnum(number)
              asnum(numbers)

  Returns true if the ``bestwho`` IP address is determined to be from
  any of the listed AS numbers.

  :param int number: An AS number
  :param [int] numbers: A list of AS numbers

.. function:: country(country)
              country(countries)

  Returns true if the ``bestwho`` IP address of the client is within the
  two letter ISO country code passed, as described in :doc:`backends/geoip`.

  :param string country: A country code like "NL"
  :param [string] countries: A list of country codes

.. function:: continent(continent)
              continent(continents)

  Returns true if the ``bestwho`` IP address of the client is within the
  continent passed, as described in :doc:`backends/geoip`.

  :param string continent: A continent code like "EU"
  :param [string] continents: A list of continent codes

.. function:: netmask(netmasks)

  Returns true if ``bestwho`` is within any of the listed subnets.

  :param [string] netmasks: The list of IP addresses to check against

Details & Security
------------------
LUA records are synthesized on query. They can also be transferred via AXFR
to other PowerDNS servers.

LUA records themselves can not be queried however, as this would allow third parties to see load balancing internals
they do not need to see.

A non-supporting DNS server will also serve a zone with LUA records, but
they will not function, and will in fact leak the contents of the LUA record.

.. note::
  Under NO circumstances serve LUA records from zones from untrusted sources! 
  LUA records will be able to bring down your system and possible take over
  control of it. Use TSIG on AXFR even from trusted sources!

LUA records can be DNSSEC signed, but because they are dynamic, it is not
possible to combine pre-signed DNSSEC zone and LUA records. In other words,
the signing key must be available on the server creating answers based on
LUA records.

Note that to protect operators, support for the LUA record must be enabled
explicitly, either globally (``enable-lua-record``) or per zone
(``ENABLE-LUA-RECORD`` = 1).
