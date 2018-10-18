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

  - ``selector``: used to pick the IP address from list of viable candidates. Choices include 'closest', 'random', 'hashed'.
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

  - ``selector``: used to pick the IP address from list of viable candidates. Choices include 'closest', 'random', 'hashed'.
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
