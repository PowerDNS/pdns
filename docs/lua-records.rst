Lua Records
===========

To facilitate dynamic behaviour, such as Global Server Load Balancing,
PowerDNS Authoritative Server version 4.1.1 and later support dynamic DNS
records.

These records contain small snippets of configuration that enable dynamic
behaviour based on requestor IP address, requestor's EDNS Client Subnet,
server availability or other factors.

Capabilities range from very simple to highly advanced multi-pool
geographically & weighed load balanced IP address selection.

Although users need not be aware, PowerDNS dynamic DNS records are actually
tiny (or larger) `Lua <https://www.lua.org>`_ statements. 

.. note::
  This is a PowerDNS specific feature, and is not (yet) standardized by the
  IETF or other standards bodies. We are committed however to
  interoperability, and strive to turn this functionalitity into a broadly
  supported standard.

Examples
--------

Before delving into the details, some examples may be of use to explain what
dynamic records can do.

Here is a very basic example::

     www	IN	LUA	A	"return ifportup(443, {'192.0.2.1', '192.0.2.2'})"

This turns the 'www' name within a zone into a magical record that will
randomly return 192.0.2.1 or 192.0.2.2, as long as both of these IP
addresses listen on port 443. 

If either IP address stops listening, only the other address will be
returned. If all IP addresses are down a random one is returned anyhow.

Because DNS queries require rapid answers, server availability is not checked
synchronously. In the background, a process periodically determines if IP
addresses mentioned in availability rules are, in fact, available.

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

    west    IN    LUA    A    ( "return ifurlup('https://www.lua.org/',           "
                                "{{'192.0.2.1', '192.0.2.2'}, {'198.51.100.1'}},  "
                                "{stringmatch='Programming in Lua'})              " )

In this case, IP addresses are tested to see if they will serve
https for 'www.lua.org', and if that page contains the string 'Programming
in Lua'.

Two sets of IP addresses are supplied.  If an IP address from the first set
is available, it will be returned. If no addresses work in the first set,
the second set is tried.

This configuration makes sense in the following context::

    www    IN    LUA    CNAME   ( "if(continent('EU')) then return 'west.powerdns.org' "
                                  "else return 'usa.powerdns.org' end" )


This sends queries that are geolocated to Europe to 'west.powerdns.org', and
the rest to 'usa.powerdns.org'. The configuration for that name would then
be::

    usa    IN    LUA    A    ( "return ifurlup('https://www.lua.org/',           "
                               "{{'198.51.100.1'}, {'192.0.2.1', '192.0.2.2'}},  "
                               "{stringmatch='Programming in Lua'})              " )

Note that the sets of IP addresses have reversed order - visitors geolocated
outside of Europe will hit 198.51.100.1 as long as it is available, and the
192.0.2.1 and 192.0.2.2 servers as backup.

Advanced topics
---------------

To keep records more concise and readable, configuration can be stored in
separate records. The full example from above can also be written as::

    config    IN    LUA    LUA ("settings={stringmatch='Programming in Lua'}  "
                                "EUips={'192.0.2.1', '192.0.2.2'}             "
                                "USAips={'198.51.100.1'}                      ")

    www       IN    LUA    CNAME ( "if(continent('EU')) then return 'west.powerdns.org' "
                                   "else return 'usa.powerdns.org' end" )

    usa       IN    LUA    A    ( "include(config)                               "
                                  "return ifurlup('https://www.lua.org/',        "
                                  "{USAips, EUips}, settings)                    " )

    west      IN    LUA    A    ( "include(config)                               "
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


``ecs-who``
~~~~~~~~~~~
The EDNS Client Subnet, should one have been set on the query. Unset
otherwise.

``best-who``
~~~~~~~~~~~~
In absence of ECS, this is set to the IP address of requesting resolver. 
Otherwise set to the network part of the EDNS Client Subnet supplied by the
resolver.

Functions available
-------------------

``ifportup(portnum, {'ip1', 'ip2'})``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Simplistic test to see if an IP address listens on a certain port. Note that
both IPv4 and IPv6 addresses can be tested, but that it is an error to list
IPv4 addresses on an AAAA record, or IPv6 addresses on an A record.

Will return a single IP address from the set of available IP addresses. If
no IP address is available, will return a random element of the set of
addresses suppplied for testing.

``ifurlup(url, {{'ip1', 'ip2'}, {ip3}, options)``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
More sophisticated test that attempts an actual http(s) connection to
``url``. In addition, multiple groups of IP addresses can be supplied. The
first set with a working (available) IP address is used. 

If all addresses are down, as usual, a random element from all sets is
returned.

Various options can be set in the ``options`` parameter:

 - ``interval``: number of seconds to wait between checks
 - ``stringmatch``: check ``url`` for this string, only declare 'up' if
   found

``pickrandom({'ip1', ip2'})``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Returns a random IP address from the list supplied.

``view({{{'netmask1', 'netmask2'}, {'content1', 'content2'}}, ...})``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Shorthand function to implement 'views' for all record types.

The input consists of a list of netmask/result pairs. 

An example::

    view.v4.powerdns.org    IN    LUA    A ("return view({                           "
                                            "{ {'192.168.0.0/16'}, {'192.168.1.54'}}," 
                                            "{ {'0.0.0.0/0'}, {'1.2.3.4'}}           "
                                            " }) " )

This will return IP address 192.168.1.54 for queries coming from
192.168.0.0/16, and 1.2.3.4 for all other queries.

This function also works for CNAME or TXT records.

``wrandom({{weight, 'ip1'}, {weight, 'ip2'}})``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
Returns a random IP address from the list supplied, as weighted by the
various ``weight`` parameters. Performs no uptime checking.

``country('NL')``
~~~~~~~~~~~~~~~~~
Returns true if the ``best-who`` IP address of the client is within the
two letter ISO country code passed, as described in :doc:`backends/geoip`.

``continent('EU')``
~~~~~~~~~~~~~~~~~~~
Returns true if the ``best-who`` IP address of the client is within the
continent passed, as described in :doc:`backends/geoip`. 

Details & Security
------------------
LUA records are synthesized on query. They can also be transferred via AXFR
to other PowerDNS servers. LUA records themselves can not be queried
however, as this would allow third parties to see load balancing internals
they do not need to see.

A non-supporting DNS server will also serve a zone with LUA records, but
they will not function.

LUA records can be DNSSEC signed, but because they are dynamic, it is not
possible to combine pre-signed DNSSEC zone and LUA records. In other words,
the signing key must be available on the server creating answers based on
LUA records.
