Preset variables
----------------

LUA rules run within the same environment as described in
:doc:`../modes-of-operation`.

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

  - ``selector``: used to pick the IP address from list of viable candidates. Choices include 'pickclosest', 'random', 'hashed', 'all' (default to 'random').
  - ``backupSelector``: used to pick the IP address from list of all candidates if all addresses are down. Choices include 'pickclosest', 'random', 'hashed', 'all' (default to 'random').
  - ``source``: Source IP address to check from


.. function:: ifurlup(url, addresses[, options])

  More sophisticated test that attempts an actual http(s) connection to
  ``url``. In addition, multiple groups of IP addresses can be supplied. The
  first set with a working (available) IP address is used. URL is considered up if
  HTTP response code is 200 and optionally if the content matches ``stringmatch``
  option.

  :param string url: The url to retrieve.
  :param addresses: List of lists of IP addresses to check the URL on.
  :param options: Table of options for this specific check, see below.

  Various options can be set in the ``options`` parameter:

  - ``selector``: used to pick the IP address from list of viable candidates. Choices include 'pickclosest', 'random', 'hashed', 'all' (default to 'random').
  - ``backupSelector``: used to pick the IP address from list of all candidates if all addresses are down. Choices include 'pickclosest', 'random', 'hashed', 'all' (default to 'random').
  - ``source``: Source IP address to check from
  - ``stringmatch``: check ``url`` for this string, only declare 'up' if found
  - ``useragent``: Set the HTTP "User-Agent" header in the requests. By default it is set to "PowerDNS Authoritative Server"

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
~~~~~~~~~~~~~~~~~~~~~

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
  two letter ISO country code passed, as described in :doc:`../backends/geoip`.

  :param string country: A country code like "NL"
  :param [string] countries: A list of country codes

.. function:: continent(continent)
              continent(continents)

  Returns true if the ``bestwho`` IP address of the client is within the
  continent passed, as described in :doc:`../backends/geoip`.

  :param string continent: A continent code like "EU"
  :param [string] continents: A list of continent codes

.. function:: netmask(netmasks)

  Returns true if ``bestwho`` is within any of the listed subnets.

  :param [string] netmasks: The list of IP addresses to check against
