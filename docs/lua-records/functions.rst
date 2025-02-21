Preset variables
----------------

LUA rules run within the same environment as described in
:doc:`../modes-of-operation`.

The Lua snippets can query the following variables:

Query variables
~~~~~~~~~~~~~~~
``dh``
  The :class:`DNSHeader` of the received query.
``dnssecOK``
  A boolean describing if the DNSSEC OK (DO) bit was set in the query.
``ednsPKTSize``
  The advertised EDNS buffer size.
``qname``
  The name of the requested record. This is a :class:`DNSName`.
``zone``
  The zone this LUA record is in. This is a :class:`DNSName`.
``zoneid``
  The id of the zone. This is an integer.
``tcp``
  Whether or not the query was received over TCP.

Client variables
~~~~~~~~~~~~~~~~
``ecswho``
  The EDNS Client Subnet, should one have been set on the query. Unset
  otherwise. This is a :class:`Netmask`.
``bestwho``
  In absence of ECS, this is set to the IP address of requesting resolver.
  Otherwise set to the network part of the EDNS Client Subnet supplied by the
  resolver. This is a :class:`ComboAddress`.
``who``
  IP address of requesting resolver as a :class:`ComboAddress`.
``localwho``
  IP address (including port) of socket on which the question arrived.

Functions available
-------------------

Record creation functions
~~~~~~~~~~~~~~~~~~~~~~~~~

  .. _if-first-run:

.. warning::
  For functions that require network traffic ``if...(..., addresses[...])``,
  the first time they're called, they effectively treat all addresses as
  failing which means that whatever fallback behavior is used will apply to
  that first resolution.

.. function:: ifportup(portnum, addresses[, options])

  Simplistic test to see if an IP address listens on a certain port. This will
  attempt a TCP connection on port ``portnum`` and consider it available if the
  connection establishes. No data will be sent or read on that connection. Note
  that both IPv4 and IPv6 addresses can be tested, but that it is an error to
  list IPv4 addresses on an AAAA record, or IPv6 addresses on an A record.

  Will return a single address from the set of available addresses. If
  no address is available (but also :ref:`on the first run <if-first-run>`),
  will return a random element of the set of addresses supplied for testing.

  :param int portnum: The port number to test connections to.
  :param {str} addresses: The list of addresses to check connectivity for.
  :param options: Table of options for this specific check, see below.

  Various options can be set in the ``options`` parameter:

  - ``selector``: used to pick the address(es) from the list of available addresses. Choices include 'pickclosest', 'random', 'hashed', 'all' (default 'random').
  - ``backupSelector``: used to pick the address(es) from all addresses if all addresses are down. Choices include 'pickclosest', 'random', 'hashed', 'all' (default 'random').
  - ``source``: Source address to check from
  - ``timeout``: Maximum time in seconds that you allow the check to take (default 2)
  - ``interval``: Time interval between two checks, in seconds. Defaults to :ref:`setting-lua-health-checks-interval` if not specified.
  - ``minimumFailures``: The number of unsuccessful checks in a row required to mark the address as down. Defaults to 1 if not specified, i.e. report as down on the first unsuccessful check.


.. function:: ifurlup(url, addresses[, options])

  More sophisticated test that attempts an actual http(s) connection to
  ``url`` (but results are not used :ref:`on the first run <if-first-run>`).
  In addition, a list of sets of IP addresses can be supplied. The
  first set with at least one available address is selected. The ``selector`` then
  selects from the subset of available addresses of the selected set.
  An URL is considered available if the HTTP response code is 200 and optionally if
  the content matches the ``stringmatch`` option.

  :param string url: The url to retrieve.
  :param addresses: List of sets of addresses to check the URL on.
  :param options: Table of options for this specific check, see below.

  .. _ifurlup-options:

  Various options can be set in the ``options`` parameter:

  - ``selector``: used to pick the address(es) from the subset of available addresses of the selected set. Choices include 'pickclosest', 'random', 'hashed', 'all' (default 'random').
  - ``backupSelector``: used to pick the address from all addresses if all addresses are down. Choices include 'pickclosest', 'random', 'hashed', 'all' (default 'random').
  - ``source``: Source address to check from
  - ``timeout``: Maximum time in seconds that you allow the check to take (default 2)
  - ``interval``: Time interval between two checks, in seconds. Defaults to :ref:`setting-lua-health-checks-interval` if not specified.
  - ``stringmatch``: check ``url`` for this string, only declare 'up' if found
  - ``useragent``: Set the HTTP "User-Agent" header in the requests. By default it is set to "PowerDNS Authoritative Server"
  - ``byteslimit``: Limit the maximum download size to ``byteslimit`` bytes (default 0 meaning no limit).
  - ``minimumFailures``: The number of unsuccessful checks in a row required to mark the address as down. Defaults to 1 if not specified, i.e. report as down on the first unsuccessful check.

  An example of a list of address sets:

  .. code-block:: lua

    ifurlup("https://example.com/", { {"192.0.2.20", "203.0.113.4"}, {"203.0.113.2"} })

.. function:: ifurlextup(groups-of-address-url-pairs[, options])

  Very similar to ``ifurlup``, but the returned IPs are decoupled from their external health check URLs.
  This is useful when health checking already happens elsewhere, and that state is exposed over HTTP(S).
  Health checks are considered positive if the HTTP response code is 200 and optionally if the content matches the ``stringmatch`` option.

  :ref:`Options <ifurlup-options>` are identical to those for ``ifurlup``.

  Example:

  .. code-block:: lua

    ifurlextup({{['192.168.0.1']='https://example.com/',['192.168.0.2']='https://example.com/404'}})

  Example with two groups:

  .. code-block:: lua

    ifurlextup({{['192.168.0.1']='https://example.net/404',['192.168.0.2']='https://example.com/404'}, {['192.168.0.3']='https://example.net/'}})"

  The health checker will look up the first two URLs (using normal DNS resolution to find them - whenever possible, use URLs with IPs in them).
  The 404s will cause the first group of IPs to get marked as down, after which the URL in the second group is tested.
  The third IP will get marked up assuming ``https://example.net/`` responds with HTTP response code 200.

.. function:: pickrandom(values)

  Returns a random value from the list supplied.

  :param values: A list of strings such as IPv4 or IPv6 address.

  This function also works for CNAME or TXT records.

.. function:: pickselfweighted(url, addresses[, options])

  Selects an IP address from the supplied list, weighted according to the results of `isUp` checks. Each address is evaluated, and if its associated weight (from `isUp`) is greater than 0, it is considered for selection using a weighted hash based on `bestwho`. If no address is "up" the function defaults to a random selection.

  :param string url: The health check url to retrieve.
  :param addresses: A list of IP addresses to evaluate.
  :param options: Table of options for this specific check, see below.

  Various options can be set in the ``options`` parameter:

  - ``selector``: used to pick the address(es) from the subset of available addresses of the selected set. Choices include 'pickclosest', 'random', 'hashed', 'all' (default 'random').
  - ``backupSelector``: used to pick the address from all addresses if all addresses are down. Choices include 'pickclosest', 'random', 'hashed', 'all' (default 'random').
  - ``source``: Source address to check from
  - ``timeout``: Maximum time in seconds that you allow the check to take (default 2)
  - ``stringmatch``: check ``url`` for this string, only declare 'up' if found
  - ``useragent``: Set the HTTP "User-Agent" header in the requests. By default it is set to "PowerDNS Authoritative Server"
  - ``byteslimit``: Limit the maximum download size to ``byteslimit`` bytes (default 0 meaning no limit).

  An example of a list of address sets:

  .. code-block:: lua

    pickselfweighted("http://example.com/weight", { "192.0.2.20", "203.0.113.4", "203.0.113.2" })

  This function is ideal for scenarios where candidates can self-determine their weights, while also providing fallback behavior when all addresses are down.

.. function:: pickrandomsample(number, values)

  Returns N random values from the list supplied.

  :param number: Number of values to return
  :param values: A list of strings such as IPv4 or IPv6 address.

  This function also works for CNAME or TXT records.

.. function:: pickhashed(values)

  Based on the hash of ``bestwho``, returns a random value from the list supplied.

  :param values: A list of strings such as IPv4 or IPv6 address.

  This function also works for CNAME or TXT records.

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

.. function:: all(values)

  Returns all values.

  :param values: A list of strings such as IPv4 or IPv6 address.

  This function also works for CNAME or TXT records.

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

.. function:: pickchashed(values)

  Based on the hash of ``bestwho``, returns a string from the list
  supplied, as weighted by the various ``weight`` parameters and distributed consistently.
  Performs no uptime checking.

  :param values: table of weight, string (such as IPv4 or IPv6 address).

  This function works almost like :func:`pickwhashed` while bringing the following properties:

  - reordering the list of entries won't affect the distribution
  - updating the weight of an entry will only affect a part of the distribution
  - because of the previous properties, the CPU and memory cost is a bit higher than :func:`pickwhashed`

  Hashes will be pre computed the first time such a record is hit and refreshed if needed. If updating the list is done often,
  the cache may grow. A cleanup routine is performed every :ref:`setting-lua-consistent-hashes-cleanup-interval` seconds (default 1h)
  and cleans cached entries for records that haven't been used for :ref:`setting-lua-consistent-hashes-expire-delay` seconds (default 24h)

  An example::

    mydomain.example.com    IN    LUA    A ("pickchashed({                             "
                                            "        {15,  "192.0.2.1"},               "
                                            "        {100, "198.51.100.5"}             "
                                            "})                                        ")


.. function:: pickwhashed(values)

  Based on the hash of ``bestwho``, returns a string from the list
  supplied, as weighted by the various ``weight`` parameters.
  Performs no uptime checking.

  :param values: table of weight, string (such as IPv4 or IPv6 address).

  Because of the hash, the same client keeps getting the same answer, but
  given sufficient clients, the load is still spread according to the weight
  factors.

  This function also works for CNAME or TXT records.

  An example::

    mydomain.example.com    IN    LUA    A ("pickwhashed({                             "
                                            "        {15,  "192.0.2.1"},               "
                                            "        {100, "198.51.100.5"}             "
                                            "})                                        ")

.. function:: picknamehashed(values)

  Based on the hash of the DNS record name, returns a string from the list supplied, as weighted by the various ``weight`` parameters.
  Performs no uptime checking.

  :param values: table of weight, string (such as IPv4 or IPv6 address).

  This allows basic persistent load balancing across a number of backends.
  It means that ``test.mydomain.example.com`` will always resolve to the same IP, but ``test2.mydomain.example.com`` may go elsewhere.
  This function is only useful for wildcard records.

  This works similar to round-robin load balancing, but has the advantage of making traffic for the same domain always end up on the same server which can help cache hit rates.

  This function also works for CNAME or TXT records.

  An example::

    *.mydomain.example.com    IN    LUA    A ("picknamehashed({                        "
                                              "        {15,  "192.0.2.1"},             "
                                              "        {100, "198.51.100.5"}           "
                                              "})                                      ")


.. function:: pickwrandom(values)

  Returns a random string from the list supplied, as weighted by the
  various ``weight`` parameters. Performs no uptime checking.

  :param values: table of weight, string (such as IPv4 or IPv6 address).

  See :func:`pickwhashed` for an example.

  This function also works for CNAME or TXT records.

Reverse DNS functions
~~~~~~~~~~~~~~~~~~~~~

.. warning::
  For :func:`createForward` and :func:`createForward6`, we recommend filtering with :func:`filterForward`, to prevent PowerDNS from generating A/AAAA responses to addresses outside of your network.
  Not limiting responses like this may, in some situations, help attackers with impersonation and attacks like such as cookie stealing.

.. function:: createReverse(format, [exceptions])

  Used for generating default hostnames from IPv4 wildcard reverse DNS records, e.g. ``*.0.0.127.in-addr.arpa``

  See :func:`createReverse6` for IPv6 records (ip6.arpa)

  See :func:`createForward` for creating the A records on a wildcard record such as ``*.static.example.com``

  Returns a formatted hostname based on the format string passed.

  :param format: A hostname string to format, for example ``%1%.%2%.%3%.%4%.static.example.com``.
  :param exceptions: An optional table of overrides. For example ``{['10.10.10.10'] = 'quad10.example.com.'}`` would, when generating a name for IP ``10.10.10.10``, return ``quad10.example.com`` instead of something like ``10.10.10.10.example.com``.

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

  This function supports the forward dotted format (``127.0.0.1.static.example.com``), and the hex format, when prefixed by two ignored characters (``ip40414243.static.example.com``)

  When queried::

    $ dig +short A 127.0.0.5.static.example.com @ns1.example.com
    127.0.0.5

  Since 4.8.0: the hex format can be prefixed by any number of characters (within DNS label length limits), including zero characters (so no prefix).

.. function:: createReverse6(format[, exceptions])

  Used for generating default hostnames from IPv6 wildcard reverse DNS records, e.g. ``*.1.0.0.2.ip6.arpa``

  **For simplicity purposes, only small sections of IPv6 rDNS domains are used in most parts of this guide,**
  **as a full ip6.arpa record is around 80 characters long.**

  See :func:`createReverse` for IPv4 records (in-addr.arpa)

  See :func:`createForward6` for creating the AAAA records on a wildcard record such as ``*.static.example.com``

  Returns a formatted hostname based on the format string passed.

  :param format: A hostname string to format, for example ``%33%.static6.example.com``.
  :param exceptions: An optional table of overrides. For example ``{['2001:db8::1'] = 'example.example.com.'}`` would, when generating a name for IP ``2001:db8::1``, return ``example.example.com`` instead of something like ``2001--db8.example.com``.

  Formatting options:

  - ``%1%`` to ``%32%`` are individual characters (nibbles)
      - **Example PTR record query:** ``a.0.0.0.1.0.0.2.ip6.arpa``
      - ``%1%`` = 2
      - ``%2%`` = 0
      - ``%3%`` = 0
      - ``%4%`` = 1
  - ``%33%`` converts the compressed address format into a dashed format, e.g. ``2001:a::1`` to ``2001-a--1``
      This format may add '0' to the result, preventing it from being identified as an illegal IDN by ``dig``.
  - ``%34%`` to ``%41%`` represent the 8 uncompressed 2-byte chunks
      - **Example:** PTR query for ``2001:a:b::123``
      - ``%34%`` - returns ``2001`` (chunk 1)
      - ``%35%`` - returns ``000a`` (chunk 2)
      - ``%41%`` - returns ``0123`` (chunk 8)

  Example records::

    *.1.0.0.2.ip6.arpa IN    LUA    PTR "createReverse6('%33%.static6.example.com')"
    *.2.0.0.2.ip6.arpa IN    LUA    PTR "createReverse6('%34%.%35%.static6.example.com')"

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

  This function supports the dashed compressed format (i.e. ``2001-a-b--1.static6.example.com``), and the dot-split uncompressed format (``2001.db8.6.5.4.3.2.1.static6.example.com``)

  When queried::

    $ dig +short AAAA 2001-a-b--1.static6.example.com @ns1.example.com
    2001:a:b::1

  Since 4.8.0: a non-split full length format (``20010002000300040005000600070db8.example.com``) is also supported, optionally prefixed, in which case only the last 32 characters will be considered.

.. function:: filterForward(address, masks[, fallback])

  .. versionadded:: 4.5.0

  Used for limiting the output of :func:`createForward` and :func:`createForward6` to a set of netmasks.

  :param address: A string containing an address, usually taken directly from :func:`createForward: or :func:`createForward6`.
  :param masks: A NetmaskGroup; any address not matching the NMG will be replaced by the fallback address.
  :param fallback: A string containing the fallback address. Defaults to ``0.0.0.0`` or ``::``.

  Example::

    *.static4.example.com IN LUA A "filterForward(createForward(), newNMG({'192.0.2.0/24', '10.0.0.0/8'}))"

  Since 4.9.0: if the fallback parameter is an empty string, ``filterForward`` returns an empty set, yielding a NODATA answer.
  You cannot combine this feature with DNSSEC.

Helper functions
~~~~~~~~~~~~~~~~

.. function:: geoiplookup(address, attr)

  Retrieve specific attributes related to an IP address.

  :param string address: The IP address to lookup.
  :param int attr: The attribute identifier for the lookup.

  You can use the following constants as the attribute:

  - `GeoIPQueryAttribute.ASn`
  - `GeoIPQueryAttribute.City`
  - `GeoIPQueryAttribute.Continent`
  - `GeoIPQueryAttribute.Country`
  - `GeoIPQueryAttribute.Country2`
  - `GeoIPQueryAttribute.Name`
  - `GeoIPQueryAttribute.Region`
  - `GeoIPQueryAttribute.Location`

  Example::

    asn.example.com       IN LUA TXT "geoiplookup(bestwho:toString(), GeoIPQueryAttribute.ASn)"       ; 1
    city.example.com      IN LUA TXT "geoiplookup(bestwho:toString(), GeoIPQueryAttribute.City)"      ; auckland
    continent.example.com IN LUA TXT "geoiplookup(bestwho:toString(), GeoIPQueryAttribute.Continent)" ; oc
    country.example.com   IN LUA TXT "geoiplookup(bestwho:toString(), GeoIPQueryAttribute.Country)"   ; nz
    country2.example.com  IN LUA TXT "geoiplookup(bestwho:toString(), GeoIPQueryAttribute.Country2)"  ; nz
    name.example.com      IN LUA TXT "geoiplookup(bestwho:toString(), GeoIPQueryAttribute.Name)"      ; lvlt-1
    region.example.com    IN LUA TXT "geoiplookup(bestwho:toString(), GeoIPQueryAttribute.Region)"    ; auk
    location.example.com  IN LUA TXT "geoiplookup(bestwho:toString(), GeoIPQueryAttribute.Location)"  ; -36.000000 174.000000

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

.. function:: countryCode()

  Returns two letter ISO country code based ``bestwho`` IP address, as described in :doc:`../backends/geoip`.
  If the two letter ISO country code is unknown "--" will be returned.

.. function:: region(region)
              region(regions)

  Returns true if the ``bestwho`` IP address of the client is within the
  two letter ISO region code passed, as described in :doc:`../backends/geoip`.

  :param string region: A region code like "CA"
  :param [string] regions: A list of regions codes

.. function:: regionCode()

  Returns two letter ISO region code based ``bestwho`` IP address, as described in :doc:`../backends/geoip`.
  If the two letter ISO region code is unknown "--" will be returned.

.. function:: continent(continent)
              continent(continents)

  Returns true if the ``bestwho`` IP address of the client is within the
  continent passed, as described in :doc:`../backends/geoip`.

  :param string continent: A continent code like "EU"
  :param [string] continents: A list of continent codes

.. function:: continentCode()

  Returns two letter ISO continent code based ``bestwho`` IP address, as described in :doc:`../backends/geoip`.
  If the two letter ISO continent code is unknown "--" will be returned.

.. function:: netmask(netmasks)

  Returns true if ``bestwho`` is within any of the listed subnets.

  :param [string] netmasks: The list of IP addresses to check against

.. function:: dblookup(name, type)

  .. versionadded:: 4.9.0

  Does a database lookup for name and type, and returns a (possibly empty) array of string results.

  Please keep the following in mind:

  * it does not evaluate any LUA code found
  * if you needed just one string, perhaps you want ``dblookup('www.example.org', pdns.A)[1]`` to take the first item from the array
  * some things, like ifurlup, don't like empty tables, so be careful not to accidentally look up a name that does not have any records of that type, if you are going to use the result in ``ifurlup``

  Example usage: ::

    www IN LUA A "ifurlup('https://www.example.com/', {dblookup('www1.example.com', pdns.A), dblookup('www2.example.com', pdns.A), dblookup('www3.example.com', pdns.A)})"

  :param string name: Name to look up in the database
  :param int type: DNS type to look for
