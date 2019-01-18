DNS64 support
=============

DNS64, described in :rfc:`6147` is a technology to allow IPv6-only clients to receive special IPv6 addresses that are proxied to IPv4 addresses.
This proxy service is then called NAT64.

As an example, let's say an IPv6 only client would want to connect to ``www.example.com``, it would request the AAAA records for that name.
However, if ``example.com`` does not actually have an IPv6 address, what we do is 'fake up' an IPv6 address.
We do this by retrieving the A records for ``www.example.com``, and translating them to AAAA records.
Elsewhere, a NAT64 device listens on these IPv6 addresses, and extracts the IPv4 address from each packet, and proxies it on.

For maximum flexibility, DNS64 support is included in the :doc:`lua-scripting/index`.
This allows for example to hand out custom IPv6 gateway ranges depending on the location of the requestor, enabling the use of NAT64 services close to the user.

Apart from faking AAAA records, it is also possible to also generate the associated PTR records.
This makes sure that reverse lookup of DNS64-generated IPv6 addresses generate the right name.
The procedure is similar, a request for an IPv6 PTR is converted into one for the corresponding IPv4 address.

To setup DNS64, with both forward and reverse records, create the following Lua script and save it to a file called ``dns64.lua``

.. literalinclude:: ../contrib/dns64.lua
    :language: lua

Where fe80::21b:77ff:0:0 is your "Pref64" translation prefix and the "ip6.arpa" string is the reversed form of this Pref64 address.
Now ensure your script gets loaded by specifying it with :ref:`lua-dns-script=dns64.lua <setting-lua-dns-script>`.

To enhance DNS64, see the :doc:`lua-scripting/index` documentation.
