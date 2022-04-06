.. _proxymapping:

Table Based Proxy Mapping
=========================
Starting with version 4.7.0, the PowerDNS Recursor has the ability to map source IP addresses to alternative addresses, which is for example useful when some clients reach the recursor via a reverse-proxy.
The mapped address is used internally for ACL and similar checks.
If the :ref:`setting-proxy-protocol-from` is also used, the substitution is done on the source address specified in the proxy protocol header.

Depending on context, the incoming address can be

The physical address ``P``
  the physical address the query is received on.
The source address ``S``
  the source address as specified in the Proxy protocol
The mapped address ``M``
  the source address mapped by Table Based Proxy Mapping

``S equals P`` if no Proxy Protocol is used.

``M equals S`` if no Table Based Proxy Mapping is used.

``P`` determines if the Proxy Protocol is used (:ref:`setting-proxy-protocol-from`).

``S`` is passed to Lua functions and RPZ processing

``M`` is used for incoming ACL checking (:ref:`setting-allow-from`) and to determine the ECS processing (:ref:`setting-ecs-add-for`).

An example use:

.. code-block:: Lua

  addProxyMapping("127.0.0.0/24", "203.0.113.1")
  domains = { "example.com", "example.net" }
  addProxyMapping("10.0.0.0/8", "203.0.113.2", domains)


The following function is available to configure table based proxy mapping.
Reloading the Lua configuration will replace the current configuration with the new one.
If the subnets specified in multiple :func:`addProxyMapping` calls overlap, the most specific one is used.
By default, the address *before* mapping ``S`` is used for internal logging and ``Protobuf`` messages.
See :func:`protobufServer` on how to tune the source address logged in ``Protobuf`` messages.

.. function:: addProxyMapping(subnet, ip [, domains])

  .. versionadded:: 4.7.0

  Specify a table based mapping for a subnet.

  :param string subnet: a subnet to match
  :param string ip: the IP address or IPaddress port combination to match the subnet to.
  :param array domains: An array of strings used to fill a :ref:`dns-suffix-match-group`.

If the optional ``domains`` argument is given to this function, only queries for names matching the :ref:`dns-suffix-match-group` will use the value ``M`` to determine the outgoing ECS; other queries will use the value ``S``.
The ACL check will be done against the mapped address ``M`` for all queries, independent of the name queried.
If the ``domains`` argument is absent, no extra condition (apart from matching the subnet) applies to determine the outgoing ECS value.

