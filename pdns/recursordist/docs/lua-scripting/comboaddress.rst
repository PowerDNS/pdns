The ``ComboAddress`` class
==========================

IP addresses are moved around in a native format, called ComboAddress within PowerDNS.
ComboAddresses can be IPv4 or IPv6, and unless you want to know, you don't need to.

Make a :class:`ComboAddress` with:

.. code-block:: Lua

    newCA("::1")

A :class:`ComboAddress` can be compared against a NetmaskGroup with the :meth:`NetMaskGroup:match` function.

To compare the address (so not the port) of two ComboAddresses, use :meth:`:equal <ComboAddress:equal>`:

.. code-block:: Lua

    a = newCA("[::1]:56")
    b = newCA("[::1]:53")
    a == b     -- false, port mismatch
    a:equal(b) -- true

To convert an address to human-friendly representation, use :meth:`:toString <ComboAddress:toString>` or :meth:`:toStringWithPort <ComboAddress:toStringWithPort()>`.
To get only the port number, use :meth:`:getPort() <ComboAddress:getPort>`.

.. function:: NewCA(address) -> ComboAddress

  Creates a :class:`ComboAddress`.

  :param string address: The address to convert

.. class:: ComboAddress

  An object representing an IP address and port tuple.

  .. method:: ComboAddress:getPort() -> int

      The portnumber.

  .. method:: ComboAddress:getRaw() -> str

      A bytestring representing the address.

  .. method:: ComboAddress:isIPv4() -> bool

      True if the address is an IPv4 address.

  .. method:: ComboAddress:isIPv6() -> bool

      True if the address is an IPv6 address.

  .. method:: ComboAddress:isMappedIPv4() -> bool

      True if the address is an IPv4 address mapped into an IPv6 one.

  .. method:: ComboAddress:mapToIPv4() -> ComboAddress

      If the address is an IPv4 mapped into an IPv6 one, return the corresponding IPv4 :class:`ComboAddress`.

  .. method:: ComboAddress:toString() -> str

      Returns the IP address without the port number as a string.

  .. method:: ComboAddress:toStringWithPort() -> str

      Returns the IP address with the port number as a string.

  .. method:: ComboAddress:truncate(bits)

      Truncate to the supplied number of bits

      :param int bits: The number of bits to truncate to
