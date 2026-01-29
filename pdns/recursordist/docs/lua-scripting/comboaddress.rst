The ``ComboAddress`` class
==========================

IP addresses are moved around in a native format, called ComboAddress within PowerDNS.
ComboAddresses can be IPv4 or IPv6, and unless you want to know, you don't need to.

Make a :class:`ComboAddress` with:

.. code-block:: Lua

    newCA("::1")

A :class:`ComboAddress` object can be compared against a :class:`NetMaskGroup` object with the :meth:`NetMaskGroup:match` function.

To compare the address (so not the port) of two :class:`ComboAddresses` instances, use :meth:`:equal <ComboAddress:equal>`:

.. code-block:: Lua

    a = newCA("[::1]:56")
    b = newCA("[::1]:53")
    a == b                                       -- false, reference mismatch
    a:toStringWithPort() == b:toStringWithPort() -- false, port mismatch
    a:equal(b)                                   -- true

To convert an address to human-friendly representation, use :meth:`:toString <ComboAddress:toString>` or :meth:`:toStringWithPort <ComboAddress:toStringWithPort()>`.
To get only the port number, use :meth:`:getPort() <ComboAddress:getPort>`.

.. function:: newCA(address) -> ComboAddress

  Creates a :class:`ComboAddress`.

  :param string address: The address to convert

.. class:: ComboAddress

  An object representing an IP address and port tuple.

  .. method:: equal(ComboAddress) -> bool

      Compare the address to another :class:`ComboAddress` object. The port numbers are *not* relevant.

  .. method:: getPort() -> int

      The portnumber.

  .. method:: getRaw() -> str

      A bytestring representing the address.

  .. method:: isIPv4() -> bool

      True if the address is an IPv4 address.

  .. method:: isIPv6() -> bool

      True if the address is an IPv6 address.

  .. method:: isMappedIPv4() -> bool

      True if the address is an IPv4 address mapped into an IPv6 one.

  .. method:: mapToIPv4() -> ComboAddress

      If the address is an IPv4 mapped into an IPv6 one, return the corresponding IPv4 :class:`ComboAddress`.

  .. method:: toString() -> str

      Returns the IP address without the port number as a string.

  .. method:: toStringWithPort() -> str

      Returns the IP address with the port number as a string.

  .. method:: truncate(bits)

      Truncate to the supplied number of bits

      :param int bits: The number of bits to truncate to
