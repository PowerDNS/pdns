.. _ComboAddress:

ComboAddress objects
^^^^^^^^^^^^^^^^^^^^

IP addresses are moved around in a native format, called a ComboAddress.
ComboAddresses can be IPv4 or IPv6, and unless you want to know, you don’t need to.

Functions and methods of a ``ComboAddress``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. function:: newCA(address) -> ComboAddress

  Returns a new :class:`ComboAddress` object based on address

  :param string address: The IP address, with optional port, to represent

  .. code-block:: lua

    addr = newCA("1.2.3.4")

.. function:: newCAFromRaw(rawaddress[, port]) -> ComboAddress

  Returns a new :class:`ComboAddress` object based on the 4- or 16-octet string.
  For example, ``newCAFromRaw('ABCD')`` makes a ``ComboAddress`` object holding the IP ``65.66.67.68``, because those are the ASCII values for those four letters.

  :param string rawaddress: The IPv4 of IPv6 address as a 4/16 octet string
  :param int port: The optional port number

.. class:: ComboAddress

  A ``ComboAddress`` represents an IP address with possibly a port number.
  The object can be an IPv4 or an IPv6 address.
  It has these methods:

  .. method:: ComboAddress:getPort() -> int

    Returns the port number.

  .. method:: ComboAddress:isIPv4() -> bool

    Returns true if the address is an IPv4, false otherwise

  .. method:: ComboAddress:isIPv6() -> bool

    Returns true if the address is an IPv6, false otherwise

  .. method:: ComboAddress:isMappedIPv4() -> bool

    Returns true if the address is an IPv4 mapped into an IPv6, false otherwise

  .. method:: ComboAddress:mapToIPv4() -> ComboAddress

    Convert an IPv4 address mapped in a v6 one into an IPv4.
    Returns a new ComboAddress

  .. method:: ComboAddress:toString() -> string

    Returns in human-friendly format

  .. method:: ComboAddress:getRaw() -> string

    Returns in raw bytes format

  .. method:: ComboAddress:toStringWithPort() -> string

    Returns in human-friendly format, with port number

  .. method:: ComboAddress:truncate(bits)

    Truncate the ComboAddress to the specified number of bits.
    This essentially zeroes all bits after ``bits``.

    :param int bits: Amount of bits to truncate to

.. _ComboAddressSet:

ComboAddressSet objects
^^^^^^^^^^^^^^^^^^^^^^^

We provide a convenient object class that can store unique ComboAddresses in no particular
order and allows fast retrieval of individual elements based on their values

.. code-block:: lua

  addr = newCA("1.2.3.4")
  myset = newCAS()
  myset:add(addr)
  if myset:check(addr) then -- prints "found!"
    print('found!')
  end

Functions and methods of a ``ComboAddressSet``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. function:: newCAS() -> ComboAddressSet

  Returns an empty :class:`ComboAddressSet` object

.. class:: ComboAddressSet

  A ``ComboAddressSet`` can store multiple `ComboAddress`

  It has these methods:

  .. method:: ComboAddressSet:add(addr)
  .. method:: ComboAddressSet:add(addrs)
  .. method:: ComboAddressSet:add(ca)

    Add the given addresses to set. the parameter can be of the following types:

    :param string addr: Handy way to add `ComboAddress` from its string representation
    :param [string] addrs: Add the given list of addresses to the set
    :param ComboAddress ca: The `ComboAddress` object to add to set

  .. code-block:: lua

    addr = newCA("1.2.3.4")
    myset = newCAS()
    myset:add(addr)
    myset:add("5.6.7.8")
    myset:add({"::1/128", "10.11.12.13"})
