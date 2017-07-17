.. _ComboAddress:

ComboAddress
============

.. class:: ComboAddress

  A ``ComboAddress`` represents an IP address with possibly a port number.
  The object can be an IPv4 or an IPv6 address.

Functions and methods related to ``ComboAddress``

.. function:: newCA(address) -> :class:`ComboAddress`

  Returns a :class:`ComboAddress` based on ``address``

  :param string address: The IP address, with optional port, to represent.

.. classmethod:: ComboAddress:getPort() -> int

  Returns the port number.

.. classmethod:: ComboAddress:isIPv4() -> bool

  Returns true if the address is an IPv4, false otherwise

.. classmethod:: ComboAddress:isIPv6() -> bool

  Returns true if the address is an IPv6, false otherwise

.. classmethod:: ComboAddress:isMappedIPv4() -> bool

  Returns true if the address is an IPv4 mapped into an IPv6, false otherwise

.. classmethod:: ComboAddress:mapToIPv4() -> ComboAddress

  Convert an IPv4 address mapped in a v6 one into an IPv4.
  Returns a new ComboAddress

.. classmethod:: ComboAddress:tostring() -> string
                 ComboAddress:toString() -> string

  Returns in human-friendly format

.. classmethod:: ComboAddress:tostringWithPort() -> string
                 ComboAddress:toStringWithPort() -> string

  Returns in human-friendly format, with port number

.. classmethod:: ComboAddress:truncate(bits)

  Truncate the ComboAddress to the specified number of bits.
  This essentially zeroes all bits after ``bits``.

  :param int bits: Amount of bits to truncate to
