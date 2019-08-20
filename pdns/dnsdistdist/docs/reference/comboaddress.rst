.. _ComboAddress:

ComboAddress
============

IP addresses are moved around in a native format, called a ComboAddress.
ComboAddresses can be IPv4 or IPv6, and unless you want to know, you don't need to.

.. function:: newCA(address) -> :class:`ComboAddress`

  Returns a :class:`ComboAddress` based on ``address``

  :param string address: The IP address, with optional port, to represent.

.. class:: ComboAddress

  A ``ComboAddress`` represents an IP address with possibly a port number.
  The object can be an IPv4 or an IPv6 address.
  It has these methods:

  .. method:: ComboAddress:getPort() -> int

    Returns the port number.

  .. method:: ComboAddress:ipdecrypt(key) -> ComboAddress

    Decrypt this IP address as described in https://powerdns.org/ipcipher

    :param string key: A 16 byte key. Note that this can be derived from a passphrase with the standalone function `makeIPCipherKey`

  .. method:: ComboAddress:ipencrypt(key) -> ComboAddress

    Encrypt this IP address as described in https://powerdns.org/ipcipher

    :param string key: A 16 byte key. Note that this can be derived from a passphrase with the standalone function `makeIPCipherKey`

  .. method:: ComboAddress:isIPv4() -> bool

    Returns true if the address is an IPv4, false otherwise

  .. method:: ComboAddress:isIPv6() -> bool

    Returns true if the address is an IPv6, false otherwise

  .. method:: ComboAddress:isMappedIPv4() -> bool

    Returns true if the address is an IPv4 mapped into an IPv6, false otherwise

  .. method:: ComboAddress:mapToIPv4() -> ComboAddress

    Convert an IPv4 address mapped in a v6 one into an IPv4.
    Returns a new ComboAddress

  .. method:: ComboAddress:tostring() -> string
                   ComboAddress:toString() -> string

    Returns in human-friendly format

  .. method:: ComboAddress:tostringWithPort() -> string
                   ComboAddress:toStringWithPort() -> string

    Returns in human-friendly format, with port number

  .. method:: ComboAddress:truncate(bits)

    Truncate the ComboAddress to the specified number of bits.
    This essentially zeroes all bits after ``bits``.

    :param int bits: Amount of bits to truncate to
