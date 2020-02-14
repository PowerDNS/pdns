Netmask
=======

.. function:: newNetmask(str) -> Netmask
              newNetmask(ca, bits) -> Netmask

  .. versionadded:: 1.5.0

  Returns a Netmask

  :param string str: A netmask, like ``192.0.2.0/24``.
  :param ComboAddress ca: A :class:`ComboAddress`.
  :param int bits: The number of bits in this netmask.

.. class:: Netmask

  .. versionadded:: 1.5.0

   Represents a netmask.

  .. method:: Netmask:getBits() -> int

    Return the number of bits of this netmask, for example ``24`` for ``192.0.2.0/24``.

  .. method:: Netmask:getMaskedNetwork() -> ComboAddress

    Return a :class:`ComboAddress` object representing the base network of this netmask object after masking any additional bits if necessary (for example ``192.0.2.0`` if the netmask was constructed with ``newNetmask('192.0.2.1/24')).

  .. method:: Netmask:empty() -> bool

    Return true if the netmask is empty, meaning that the netmask has not been set to a proper value.

  .. method:: Netmask:isIPv4() -> bool

    Return true if the netmask is an IPv4 one.

  .. method:: Netmask:isIPv6() -> bool

    Return true if the netmask is an IPv6 one.

  .. method:: Netmask:getNetwork() -> ComboAddress

    Return a :class:`ComboAddress` object representing the base network of this netmask object.

  .. method:: Netmask:match(str) -> bool

    Return true if the address passed in the ``str`` parameter belongs to this netmask.

    :param string str: A network address, like ``192.0.2.0``.

  .. method:: Netmask:toString() -> string

    Return a string representation of the netmask, for example ``192.0.2.0/24``.
