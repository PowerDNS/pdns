.. _scripting-netmasks:

Netmasks and NetMaskGroups
==========================

There are two classes in the PowerDNS Recursor that can be used to match IP addresses against.

Netmask class
-------------
The :class:`Netmask` class represents an IP netmask.

.. code-block:: Lua

    mask = newNetmask("192.0.2.1/24")
    mask:isIPv4() -- true
    mask:match("192.0.2.8") -- true

.. function:: newNetmask(mask) -> Netmask

  Creates a new :class:`Netmask`.

  :param str mask: The mask to convert.

.. class:: Netmask

  Represents a netmask.

  .. method:: Netmask:empty() -> bool

      True if the netmask doesn't contain a valid address.

  .. method:: Netmask:getBits() -> int

      The number of bits in the address.

  .. method:: Netmask:getNetwork() -> ComboAddress

      Returns a :class:`ComboAddress` representing the network (no mask applied).

  .. method:: Netmask:getMaskedNetwork() -> ComboAddress

      Returns a :class:`ComboAddress` representing the network (truncating according to the mask).

  .. method:: Netmask:isIpv4() -> bool

  .. deprecated:: v4.3.0

      True if the netmask is an IPv4 netmask.

  .. method:: Netmask:isIPv4() -> bool

  .. versionadded:: v4.3.0

      True if the netmask is an IPv4 netmask.

  .. method:: Netmask:isIpv6() -> bool

  .. deprecated:: v4.3.0

      True if the netmask is an IPv6 netmask.

  .. method:: Netmask:isIPv6() -> bool

  .. deprecated:: v4.3.0

      True if the netmask is an IPv6 netmask.

  .. method:: Netmask:match(address) -> bool

      True if the address passed in address matches

      :param str address: IP Address to match against.

  .. method:: Netmask:toString() -> str

      Returns a human-friendly representation.

NetMaskGroup class
------------------

NetMaskGroups are more powerful than plain Netmasks.
They can be matched against netmasks objects:

.. code-block:: lua

  nmg = newNMG()
  nmg:addMask("127.0.0.0/8")
  nmg:addMasks({"213.244.168.0/24", "130.161.0.0/16"})
  nmg:addMasks(dofile("bad.ips")) -- contains return {"ip1","ip2"..}

  if nmg:match(dq.remoteaddr) then
    print("Intercepting query from ", dq.remoteaddr)
  end

Prefixing a mask with ``!`` excludes that mask from matching.

.. function:: newNMG() -> NetMaskGroup

  Returns a new, empty :class:`NetMaskGroup`.

.. class:: NetMaskGroup

  IP addresses are passed to Lua in native format.

  .. method:: NetMaskGroup:addMask(mask)

      Adds ``mask`` to the NetMaskGroup.

      :param str mask: The mask to add.

  .. method:: NetMaskGroup:addMasks(masks)

      Adds ``masks`` to the NetMaskGroup.

      :param {str} mask: The masks to add.

  .. method:: NetMaskGroup:match(address) -> bool

      Returns true if ``address`` matches any of the masks in the group.

      :param ComboAddress address: The IP addres to match the netmasks against.
