.. _scripting-netmasks:

Netmasks and NetMaskGroups
==========================

There are two classes in the PowerDNS Recursor that can be used to match IP addresses against.

Netmask class
-------------

.. class:: Netmask

    Represents an IP netmask.
    Can be created with

    .. code-block:: Lua

        newNetmask("192.0.2.1/24")

.. classmethod:: Netmask:empty() -> bool

    True if the netmask doesn't contain a valid address.

.. classmethod:: Netmask:getBits() -> int

    The number of bits in the address.

.. classmethod:: Netmask:getNetwork() -> ComboAddress

    Returns a :class:`ComboAddress` representing the network (no mask applied).

.. classmethod:: Netmask:getMaskedNetwork() -> ComboAddress

    Returns a :class:`ComboAddress` representing the network (truncating according to the mask).

.. classmethod:: Netmask:isIpv4() -> bool

    True if the netmask is an IPv4 netmask.

.. classmethod:: Netmask:isIpv6 -> bool

    True if the netmask is an IPv6 netmask.

.. classmethod:: Netmask:match(address) -> bool

    True if the address passed in address matches

    :param str address: IP Address to match against.

.. classmethod:: Netmask:toString() -> str

    Returns a human-friendly representation.

NetMaskGroup class
------------------

NetMaskGroups are more powerful than plain Netmasks.

.. class:: NetMaskGroup

   IP addresses are passed to Lua in native format.
   They can be matched against netmasks objects:

   .. code-block:: Lua

        nmg = newNMG()
        nmg:addMask("127.0.0.0/8")
        nmg:addMasks({"213.244.168.0/24", "130.161.0.0/16"})
        nmg:addMasks(dofile("bad.ips")) -- contains return {"ip1","ip2"..}

        if nmg:match(dq.remoteaddr) then
            print("Intercepting query from ", dq.remoteaddr)
        end

   Prefixing a mask with ``!`` excludes that mask from matching.

.. classmethod:: NetMaskGroup:addMask(mask)

    Adds ``mask`` to the NetMaskGroup.

    :param str mask: The mask to add.

.. classmethod:: NetMaskGroup:addMasks(masks)

    Adds ``masks`` to the NetMaskGroup.

    :param {str} mask: The masks to add.

.. classmethod:: NetMaskGroup:match(address) -> bool

    Returns true if ``address`` matches any of the masks in the group.

    :param ComboAddress address: The IP addres to match the netmasks against.
