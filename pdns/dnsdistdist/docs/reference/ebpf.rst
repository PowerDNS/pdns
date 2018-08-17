eBPF functions and objects
==========================

These are all the functions, objects and methods related to the :doc:`../advanced/ebpf`.

.. function:: addBPFFilterDynBlocks(addresses, dynbpf[[, seconds=10], msg])

  .. versionchanged:: 1.3.0
    ``msg`` optional parameter added.

  This is the eBPF equivalent of :func:`addDynBlocks`, blocking a set of addresses for (optionally) a number of seconds, using an eBPF dynamic filter.
  The default number of seconds to block for is 10.

  :param addresses: set of Addresses as returned by an :ref:`exceed function <exceedfuncs>`
  :param DynBPFFilter dynbpf: The dynamic eBPF filter to use
  :param int seconds: The number of seconds this block to expire
  :param str msg: A message to display while inserting the block

.. function:: newBPFFilter(maxV4, maxV6, maxQNames) -> BPFFilter

  Return a new eBPF socket filter with a maximum of maxV4 IPv4, maxV6 IPv6 and maxQNames qname entries in the block table.

  :param int maxV4: Maximum number of IPv4 entries in this filter
  :param int maxV6: Maximum number of IPv6 entries in this filter
  :param int maxQNames: Maximum number of QName entries in this filter

.. function:: newDynBPFFilter(bpf) -> DynBPFFilter

  Return a new dynamic eBPF filter associated to a given BPF Filter.

  :param BPFFilter bpf: The underlying eBPF filter

.. function:: setDefaultBPFFilter(filter)

  When used at configuration time, the corresponding BPFFilter will be attached to every bind.

  :param BPFFilter filter: The filter to attach

.. function:: registerDynBPFFilter(dynbpf)

   Register a DynBPFFilter filter so that it appears in the web interface and the API.

  :param DynBPFFilter dynbpf: The dynamic eBPF filter to register

.. function:: unregisterDynBPFFilter(dynbpf)

   Remove a DynBPFFilter filter from the web interface and the API.

  :param DynBPFFilter dynbpf: The dynamic eBPF filter to unregister

.. class:: BPFFilter

  Represents an eBPF filter

  .. method:: BPFFilter:attachToAllBinds()

    Attach this filter to every bind already defined.
    This is the run-time equivalent of :func:`setDefaultBPFFilter`

  .. method:: BPFFilter:block(address)

    Block this address

    :param ComboAddress address: The address to block

  .. method:: BPFFilter:blockQName(name [, qtype=255])

    Block queries for this exact qname. An optional qtype can be used, defaults to 255.

    :param DNSName name: The name to block
    :param int qtype: QType to block

  .. method:: BPFFilter:getStats()

    Print the block tables.

  .. method:: BPFFilter:unblock(address)

    Unblock this address.

    :param ComboAddress address: The address to unblock

  .. method:: BPFFilter:unblockQName(name [, qtype=255])

    Remove this qname from the block list.

    :param DNSName name: the name to unblock
    :param int qtype: The qtype to unblock

.. class:: DynBPFFilter

  Represents an dynamic eBPF filter, allowing the use of ephemeral rules to an existing eBPF filter.

  .. method:: DynBPFFilter:purgeExpired()

    Remove the expired ephemeral rules associated with this filter.

  .. method:: DynBPFFilter:excludeRange(netmasks)

    .. versionadded:: 1.3.3

    Exclude this range, or list of ranges, meaning that no dynamic block will ever be inserted for clients in that range. Default to empty, meaning rules are applied to all ranges. When used in combination with :meth:`DynBPFFilter:includeRange`, the more specific entry wins.

    :param int netmasks: A netmask, or list of netmasks, as strings, like for example "192.0.2.1/24"

  .. method:: DynBPFFilter:includeRange(netmasks)

    .. versionadded:: 1.3.3

    Include this range, or list of ranges, meaning that rules will be applied to this range. When used in combination with :meth:`DynBPFFilter:excludeRange`, the more specific entry wins.

    :param int netmasks: A netmask, or list of netmasks, as strings, like for example "192.0.2.1/24"
