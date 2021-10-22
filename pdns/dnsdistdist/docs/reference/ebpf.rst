eBPF functions and objects
==========================

These are all the functions, objects and methods related to the :doc:`../advanced/ebpf`.

.. function:: addBPFFilterDynBlocks(addresses, dynbpf[[, seconds=10], msg])

  This is the eBPF equivalent of :func:`addDynBlocks`, blocking a set of addresses for (optionally) a number of seconds, using an eBPF dynamic filter.
  The default number of seconds to block for is 10.

  :param addresses: set of Addresses as returned by an :ref:`exceed function <exceedfuncs>`
  :param DynBPFFilter dynbpf: The dynamic eBPF filter to use
  :param int seconds: The number of seconds this block to expire
  :param str msg: A message to display while inserting the block

.. function:: newBPFFilter(maxV4, maxV6, maxQNames) -> BPFFilter
              newBPFFilter(v4Parameters, v6Parameters, qnamesParameters) -> BPFFilter

  .. versionchanged:: 1.7.0
    This function now supports a table for each parameters, and the ability to use pinned eBPF maps.

  Return a new eBPF socket filter with a maximum of maxV4 IPv4, maxV6 IPv6 and maxQNames qname entries in the block tables.
  Maps can be pinned to a filesystem path, which makes their content persistent across restarts and allows external programs to read their content and to add new entries. dnsdist will try to load maps that are pinned to a filesystem path on startups, inheriting any existing entries, and fall back to creating them if they do not exist yet. Note that the user dnsdist is running under must have the right privileges to read and write to the given file, and to go through all the directories in the path leading to that file.

  :param int maxV4: Maximum number of IPv4 entries in this filter
  :param int maxV6: Maximum number of IPv6 entries in this filter
  :param int maxQNames: Maximum number of QName entries in this filter

  :param table v4Params: A table of options for the IPv4 filter map, see below
  :param table v6Params: A table of options for the IPv6 filter map, see below
  :param table qnameParams: A table of options for the qnames filter map, see below

  Options:

  * ``maxItems``: int - The maximum number of entries in a given map. Default is 0 which will not allow any entry at all.
  * ``pinnedPaths``: str - The filesystem path this map should be pinned to.

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

  Represents an dynamic eBPF filter, allowing the use of ephemeral rules to an existing eBPF filter. Note that since 1.6.0 the default BPF filter set via :func:`setDefaultBPFFilter` will automatically be used by a :ref:`DynBlockRulesGroup`, becoming the preferred way of dealing with ephemeral rules.

  .. method:: DynBPFFilter:purgeExpired()

    Remove the expired ephemeral rules associated with this filter.

  .. method:: DynBPFFilter:excludeRange(netmasks)

    Exclude this range, or list of ranges, meaning that no dynamic block will ever be inserted for clients in that range. Default to empty, meaning rules are applied to all ranges. When used in combination with :meth:`DynBPFFilter:includeRange`, the more specific entry wins.

    :param int netmasks: A netmask, or list of netmasks, as strings, like for example "192.0.2.1/24"

  .. method:: DynBPFFilter:includeRange(netmasks)

    Include this range, or list of ranges, meaning that rules will be applied to this range. When used in combination with :meth:`DynBPFFilter:excludeRange`, the more specific entry wins.

    :param int netmasks: A netmask, or list of netmasks, as strings, like for example "192.0.2.1/24"
