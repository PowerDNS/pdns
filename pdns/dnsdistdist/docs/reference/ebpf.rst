eBPF functions and objects
==========================

These are all the functions, objects and methods related to the :doc:`../advanced/ebpf`.

.. function:: addBPFFilterDynBlocks(addresses, dynbpf[[, seconds=10], msg])

  This is the eBPF equivalent of :func:`addDynBlocks`, blocking a set of addresses for (optionally) a number of seconds, using an eBPF dynamic filter.
  The default number of seconds to block for is 10.
  Since 1.6.0, the use of a :ref:`DynBlockRulesGroup` is a much more efficient way of doing the same thing.

  :param addresses: set of Addresses as returned by an :ref:`exceed function <exceedfuncs>`
  :param DynBPFFilter dynbpf: The dynamic eBPF filter to use
  :param int seconds: The number of seconds this block to expire
  :param str msg: A message to display while inserting the block

.. function:: newBPFFilter(options) -> BPFFilter
              newBPFFilter(v4Parameters, v6Parameters, qnamesParameters) -> BPFFilter (1.7.x)
              newBPFFilter(maxV4, maxV6, maxQNames) -> BPFFilter (before 1.7.0)

  .. versionchanged:: 1.7.0
    This function now supports a table for each parameters, and the ability to use pinned eBPF maps.
  .. versionchanged:: 1.8.0
    This function now gets its parameters via a table.

  Return a new eBPF socket filter with a maximum of maxV4 IPv4, maxV6 IPv6 and maxQNames qname entries in the block tables.
  Maps can be pinned to a filesystem path, which makes their content persistent across restarts and allows external programs to read their content and to add new entries. dnsdist will try to load maps that are pinned to a filesystem path on startups, inheriting any existing entries, and fall back to creating them if they do not exist yet. Note that the user dnsdist is running under must have the right privileges to read and write to the given file, and to go through all the directories in the path leading to that file. The pinned path must be on a filesystem of type ``BPF``, usually below ``/sys/fs/bpf/``.

  :param table options: A table with key: value pairs with options.

  Options:

  * ``ipv4MaxItems``: int - The maximum number of entries in the IPv4 map. Default is 0 which will not allow any entry at all.
  * ``ipv4PinnedPath``: str - The filesystem path this map should be pinned to.
  * ``ipv6MaxItems``: int - The maximum number of entries in the IPv6 map. Default is 0 which will not allow any entry at all.
  * ``ipv6PinnedPath``: str - The filesystem path this map should be pinned to.
  * ``cidr4MaxItems``: int - The maximum number of entries in the IPv4 range block map. Default is 0 which will not allow any entry at all.
  * ``cidr4PinnedPath``: str - The filesystem path this map should be pinned to.
  * ``cidr6MaxItems``: int - The maximum number of entries in the IPv6 range block map. Default is 0 which will not allow any entry at all.
  * ``cidr6PinnedPath``: str - The filesystem path this map should be pinned to.
  * ``qnamesMaxItems``: int - The maximum number of entries in the qname map. Default is 0 which will not allow any entry at all.
  * ``qnamesPinnedPath``: str - The filesystem path this map should be pinned to.
  * ``external``: bool - If set to true, DNSDist does not load the internal eBPF program.

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
    This is the run-time equivalent of :func:`setDefaultBPFFilter`.
    This method can be used at run-time only.


  .. method:: BPFFilter:block(address)

    Block this address

    :param ComboAddress address: The address to block

  .. method:: BPFFilter:addRangeRule(Netmask , action [, force=false])

    .. versionadded:: 1.8.0

    Block all IP addresses in this range.

    DNSDist eBPF code first checks if an exact IP match is found, then if a range matches, and finally if a DNSName does.

    :param string Netmask: The ip range to block, allow or truncate
    :param int action: set ``action``  to ``0`` to allow a range, set ``action`` to ``1`` to block a range, set ``action`` to ``2`` to truncate a range.
    :param bool force: When ``force`` is set to true, DNSDist always accepts adding a new item to BPF maps, even if the item to be added may already be included in the larger network range.

  .. method:: BPFFilter:blockQName(name [, qtype=65535])

  .. versionchanged:: 2.0.0
    Before 2.0.0 the value used to block queries for all types was 255. It also used to be the default value. This was changed because it prevented blocking only queries for the ``ANY`` (255) qtype.

    Block queries for this exact qname. An optional qtype can be used, defaults to 65535 which blocks queries for all types.

    :param DNSName name: The name to block
    :param int qtype: QType to block

  .. method:: BPFFilter:getStats()

    Print the block tables.

  .. method:: BPFFilter:unblock(address)

    Unblock this address.

    :param ComboAddress address: The address to unblock

  .. method:: BPFFilter:rmRangeRule(Netmask)

    .. versionadded:: 1.8.0

    :param Netmask string: The rule you want to remove

  .. method:: BPFFilter:lsRangeRule()

    .. versionadded:: 1.8.0

    List all range rule.

  .. method:: BPFFilter:unblockQName(name [, qtype=65535])

  .. versionchanged:: 2.0.0
    Before 2.0.0 the value used to block queries for all types was 255. It also used to be the default value. This was changed because it prevented blocking only queries for the ``ANY`` (255) qtype.

    Remove this qname from the block list.

    :param DNSName name: the name to unblock
    :param int qtype: The qtype to unblock

.. class:: DynBPFFilter

  Represents an dynamic eBPF filter, allowing the use of ephemeral rules to an existing eBPF filter. Note that since 1.6.0 the default BPF filter set via :func:`setDefaultBPFFilter` will automatically be used by a :ref:`DynBlockRulesGroup`, becoming the preferred way of dealing with ephemeral rules.

  .. method:: DynBPFFilter:purgeExpired()

    Remove the expired ephemeral rules associated with this filter.

  .. method:: DynBPFFilter:excludeRange(netmasks)

    Exclude this range, or list of ranges, meaning that no dynamic block will ever be inserted for clients in that range. Default to empty, meaning rules are applied to all ranges. When used in combination with :meth:`DynBPFFilter:includeRange`, the more specific entry wins.

    :param str or list of str netmasks: A netmask, or list of netmasks, as strings, like for example "192.0.2.1/24"

  .. method:: DynBPFFilter:includeRange(netmasks)

    Include this range, or list of ranges, meaning that rules will be applied to this range. When used in combination with :meth:`DynBPFFilter:excludeRange`, the more specific entry wins.

    :param str or list of str netmasks: A netmask, or list of netmasks, as strings, like for example "192.0.2.1/24"
