eBPF functions and objects
==========================

These are all the functions, objects and methods related to the :doc:`../advanced/ebpf`.

.. function:: newBPFFilter(maxV4, maxV6, maxQNames) -> BPFFilter

  Return a new eBPF socket filter with a maximum of maxV4 IPv4, maxV6 IPv6 and maxQNames qname entries in the block table.

  :param int maxV4: Maximum number of IPv4 entries in this filter
  :param int maxV6: Maximum number of IPv6 entries in this filter
  :param int maxQNames: Maximum number of QName entries in this filter

.. function:: setDefaultBPFFilter(filter)

  When used at configuration time, the corresponding BPFFilter will be attached to every bind.

  :param BPFFilter filter: The filter ro attach

.. class:: BPFFilter

  Represents an eBPF filter

.. classmethod:: BPFFilter:attachToAllBinds()

  Attach this filter to every bind already defined.
  This is the run-time equivalent of :func:`setDefaultBPFFilter`

.. classmethod:: BPFFilter:block(address)

  Block this address

  :param ComboAddress address: The address to block

.. classmethod:: BPFFilter:blockQName(name [, qtype=255])

  Block queries for this exact qname. An optional qtype can be used, defaults to 255.

  :param DNSName name: The name to block
  :param int qtype: QType to block

.. classmethod:: BPFFilter:getStats()

  Print the block tables.

.. classmethod:: BPFFilter:unblock(address)

  Unblock this address.

  :param ComboAddress address: The address to unblock

.. classmethod:: BPFFilter:unblockQName(name [, qtype=255])

  Remove this qname from the block list.

  :param DNSName name: the name to unblock
  :param int qtype: The qtype to unblock
