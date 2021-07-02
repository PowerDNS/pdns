eBPF Socket Filtering
=====================

:program:`dnsdist` can use `eBPF <http://www.brendangregg.com/ebpf.html>`_ socket filtering on recent Linux kernels (4.1+) built with eBPF support (``CONFIG_BPF``, ``CONFIG_BPF_SYSCALL``, ideally ``CONFIG_BPF_JIT``). It requires dnsdist to have the ``CAP_SYS_ADMIN`` capabilities at startup, or the more restrictive ``CAP_BPF`` one since Linux 5.8.

This feature allows dnsdist to ask the kernel to discard incoming packets in kernel-space instead of them being copied to userspace just to be dropped, thus being a lot of faster. The current implementation supports dropping UDP and TCP queries based on the source IP and UDP datagrams on exact DNS names. We have not been able to implement suffix matching yet, due to a limit on the maximum number of EBPF instructions.

The following figure show the CPU usage of dropping around 20k qps of traffic, first in userspace (34 to 36) then in kernel space with eBPF (37 to 39). The spikes are caused because the drops are triggered by dynamic rules, so the first spike is the abuse traffic before a rule is automatically inserted, and the second spike is because the rule expires automatically after 60s before being inserted again.

.. figure:: ../imgs/ebpf_drops.png
   :align: center
   :alt: eBPF in action

The BPF filter can be used to block incoming queries manually::

  > bpf = newBPFFilter(1024, 1024, 1024)
  > bpf:attachToAllBinds()
  > bpf:block(newCA("2001:DB8::42"))
  > bpf:blockQName(newDNSName("evildomain.com"), 255)
  > bpf:getStats()
  [2001:DB8::42]: 0
  evildomain.com. 255: 0
  > bpf:unblock(newCA("2001:DB8::42"))
  > bpf:unblockQName(newDNSName("evildomain.com"), 255)
  > bpf:getStats()

The :meth:`BPFFilter:blockQName` method can be used to block queries based on the exact qname supplied, in a case-insensitive way, and an optional qtype.
Using the 255 (ANY) qtype will block all queries for the qname, regardless of the qtype.
Contrary to source address filtering, qname filtering only works over UDP. TCP qname filtering can be done the usual way::

  addAction(AndRule({TCPRule(true), makeRule("evildomain.com")}), DropAction())

The :meth:`BPFFilter:attachToAllBinds` method attaches the filter to every existing bind at runtime, but it's also possible to define a default BPF filter at configuration time, so it's automatically attached to every bind::

  bpf = newBPFFilter(1024, 1024, 1024)
  setDefaultBPFFilter(bpf)

Finally, it's also possible to attach it to specific binds at runtime::

  > bpf = newBPFFilter(1024, 1024, 1024)
  > showBinds()
  #   Address              Protocol  Queries
  0   [::]:53              UDP       0
  1   [::]:53              TCP       0
  > bd = getBind(0)
  > bd:attachFilter(bpf)

:program:`dnsdist` also supports adding dynamic, expiring blocks to a BPF filter::

  bpf = newBPFFilter(1024, 1024, 1024)
  setDefaultBPFFilter(bpf)
  dbpf = newDynBPFFilter(bpf)
  function maintenance()
          addBPFFilterDynBlocks(exceedQRate(20, 10), dbpf, 60)
          dbpf:purgeExpired()
  end

This will dynamically block all hosts that exceeded 20 queries/s as measured over the past 10 seconds, and the dynamic block will last for 60 seconds.

The dynamic eBPF blocks and the number of queries they blocked can be seen in the web interface and retrieved from the API. Note however that eBPF dynamic objects need to be registered before they appear in the web interface or the API, using the :func:`registerDynBPFFilter` function::

  registerDynBPFFilter(dbpf)

They can be unregistered at a later point using the :func:`unregisterDynBPFFilter` function.

Since 1.6.0, the default BPF filter set via :func:`setDefaultBPFFilter` will automatically get used when a "drop" dynamic block is inserted via a :ref:`DynBlockRulesGroup`.

That feature might require an increase of the memory limit associated to a socket, via the sysctl setting ``net.core.optmem_max``.
When attaching an eBPF program to a socket, the size of the program is checked against this limit, and the default value might not be enough.
Large map sizes might also require an increase of ``RLIMIT_MEMLOCK``.
