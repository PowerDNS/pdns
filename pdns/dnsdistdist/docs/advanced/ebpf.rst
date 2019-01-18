eBPF Socket Filtering
=====================

:program:`dnsdist` can use `eBPF <http://www.brendangregg.com/ebpf.html>`_ socket filtering on recent Linux kernels (4.1+) built with eBPF support (``CONFIG_BPF``, ``CONFIG_BPF_SYSCALL``, ideally ``CONFIG_BPF_JIT``).
This feature might require an increase of the memory limit associated to a socket, via the sysctl setting ``net.core.optmem_max``.
When attaching an eBPF program to a socket, the size of the program is checked against this limit, and the default value might not be enough.
Large map sizes might also require an increase of ``RLIMIT_MEMLOCK``.

This feature allows dnsdist to ask the kernel to discard incoming packets in kernel-space instead of them being copied to userspace just to be dropped, thus being a lot of faster.

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

This feature has been successfully tested on Arch Linux, Arch Linux ARM, Fedora Core 23 and Ubuntu Xenial
