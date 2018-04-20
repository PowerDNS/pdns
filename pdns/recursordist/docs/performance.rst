Performance Guide
=================

To get the best out of the PowerDNS recursor, which is important if you are doing thousands of queries per second, please consider the following.

A busy server may need hundreds of file descriptors on startup, and deals with spikes better if it has that many available later on.
Linux by default restricts processes to 1024 file descriptors, which should suffice most of the time, but Solaris has a default limit of 256.
This can be raised using the ``ulimit`` command or via the ``LimitNOFILE`` unit directive when ``systemd`` is used.
FreeBSD has a default limit that is high enough for even very heavy duty use.

Limit the size of the caches to a sensible value.
Cache hit rate does not improve meaningfully beyond 4 million :ref:`setting-max-cache-entries` per thread, reducing the memory footprint reduces CPU cache misses.
See below for more information about the various caches.

When deploying (large scale) IPv6, please be aware some Linux distributions leave IPv6 routing cache tables at very small default values.
Please check and if necessary raise ``sysctl net.ipv6.route.max_size``.

Set :ref:`setting-threads` to your number of CPU cores (but values above 8 rarely improve performance). 

Threading and distribution of queries
-------------------------------------

When running with several threads, you can either ask PowerDNS to start a special thread to dispatch the incoming queries to the  workers by setting :ref:`setting-pdns-distributes-queries` to true, or let the worker threads handle the incoming queries themselves.
The dispatch thread enabled by :ref:`setting-pdns-distributes-queries` tries to send the same queries to the same thread to maximize the cache-hit ratio, but it might become a bottleneck if the incoming queries rate is too high to be handled by a single thread.

If :ref:`setting-pdns-distributes-queries` is set to false and either ``SO_REUSEPORT`` support is not available or the :ref:`setting-reuseport` directive is set to false, all worker threads share the same listening sockets.

This prevents a single thread from having to handle every incoming queries, but can lead to thundering herd issues where all threads are awoken at once when a query arrives.

If ``SO_REUSEPORT`` support is available and :ref:`setting-reuseport` is set to true, separate listening sockets are opened for each worker thread and the query distributions is handled by the kernel, avoiding any thundering herd issue as well as preventing the distributor thread from becoming the bottleneck.

.. versionadded:: 4.1.0
   The :ref:`setting-cpu-map` parameter can be used to pin worker threads to specific CPUs, in order to keep caches as warm as possible and optimize memory access on NUMA systems.

MTasker and MThreads
--------------------

PowerDNS Recursor uses a cooperative multitasking in userspace called ``MTasker``, based either on ``boost::context`` if available, or on ``System V ucontexts`` otherwise. For maximum performance, please make sure that your system supports ``boost::context``, as the alternative has been known to be quite slower.

The maximum number of simultaneous MTasker threads, called ``MThreads``, can be tuned via :ref:`setting-max-mthreads`, as the default value of 2048 might not be enough for large-scale installations.

When a ``MThread`` is started, a new stack is dynamically allocated for it on the heap. The size of those stacks can be configured via the :ref:`setting-stack-size` parameter, whose default value is 200k which should be enough in most cases.
Modern memory allocators should be quite good at keeping released stacks around for a while in per-thread free list, making the allocation of a new stack very cheap. Still on older allocators, it might be helpful to maintain that free list directly inside the recursor, to make sure that the allocation stays cheap. This can be done via the :ref:`setting-mtasker-stacks-cache-size` setting, which configures the number of released stacks the recursor will keep in cache, ready to be reused again. The only trade-off of enabling this cache should be a slightly increased memory consumption, equals to the number of stacks specified by :ref:`setting-mtasker-stacks-cache-size` multiplied by the size of one stack, itself specified via :ref:`setting-stack-size`.

Performance tips
----------------

For best PowerDNS Recursor performance, use a recent version of your operating system, since this generally offers the best event multiplexer implementation available (``kqueue``, ``epoll``,  ``ports`` or ``/dev/poll``).

On AMD/Intel hardware, wherever possible, run a 64-bit binary. This delivers a nearly twofold performance increase.
On UltraSPARC, there is no need to run with 64 bits.

Consider performing a 'profiled build' by building with ``gprof`` support enabled, running the recursor a bit then feed that info into the next build.
This is good for a 20% performance boost in some cases.

When running with >3000 queries per second, and running Linux versions prior to 2.6.17 on some motherboards, your computer may spend an inordinate amount of time working around an ACPI bug for each call to gettimeofday.
This is solved by rebooting with ``clock=tsc`` or upgrading to a 2.6.17 kernel.
This is relevant if dmesg shows ``Using pmtmr for high-res timesource``.

Connection tracking and firewalls
---------------------------------

A Recursor under high load puts a severe stress on any stateful (connection tracking) firewall, so much so that the firewall may fail.

Specifically, many Linux distributions run with a connection tracking firewall configured.
For high load operation (thousands of queries/second), It is advised to either turn off iptables completely, or use the ``NOTRACK`` feature to make sure DNS traffic bypasses the connection tracking.

Sample Linux command lines would be::

    ## IPv4
    iptables -t raw -I OUTPUT -p udp --dport 53 -j CT --notrack
    iptables -t raw -I OUTPUT -p udp --sport 53 -j CT --notrack
    iptables -t raw -I PREROUTING -p udp --dport 53 -j CT --notrack
    iptables -t raw -I PREROUTING -p udp --sport 53 -j CT --notrack
    iptables -I INPUT -p udp --dport 53 -j ACCEPT
    iptables -I INPUT -p udp --sport 53 -j ACCEPT
    iptables -I OUTPUT -p udp --dport 53 -j ACCEPT
    iptables -I OUTPUT -p udp --sport 53 -j ACCEPT

    ## IPv6
    ip6tables -t raw -I OUTPUT -p udp --dport 53 -j CT --notrack
    ip6tables -t raw -I OUTPUT -p udp --sport 53 -j CT --notrack
    ip6tables -t raw -I PREROUTING -p udp --sport 53 -j CT --notrack
    ip6tables -t raw -I PREROUTING -p udp --dport 53 -j CT --notrack
    ip6tables -I INPUT -p udp --dport 53 -j ACCEPT
    ip6tables -I INPUT -p udp --sport 53 -j ACCEPT
    ip6tables -I OUTPUT -p udp --dport 53 -j ACCEPT
    ip6tables -I OUTPUT -p udp --sport 53 -j ACCEPT

When using FirewallD (Centos 7+ / RedHat 7+ / Fedora 21+), connection tracking can be disabled via direct rules.
The settings can be made permanent by using the ``--permanent`` flag::

    ## IPv4
    firewall-cmd --direct --add-rule ipv4 raw OUTPUT 0 -p udp --dport 53 -j CT --notrack
    firewall-cmd --direct --add-rule ipv4 raw OUTPUT 0 -p udp --sport 53 -j CT --notrack
    firewall-cmd --direct --add-rule ipv4 raw PREROUTING 0 -p udp --dport 53 -j CT --notrack
    firewall-cmd --direct --add-rule ipv4 raw PREROUTING 0 -p udp --sport 53 -j CT --notrack
    firewall-cmd --direct --add-rule ipv4 filter INPUT 0 -p udp --dport 53 -j ACCEPT
    firewall-cmd --direct --add-rule ipv4 filter INPUT 0 -p udp --sport 53 -j ACCEPT
    firewall-cmd --direct --add-rule ipv4 filter OUTPUT 0 -p udp --dport 53 -j ACCEPT
    firewall-cmd --direct --add-rule ipv4 filter OUTPUT 0 -p udp --sport 53 -j ACCEPT

    ## IPv6
    firewall-cmd --direct --add-rule ipv6 raw OUTPUT 0 -p udp --dport 53 -j CT --notrack
    firewall-cmd --direct --add-rule ipv6 raw OUTPUT 0 -p udp --sport 53 -j CT --notrack
    firewall-cmd --direct --add-rule ipv6 raw PREROUTING 0 -p udp --dport 53 -j CT --notrack
    firewall-cmd --direct --add-rule ipv6 raw PREROUTING 0 -p udp --sport 53 -j CT --notrack
    firewall-cmd --direct --add-rule ipv6 filter INPUT 0 -p udp --dport 53 -j ACCEPT
    firewall-cmd --direct --add-rule ipv6 filter INPUT 0 -p udp --sport 53 -j ACCEPT
    firewall-cmd --direct --add-rule ipv6 filter OUTPUT 0 -p udp --dport 53 -j ACCEPT
    firewall-cmd --direct --add-rule ipv6 filter OUTPUT 0 -p udp --sport 53 -j ACCEPT

Following the instructions above, you should be able to attain very high query rates.

Recursor Caches
---------------

The PowerDNS Recursor contains a number of caches, or information stores:

Nameserver speeds cache
^^^^^^^^^^^^^^^^^^^^^^^

The "NSSpeeds" cache contains the average latency to all remote authoritative servers.

Negative cache
^^^^^^^^^^^^^^

The "Negcache" contains all domains known not to exist, or record types not to exist for a domain.

Recursor Cache
^^^^^^^^^^^^^^

The Recursor Cache contains all DNS knowledge gathered over time.
This is also knows as a "record cache".

Packet Cache
^^^^^^^^^^^^

The Packet Cache contains previous answers sent to clients.
If a question comes in that matches a previous answer, this is sent back directly.

The Packet Cache is consulted first, immediately after receiving a packet.
This means that a high hitrate for the Packet Cache automatically lowers the cache hitrate of subsequent caches.

Measuring performance
---------------------

The PowerDNS Recursor exposes many :doc:`metrics <metrics>` that can be graphed and monitored.
