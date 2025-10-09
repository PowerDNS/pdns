XSK / AF_XDP functions and objects
==================================

These are all the functions, objects and methods related to :doc:`../advanced/xsk`.

.. function:: newXSK(options)

  .. versionadded:: 1.9.0

  This function creates a new :class:`XskSocket` object, tied to a network interface and queue, to accept ``XSK`` / ``AF_XDP`` packet from the Linux kernel. The returned object can be passed as a parameter to :func:`addLocal` to use XSK for ``UDP`` packets between clients and dnsdist. It can also be passed to ``newServer`` to use XSK for ``UDP`` packets between dnsdist a backend.

  :param table options: A table with key: value pairs with listen options.

  Options:

  * ``ifName``: str - The name of the network interface this object will be tied to.
  * ``NIC_queue_id``: int - The queue of the network interface this object will be tied to.
  * ``frameNums``: int - The number of ``UMEM`` frames to allocate for this socket. More frames mean that a higher number of packets can be processed at the same time. 65535 is a good choice for maximum performance.
  * ``xskMapPath``: str - The path of the BPF map used to communicate with the kernel space XDP program, usually ``/sys/fs/bpf/dnsdist/xskmap``.

.. class:: XskSocket

  .. versionadded:: 1.9.0

  Represents a ``XSK`` / ``AF_XDP`` socket tied to a specific network interface and queue. This object can be created via :func:`newXSK` and passed to :func:`addLocal` to use XSK for ``UDP`` packets between clients and dnsdist. It can also be passed to :func:`newServer` to use XSK for ``UDP`` packets between dnsdist a backend.

  .. method:: XskSocket:getMetrics() -> str

    Returns a string containing ``XSK`` / ``AF_XDP`` metrics for this object, as reported by the Linux kernel.
