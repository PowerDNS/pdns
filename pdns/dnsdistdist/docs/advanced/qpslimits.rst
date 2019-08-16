Rules for traffic exceeding QPS limits
======================================

Traffic that exceeds a QPS limit, in total or per IP (subnet) can be matched by the :func:`MaxQPSIPRule`-rule. For example:

.. code-block:: lua

  addAction(MaxQPSIPRule(5, 32, 48), DelayAction(100))

This measures traffic per IPv4 address and per /48 of IPv6, and if UDP traffic for such an address (range) exceeds 5 :term:`qps`, it gets delayed by 100ms.

As another example:

.. code-block:: lua

  addAction(MaxQPSIPRule(5), NoRecurseAction())

This strips the Recursion Desired (RD) bit from any traffic per IPv4 or IPv6 /64 that exceeds 5 qps. This means any those traffic bins is allowed to make a recursor do 'work' for only 5 qps.

If this is not enough, try:

.. code-block:: lua

  addAction(MaxQPSIPRule(5), DropAction())
  -- or
  addAction(MaxQPSIPRule(5), TCAction())

This will respectively drop traffic exceeding that 5 QPS limit per IP or range, or return it with TC=1, forcing clients to fall back to TCP.

To turn this per IP or range limit into a global limit, use ``NotRule(MaxQPSRule(5000))`` instead of :func:`MaxQPSIPRule`.
