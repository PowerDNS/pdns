Dynamic Rule Generation
=======================

Dynamic Blocks can be seen are short-lived rules, automatically inserted based on configurable thresholds and the analysis of recently received traffic, and automatically removed after a configurable amount of time.

The analyzed traffic is the one kept by dnsdist in its in-memory ring buffers. The number of entries kept in these ring buffers can be set via the :func:`setRingBuffersSize` directive, and the impact in terms of CPU and memory consumption is described in :doc:`../advanced/tuning`.

That number of entries is crucial for the rate-based rules, like :func:`DynBlockRulesGroup:setQueryRate`, as they will never match if the number of entries in the ring buffer is too small for the required rate, as explained in more details below.

To set dynamic rules, based on recent traffic, define a function called :func:`maintenance` in Lua.
It will get called every second, and from this function you can set rules to block traffic based on statistics.
More exactly, the thread handling the :func:`maintenance` function will sleep for one second between each invocation, so if the function takes several seconds to complete it will not be invoked exactly every second.

As an example:

.. code-block:: lua

  local dbr = dynBlockRulesGroup()
  dbr:setQueryRate(20, 10, "Exceeded query rate", 60)

  function maintenance()
    dbr:apply()
  end

This will dynamically block all hosts that exceeded 20 queries/s as measured over the past 10 seconds, and the dynamic block will last for 60 seconds.

:ref:`DynBlockRulesGroup` is a very efficient way of processing dynamic blocks that was introduced in 1.3.0. Before that, it was possible to use :meth:`addDynBlocks` instead:

.. code-block:: lua

  -- this is a legacy method, please see above for DNSdist >= 1.3.0
  function maintenance()
      addDynBlocks(exceedQRate(20, 10), "Exceeded query rate", 60)
  end

Dynamic blocks in force are displayed with :func:`showDynBlocks` and can be cleared with :func:`clearDynBlocks`.
They return a table whose key is a :class:`ComboAddress` object, representing the client's source address, and whose value is an integer representing the number of queries matching the corresponding condition (for example the qtype for :func:`exceedQTypeRate`, rcode for :func:`exceedServFails`).

All exceed-functions are documented in the :ref:`Configuration Reference <exceedfuncs>`.

Dynamic blocks drop matched queries by default, but this behavior can be changed with :func:`setDynBlocksAction`.
For example, to send a REFUSED code instead of dropping the query::

  setDynBlocksAction(DNSAction.Refused)

Please see the documentation for :func:`setDynBlocksAction` to confirm which actions are supported.

.. _DynBlockRulesGroup:

DynBlockRulesGroup
------------------

Starting with dnsdist 1.3.0, a new :func:`dynBlockRulesGroup` function can be used to return a :class:`DynBlockRulesGroup` instance,
designed to make the processing of multiple rate-limiting rules faster by walking the query and response buffers only once
for each invocation, instead of once per existing `exceed*()` invocation.

The new syntax would be:

.. code-block:: lua

  local dbr = dynBlockRulesGroup()
  dbr:setQueryRate(30, 10, "Exceeded query rate", 60)
  dbr:setRCodeRate(DNSRCode.NXDOMAIN, 20, 10, "Exceeded NXD rate", 60)
  dbr:setRCodeRate(DNSRCode.SERVFAIL, 20, 10, "Exceeded ServFail rate", 60)
  dbr:setQTypeRate(DNSQType.ANY, 5, 10, "Exceeded ANY rate", 60)
  dbr:setResponseByteRate(10000, 10, "Exceeded resp BW rate", 60)

  function maintenance()
    dbr:apply()
  end

Before 1.3.0 the legacy syntax was:

.. code-block:: lua

  function maintenance()
    -- this example is using legacy methods, please see above for DNSdist >= 1.3.0
    addDynBlocks(exceedQRate(30, 10), "Exceeded query rate", 60)
    addDynBlocks(exceedNXDOMAINs(20, 10), "Exceeded NXD rate", 60)
    addDynBlocks(exceedServFails(20, 10), "Exceeded ServFail rate", 60)
    addDynBlocks(exceedQTypeRate(DNSQType.ANY, 5, 10), "Exceeded ANY rate", 60)
    addDynBlocks(exceedRespByterate(1000000, 10), "Exceeded resp BW rate", 60)
  end


The old syntax would walk the query buffer 2 times and the response one 3 times, while the new syntax does it only once for each.
It also reuse the same internal table to keep track of the source IPs, reducing the CPU usage.

DynBlockRulesGroup also offers the ability to specify that some network ranges should be excluded from dynamic blocking:

.. code-block:: lua

  -- do not add dynamic blocks for hosts in the 192.0.2.0/24 and 2001:db8::/32 ranges
  dbr:excludeRange({"192.0.2.0/24", "2001:db8::/32" })
  -- except for 192.0.2.1
  dbr:includeRange("192.0.2.1/32")


Since 1.3.3, it's also possible to define a warning rate. When the query or response rate raises above the warning level but below
the trigger level, a warning message will be issued along with a no-op block. If the rate reaches the trigger level, the regular
action is applied.

.. code-block:: lua

  local dbr = dynBlockRulesGroup()
  -- Generate a warning if we detect a query rate above 100 qps for at least 10s.
  -- If the query rate raises above 300 qps for 10 seconds, we'll block the client for 60s.
  dbr:setQueryRate(300, 10, "Exceeded query rate", 60, DNSAction.Drop, 100)

Since 1.6.0, if a default eBPF filter has been set via :func:`setDefaultBPFFilter` dnsdist will automatically try to use it when a "drop" dynamic block is inserted via a :ref:`DynBlockRulesGroup`. eBPF blocks are applied in kernel space and are much more efficient than user space ones. Note that a regular block is also inserted so that any failure will result in a regular block being used instead of the eBPF one.

Rate rules and size of the ring buffers
---------------------------------------

As explained in the introduction, the whole dynamic block feature is based on analyzing the recent traffic kept in dnsdist's in-memory ring buffers, whose content can be inspected via :func:`grepq`.

The sizing of the buffers, in addition to having performance impacts explained in :doc:`../advanced/tuning`, directly impacts some of the dynamic block rules, like the rate and ratio-based ones.

For example, if :func:`DynBlockRulesGroup:setQueryRate` is used to request the blocking for 60s of any client exceeding 1000 qps over 10s, like this:

.. code-block:: lua

  dbr:setQueryRate(1000, 10, "Exceeded query rate", 60, DNSAction.Drop)

For this rule to trigger, dnsdist will need to scan the ring buffers and find 1000 * 10 = 10000 queries, not older than 10s, from that client. Since a ring buffer has a fixed size, and new entries override the oldest ones when the buffer is full, that only works if there are enough entries in the buffer.

This is even more obvious for the ratio-based rules, when they have a minimum number of responses set, because in that case they clearly require that number of responses to fit in the buffer.

That requirement could be lifted a bit by the use of sampling, meaning that only one query out of 10 would be recorded, for example, and the total amount would be inferred from the queries present in the buffer. As of 1.7.0, sampling as unfortunately not been implemented yet.
