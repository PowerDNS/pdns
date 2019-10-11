Dynamic Rule Generation
=======================

To set dynamic rules, based on recent traffic, define a function called :func:`maintenance` in Lua.
It will get called every second, and from this function you can set rules to block traffic based on statistics.
More exactly, the thread handling the :func:`maintenance` function will sleep for one second between each invocation, so if the function takes several seconds to complete it will not be invoked exactly every second.

As an example::

  function maintenance()
      addDynBlocks(exceedQRate(20, 10), "Exceeded query rate", 60)
  end

This will dynamically block all hosts that exceeded 20 queries/s as measured over the past 10 seconds, and the dynamic block will last for 60 seconds.

Dynamic blocks in force are displayed with :func:`showDynBlocks` and can be cleared with :func:`clearDynBlocks`.
They return a table whose key is a :class:`ComboAddress` object, representing the client's source address, and whose value is an integer representing the number of queries matching the corresponding condition (for example the qtype for :func:`exceedQTypeRate`, rcode for :func:`exceedServFails`).

All exceed-functions are documented in the :ref:`Configuration Reference <exceedfuncs>`.

Dynamic blocks drop matched queries by default, but this behavior can be changed with :func:`setDynBlocksAction`.
For example, to send a REFUSED code instead of droppping the query::

  setDynBlocksAction(DNSAction.Refused)

Please see the documentation for :func:`setDynBlocksAction` to confirm which actions are supported.

.. _DynBlockRulesGroup:

DynBlockRulesGroup
------------------

Starting with dnsdist 1.3.0, a new :ref:`dynBlockRulesGroup` function can be used to return a `DynBlockRulesGroup` instance,
designed to make the processing of multiple rate-limiting rules faster by walking the query and response buffers only once
for each invocation, instead of once per existing `exceed*()` invocation.

For example, instead of having something like:

.. code-block:: lua

  function maintenance()
    addDynBlocks(exceedQRate(30, 10), "Exceeded query rate", 60)
    addDynBlocks(exceedNXDOMAINs(20, 10), "Exceeded NXD rate", 60)
    addDynBlocks(exceedServFails(20, 10), "Exceeded ServFail rate", 60)
    addDynBlocks(exceedQTypeRate(dnsdist.ANY, 5, 10), "Exceeded ANY rate", 60)
    addDynBlocks(exceedRespByterate(1000000, 10), "Exceeded resp BW rate", 60)
  end

The new syntax would be:

.. code-block:: lua

  local dbr = dynBlockRulesGroup()
  dbr:setQueryRate(30, 10, "Exceeded query rate", 60)
  dbr:setRCodeRate(dnsdist.NXDOMAIN, 20, 10, "Exceeded NXD rate", 60)
  dbr:setRCodeRate(dnsdist.SERVFAIL, 20, 10, "Exceeded ServFail rate", 60)
  dbr:setQTypeRate(dnsdist.ANY, 5, 10, "Exceeded ANY rate", 60)
  dbr:setResponseByteRate(10000, 10, "Exceeded resp BW rate", 60)

  function maintenance()
    dbr:apply()
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

