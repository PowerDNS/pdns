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
