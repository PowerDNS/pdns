Runtime-modifiable IP address sets
==================================

.. versionadded:: 1.2.0

From within :func:`maintenance` or other places, we may find that certain IP
addresses must be treated differently for a certain time.

This may be used to temporarily shunt traffic to another pool for example.

:func:`TimedIPSetRule` creates an object to which native IP addresses can be
added in :class:`ComboAddress` form.

.. function:: TimedIPSetRule() -> TimedIPSetRule

  Returns a :class:`TimedIPSetRule`.

.. class:: TimedIPSetRule

  Can be used to handle IP addresses differently for a certain time.

  .. method:: TimedIPSetRule:add(address, seconds)

    Add an IP address to the set for the next ``second`` seconds.

    :param ComboAddress address: The address to add
    :param int seconds: Time to keep the address in the Rule

  .. method:: TimedIPSetRule:cleanup()

    Purge the set from expired IP addresses

  .. method:: TimedIPSetRule:clear()

    Clear the entire set

  .. method:: TimedIPSetRule:slice()

    Convert the TimedIPSetRule into a DNSRule that can be passed to :func:`addAction`

A working example:

.. code-block:: lua

  tisrElGoog=TimedIPSetRule()
  tisrRest=TimedIPSetRule()
  addAction(tisrElGoog:slice(), PoolAction("elgoog"))
  addAction(tisrRest:slice(), PoolAction(""))

  elgoogPeople=newNMG()
  elgoogPeople:addMask("192.168.5.0/28")

  function pickPool(dq)
          if(elgoogPeople:match(dq.remoteaddr)) -- in real life, this would be external
          then
                  print("Lua caught query for a googlePerson")
                  tisrElGoog:add(dq.remoteaddr, 10)
                  return DNSAction.Pool, "elgoog"
          else
                  print("Lua caught query for restPerson")
                  tisrRest:add(dq.remoteaddr, 60)
                  return DNSAction.None, ""
          end
  end

  addAction(AllRule(), LuaAction(pickPool))
