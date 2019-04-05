Lua actions in rules
====================

While we can pass every packet through the :func:`blockFilter` functions, it is also possible to configure :program:`dnsdist` to only hand off some packets for Lua inspection. 
If you think Lua is too slow for your query load, or if you are doing heavy processing in Lua, this may make sense.

To select specific packets for Lua attention, use :func:`addAction` with :func:`LuaAction`, or :func:`addResponseAction` with :func:`LuaResponseAction`.

A sample configuration could look like this::

  function luarule(dq)
    if(dq.qtype==35) -- NAPTR
    then
      return DNSAction.Pool, "abuse" -- send to abuse pool
    else
      return DNSAction.None, ""      -- no action
    end
  end

  addAction(AllRule(), LuaAction(luarule))
