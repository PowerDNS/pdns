Lua actions in rules
====================

:program:`dnsdist` comes with a lot of built-in :doc:`selectors<../reference/selectors>` and :doc:`actions<../reference/actions>`, but it is also
possible to write custom selectors and actions in Lua. Note that Lua is usually slower than built-in options written in C++, although the FFI
and per-thread FFI options can be quite competitive, as explained in :doc:`tuning guide<tuning>`.

To write a custom selector in Lua, one can do:

.. code-block:: lua

  function lua_selector(dq)
    return dq.qtype == DNSQType.A
  end
  addAction(LuaRule(lua_selector), DropAction())


And for a custom action:

.. code-block:: lua

  function lua_route_tc_to_abuse_pool(dq)
    local tc = dq.dh:getTC()
    -- The TC (truncated) bit should not be set in a query
    if tc then
      return DNSAction.Pool, "abuse" -- send to abuse pool
    end
    -- otherwise we keep processing subsequent rules, if any
    return DNSAction.None
  end
  addAction(AllRule(), LuaAction(lua_route_tc_to_abuse_pool))

If the YAML configuration is used, there are three different ways of calling a Lua function. The first option is to declare the Lua function in
a global Lua file that will loaded before the YAML configuration is parsed. This is done by creating a Lua file with the exact same name as
the YAML configuration one, but with a ``.lua`` extension. See :doc:`../reference/yaml-settings` for more information. For example, creating
a file named ``/etc/dnsdist/dnsdist.lua`` containing:

.. code-block:: lua

  function lua_route_tc_to_abuse_pool(dq)
    local tc = dq.dh:getTC()
    -- The TC (truncated) bit should not be set in a query
    if tc then
      return DNSAction.Pool, "abuse" -- send to abuse pool
    end
    -- otherwise we keep processing subsequent rules, if any
    return DNSAction.None
  end

it is now possible to call this function from the YAML configuration at ``/etc/dnsdist/dnsdist.yml``

.. code-block:: yaml

  query_rules:
    - name: "route truncated queries for powerdns.com to the abuse pool"
      selector:
        type: "QNameSet"
        qnames:
          - "powerdns.com."
      action:
        type: "Lua"
        function_name: "lua_route_tc_to_abuse_pool"


A second option is to declare the Lua code inline in the YAML configuration file, which requires returning a Lua function, which does not need to be named:

.. code-block:: yaml

  query_rules:
    - name: "route truncated queries for powerdns.com to the abuse pool"
      selector:
        type: "QNameSet"
        qnames:
          - "powerdns.com."
      action:
        type: "Lua"
        function_code: |
          return function lua_route_tc_to_abuse_pool(dq)
            local tc = dq.dh:getTC()
            -- The TC (truncated) bit should not be set in a query
            if tc then
              return DNSAction.Pool, "abuse" -- send to abuse pool
            end
            -- otherwise we keep processing subsequent rules, if any
            return DNSAction.None
          end


Finally the third option is to declare the Lua code in a separate file which is referenced from the YAML configuration. The separate file has to return a Lua function, as in the previous case:

.. code-block:: yaml

  query_rules:
    - name: "route truncated queries for powerdns.com to the abuse pool"
      selector:
        type: "QNameSet"
        qnames:
          - "powerdns.com."
      action:
        type: "Lua"
        function_file: "/etc/dnsdist/truncated-to-pool-abuse.lua"


where the ``/etc/dnsdist/truncated-to-pool-abuse.lua`` file contains:

.. code-block:: lua

  return function(dq)
    local tc = dq.dh:getTC()
    -- The TC (truncated) bit should not be set in a query
    if tc then
      return DNSAction.Pool, "abuse" -- send to abuse pool
    end
    -- otherwise we keep processing subsequent rules, if any
    return DNSAction.None
  end
