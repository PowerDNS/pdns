Loadbalancing and Server Policies
=================================

:program:`dnsdist` selects the server (if there are multiple eligible) to send queries to based on the configured policy.
Only servers that are marked as 'up', either forced so by the administrator or as the result of the last health check, might
be selected.

Built-in Policies
-----------------

``leastOutstanding``
~~~~~~~~~~~~~~~~~~~~

The default load balancing policy is called ``leastOutstanding``, which means the server with the least queries 'in the air' is picked.
The exact selection algorithm is:

- pick the server with the least queries 'in the air' ;
- in case of a tie, pick the one with the lowest configured 'order' ;
- in case of a tie, pick the one with the lowest measured latency (over an average on the last 128 queries answered by that server).

``firstAvailable``
~~~~~~~~~~~~~~~~~~

The ``firstAvailable`` policy, picks the first available server that has not exceeded its QPS limit, ordered by increasing 'order'.
If all servers are above their QPS limit, a server is selected based on the ``leastOutstanding`` policy.
For now this is the only policy using the QPS limit.

``wrandom``
~~~~~~~~~~~

A further policy, ``wrandom`` assigns queries randomly, but based on the weight parameter passed to :func:`newServer`.

For example, if two servers are available, the first one with a weight of 2 and the second one with a weight of 1 (the default), the
first one should get two-thirds of the incoming queries and the second one the remaining third.

Since 1.5.0, a bounded-load version is also supported, trying to prevent one server from receiving much more queries than intended, even if the distribution of queries is not perfect. This "weighted random with bounded loads" algorithm is enabled by setting :func:`setWeightedBalancingFactor` to a value other than 0, which is the default. This value is the maximum number of outstanding queries that a given server can have at a given time, as a ratio of the total number of outstanding queries for all the active servers in the pool, pondered by the weight of the server.

The algorithm will try to select a server randomly, as is done when no bounded-load is set, but will disqualify all servers that have more outstanding queries than intended times the factor, until a suitable server is found. The higher the factor, the more imbalance between the servers is allowed.

For example, if we have two servers, with respective weights of 1 and 4, we expect the first server to get a fifth of the queries, and the second one 4/5. As the random distribution is not perfect, some server might get more queries than expected. Setting :func:`setWeightedBalancingFactor` to 1.1 limits the imbalance between the ratio of outstanding queries actually handled by a server and the expected number, so in this example the first server would not be allowed to handle more than 1.1/5 of all the outstanding queries at a given time.

``whashed``
~~~~~~~~~~~

``whashed`` is a similar weighted policy, but assigns questions with identical hash to identical servers, allowing for better cache concentration ('sticky queries').
The current hash algorithm is based on the qname of the query.

.. function:: setWHashedPertubation(value)

  Set the hash perturbation value to be used in the whashed policy instead of a random one, allowing to have consistent whashed results on different instances.

Since 1.5.0, a bounded-load version is also supported, trying to prevent one server from receiving much more queries than intended, even if the distribution of queries is not perfect. This "weighted hashing with bounded loads" algorithm is enabled by setting :func:`setWeightedBalancingFactor` to a value other than 0, which is the default. This value is the maximum number of outstanding queries that a given server can have at a given time, as a ratio of the total number of outstanding queries for all the active servers in the pool, pondered by the weight of the server.

The algorithm will try to select a server based on the hash of the qname, as is done when no bounded-load is set, but will disqualify all servers that have more outstanding queries than intended times the factor, until a suitable server is found. The higher the factor, the more imbalance between the servers is allowed.

For example, if we have two servers, with respective weights of 1 and 4, we expect the first server to get a fifth of the queries, and the second one 4/5. If the qname of the queries are not perfectly distributed, some server might get more queries than expected. Setting :func:`setWeightedBalancingFactor` to 1.1 limits the imbalance between the ratio of outstanding queries actually handled by a server and the expected number, so in this example the first server would not be allowed to handle more than 1.1/5 of all the outstanding queries at a given time.

``chashed``
~~~~~~~~~~~

``chashed`` is a consistent hashing distribution policy. Identical questions with identical hashes will be distributed to the same servers. But unlike the ``whashed`` policy, this distribution will keep consistent over time. Adding or removing servers will only remap a small part of the queries.

Increasing the weight of servers to a value larger than the default is required to get a good distribution of queries. Small values like 100 or 1000 should be enough to get a correct distribution.
This is a side-effect of the internal implementation of the consistent hashing algorithm, which assigns as many points on a circle to a server than its weight, and distributes a query to the server who has the closest point on the circle from the hash of the query's qname. Therefore having very few points, as is the case with the default weight of 1, leads to a poor distribution of queries.

You can also set the hash perturbation value, see :func:`setWHashedPertubation`. To achieve consistent distribution over :program:`dnsdist` restarts, you will also need to explicitly set the backend's UUIDs with the ``id`` option of :func:`newServer`. You can get the current UUIDs of your backends by calling :func:`showServers` with the ``showUUIDs=true`` option.

Since 1.5.0, a bounded-load version is also supported, preventing one server from receiving much more queries than intended, even if the distribution of queries is not perfect. This "consistent hashing with bounded loads" algorithm is enabled by setting :func:`setConsistentHashingBalancingFactor` to a value other than 0, which is the default. This value is the maximum number of outstanding queries that a given server can have at a given time, as a ratio of the total number of outstanding queries for all the active servers in the pool, pondered by the weight of the server.

The algorithm will try to select a server based on the hash of the qname, as is done when no bounded-load is set, but will disqualify all servers that have more outstanding queries than intended times the factor, until a suitable server is found. The higher the factor, the more imbalance between the servers is allowed.

For example, if we have two servers, with respective weights of 1 and 4, we expect the first server to get a fifth of the queries, and the second one 4/5. If the qname of the queries are not perfectly distributed, some server might get more queries than expected. Setting :func:`setConsistentHashingBalancingFactor` to 1.1 limits the imbalance between the ratio of outstanding queries actually handled by a server and the expected number, so in this example the first server would not be allowed to handle more than 1.1/5 of all the outstanding queries at a given time.

``roundrobin``
~~~~~~~~~~~~~~

The last available policy is ``roundrobin``, which indiscriminately sends each query to the next server that is up.
If all servers are down, the policy will still select one server by default. Setting :func:`setRoundRobinFailOnNoServer` to ``true`` will change this behavior.

Lua server policies
-------------------

If you don't like the default policies you can create your own, like this for example::

  counter=0
  function luaroundrobin(servers, dq)
       counter=counter+1
       return servers[1+(counter % #servers)]
  end

  setServerPolicyLua("luaroundrobin", luaroundrobin)

Incidentally, this is similar to setting: ``setServerPolicy(roundrobin)`` which uses the C++ based roundrobin policy.

Or::

  newServer("192.168.1.2")
  newServer({address="8.8.4.4", pool="numbered"})

  function splitSetup(servers, dq)
    if(string.match(dq.qname:toString(), "%d"))
    then
      print("numbered pool")
      return leastOutstanding.policy(getPoolServers("numbered"), dq)
    else
      print("standard pool")
      return leastOutstanding.policy(servers, dq)
    end
  end

  setServerPolicyLua("splitsetup", splitSetup)

A faster, FFI version is also available since 1.5.0:

.. code-block:: lua

  local ffi = require("ffi")
  local C = ffi.C

  local counter = 0
  function luaffiroundrobin(servers_list, dq)
    counter = counter + 1
    return (counter % tonumber(C.dnsdist_ffi_servers_list_get_count(servers_list)))
  end
  setServerPolicyLuaFFI("luaffiroundrobin", luaffiroundrobin)

Note that this version returns the index (starting at 0) of the server to select,
instead of returning the server itself. It was initially not possible to indicate
that all servers were unavailable from these policies, but since 1.9.2 returning
a value equal or greater than the number of servers will be interpreted as such.

For performance reasons, 1.6.0 introduced per-thread Lua FFI policies that are run in a lock-free per-thread Lua context instead of the global one.
This reduces contention between threads at the cost of preventing sharing data between threads for these policies. Since the policy needs to be recompiled
in the context of each thread instead of the global one, Lua code that returns a function should be passed to the function as a string instead of directly
passing the name of a function:

.. code-block:: lua

  setServerPolicyLuaFFIPerThread("luaffiroundrobin", [[
    local ffi = require("ffi")
    local C = ffi.C

    local counter = 0
    return function(servers_list, dq)
      counter = counter + 1
      return (counter % tonumber(C.dnsdist_ffi_servers_list_get_count(servers_list)))
    end
  ]])

Note that this version, like the one above, returns the index (starting at 0) of the server to select.
It was initially not possible to indicate that all servers were unavailable from these policies, but
since 1.9.2 returning a value equal or greater than the number of servers will be interpreted as such.

ServerPolicy Objects
--------------------

.. class:: ServerPolicy

  This represents a server policy.
  The built-in policies are of this type

.. function:: ServerPolicy.policy(servers, dq) -> Server

  Run the policy to receive the server it has selected.

  :param servers: A list of :class:`Server` objects
  :param DNSQuestion dq: The incoming query

  .. attribute:: ServerPolicy.ffipolicy

    .. versionadded: 1.5.0

    For policies implemented using the Lua FFI interface, the policy function itself.

  .. attribute:: ServerPolicy.isFFI

    .. versionadded: 1.5.0

    Whether a Lua-based policy is implemented using the FFI interface.

  .. attribute:: ServerPolicy.isLua

    Whether this policy is a native (C++) policy or a Lua-based one.

  .. attribute:: ServerPolicy.isPerThread

    .. versionadded: 1.6.0

    Whether a FFI Lua-based policy is executed in a lock-free per-thread context instead of running in the global Lua context.

  .. attribute:: ServerPolicy.name

    The name of the policy.

  .. attribute:: ServerPolicy.policy

    The policy function itself, except for FFI policies.

  .. method:: Server:toString()

    Return a textual representation of the policy.


Functions
---------

.. function:: newServerPolicy(name, function) -> ServerPolicy

  Create a policy object from a Lua function.
  ``function`` must match the prototype for :func:`ServerPolicy.policy`.

  :param string name: Name of the policy
  :param string function: The function to call for this policy

.. function:: setConsistentHashingBalancingFactor(factor)

  .. versionadded: 1.5.0

  Set the maximum imbalance between the number of outstanding queries intended for a given server, based on its weight,
  and the actual number, when using the ``chashed`` consistent hashing load-balancing policy.
  Default is 0, which disables the bounded-load algorithm.

.. function:: setServerPolicy(policy)

  Set server selection policy to ``policy``.

  :param ServerPolicy policy: The policy to use

.. function:: setServerPolicyLua(name, function)

  Set server selection policy to one named ``name`` and provided by ``function``.

  :param string name: name for this policy
  :param string function: name of the function

.. function:: setServerPolicyLuaFFI(name, function)

  .. versionadded:: 1.5.0

  .. versionchanged:: 1.9.2
    Returning a value equal or greater than the number of servers will be interpreted as all servers being unavailable.

  Set server selection policy to one named ``name`` and provided by the FFI function ``function``.

  :param string name: name for this policy
  :param string function: name of the FFI function

.. function:: setServerPolicyLuaFFIPerThread(name, code)

  .. versionadded:: 1.6.0

  .. versionchanged:: 1.9.2
    Returning a value equal or greater than the number of servers will be interpreted as all servers being unavailable.

  Set server selection policy to one named ``name`` and the Lua FFI function returned by the Lua code passed in ``code``.
  The resulting policy will be executed in a lock-free per-thread context, instead of running in the global Lua context.

  :param string name: name for this policy
  :param string code: Lua FFI code returning the function to execute as a server selection policy

.. function:: setServFailWhenNoServer(value)

  If set, return a ServFail when no servers are available, instead of the default behaviour of dropping the query.

  :param bool value: whether to return a servfail instead of dropping the query

.. function:: setPoolServerPolicy(policy, pool)

  Set the server selection policy for ``pool`` to ``policy``.

  :param ServerPolicy policy: The policy to apply
  :param string pool: Name of the pool

.. function:: setPoolServerPolicyLua(name, function, pool)

  Set the server selection policy for ``pool`` to one named ``name`` and provided by ``function``.

  :param string name: name for this policy
  :param string function: name of the function
  :param string pool: Name of the pool

.. function:: setRoundRobinFailOnNoServer(value)

  .. versionadded:: 1.4.0

  By default the roundrobin load-balancing policy will still try to select a backend even if all backends are currently down. Setting this to true will make the policy fail and return that no server is available instead.

  :param bool value: whether to fail when all servers are down

.. function:: setWeightedBalancingFactor(factor)

  .. versionadded: 1.5.0

  Set the maximum imbalance between the number of outstanding queries intended for a given server, based on its weight,
  and the actual number, when using the ``whashed`` or ``wrandom`` load-balancing policy.
  Default is 0, which disables the bounded-load algorithm.

.. function:: showPoolServerPolicy(pool)

  Print server selection policy for ``pool``.

  :param string pool: The pool to print the policy for
