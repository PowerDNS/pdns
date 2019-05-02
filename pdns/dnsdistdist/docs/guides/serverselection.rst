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

``whashed``
~~~~~~~~~~~

``whashed`` is a similar weighted policy, but assigns questions with identical hash to identical servers, allowing for better cache concentration ('sticky queries').
The current hash algorithm is based on the qname of the query.

.. function:: setWHashedPertubation(value)

  Set the hash perturbation value to be used in the whashed policy instead of a random one, allowing to have consistent whashed results on different instances.

``chashed``
~~~~~~~~~~~

``chashed`` is a consistent hashing distribution policy. Identical questions with identical hashes will be distributed to the same servers. But unlike the ``whashed`` policy, this distribution will keep consistent over time. Adding or removing servers will only remap a small part of the queries.

You can also set the hash perturbation value, see :func:`setWHashedPertubation`. To achieve consistent distribution over :program:`dnsdist` restarts, you will also need to explicitly set the backend's UUIDs with the ``id`` option of :func:`newServer`. You can get the current UUIDs of your backends by calling :func:`showServers` with the ``showUUIDs=true`` option.

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

ServerPolicy Objects
--------------------

.. class:: ServerPolicy

  This represents a server policy.
  The built-in policies are of this type

.. function:: ServerPolicy.policy(servers, dq) -> Server

  Run the policy to receive the server it has selected.

  :param servers: A list of :class:`Server` objects
  :param DNSQuestion dq: The incoming query

Functions
---------

.. function:: newServerPolicy(name, function) -> ServerPolicy

  Create a policy object from a Lua function.
  ``function`` must match the prototype for :func:`ServerPolicy.policy`.

  :param string name: Name of the policy
  :param string function: The function to call for this policy

.. function:: setServerPolicy(policy)

  Set server selection policy to ``policy``.

  :param ServerPolicy policy: The policy to use

.. function:: setServerPolicyLua(name, function)

  Set server selection policy to one named `name`` and provided by ``function``.

  :param string name: name for this policy
  :param string function: name of the function

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

.. function:: showPoolServerPolicy(pool)

  Print server selection policy for ``pool``.

  :param string pool: The pool to print the policy for
