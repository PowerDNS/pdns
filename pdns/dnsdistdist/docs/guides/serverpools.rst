Server pools
------------

dnsdist has the concept to "server pools", any number of servers can belong to a group.

Let's say we know we're getting a whole bunch of traffic for a domain used in DoS attacks, for example 'example.com'.
We can do two things with this kind of traffic.
Either we block it outright, like this:

.. code-block:: lua

  addAction("bad-domain.example.", DropAction())

Or we configure a server pool dedicated to receiving the nasty stuff:

.. code-block:: lua

  newServer({address="192.0.2.3", pool="abuse"})         -- Add a backend server with address 192.0.2.3 and assign it to the "abuse" pool
  addAction({'bad-domain1.example', 'bad-domain2.example.'}, PoolAction("abuse")) -- Send all queries for "bad-domain1.example." and "bad-domain2.example" to the "abuse" pool

The wonderful thing about this last solution is that it can also be used for things where a domain might possibly be legit, but it is still causing load on the system and slowing down the internet for everyone.
With such an abuse server, 'bad traffic' still gets a chance of an answer, but without impacting the rest of the world (too much).

We can similarly add clients to the abuse server:

.. code-block:: lua

  addAction({"192.168.12.0/24", "192.168.13.14"}, PoolAction("abuse"))

To define a pool that should receive only a :term:`QPS`-limited amount of traffic, do:

.. code-block:: lua

  addAction("com.", QPSPoolAction(10000, "gtld-cluster"))

Traffic exceeding the :term:`QPS` limit will not match that rule, and subsequent rules will apply normally.

:class:`Servers <Server>` can be added to or removed from pools with the :func:`Server:addPool` and :func:`Server:rmPool` functions respectively:

.. code-block:: lua

  getServer(4):addPool("abuse")
  getServer(4):rmPool("abuse")

