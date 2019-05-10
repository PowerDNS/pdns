Quickstart Guide
================

This guide gives an overview of dnsdist features and operations.

Running in the Foreground
-------------------------

After :doc:`installing <install>` dnsdist, the quickest way to start experimenting is launching it on the foreground with::

   dnsdist -l 127.0.0.1:5300 8.8.8.8 2001:4860:4860::8888

This will make dnsdist listen on IP address 127.0.0.1, port 5300 and forward all queries to the two listed IP addresses, with a sensible balancing policy.

``dnsdist`` Console and Configuration
-------------------------------------

Here is more complete configuration, save it to ``dnsdist.conf``::

  newServer({address="2001:4860:4860::8888", qps=1})
  newServer({address="2001:4860:4860::8844", qps=1})
  newServer({address="2620:0:ccc::2", qps=10})
  newServer({address="2620:0:ccd::2", name="dns1", qps=10})
  newServer("192.168.1.2")
  setServerPolicy(firstAvailable) -- first server within its QPS limit

The :func:`newServer` function is used to add a backend server to the configuration.

Now run dnsdist again, reading this configuration::

  $ dnsdist -C dnsdist.conf --local=0.0.0.0:5300
  Marking downstream [2001:4860:4860::8888]:53 as 'up'
  Marking downstream [2001:4860:4860::8844]:53 as 'up'
  Marking downstream [2620:0:ccc::2]:53 as 'up'
  Marking downstream [2620:0:ccd::2]:53 as 'up'
  Marking downstream 192.168.1.2:53 as 'up'
  Listening on 0.0.0.0:5300
  >

You can now send queries to port 5300, and get answers::

  $ dig -t aaaa powerdns.com @127.0.0.1 -p 5300 +short +nocookie
  2001:888:2000:1d::2

Note that dnsdist dropped us in a prompt above, where we can get some statistics::

  > showServers()
  #   Address                   State     Qps    Qlim Ord Wt    Queries   Drops Drate   Lat Pools
  0   [2001:4860:4860::8888]:53    up     0.0       1   1  1          1       0   0.0   0.0
  1   [2001:4860:4860::8844]:53    up     0.0       1   1  1          0       0   0.0   0.0
  2   [2620:0:ccc::2]:53           up     0.0      10   1  1          0       0   0.0   0.0
  3   [2620:0:ccd::2]:53           up     0.0      10   1  1          0       0   0.0   0.0
  4   192.168.1.2:53               up     0.0       0   1  1          0       0   0.0   0.0
  All                                     0.0                         1       0

:func:`showServers()` is usually one of the first commands you will use when logging into the console. More advanced topics are covered in :doc:`guides/console`.

Here we also see our configuration. 5 downstream servers have been configured, of which the first 4 have a QPS limit (of 1, 1, 10 and 10 queries per second, respectively).

The final server has no limit, which we can easily test::

  $ for a in {0..1000}; do dig powerdns.com @127.0.0.1 -p 5300 +noall +nocookie > /dev/null; done

::

  > showServers()
  #   Address                   State     Qps    Qlim Ord Wt    Queries   Drops Drate   Lat Pools
  0   [2001:4860:4860::8888]:53    up     1.0       1   1  1          7       0   0.0   1.6
  1   [2001:4860:4860::8844]:53    up     1.0       1   1  1          6       0   0.0   0.6
  2   [2620:0:ccc::2]:53           up    10.3      10   1  1         64       0   0.0   2.4
  3   [2620:0:ccd::2]:53           up    10.3      10   1  1         63       0   0.0   2.4
  4   192.168.1.2:53               up   125.8       0   1  1        671       0   0.0   0.4
  All                                   145.0                       811       0

Note that the first 4 servers were all limited to near their configured QPS, and that our final server was taking up most of the traffic.
No queries were dropped, and all servers remain up.

Changing Server Settings
~~~~~~~~~~~~~~~~~~~~~~~~

The servers from :func:`showServers` are numbered, :func:`getServer` is used to get this :class:`Server` object to manipulate it.

To force a server down, try :attr:`Server:setDown()`::

  > getServer(0):setDown()
  > showServers()
  #   Address                   State     Qps    Qlim Ord Wt    Queries   Drops Drate   Lat Pools
  0   [2001:4860:4860::8888]:53  DOWN     0.0       1   1  1          8       0   0.0   0.0
  ...

The ``DOWN`` in all caps means it was forced down.
A lower case ``down`` would've meant that dnsdist itself had concluded the server was down.
Similarly, :meth:`Server:setUp()` forces a server to be up, and :meth:`Server:setAuto` returns it to the default availability-probing.

To change the QPS for a server, use :meth:`Server:setQPS`::

  > getServer(0):setQPS(1000)

Restricting Access
------------------

By default, dnsdist listens on ``127.0.0.1`` (not ``::1``!), port 53.

To listen on a different address, use the ``-l`` command line option (useful for testing in the foreground), or use :func:`setLocal` and :func:`addLocal` in the configuration file:

.. code-block:: lua

  setLocal('192.0.2.53')      -- Listen on 192.0.2.53, port 53
  addLocal('[::1]:5300') -- Also listen on ::1, port 5300

Before packets are processed they have to pass the ACL, which helpfully defaults to :rfc:`1918` private IP space.
This prevents us from easily becoming an open DNS resolver.

Adding network ranges to the :term:`ACL` is done with the :func:`setACL` and :func:`addACL` functions:

.. code-block:: lua

  setACL({'192.0.2.0/28', '2001:DB8:1::/56'}) -- Set the ACL to only allow these subnets
  addACL('2001:DB8:2::/56')                   -- Add this subnet to the existing ACL

More Information
----------------

Following this quickstart guide allowed you to set up a basic balancing dnsdist instance.
However, dnsdist is much more powerful.
See the :doc:`guides/index` and/or the :doc:`advanced/index` sections on how to shape, shut and otherwise manipulate DNS traffic.
