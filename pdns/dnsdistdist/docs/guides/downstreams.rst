Configuring Downstream Servers
==============================

As dnsdist is a loadbalancer and does not do any DNS resolving or serving by itself, it needs downstream servers.
To add downstream servers, either include them on the command line::

    dnsdist -l 130.161.252.29 -a 130.161.0.0/16 8.8.8.8 208.67.222.222 2620:0:ccc::2 2620:0:ccd::2

Or add them to the configuration file:

.. code-block:: lua

    setLocal("130.161.252.29:53")
    setACL("130.161.0.0/16")
    newServer("8.8.8.8")
    newServer("208.67.222.222")
    newServer("2620:0:ccc::2")
    newServer("2620:0:0ccd::2")

These two equivalent configurations give you sane load balancing using a very sensible distribution policy.
Many users will simply be done with this configuration.
It works as well for authoritative as for recursive servers.

Healthcheck
-----------
dnsdist uses a health check, sent once every second, to determine the availability of a backend server.

By default, an A query for "a.root-servers.net." is sent.
A different query type and target can be specified by passing, respectively, the ``checkType`` and ``checkName`` parameters to :func:`newServer`.

The default behavior is to consider any valid response with an RCODE different from ServFail as valid.
If the ``mustResolve`` parameter of :func:`newServer` is set to ``true``, a response will only be considered valid if its RCODE differs from NXDomain, ServFail and Refused.

The number of health check failures before a server is considered down is configurable via the ``maxCheckFailures`` parameter, defaulting to 1.
The CD flag can be set on the query by setting ``setCD`` to true.
e.g.::

  newServer({address="192.0.2.1", checkType="AAAA", checkName="a.root-servers.net.", mustResolve=true})

Source address selection
------------------------

In multi-homed setups, it can be useful to be able to select the source address or the outgoing
interface used by dnsdist to contact a downstream server. This can be done by using the `source` parameter::

  newServer({address="192.0.2.1", source="192.0.2.127"})
  newServer({address="192.0.2.1", source="eth1"})
  newServer({address="192.0.2.1", source="192.0.2.127@eth1"})

The supported values for source are:
- an IPv4 or IPv6 address, which must exist on the system
- an interface name
- an IPv4 or IPv6 address followed by '@' then an interface name

Please note that specifying the interface name is only supported on system having `IP_PKTINFO`.
