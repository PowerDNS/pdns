AXFR, IXFR and NOTIFY
=====================

In front of primaries
---------------------

When :program:`dnsdist` is deployed in front of a primary authoritative server, it might receive
AXFR or IXFR queries destined to this primary. There are two issues that can arise in this kind of setup:

- If the primary is part of a pool of servers, the first `SOA` query can be directed
  by :program:`dnsdist` to a different server than the following AXFR/IXFR one, which might fail if the servers
  are not perfectly synchronised.
- If the primary only allows AXFR/IXFR based on the source address of the requestor,
  it might be confused by the fact that the source address will be the one from the :program:`dnsdist` server.

The first issue can be solved by routing SOA, AXFR and IXFR requests explicitly to the primary::

  newServer({address="192.168.1.2", name="primary", pool={"primary", "otherpool"}})
  addAction(OrRule({QTypeRule(DNSQType.SOA), QTypeRule(DNSQType.AXFR), QTypeRule(DNSQType.IXFR)}), PoolAction("primary"))

The second one might require allowing AXFR/IXFR from the :program:`dnsdist` source address
and moving the source address check to :program:`dnsdist`'s side::

  addAction(AndRule({OrRule({QTypeRule(DNSQType.AXFR), QTypeRule(DNSQType.IXFR)}), NotRule(NetmaskGroupRule("192.168.1.0/24"))}), RCodeAction(DNSRCode.REFUSED))

.. versionchanged:: 1.4.0
  Before 1.4.0, the QTypes were in the ``dnsdist`` namespace. Use ``dnsdist.AXFR`` and ``dnsdist.IXFR`` in these versions.
  Before 1.4.0, the RCodes were in the ``dnsdist`` namespace. Use ``dnsdist.REFUSED`` in these versions.

A different way would be to configure dnsdist to pass the source IP of the client to the backend. The different options
to do that are described in :doc:`Passing the source address to the backend <passing-source-address>`.

.. warning::

  Be wary of dnsdist caching the responses to AXFR and IXFR queries and sending these to the wrong clients.
  This is mitigated by default when the source IP of the client is passed using EDNS Client Subnet, but
  not when the proxy protocol is used, so disabling caching for these kinds of queries is advised:

  .. code-block:: lua

    -- this rule will not stop the processing, but disable caching for AXFR and IXFR responses
    addAction(OrRule({QTypeRule(DNSQType.AXFR), QTypeRule(DNSQType.IXFR)}), SetSkipCacheAction())
    -- this rule will route SOA, AXFR and IXFR queries to a specific pool of servers
    addAction(OrRule({QTypeRule(DNSQType.SOA), QTypeRule(DNSQType.AXFR), QTypeRule(DNSQType.IXFR)}), PoolAction("primary"))

.. versionchanged:: 1.8.0
  Since 1.8.0, dnsdist will no longer cache responses to AXFR and IXFR queries.

In front of secondaries
-----------------------

When :program:`dnsdist` is deployed in front of secondaries, however, an issue might arise with NOTIFY
queries, because the secondary will receive a notification coming from the :program:`dnsdist` address,
and not the primary's one. One way to fix this issue is to allow NOTIFY from the :program:`dnsdist`
address on the secondary side (for example with PowerDNS's `trusted-notification-proxy`) and move the address
check to :program:`dnsdist`'s side::

  addAction(AndRule({OpcodeRule(DNSOpcode.Notify), NotRule(NetmaskGroupRule("192.168.1.0/24"))}), RCodeAction(DNSRCode.REFUSED))

.. versionchanged:: 1.4.0
  Before 1.4.0, the RCodes were in the ``dnsdist`` namespace. Use ``dnsdist.REFUSED`` in these versions.

.. warning::

  Be wary of dnsdist caching the responses to NOTIFY queries and sending these to the wrong clients.
  This is mitigated by default when the source IP of the client is passed using EDNS Client Subnet, but
  not when the proxy protocol is used, so disabling caching for these kinds of queries is advised:

  .. code-block:: lua

    -- this rule will disable the caching of responses for NOTIFY queries
    addAction(OpcodeRule(DNSOpcode.Notify), SetSkipCacheAction())
