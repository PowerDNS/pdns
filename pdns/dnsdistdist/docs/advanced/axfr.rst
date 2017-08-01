AXFR, IXFR and NOTIFY
=====================

When :program:`dnsdist` is deployed in front of a master authoritative server, it might receive
AXFR or IXFR queries destined to this master. There are two issues that can arise in this kind of setup:

- If the master is part of a pool of servers, the first `SOA` query can be directed
  by :program:`dnsdist` to a different server than the following AXFR/IXFR one, which might fail if the servers
  are not perfectly synchronised.
- If the master only allows AXFR/IXFR based on the source address of the requestor,
  it might be confused by the fact that the source address will be the one from the :program:`dnsdist` server.

The first issue can be solved by routing SOA, AXFR and IXFR requests explicitly to the master::

  newServer({address="192.168.1.2", name="master", pool={"master", "otherpool"}})
  addAction(OrRule({QTypeRule(dnsdist.SOA), QTypeRule(dnsdist.AXFR), QTypeRule(dnsdist.IXFR)}), PoolAction("master"))

The second one might require allowing AXFR/IXFR from the :program:`dnsdist` source address
and moving the source address check on :program:`dnsdist`'s side::

  addAction(AndRule({OrRule({QTypeRule(dnsdist.AXFR), QTypeRule(dnsdist.IXFR)}), NotRule(makeRule("192.168.1.0/24"))}), RCodeAction(dnsdist.REFUSED))

When :program:`dnsdist` is deployed in front of slaves, however, an issue might arise with NOTIFY
queries, because the slave will receive a notification coming from the :program:`dnsdist` address,
and not the master's one. One way to fix this issue is to allow NOTIFY from the :program:`dnsdist`
address on the slave side (for example with PowerDNS's `trusted-notification-proxy`) and move the address
check on :program:`dnsdist`'s side::

  addAction(AndRule({OpcodeRule(DNSOpcode.Notify), NotRule(makeRule("192.168.1.0/24"))}), RCodeAction(dnsdist.REFUSED))

