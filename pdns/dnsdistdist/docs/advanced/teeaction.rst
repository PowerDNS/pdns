TeeAction: copy the DNS traffic stream
======================================

This action sends off a copy of a UDP query to another server, and keeps statistics on the responses received. Sample use::

  > addAction(AllRule(), TeeAction("192.0.2.54"))
  > getAction(0):printStats()
  refuseds    0
  nxdomains   0
  noerrors    0
  servfails   0
  recv-errors 0
  tcp-drops   0
  responses   0
  other-rcode 0
  send-errors 0
  queries 0

It is also possible to share a :func:`TeeAction` between several rules. Statistics will be combined in that case.
