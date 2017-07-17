Constants
=========

There are many constants in :program:`dnsdist`.

.. _DNSOpcode:

OPCode
------

- ``DNSOpcode.Query``
- ``DNSOpcode.IQuery``
- ``DNSOpcode.Status``
- ``DNSOpcode.Notify``
- ``DNSOpcode.Update``

.. _DNSQClass:

QClass
------

- ``QClass.IN``
- ``QClass.CHAOS``
- ``QClass.NONE``
- ``QClass.ANY``

.. _DNSRCode:

RCode
-----

- ``dnsdist.NOERROR``
- ``dnsdist.FORMERR``
- ``dnsdist.SERVFAIL``
- ``dnsdist.NXDOMAIN``
- ``dnsdist.NOTIMP``
- ``dnsdist.REFUSED``
- ``dnsdist.YXDOMAIN``
- ``dnsdist.YXRRSET``
- ``dnsdist.NXRRSET``
- ``dnsdist.NOTAUTH``
- ``dnsdist.NOTZONE``

.. _DNSSection:

DNS Section
-----------

- ``DNSSection.Question``
- ``DNSSection.Answer``
- ``DNSSection.Authority``
- ``DNSSection.Additional``

.. _DNSAction:

DNSAction
---------

These constants represent an Action that can be returned from the functions invoked by :func:`addLuaAction` and :func:`addLuaResponseAction`.

 * ``DNSAction.Allow``: let the query pass, skipping other rules
 * ``DNSAction.Delay``: delay the response for the specified milliseconds (UDP-only), continue to the next rule
 * ``DNSAction.Drop``: drop the query
 * ``DNSAction.HeaderModify``: indicate that the query has been turned into a response
 * ``DNSAction.None``: continue to the next rule
 * ``DNSAction.Nxdomain``: return a response with a NXDomain rcode
 * ``DNSAction.Pool``: use the specified pool to forward this query
 * ``DNSAction.Refused``: return a response with a Refused rcode
 * ``DNSAction.Spoof``: spoof the response using the supplied IPv4 (A), IPv6 (AAAA) or string (CNAME) value
