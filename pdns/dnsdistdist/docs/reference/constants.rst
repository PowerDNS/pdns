Constants
=========

There are many constants in :program:`dnsdist`.

.. _DNSOpcode:

OPCode
------

These constants represent the `OpCode <https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5>`__ of a query.

- ``DNSOpcode.Query``
- ``DNSOpcode.IQuery``
- ``DNSOpcode.Status``
- ``DNSOpcode.Notify``
- ``DNSOpcode.Update``

.. _DNSQClass:

QClass
------

These constants represent the `CLASS <https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2>`__ of a DNS record

- ``QClass.IN``
- ``QClass.CHAOS``
- ``QClass.NONE``
- ``QClass.ANY``

.. _DNSRCode:

RCode
-----

These constants represent the different `RCODEs <https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6>`__ for DNS messages.

.. versionchanged:: 1.3.0
  The prefix is changed from ``dnsdist`` to ``DNSRCode``.

- ``DNSRCode.NOERROR``
- ``DNSRCode.FORMERR``
- ``DNSRCode.SERVFAIL``
- ``DNSRCode.NXDOMAIN``
- ``DNSRCode.NOTIMP``
- ``DNSRCode.REFUSED``
- ``DNSRCode.YXDOMAIN``
- ``DNSRCode.YXRRSET``
- ``DNSRCode.NXRRSET``
- ``DNSRCode.NOTAUTH``
- ``DNSRCode.NOTZONE``

.. _DNSSection:

DNS Packet Sections
-------------------

These constants represent the section in the DNS Packet.

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

.. _DNSQType:

QType
-----

.. versionchanged:: 1.3.0
  The prefix is changed from ``dnsdist.`` to ``QType``.

All named `QTypes <https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4>`__ are available as constants, prefixed with ``QType.``, e.g.:

 * ``DNSQType.AAAA``
 * ``DNSQType.AXFR``
 * ``DNSQType.A``
 * ``DNSQType.NS``
 * ``DNSQType.SOA``
 * etc.
