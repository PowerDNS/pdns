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

Reference: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5

.. _DNSClass:

DNSClass
--------

These constants represent the `CLASS <https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2>`__ of a DNS record.

- ``DNSClass.IN``
- ``DNSClass.CHAOS``
- ``DNSClass.NONE``
- ``DNSClass.ANY``

Reference: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2

.. _DNSRCode:

RCode
-----

These constants represent the different `RCODEs <https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6>`__ for DNS messages.

.. versionchanged:: 1.4.0
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

RCodes below are extended RCodes that can only be matched using :func:`ERCodeRule`.

- ``DNSRCode.BADVERS``
- ``DNSRCode.BADSIG``
- ``DNSRCode.BADKEY``
- ``DNSRCode.BADTIME``
- ``DNSRCode.BADMODE``
- ``DNSRCode.BADNAME``
- ``DNSRCode.BADALG``
- ``DNSRCode.BADTRUNC``
- ``DNSRCode.BADCOOKIE``

.. _EDNSOptionCode:

EDNSOptionCode
--------------

- ``EDNSOptionCode.DHU``
- ``EDNSOptionCode.ECS``
- ``EDNSOptionCode.N3U``
- ``EDNSOptionCode.DAU``
- ``EDNSOptionCode.TCPKEEPALIVE``
- ``EDNSOptionCode.COOKIE``
- ``EDNSOptionCode.PADDING``
- ``EDNSOptionCode.KEYTAG``
- ``EDNSOptionCode.NSID``
- ``EDNSOptionCode.CHAIN``
- ``EDNSOptionCode.EXPIRE``

Reference: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11

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

These constants represent an Action that can be returned from :func:`LuaAction` functions.

 * ``DNSAction.Allow``: let the query pass, skipping other rules
 * ``DNSAction.Delay``: delay the response for the specified milliseconds (UDP-only), continue to the next rule
 * ``DNSAction.Drop``: drop the query
 * ``DNSAction.HeaderModify``: indicate that the query has been turned into a response
 * ``DNSAction.None``: continue to the next rule
 * ``DNSAction.NoOp``: continue to the next rule (used for Dynamic Block actions where None has a different meaning)
 * ``DNSAction.Nxdomain``: return a response with a NXDomain rcode
 * ``DNSAction.Pool``: use the specified pool to forward this query
 * ``DNSAction.Refused``: return a response with a Refused rcode
 * ``DNSAction.ServFail``: return a response with a ServFail rcode
 * ``DNSAction.Spoof``: spoof the response using the supplied IPv4 (A), IPv6 (AAAA) or string (CNAME) value
 * ``DNSAction.Truncate``: truncate the response
 * ``DNSAction.NoRecurse``: set rd=0 on the query

.. _DNSQType:

DNSQType
--------

.. versionchanged:: 1.4.0
  The prefix is changed from ``dnsdist.`` to ``DNSQType``.

All named `QTypes <https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4>`__ are available as constants, prefixed with ``DNSQType.``, e.g.:

 * ``DNSQType.AAAA``
 * ``DNSQType.AXFR``
 * ``DNSQType.A``
 * ``DNSQType.NS``
 * ``DNSQType.SOA``
 * etc.

.. _DNSResponseAction:

DNSResponseAction
-----------------

These constants represent an Action that can be returned from :func:`LuaResponseAction` functions.

 * ``DNSResponseAction.Allow``: let the response pass, skipping other rules
 * ``DNSResponseAction.Delay``: delay the response for the specified milliseconds (UDP-only), continue to the next rule
 * ``DNSResponseAction.Drop``: drop the response
 * ``DNSResponseAction.HeaderModify``: indicate that the query has been turned into a response
 * ``DNSResponseAction.None``: continue to the next rule
 * ``DNSResponseAction.ServFail``: return a response with a ServFail rcode
