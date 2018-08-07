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

Reference: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5

.. _DNSQClass:

QClass
------

- ``QClass.IN``
- ``QClass.CHAOS``
- ``QClass.NONE``
- ``QClass.ANY``

Reference: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2

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
- ``dnsdist.BADVERS``
- ``dnsdist.BADSIG``
- ``dnsdist.BADKEY``
- ``dnsdist.BADTIME``
- ``dnsdist.BADMODE``
- ``dnsdist.BADNAME``
- ``dnsdist.BADALG``
- ``dnsdist.BADTRUNC``
- ``dnsdist.BADCOOKIE``

RCodes below and including ``BADVERS`` are extended RCodes that can only be matched using :func:`ERCodeRule`.

Reference: https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6


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

DNS Section
-----------

- ``DNSSection.Question``
- ``DNSSection.Answer``
- ``DNSSection.Authority``
- ``DNSSection.Additional``

.. _DNSAction:

DNSAction
---------

These constants represent an Action that can be returned from the functions invoked by :func:`addLuaAction`.

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


.. _DNSResponseAction:

DNSResponseAction
-----------------

These constants represent an Action that can be returned from the functions invoked by :func:`addLuaResponseAction`.

 * ``DNSResponseAction.Allow``: let the response pass, skipping other rules
 * ``DNSResponseAction.Delay``: delay the response for the specified milliseconds (UDP-only), continue to the next rule
 * ``DNSResponseAction.Drop``: drop the response
 * ``DNSResponseAction.HeaderModify``: indicate that the query has been turned into a response
 * ``DNSResponseAction.None``: continue to the next rule
 * ``DNSResponseAction.ServFail``: return a response with a ServFail rcode
