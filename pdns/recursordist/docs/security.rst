Security of the PowerDNS :program:`Recursor`
============================================

For Security Advisories, see the :doc:`dedicated page <security-advisories/index>`.

.. _securitypolicy:

.. include:: common/security-policy.rst

Anti-spoofing
-------------

:program:`Recursor` uses a fresh UDP source port for each outgoing query, making spoofing around 64000 times harder.
This raises the bar from 'easily doable given some time' to 'very hard'.
Under some circumstances, 'some time' has been measured at 2 seconds.
This technique was first used by ``dnscache`` by Dan J. Bernstein and is standardized in :rfc:`5452`

In addition, :program:`Recursor` detects when it is being sent too many unexpected answers, and mistrusts a proper answer if found within a clutch of unexpected ones.
When this happens, the query to the authoritative server is retried over TCP.

This behaviour can be tuned using the :ref:`setting-yaml-recursor.spoof_nearmiss_max`.

Throttling
----------

:program:`Recursor` implements a very simple but effective resolver.
Care has been taken not to overload remote servers in case of overly active clients.

This is implemented using the 'throttle'.
This accounts all recent traffic and prevents queries that have been sent out recently from going out again.

There are three levels of throttling.

-  If a remote server indicates that it is lame for a zone, the exact question won't be repeated in the next 60 seconds.
-  After 4 ServFail responses in 60 seconds, the query gets throttled too.
-  5 timeouts in 20 seconds also lead to query suppression.

.. _securitypolling:

.. include:: common/secpoll.rst

.. _pointers:

Decompression limits on DNS packets
-----------------------------------

:program:`Recursor` enforces several limits on pointers while parsing a DNS packet.
DNS allows names to use pointers: the tail end of a name is constructed by following a pointer to a name occurring previously in the packet.
As names in a packet share suffixes in a lot of cases this allows to save many bytes at the cost of extra work while parsing.
For decompressing names, three limits apply to limit the amount of work while parsing a packet:

- :ref:`setting-max-pointers-per-packet-byte`: a limit for the total number of pointers followed to parse *all* names in a packet. This limit is 4 * the packet size by default.
  This seems generous, but it is possible to construct legit DNS packets that approach this limit, as constructing a single name can imply following multiple pointers.
- :ref:`setting-max-pointers-to-pointers`: a limit to the pointer directly pointing at a pointer cases while decompressing a *single* name.
  In this case the first pointer does not add any useful information and could have been replaced by the target pointer.
  The default value is 4.
- :ref:`setting-max-pointers-per-name`: a limit to the pointers followed while decompressing a *single* name.
  This limits the case where a pointer does not point at another compression pointer directly but adds some bytes followed by a pointer.
  The default value is 10.

If a limit is reached while parsing a packet, :program:`Recursor` will act as it normally does for malformed answers received: advance to an alternative authoritative server if available.
If no more authoritative server are available the client will receive a ``ServFail`` answer.
