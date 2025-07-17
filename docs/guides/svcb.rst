Using SVCB and derived records
==============================
The PowerDNS Authoritative Server has support for the SVCB record and derived records (like HTTPS).
This support includes doing the standards recommended following of alias-form records in-zone and adding those to the additional section.
Apart from that, there's the PowerDNS special for "autohints".

.. _svc-autohints:

Automatic hints
---------------
PowerDNS can automatically fill in ``ipv4hint`` and ``ipv6hint`` parameters in SVCB records based on A and AAAA records already present in the zone.
This can be enabled by setting :ref:`setting-svc-autohints` to 'yes'.

.. versionadded:: 4.5.0
  The ``svc-autohints`` setting was added in 4.5.0

Consider the following zone content::

  example.org      IN HTTPS 0 www.example.org

  www.example.org  IN HTTPS 1 . ipv4hint=auto
  www.example.org  IN A     192.0.2.1
  www.example.org  IN AAAA  2001:db8::1

  ipv6.example.org IN HTTPS 1 . ipv6hint=auto
  ipv6.example.org IN AAAA  2001:db8::2
  ipv6.example.org IN AAAA  2001:db8::3

A query for ``example.org|HTTPS`` will be responded to like this::

  ;; QUESTION SECTION:
  ;example.org.			IN	HTTPS

  ;; ANSWER SECTION:
  example.org.		3600	IN	HTTPS	0 www.example.org

  ;; ADDITIONAL SECTION:
  www.example.org.	3600	IN	A	192.0.2.1
  www.example.org.	3600	IN	HTTPS	1 . ipv4hint=192.0.2.1
  www.example.org.	3600	IN	AAAA	2001:db8::1

Notice that PowerDNS did additional processing and added the target HTTPS record, and the address records to the additional section.
Also notice that the ipv4hint in the ``www.example.org|HTTPS`` records is set to the value of the A record.

PowerDNS takes all the corresponding address records, e.g. when asking for ipv6.example.org::

  ;; QUESTION SECTION:
  ;ipv6.example.org.		IN	HTTPS

  ;; ANSWER SECTION:
  ipv6.example.org.	3600	IN	HTTPS	1 . ipv6hint=2001:db8::2,2001:db8::3

  ;; ADDITIONAL SECTION:
  ipv6.example.org.	3600	IN	AAAA	2001:db8::2
  ipv6.example.org.	3600	IN	AAAA	2001:db8::3

When autohints are applied
^^^^^^^^^^^^^^^^^^^^^^^^^^
PowerDNS expands the autohints both when answering a query, as well as when serving an AXFR.
The text "auto" is **never** served over the wire, ensuring compatibility with any and all client software.

When no address records exist
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Consider the following zone content::

  no-ipv6.example.org  IN HTTPS 1 . ipv4hint=auto ipv6hint=auto
  no-ipv6.example.org  IN A     192.0.2.2

Here, no AAAA record exists for www.example.org, so PowerDNS cannot put any data in the ipv6hint.
In this case, the ipv6hint parameter is dropped when answering the query (and on AXFR)::

  ;; QUESTION SECTION:
  ;no-ipv6.example.org.		IN	HTTPS

  ;; ANSWER SECTION:
  no-ipv6.example.org.	3600	IN	HTTPS	1 . ipv4hint=192.0.2.2

  ;; ADDITIONAL SECTION:
  no-ipv6.example.org.	3600	IN	A	192.0.2.2

:doc:`pdnsutil <../manpages/pdnsutil.1>` checks if the autohints in SVCB and derived records can be found in the zone when using ``pdnsutil zone check``
(``pdnsutil check-zone`` prior to version 5.0).
It will emit a warning when there are no hints to be found::

  [warning] HTTPS record for no-ipv6.example.org has automatic IPv6 hints, but no AAAA-record for the target at no-ipv6.example.org exists.

When autohints exist but are disabled
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
When :ref:`setting-svc-autohints` is not enabled, the parameter is dropped when its value is ``auto``.
