Using ALIAS records
===================

The ALIAS record provides a way to have CNAME-like behaviour on the zone
apex.

In order to correctly serve ALIAS records in PowerDNS Authoritative
Server 4.1.0 or higher, set the :ref:`setting-resolver`
setting to an existing resolver and enable
:ref:`setting-expand-alias`:

.. code-block:: ini

    resolver=[::1]:5300
    expand-alias=yes

.. note::
  If :ref:`setting-resolver` is unset, ALIAS expansion is disabled!

Then add the ALIAS record to your zone apex. e.g.:

::

    $ORIGIN example.net
    $TTL 1800

    @ IN SOA ns1.example.net. hostmaster.example.net. 2015121101 1H 15 1W 2H

    @ IN NS ns1.example.net.

    @ IN ALIAS mywebapp.paas-provider.net.

When the authoritative server receives a query for the A-record for
``example.net``, it will resolve the A record for
``mywebapp.paas-provider.net`` and serve an answer for ``example.net``
with that A record.
If the ALIAS target cannot be resolved (SERVFAIL) or does not exist (NXDOMAIN) the authoritative server will answer SERVFAIL.

.. warning::
  You should make sure that the :ref:`setting-resolver` does not point to
  PowerDNS itself, to prevent infinite query loops.

.. _alias_axfr:

AXFR Zone transfers
-------------------

When a zone containing ALIAS records is transferred over AXFR, the :ref:`setting-outgoing-axfr-expand-alias` setting controls the behaviour of ALIAS records.

When set to 'no' (the default), ALIAS records are sent as-is (RRType 65401 and a DNSName in the RDATA) in the AXFR.

When set to 'yes', PowerDNS will look up the A and AAAA records of the name in the ALIAS-record and send the results in the AXFR.
This is useful when your secondary servers do not understand ALIAS, or should not look up the addresses themselves.
Note that secondaries will not automatically follow changes in those A/AAAA records unless you AXFR regularly.

If the ALIAS target cannot be resolved, the AXFR will fail.
When set to 'ignore-errors', an unresolvable ALIAS target will be omitted from the outgoing transfer.

.. warning::
  Setting ``setting-outgoing-axfr-expand-alias`` to 'ignore-errors', will allow an outgoing AXFR with a broken ALIAS target to complete, but the secondary server will receive an incomplete zone.
  There is no standard mechanism for automatic re-transfer for zones broken in this way.
  You should make sure this behaviour is acceptable in your use case, provide custom integration tooling to monitor such problems, and possibly fix them automatically.


.. note::
  The ``expand-alias`` setting does not exist in PowerDNS
  Authoritative Server 4.0.x. Hence, ALIAS records are always expanded on
  a direct A or AAAA query.

.. _alias_and_dnssec:

ALIAS and DNSSEC
----------------

Starting with the PowerDNS Authoritative Server 4.0.0, DNSSEC 'washing'
of ALIAS records is supported on AXFR (**not** on live-signing). Set
``outgoing-axfr-expand-alias`` to 'yes' and enable DNSSEC for the zone
on the primary. PowerDNS will sign the A/AAAA records during the AXFR.
