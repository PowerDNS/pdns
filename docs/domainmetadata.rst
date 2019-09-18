Per zone settings: Domain Metadata
==================================

Each served zone can have "metadata". Such metadata determines how this
zone behaves in certain circumstances.

.. warning::
  Domain metadata is only available for DNSSEC capable
  backends! Make sure to enable the proper '-dnssec' setting to benefit.

For the BIND backend, this information is either stored in the
:ref:`setting-bind-dnssec-db` or the hybrid database,
depending on your settings.

For the implementation in non-sql backends, please review your backend's
documentation.

Apart from raw SQL statements, setting domain metadata can be done with
``pdnsutil set-meta`` and retrieving metadata is done with ``pdnsutil get-meta``.

The following options can only be read (not written to) via the HTTP API metadata endpoint.

* API-RECTIFY
* AXFR-MASTER-TSIG
* LUA-AXFR-SCRIPT
* NSEC3NARROW
* NSEC3PARAM
* PRESIGNED
* TSIG-ALLOW-AXFR

The option SOA-EDIT-API can not be written or read via the HTTP API metadata endpoint.

.. _metadata-allow-axfr-from:

ALLOW-AXFR-FROM
---------------

Per-zone AXFR ACLs can be stored in the domainmetadata table.

Each ACL specifies one subnet (v4 or v6), or the magical value 'AUTO-NS'
that tries to allow all potential slaves in.

Example:

.. code-block:: shell

    pdnsutil set-meta powerdns.org ALLOW-AXFR-FROM AUTO-NS 2001:db8::/48

Each ACL has its own row in the database:

::

    sql> select id from domains where name='example.com';
    7
    sql> insert into domainmetadata (domain_id, kind, content) values (7,'ALLOW-AXFR-FROM','AUTO-NS');
    sql> insert into domainmetadata (domain_id, kind, content) values (7,'ALLOW-AXFR-FROM','2001:db8::/48');

To disallow all IP's, except those explicitly allowed by domainmetadata
records, add ``allow-axfr-ips=`` to ``pdns.conf``.

.. _metadata-api-rectify:

API-RECTIFY
-----------
.. versionadded:: 4.1.0

This metadata item controls whether or not a zone is fully rectified on changes
to the contents of a zone made through the :doc:`API <http-api/index>`.

When the ``API-RECTIFY`` value is "1", the zone will be rectified on changes.
Any other other value means that it will not be rectified. If this is not set
at all, rectifying of the zone depends on the config variable
:ref:`setting-default-api-rectify`.

.. _metadata-axfr-source:

AXFR-SOURCE
-----------

The IP address to use as a source address for sending AXFR and IXFR
requests.

ALLOW-DNSUPDATE-FROM, TSIG-ALLOW-DNSUPDATE, FORWARD-DNSUPDATE, SOA-EDIT-DNSUPDATE, NOTIFY-DNSUPDATE
---------------------------------------------------------------------------------------------------

See the documentation on :ref:`Dynamic DNS update <dnsupdate-metadata>`.

.. _metadata-also-notify:

ALSO-NOTIFY
-----------

When notifying this domain, also notify this nameserver (can occur
multiple times). The nameserver may have contain an optional port
number. e.g.:

.. code-block:: shell

    pdnsutil set-meta powerdns.org ALSO-NOTIFY 192.0.2.1:5300
    pdnsutil set-meta powerdns.org ALLOW-AXFR-FROM 2001:db8:53::1

Or in SQL:

.. code-block:: SQL

    insert into domainmetadata (domain_id, kind, content) values (7,'ALSO-NOTIFY','192.0.2.1:5300');
    insert into domainmetadata (domain_id, kind, content) values (7,'ALLOW-AXFR-FROM','2001:db8:53::1');

AXFR-MASTER-TSIG
----------------

Use this named TSIG key to retrieve this zone from its master, see :ref:`tsig-provision-signed-notify-axfr`.

GSS-ALLOW-AXFR-PRINCIPAL
------------------------

Allow this GSS principal to perform AXFR retrieval. Most commonly it is
``host/something@REALM``, ``DNS/something@REALM`` or ``user@REALM``.
(See :ref:`tsig-gss-tsig`).

GSS-ACCEPTOR-PRINCIPAL
----------------------

Use this principal for accepting GSS context.
(See :ref:`tsig-gss-tsig`).

IXFR
----

If set to 1, attempt IXFR when retrieving zone updates. Otherwise IXFR
is not attempted.

LUA-AXFR-SCRIPT
---------------

Script to be used to edit incoming AXFRs, see :ref:`modes-of-operation-axfrfilter`.
This value will override the :ref:`setting-lua-axfr-script` setting. Use
'NONE' to remove a global script.

NSEC3NARROW
-----------

Set to "1" to tell PowerDNS this zone operates in NSEC3 'narrow' mode.
See ``set-nsec3`` for :doc:`pdnsutil <dnssec/pdnsutil>`.

NSEC3PARAM
----------

NSEC3 parameters of a DNSSEC zone. Will be used to synthesize the
NSEC3PARAM record. If present, NSEC3 is used, if not present, zones
default to NSEC. See ``set-nsec3`` in :doc:`pdnsutil <dnssec/pdnsutil>`.
Example content: "1 0 1 ab".

.. _metadata-presigned:

PRESIGNED
---------

This zone carries DNSSEC RRSIGs (signatures), and is presigned. PowerDNS
sets this flag automatically upon incoming zone transfers (AXFR) if it
detects DNSSEC records in the zone. However, if you import a presigned
zone using ``zone2sql`` or ``pdnsutil load-zone`` you must explicitly
set the zone to be ``PRESIGNED``. Note that PowerDNS will not be able to
correctly serve the zone if the imported data is bogus or incomplete.
Also see ``set-presigned`` in :doc:`pdnsutil <dnssec/pdnsutil>`.

If a zone is presigned, the content of the metadata must be "1" (without
the quotes). Any other value will not signal presignedness.

PUBLISH-CDNSKEY, PUBLISH-CDS
----------------------------

Whether to publish CDNSKEY and/or CDS recording defined in :rfc:`7344`.

To publish CDNSKEY records of the KSKs for the zone, set
``PUBLISH-CDNSKEY`` to ``1``.

To publish CDS records for the KSKs in the zone, set ``PUBLISH-CDS`` to
a comma- separated list of `signature algorithm
numbers <http://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml#ds-rr-types-1>`__.

This metadata can also be set using the
:doc:`pdnsutil <dnssec/pdnsutil>` commands ``set-publish-cdnskey``
and ``set-publish-cds``. For an example for an :rfc:`7344` key rollover,
see the :doc:`guides/kskrollcdnskey`.

.. _metadata-slave-renotify:

SLAVE-RENOTIFY
--------------
.. versionadded:: 4.3.0

If set to 1, will make PowerDNS renotify the slaves after an AXFR is received from a master.
Any other value means that no renotifies are done. If not set at all, action will depend on
the :ref:`setting-slave-renotify` setting.

.. _metadata-soa-edit:

SOA-EDIT
--------

When serving this zone, modify the SOA serial number in one of several
ways. Mostly useful to get slaves to re-transfer a zone regularly to get
fresh RRSIGs. See the :ref:`DNSSEC
documentation <soa-edit-ensure-signature-freshness-on-slaves>`
for more information.

.. _metadata-soa-edit-api:

SOA-EDIT-API
------------

On changes to the contents of a zone made through the :doc:`API <http-api/index>`,
the SOA record will be edited according to the SOA-EDIT-API rules. These rules
are the same as the :ref:`SOA-EDIT-DNSUPDATE <dnsupdate-soa-serial-updates>` rules.
If not set during zone creation, a SOA-EDIT-API metadata record is created and set to ``DEFAULT``.
If this record is removed from the backend, the default behaviour is to not do any SOA editing based on this setting.
This is different from setting ``DEFAULT``.


TSIG-ALLOW-AXFR
---------------

Allow these named TSIG keys to AXFR this zone, see :ref:`tsig-provision-signed-notify-axfr`.

TSIG-ALLOW-DNSUPDATE
--------------------

This setting allows you to set the TSIG key required to do an :doc:`dnsupdate`.
If :ref:`GSS-TSIG <tsig-gss-tsig>` is enabled, you can put kerberos principals here as well.

Extra metadata
--------------

Through the API and on the ``pdnsutil set-meta`` commandline, metadata
unused by PowerDNS can be added. It is mandatory to prefix this extra
metadata with "X-" and the name of the external application; the API
will only allow this metadata if it starts with "X-".
