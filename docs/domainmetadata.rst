Per zone settings: Domain Metadata
==================================

Each served zone can have "metadata". Such metadata determines how this
zone behaves in certain circumstances.

.. warning::
  When multiple backends are in use, domain metadata is only retrieved from and written to the first DNSSEC-capable or metadata-capable backend, no matter where the related zones live.

For the BIND backend, this information is either stored in the
:ref:`setting-bind-dnssec-db` or the hybrid database,
depending on your settings.

For the implementation in non-sql backends, please review your backend's
documentation.

Apart from raw SQL statements, setting domain metadata can be done with
``pdnsutil metadata set`` and retrieving metadata with ``pdnsutil metadata get``
(respectively ``pdnsutil set-meta`` and ``pdnsutil get-meta`` prior to version
5.0).

The following options can only be read (not written to) via the HTTP API metadata endpoint.

* AXFR-MASTER-TSIG
* LUA-AXFR-SCRIPT
* NSEC3NARROW
* NSEC3PARAM
* PRESIGNED
* SOA-EDIT

The following options cannot be written or read via the HTTP API metadata endpoint.

* API-RECTIFY
* ENABLE-LUA-RECORDS
* SOA-EDIT-API

.. _metadata-allow-axfr-from:

ALLOW-AXFR-FROM
---------------

Per-zone AXFR ACLs can be stored in the domainmetadata table.

Each ACL specifies one subnet (v4 or v6), or the magical value 'AUTO-NS'
that tries to allow all potential secondaries in.

Example:

.. code-block:: shell

    pdnsutil metadata set powerdns.org ALLOW-AXFR-FROM AUTO-NS 2001:db8::/48

or, prior to version 5.0:

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

ALLOW-DNSUPDATE-FROM, FORWARD-DNSUPDATE, NOTIFY-DNSUPDATE, SOA-EDIT-DNSUPDATE
-----------------------------------------------------------------------------

See the documentation on :ref:`Dynamic DNS update <dnsupdate-metadata>`.

.. _metadata-also-notify:

ALSO-NOTIFY
-----------

When notifying this domain, also notify this nameserver (can occur
multiple times). The nameserver may contain an optional port
number. e.g.:

.. code-block:: shell

    pdnsutil metadata set powerdns.org ALSO-NOTIFY 192.0.2.1:5300
    pdnsutil metadata set powerdns.org ALLOW-AXFR-FROM 2001:db8:53::1

or, prior to version 5.0:

.. code-block:: shell

    pdnsutil set-meta powerdns.org ALSO-NOTIFY 192.0.2.1:5300
    pdnsutil set-meta powerdns.org ALLOW-AXFR-FROM 2001:db8:53::1

API-RECTIFY
-----------
.. versionadded:: 4.1.0

This metadata item controls whether or not a zone is fully rectified on changes
to the contents of a zone made through the :doc:`API <http-api/index>`.

When the ``API-RECTIFY`` value is "1", the zone will be rectified on changes.
Any other value means that it will not be rectified. If this is not set
at all, rectifying of the zone depends on the config variable
:ref:`setting-default-api-rectify`.

.. _metadata-axfr-source:

AXFR-MASTER-TSIG
----------------

Use this named TSIG key to retrieve this zone from its primary, see :ref:`tsig-provision-signed-notify-axfr`.

AXFR-SOURCE
-----------

The IP address to use as a source address for sending AXFR and IXFR
requests.

ENABLE-LUA-RECORDS
------------------

If set to 1, allows :doc:`LUA records <lua-records/index>` to be used within
this zone, even if :ref:`setting-enable-lua-records` is set to ``no``.

GSS-ACCEPTOR-PRINCIPAL
----------------------

Use this principal for accepting GSS context.
(See :ref:`tsig-gss-tsig`).

GSS-ALLOW-AXFR-PRINCIPAL
------------------------
.. versionchanged:: 4.3.1

   GSS support was removed

.. versionchanged:: 4.7.0

   GSS support was added back

Allow this GSS principal to perform AXFR retrieval. Most commonly it is
``host/something@REALM``, ``DNS/something@REALM`` or ``user@REALM``.
(See :ref:`tsig-gss-tsig`).

IXFR
----

If set to 1, attempt IXFR when retrieving zone updates. Otherwise, IXFR
is not attempted.

LUA-AXFR-SCRIPT
---------------

Script to be used to edit incoming AXFRs, see :ref:`modes-of-operation-axfrfilter`.
This value will override the :ref:`setting-lua-axfr-script` setting. Use
'NONE' to remove a global script.

NSEC3NARROW
-----------

Set to "1" to tell PowerDNS this zone operates in NSEC3 'narrow' mode.
See ``zone set-nsec3`` in :doc:`pdnsutil <manpages/pdnsutil.1>`.

NSEC3PARAM
----------

NSEC3 parameters of a DNSSEC zone. Will be used to synthesize the
NSEC3PARAM record. If present, NSEC3 is used, if not present, zones
default to NSEC. See ``zone set-nsec3`` in :doc:`pdnsutil <manpages/pdnsutil.1>`.
Example content: "1 0 0 -".

.. _metadata-presigned:

PRESIGNED
---------

This zone carries DNSSEC RRSIGs (signatures), and is presigned. PowerDNS
sets this flag automatically upon incoming zone transfers (AXFR) if it
detects DNSSEC records in the zone. However, if you import a presigned
zone using ``zone2sql`` or ``pdnsutil zone load`` you must explicitly
set the zone to be ``PRESIGNED``. Note that PowerDNS will not be able to
correctly serve the zone if the imported data is bogus or incomplete.
Also see ``zone set-presigned`` in :doc:`pdnsutil <manpages/pdnsutil.1>`.

If a zone is presigned, the content of the metadata must be "1" (without
the quotes). Any other value will not signal presignedness.

.. _metadata-publish-cdnskey-publish-cds:

PUBLISH-CDNSKEY, PUBLISH-CDS
----------------------------

Whether to publish CDNSKEY and/or CDS records as defined in :rfc:`7344`.

To publish CDNSKEY records of the KSKs for the zone, set
``PUBLISH-CDNSKEY`` to ``1``.

To publish CDS records for the KSKs in the zone, set ``PUBLISH-CDS`` to
a comma- separated list of `signature algorithm
numbers <https://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml#ds-rr-types-1>`__.

This metadata can also be set using the
:doc:`pdnsutil <manpages/pdnsutil.1>` commands ``zone set-publish-cdnskey``
and ``zone set-publish-cds``. For an example for an :rfc:`7344` key rollover,
see the :doc:`guides/kskrollcdnskey`.

Global defaults for these values can be set via :ref:`setting-default-publish-cdnskey` and :ref:`setting-default-publish-cds`.

.. _metadata-signaling-zone:

SIGNALING-ZONE
--------------
.. versionadded:: 5.0.0

If set to 1 (and the zone is signed and uses NSEC3 narrow mode), this setting will make
PowerDNS synthesize CDS/CDNSKEY records obtained from other zones served on the same
nameserver, in accordance with :rfc:`9615`.

Typically, this metadata does not need to be set manually; instead, you can use
``pdnsutil set-signaling-zone $zone``. This command not only configures this metadata but
also takes care of the other preconditions needed to properly set up a signaling zone.
For details, see :ref:`dnssec-bootstrapping`.

.. _metadata-slave-renotify:

SLAVE-RENOTIFY
--------------
.. versionadded:: 4.3.0

If set to 1, will make PowerDNS renotify the secondaries after an AXFR is received from a primary.
Any other value means that no renotifies are done. If not set at all, action will depend on
the :ref:`setting-secondary-do-renotify` setting.

.. _metadata-soa-edit:

SOA-EDIT
--------

When serving this zone, modify the SOA serial number in one of several
ways. Mostly useful to get secondaries to re-transfer a zone regularly to get
fresh RRSIGs. See the :ref:`DNSSEC
documentation <soa-edit-ensure-signature-freshness-on-secondaries>`
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
If :ref:`GSS-TSIG <tsig-gss-tsig>` is enabled, you can put Kerberos principals here as well.

Extra metadata
--------------

Through the API and on the ``pdnsutil metadata set`` commandline, metadata
unused by PowerDNS can be added. It is mandatory to prefix this extra
metadata with "X-" and the name of the external application; the API
will only allow this metadata if it starts with "X-".
