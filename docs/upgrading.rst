Upgrade Notes
=============

Before proceeding, it is advised to check the release notes for your
PowerDNS version, as specified in the name of the distribution file.

Please upgrade to the PowerDNS Authoritative Server 4.0.0 from 3.4.2+.
See the `3.X <https://doc.powerdns.com/3/authoritative/upgrading/>`__
upgrade notes if your version is older than 3.4.2.

4.1.X to 4.2.0
--------------

- Superslave operation is no longer enabled by default, use :ref:`setting-superslave` to enable. This setting was called ``supermaster`` in some 4.2.0 prereleases.
- The gsqlite3 backend, and the DNSSEC database for the BIND backend, have a new journal-mode setting. This setting defaults to `WAL <https://www.sqlite.org/wal.html>`_; older versions of PowerDNS did not set the journal mode, which means they used the SQLite default of DELETE.
- Autoserial support has been removed. The ``change_date`` column has been removed from the ``records`` table in all gsql backends, but leaving it in is harmless.
- The :doc:`Generic PostgreSQL backend <backends/generic-postgresql>` schema has changed: the ``notified_serial`` column type in the ``domains`` table has been changed from ``INT DEFAULT NULL`` to ``BIGINT DEFAULT NULL``: ``ALTER TABLE domains ALTER notified_serial TYPE bigint USING CASE WHEN notified_serial >= 0 THEN notified_serial::bigint END;``

4.1.0 to 4.1.1
--------------

- The :doc:`Generic MySQL backend <backends/generic-mysql>` schema has
  changed: the ``notified_serial`` column default in the ``domains``
  table has been changed from ``INT DEFAULT NULL`` to ``INT UNSIGNED
  DEFAULT NULL``:

  - ``ALTER TABLE domains MODIFY notified_serial INT UNSIGNED DEFAULT NULL;``

4.0.X to 4.1.0
--------------

- Recursion has been removed, see the :doc:`dedicated migration guide <guides/recursion>`.
- ALIAS record expansion is disabled by default, use :ref:`setting-expand-alias` to enable.
- *Your LDAP schema might need to be updated*, because new record types
  have been added (see below) and the ``dNSDomain2`` type has been
  changed.
- The :doc:`LDAP Backend <backends/ldap>` now supports additional Record types

  - NSEC3
  - NSEC3PARAM
  - TLSA
  - CDS
  - CDNSKEY
  - OPENPGPKEY
  - TKEY
  - URI
  - CAA

Changed options
^^^^^^^^^^^^^^^

-  ``experimental-lua-policy-script`` option and the feature itself have
   been completely dropped. We invite you to use `PowerDNS
   dnsdist <https://dnsdist.org>`_ instead.

- As recursion has been removed from the Authoritative Server, the
  ``allow-recursion``, ``recursive-cache-ttl`` and ``recursor`` options have
  been removed as well.

- ``default-ksk-algorithms`` has been renamed to :ref:`setting-default-ksk-algorithm`
  and only supports a single algorithm name now.

- ``default-zsk-algorithms`` has been renamed to :ref:`setting-default-zsk-algorithm`
  and only supports a single algorithm name now.

Changed defaults
~~~~~~~~~~~~~~~~

- The default value of :ref:`setting-webserver-allow-from` has been changed from ``0.0.0.0, ::/0`` to ``127.0.0.1, ::1``.

Other changes
^^^^^^^^^^^^^

The ``--with-pgsql``, ``--with-pgsql-libs``, ``--with-pgsql-includes``
and ``--with-pgsql-config`` ``configure`` options have been deprecated.
``configure`` now attempts to find the Postgresql client libraries via
``pkg-config``, falling back to detecting ``pg_config``. Use
``--with-pg-config`` to specify a path to a non-default ``pg_config`` if
you have Postgresql installed in a non-default location.

The ``--with-libsodium`` configure flag has changed from 'no' to 'auto'.
This means that if libsodium and its development header are installed, it will be linked in.

The improved :doc:`LDAP Backend <backends/ldap>` backend now requires Kerberos headers to be installed.
Specifically, it needs `krb5.h` to be installed.

4.0.X to 4.0.2
--------------

Changed options
^^^^^^^^^^^^^^^

Changed defaults
~~~~~~~~~~~~~~~~

-  :ref:`setting-any-to-tcp` changed from ``no`` to ``yes``

3.4.X to 4.0.0
--------------

Database changes
^^^^^^^^^^^^^^^^

No changes have been made to the database schema. However, several
superfluous queries have been dropped from the SQL backend. Furthermore,
the generic SQL backends switched to prepared statements. If you use a
non-standard SQL schema, please review the new defaults.

-  ``insert-ent-query``, ``insert-empty-non-terminal-query``,
   ``insert-ent-order-query`` have been replaced by one query named
   ``insert-empty-non-terminal-order-query``
-  ``insert-record-order-query`` has been dropped,
   ``insert-record-query`` now sets the ordername (or NULL)
-  ``insert-slave-query`` has been dropped, ``insert-zone-query`` now
   sets the type of zone

Changed options
^^^^^^^^^^^^^^^

Several options have been removed or renamed, for the full overview of
all options, see :doc:`settings`.

Renamed options
~~~~~~~~~~~~~~~

The following options have been renamed:

-  ``experimental-json-interface`` ==> :ref:`setting-api`
-  ``experimental-api-readonly`` ==> :ref:`setting-api-readonly`
-  ``experimental-api-key`` ==> :ref:`setting-api-key`
-  ``experimental-dname-processing`` ==> :ref:`setting-dname-processing`
-  ``experimental-dnsupdate`` ==> :ref:`setting-dnsupdate`
-  ``allow-dns-update-from`` ==> :ref:`setting-allow-dnsupdate-from`
-  ``forward-dnsupdates`` ==> :ref:`setting-forward-dnsupdate`

Changed defaults
~~~~~~~~~~~~~~~~

-  :ref:`setting-default-ksk-algorithms`
   changed from rsasha256 to ecdsa256
-  :ref:`setting-default-zsk-algorithms`
   changed from rsasha256 to empty

Removed options
~~~~~~~~~~~~~~~

The following options are removed:

-  ``pipebackend-abi-version``, it now a setting per-pipe backend.
-  ``strict-rfc-axfrs``
-  ``send-root-referral``

API
^^^

The API path has changed to ``/api/v1``.

Incompatible change: ``SOA-EDIT-API`` now follows ``SOA-EDIT-DNSUPDATE``
instead of ``SOA-EDIT`` (incl. the fact that it now has a default value
of ``DEFAULT``). You must update your existing ``SOA-EDIT-API`` metadata
(set ``SOA-EDIT`` to your previous ``SOA-EDIT-API`` value, and
``SOA-EDIT-API`` to ``SOA-EDIT`` to keep the old behaviour).

Resource Record Changes
^^^^^^^^^^^^^^^^^^^^^^^

Since PowerDNS 4.0.0 the CAA resource record (type 257) is supported.
Before PowerDNS 4.0.0 type 257 was used for a proprietary MBOXFW
resource record, which was removed from PowerDNS 4.0. Hence, if you used
CAA records with 3.4.x (stored in the DB with wrong type=MBOXFW but
worked fine) and upgrade to 4.0, PowerDNS will fail to parse this
records and will throw an exception on all queries for a label with
MBOXFW records. Thus, make sure to clean up the records in the DB.

In version 3.X, the PowerDNS Authoritative Server silently ignored records that
have a 'priority' field (like MX or SRV), but where one was not in the database.
In 4.X, :doc:`pdnsutil check-zone <manpages/pdnsutil.1>` will complain about this.
