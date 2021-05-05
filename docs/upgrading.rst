Upgrade Notes
=============

Before proceeding, it is advised to check the release notes for your
PowerDNS version, as specified in the name of the distribution file.

Please upgrade to the PowerDNS Authoritative Server 4.0.0 from 3.4.2+.
See the `3.X <https://doc.powerdns.com/3/authoritative/upgrading/>`__
upgrade notes if your version is older than 3.4.2.

4.4.x to 4.5.0 or master
------------------------

Record type changes
^^^^^^^^^^^^^^^^^^^

The in-database format of ``CSYNC``, ``IPSECKEY``, ``NID``, ``L32``, ``L64``, and ``LP`` records has changed from 'generic' format to its specialized format.

API users might notice that replacing records of these types leaves the old TYPExx records around, even if PowerDNS is not serving them.
To fix this, enable :ref:`setting-upgrade-unknown-types` and replace the records; this will then delete those TYPExx records.
Then, disable the setting again, because it has a serious performance impact on API operations.

On secondaries, it is recommended to re-transfer, using ``pdns_control retrieve ZONE``, with :ref:`setting-upgrade-unknown-types` enabled, all zones that have records of those types, or ``TYPExx``, for numbers 45 and 62.
Leave the setting on until all zones have been re-transferred.

Wording changes
^^^^^^^^^^^^^^^

Various settings have been renamed.
Their old names still work in 4.5.x, but will be removed in the release after it.

* :ref:`setting-allow-unsigned-supermaster` is now :ref:`setting-allow-unsigned-autoprimary`
* :ref:`setting-master` is now :ref:`setting-primary`
* :ref:`setting-slave-cycle-interval` is now :ref:`setting-xfr-cycle-interval`
* :ref:`setting-slave-renotify` is now :ref:`setting-secondary-do-renotify`
* :ref:`setting-slave` is now :ref:`setting-secondary`
* :ref:`setting-superslave` is now :ref:`setting-autosecondary`

Changed defaults
~~~~~~~~~~~~~~~~

- The default value of the ``timeout`` option for :ref:`ifportup` and :ref:`ifurlup` functions has been changed from ``1`` to ``2`` seconds.

4.3.x to 4.4.0
--------------

Latency calculation changes
^^^^^^^^^^^^^^^^^^^^^^^^^^^

It turned out that average latency calculations in earlier versions used integers instead of floating point variables, which led to the throwing away of any data points between 'the current average' and 1000ms above it, instead of having those data points affecting the average.
In 4.3.2 and 4.4.0, we `started using floating point variables for this <https://github.com/PowerDNS/pdns/pull/9768/files>`__, which means the latency calculation is accurate now.
Usually, this means you will see higher latency numbers after upgrading.

MySQL character set detection
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Before 4.4.0, the gmysql backend told the MySQL (or MariaDB) client libraries to automatically detect the client character set and collation, based on the environment locale.
(Look for 'autodetect' in https://dev.mysql.com/doc/refman/5.7/en/charset-connection.html to know more).
On some systems, this autodetection makes choices that are incompatible with MySQL Server 8 defaults.
On all systems, this autodetection can make choices that vary depending on how PowerDNS is started.
In other words, the autodetection provides unpredictable results.

In 4.4.0, the autodetection has been removed.
The MySQL/MariaDB client lib will now use its default settings, unless overridden in ``my.cnf``, for example::

  [client]
  default-character-set = latin1

If you have trouble connecting to your database with 4.4.0 or up, you can override the character set in ``my.cnf``.

Before upgrading, please check your database for any non-ASCII content.
The interpretation of the non-ASCII bytes in those fields might change because of a different charset suddenly being used.

Record type changes
^^^^^^^^^^^^^^^^^^^

The in-database format of the ``SVCB``, ``HTTPS`` and ``APL`` records has changed from 'generic' format to its specialized format.

API users might notice that replacing records of these types leaves the old TYPExx records around, even if PowerDNS is not serving them.
To fix this, enable :ref:`setting-upgrade-unknown-types` and replace the records; this will then delete those TYPExx records.
Then, disable the setting again, because it has a serious performance impact on API operations.

On secondaries, it is recommended to re-transfer, using ``pdns_control retrieve ZONE``, with :ref:`setting-upgrade-unknown-types` enabled, all zones that have records of those types, or ``TYPExx``, for numbers 42, 64, 65.
Leave the setting on until all zones have been re-transferred.

PostgreSQL configuration escaping
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

We now correctly quote/escape Postgres connection parameters.
If you used single quotes (or some other form of escaping) around your Postgres password because it contained spaces, you now need to put your unmodified, unescaped, unquoted password in your configuration.

New LMDB schema
^^^^^^^^^^^^^^^

An LMDB schema upgrade is mandatory.
Please carefully read :ref:`setting-lmdb-schema-version` before upgrading to 4.4.x. The new schema version is version 3.

Removed features
^^^^^^^^^^^^^^^^

SOA autofilling (i.e. allowing incomplete SOAs in the database) and the API set-ptr feature, that both were deprecated in earlier releases, have now been removed.
Please run ``pdnsutil check-all-zones`` to check for incomplete SOAs.

The :ref:`setting-do-ipv6-additional-processing` setting was removed. IPv6 additional processing now always happens when IPv4 additional processing happens.

4.3.1 to 4.3.2
--------------

Latency calculation changes
^^^^^^^^^^^^^^^^^^^^^^^^^^^

It turned out that average latency calculations in earlier versions used integers instead of floating point variables, which led to the throwing away of any data points between 'the current average' and 1000ms above it, instead of having those data points affecting the average.
In 4.3.2 and 4.4.0, we `started using floating point variables for this <https://github.com/PowerDNS/pdns/pull/9786/files>`__, which means the latency calculation is accurate now.
Usually, this means you will see higher latency numbers after upgrading.

To be very clear, there is no performance difference between 4.3.1 and 4.3.2.
The only change is in the latency calculation, which was wrong in 4.3.1 and is correct in 4.3.2.
This fix was backported to 4.3.2 from 4.4.0 so that users can fairly compare the performance of 4.3.2 and 4.4.0.

4.3.0 to 4.3.1
--------------

On RHEL/CentOS 8, the gmysql backend now uses ``mariadb-connector-c`` instead of ``mysql-libs``.
This change was made because the default MySQL implementation for RHEL8 is MariaDB, and MariaDB and MySQL cannot be installed in parallel due to conflicting RPM packages.
The mariadb client lib will connect to your existing MySQL servers without trouble.

Unknown record encoding (`RFC 3597 <https://tools.ietf.org/html/rfc3597>`__) has become more strict as a result of the fixes for :doc:`PowerDNS Security Advisory 2020-05 <../security-advisories/powerdns-advisory-2020-05>`. Please use ``pdnsutil check-all-zones`` to review your zone contents.

The previous set of indexes for the gsqlite3 backend was found to be poor.
4.3.1 ships a new schema, and a migration:

.. literalinclude:: ../modules/gsqlite3backend/4.3.0_to_4.3.1_schema.sqlite3.sql

4.2.x to 4.3.0
--------------

NSEC(3) TTL changed
^^^^^^^^^^^^^^^^^^^

NSEC(3) records now use the negative TTL, instead of the SOA minimum TTL.
See :ref:`the DNSSEC TTL notes <dnssec-ttl-notes>`  for more information.

Lua Netmask class methods changed
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Netmask class methods ``isIpv4`` and ``isIpv6`` have been deprecated in Lua, use :func:`Netmask.isIPv4` and :func:`Netmask.isIPv6` instead. In the C++ API, these methods have been removed.

``socket-dir`` changed
^^^^^^^^^^^^^^^^^^^^^^
The default :ref:`setting-socket-dir` has changed to include ``pdns`` in the path.
It is now whatever is passed to ``--with-socketdir`` during configure (``/var/run`` by default) plus ``pdns``.
The systemd unit-file is updated to reflect this change and systemd will automatically create the directory with the proper permissions.
The packaged sysV init-script also creates this directory.
For other operating systems, update your init-scripts accordingly.

Systemd service and permissions
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
The systemd service-file that is installed no longer uses the ``root`` user to start.
It uses the user and group set with the ``--with-service-user`` and ``--with-service-group`` switches during configuration, "pdns" by default.
This could mean that PowerDNS cannot read its configuration or zone-file data.
It is recommended to recursively ``chown`` directories used by PowerDNS::

  # For Debian-based systems
  chown -R root:pdns /etc/powerdns
  chown -R pdns:pdns /var/lib/powerdns

  # For CentOS and RHEL based systems
  chown -R root:pdns /etc/pdns
  chown -R pdns:pdns /var/lib/pdns

Packages provided on `the PowerDNS Repository <https://repo.powerdns.com>`__ will ``chown`` directories created by them accordingly in the post-installation steps.

New settings
^^^^^^^^^^^^

- The :ref:`setting-axfr-fetch-timeout` setting has been added.
  This setting controls how long an inbound AXFR may be idle in seconds.
  Its default is 10
- The :ref:`setting-max-generate-steps` setting has been added.
  This sets the maximum number of steps that will be performed when loading a BIND zone with the ``$GENERATE`` directive.
  The default is 0, which is unlimited.

Removed settings
^^^^^^^^^^^^^^^^

- :ref:`setting-local-ipv6` has been deprecated, and will be removed in 4.4.0. IPv4 and IPv6 listen addresses can now be set with :ref:`setting-local-address`. The default for the latter has been changed to ``0.0.0.0, ::``.

Schema changes
^^^^^^^^^^^^^^
- The new 'unpublished DNSSEC keys' feature comes with a mandatory schema change for all database backends (including BIND with a DNSSEC database).
  See files named ``4.2.0_to_4.3.0_schema.X.sql`` for your database backend in our Git repo, tarball, or distro-specific documentation path.
  For the LMDB backend, please review :ref:`setting-lmdb-schema-version`.
- If you are upgrading from beta2 or rc2, AND ONLY THEN, please read `pull request #8975 <https://github.com/PowerDNS/pdns/pull/8975>`__ very carefully.

Implicit 5->7 algorithm upgrades
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Since version 3.0 (the first version of the PowerDNS Authoritative Server that supported DNSSEC signing), we have automatically, silently, upgraded algorithm 5 (RSASHA1) keys to algorithm 7 (RSASHA1-NSEC3-SHA1) when the user enabled NSEC3. This has been a source of confusion, and because of that, we introduced warnings for users of this feature in 4.0 and 4.1. To see if you are affected, run ``pdnsutil check-all-zones`` from version 4.0 or up. In this release, the automatic upgrade is gone, and affected zones will break if no action is taken.

.. _ixfr-in-corruption-4.3.0:

IXFR-in corruption
^^^^^^^^^^^^^^^^^^

A bug in PowerDNS versions before 4.2.2/4.3.0 would cause wrong deletion or addition of records if IXFR deltas came in very quickly (within the query cache timeout, which defaults to 20/60 seconds).
If you have zones which use inbound IXFR (in other words, the ``IXFR`` metadata item for that zone is set to ``1``), we strongly suggest triggering a completely fresh transfer.
You could accomplish that by deleting all records in the zone with an SQL query and waiting for a fresh transfer, or (1) disabling IXFR (2) forcing a fresh transfer using ``pdns_control retrieve example.com`` (3) enabling IXFR again.

4.2.X to 4.2.3
--------------

Unknown record encoding (`RFC 3597 <https://tools.ietf.org/html/rfc3597>`__) has become more strict as a result of the fixes for :doc:`PowerDNS Security Advisory 2020-05 <../security-advisories/powerdns-advisory-2020-05>`. Please use ``pdnsutil check-all-zones`` to review your zone contents.

4.X.X to 4.2.2
--------------

.. _ixfr-in-corruption-4.2.2:

IXFR-in corruption
^^^^^^^^^^^^^^^^^^

A bug in PowerDNS versions before 4.2.2/4.3.0 would cause wrong deletion or addition of records if IXFR deltas came in very quickly (within the query cache timeout, which defaults to 20/60 seconds).
If you have zones which use inbound IXFR (in other words, the ``IXFR`` metadata item for that zone is set to ``1``), we strongly suggest triggering a completely fresh transfer.
You could accomplish that by deleting all records in the zone with an SQL query and waiting for a fresh transfer, or (1) disabling IXFR (2) forcing a fresh transfer using ``pdns_control retrieve example.com`` (3) enabling IXFR again.


4.1.X to 4.2.0
--------------

- Superslave operation is no longer enabled by default, use :ref:`setting-superslave` to enable. This setting was called ``supermaster`` in some 4.2.0 prereleases.
- The gsqlite3 backend, and the DNSSEC database for the BIND backend, have a new journal-mode setting. This setting defaults to `WAL <https://www.sqlite.org/wal.html>`_; older versions of PowerDNS did not set the journal mode, which means they used the SQLite default of DELETE.
- Autoserial support has been removed. The ``change_date`` column has been removed from the ``records`` table in all gsql backends, but leaving it in is harmless.
- The :doc:`Generic PostgreSQL backend <backends/generic-postgresql>` schema has changed: the ``notified_serial`` column type in the ``domains`` table has been changed from ``INT DEFAULT NULL`` to ``BIGINT DEFAULT NULL``: ``ALTER TABLE domains ALTER notified_serial TYPE bigint USING CASE WHEN notified_serial >= 0 THEN notified_serial::bigint END;``

4.1.X to 4.1.14
---------------

Unknown record encoding (`RFC 3597 <https://tools.ietf.org/html/rfc3597>`__) has become more strict as a result of the fixes for :doc:`PowerDNS Security Advisory 2020-05 <../security-advisories/powerdns-advisory-2020-05>`. Please use ``pdnsutil check-all-zones`` to review your zone contents.

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
-  ``experimental-api-readonly`` ==> ``api-readonly``
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
