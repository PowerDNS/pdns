Upgrade Notes
=============

Before proceeding, it is advised to check the release notes for your
PowerDNS version, as specified in the name of the distribution file.

Please upgrade to the PowerDNS Authoritative Server 4.0.0 from 3.4.2+.
See the `3.X <https://doc.powerdns.com/3/authoritative/upgrading/>`__
upgrade notes if your version is older than 3.4.2.

4.9.0 to 5.0.0/master
---------------------

LUA records whitespace insertion
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

:ref:`setting-lua-records-insert-whitespace`, introduced in 4.9.1 with the default value (``yes``) set to maintain the old behaviour of inserting whitespace, is set to ``no`` in 5.0.

ixfrdist IPv6 support
^^^^^^^^^^^^^^^^^^^^^

``ixfrdist`` now binds listening sockets with `IPV6_V6ONLY set`, which means that ``[::]`` no longer accepts IPv4 connections.
If you want to listen on both IPv4 and IPv6, you need to add a line with ``0.0.0.0`` to the ``listen`` section of your ixfrdist configuration.

pdnsutil behaviour changes
^^^^^^^^^^^^^^^^^^^^^^^^^^

A few changes of behaviour have been implemented in ``pdnsutil``.

* The ``add-zone-key`` command used to default to creating a ZSK,
  if no key type was given. This default has changed to KSK.

4.8.0 to 4.9.0
--------------

Removed options
^^^^^^^^^^^^^^^

Various settings, deprecated since 4.5.0, have been removed.

* :ref:`setting-allow-unsigned-supermaster` is now :ref:`setting-allow-unsigned-autoprimary`
* :ref:`setting-master` is now :ref:`setting-primary`
* :ref:`setting-slave-cycle-interval` is now :ref:`setting-xfr-cycle-interval`
* :ref:`setting-slave-renotify` is now :ref:`setting-secondary-do-renotify`
* :ref:`setting-slave` is now :ref:`setting-secondary`
* :ref:`setting-superslave` is now :ref:`setting-autosecondary`

In :ref:`setting-lmdb-sync-mode`, the previous default ``mapasync`` is no longer a valid value.
Due to a bug, it was interpreted as ``sync`` in previous versions.
To avoid operational surprises, ``sync`` is the new default value.

Renamed options
^^^^^^^^^^^^^^^

Bind backend
~~~~~~~~~~~~

Various experimental autoprimary settings have been renamed.

* ``supermaster-config`` is now ``autoprimary-config``
* ``supermasters`` is now ``autoprimaries``
* ``supermaster-destdir`` is now ``autoprimary-destdir``

Gsql backends
~~~~~~~~~~~~~

Various custom queries have been renamed.

* ``info-all-slaves-query`` is now ``info-all-secondaries-query``
* ``supermaster-query`` is now ``autoprimary-query``
* ``supermaster-name-to-ips`` is now ``autoprimary-name-to-ips``
* ``supermaster-add`` is now ``autoprimary-add``
* ``update-master-query`` is now ``update-primary-query``
* ``info-all-master-query`` is now ``info-all-primary-query``

Also, ``get-all-domains-query`` got an extra column for a zone's catalog assignment.

API changes
~~~~~~~~~~~

A long time ago (in version 3.4.2), the ``priority`` field was removed from record content in the HTTP API.
Starting with 4.9, API calls containing a ``priority`` field are actively rejected.
This makes it easier for users to detect they are attempting to use a very old API client.

any version to 4.8.x
--------------------

Use of (RSA-)SHA1 on Red Hat Enterprise Linux 9 and derivatives
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If you are using PowerDNS Authoritative Server on EL9, please read `this ticket about Red Hat's SHA1 deprecation and how it affects PowerDNS software <https://github.com/PowerDNS/pdns/issues/12890>`__.

LMDB backend
^^^^^^^^^^^^

Version 4.8.0-alpha1 ships a new version of the LMDB database schema (called version 5), for compatibility with `Lightning Stream <https://doc.powerdns.com/lightningstream>`_.
This schema is somewhat experimental, and although we do intend to make databases portable/upgradeable to future releases in the 4.8 train, we currently make no promises.
There is no downgrade process.
If you upgrade your database (by starting 4.8.0 without ``lmdb-schema-version=4``), you cannot go back.

Upgrading is only supported from database schema versions 3 and 4, that is, databases created/upgraded by version 4.4 and up.

In version 4.8.0, schema version 5 is finalised.
Databases created with -alpha1 or -beta1 work with 4.8.0.

4.6.0 to 4.7.0
--------------

Schema changes
^^^^^^^^^^^^^^

The new Catalog Zones feature comes with a mandatory schema change for the gsql database backends.
See files named ``4.3.x_to_4.7.0_schema.X.sql`` for your database backend in our Git repo, tarball, or distro-specific documentation path.
For the LMDB backend, please review :ref:`setting-lmdb-schema-version`.
The new LMDB schema version is 4.

4.5.x to 4.6.0
--------------

Automatic conversion of ``@`` signs in SOA
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Before version 4.5.0, PowerDNS would automatically replace ``@`` in the SOA RNAME with ``.``, making it easy for users to enter their hostmaster email address without having to think about syntax.
However, this feature interacts badly with handling of presigned zones.
In version 4.5.0, this feature was accidentally broken in the implementation of the zone cache.
In 4.6.0, this automatic conversion is fully removed.
If you still have ``@`` signs in any SOA RNAMEs, 4.6.0 will serve those out literally.
You can find any stray ``@`` signs by running ``pdnsutil check-all-zones``.

New default NSEC3 parameters
^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Following `draft-ietf-dnsop-nsec3-guidance (Guidance for NSEC3 parameter settings) <https://datatracker.ietf.org/doc/html/draft-ietf-dnsop-nsec3-guidance>`__, the default NSEC3PARAM settings (see :ref:`dnssec-operational-nsec-modes-params`) in pdnsutil are now `1 0 0 -` instead of `1 0 1 ab`.

SHA1 DSes
^^^^^^^^^

``pdnsutil show-zone`` and ``pdnsutil export-zone-ds`` no longer emit SHA1 DS records, unless ``--verbose`` is in use.

Privileged port binding in Docker
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

In our Docker image, our binaries are no longer granted the ``net_bind_service`` capability, as this is unnecessary in many deployments.
For more information, see the section `"Privileged ports" in Docker-README <https://github.com/PowerDNS/pdns/blob/master/Docker-README.md#privileged-ports>`__.

4.4.x to 4.5.0
--------------

Automatic conversion of ``@`` signs in SOA
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Before version 4.5.0, PowerDNS would automatically replace ``@`` in the SOA RNAME with ``.``, making it easy for users to enter their hostmaster email address without having to think about syntax.
In version 4.5.0, this feature was accidentally broken in the implementation of the zone cache, and the replacement would only happen if the zone cache was disabled.
Note that in 4.6.0, this automatic conversion is fully removed.
If you still have ``@`` signs in any SOA RNAMEs, 4.5.0 will serve those out literally if the zone cache is enabled.

Record type changes
^^^^^^^^^^^^^^^^^^^

The in-database format of ``CSYNC``, ``IPSECKEY``, ``NID``, ``L32``, ``L64``, and ``LP`` records has changed from 'generic' format to its specialized format.

Generation of the in-database format of ``SVCB`` and ``HTTPS`` received some important bug fixes.
(For these two types, you can skip the :ref:`setting-upgrade-unknown-types` setting mentioned below, but we still recommend the re-transfer.)

API users might notice that replacing records of the newly supported types leaves the old TYPExx records around, even if PowerDNS is not serving them.
To fix this, enable :ref:`setting-upgrade-unknown-types` and replace the records; this will then delete those TYPExx records.
Then, disable the setting again, because it has a serious performance impact on API operations.

On secondaries, it is recommended to re-transfer, using ``pdns_control retrieve ZONE``, with :ref:`setting-upgrade-unknown-types` enabled, all zones that have records of those types, or ``TYPExx``, for numbers 45 and 62.
Leave the setting on until all zones have been re-transferred.

Changed options
^^^^^^^^^^^^^^^

Renamed options
~~~~~~~~~~~~~~~

Various settings have been renamed.
Their old names still work in 4.5.x, but will be removed in a release after it.

* :ref:`setting-allow-unsigned-supermaster` is now :ref:`setting-allow-unsigned-autoprimary`
* :ref:`setting-master` is now :ref:`setting-primary`
* :ref:`setting-slave-cycle-interval` is now :ref:`setting-xfr-cycle-interval`
* :ref:`setting-slave-renotify` is now :ref:`setting-secondary-do-renotify`
* :ref:`setting-slave` is now :ref:`setting-secondary`
* :ref:`setting-superslave` is now :ref:`setting-autosecondary`
* :ref:`setting-domain-metadata-cache-ttl` is now :ref:`setting-zone-metadata-cache-ttl`

Changed defaults
~~~~~~~~~~~~~~~~

- The default value of the :ref:`setting-consistent-backends` option has been changed from ``no`` to ``yes``.
- The default value of the :ref:`setting-max-nsec3-iterations` option has been changed from ``500`` to ``100``.
- The default value of the ``timeout`` parameter for :func:`ifportup` and :func:`ifurlup` functions has been changed from ``1`` to ``2`` seconds.
- The default value of the new :ref:`setting-zone-cache-refresh-interval` option is ``300``.

Zone cache
~~~~~~~~~~

Version 4.5 introduces the zone cache.
The default refresh interval (:ref:`setting-zone-cache-refresh-interval`) is 300, meaning that zones newly added to your backend may need a few minutes to appear.
However, zones added using the API should not notice a delay.

If your backend is dynamic in what zones it does or does not offer, and thus cannot easily provide a complete list of zones every few minutes, set the interval to 0 to disable the feature.

Removed options
~~~~~~~~~~~~~~~
- :ref:`setting-local-ipv6` has been removed. IPv4 and IPv6 listen addresses should now be set with :ref:`setting-local-address`.
- :ref:`setting-query-local-address6` has been removed. IPv4 and IPv6 addresses used for sending queries should now be set with :ref:`setting-query-local-address`.


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

SOA autofilling (i.e. allowing incomplete SOAs in the database) and the API ``set-ptr`` feature, that both were deprecated in earlier releases, have now been removed. Please update your configuration and remove the following settings:

* :ref:`setting-default-soa-mail`
* :ref:`setting-default-soa-name`
* :ref:`setting-soa-expire-default`
* :ref:`setting-soa-minimum-ttl`
* :ref:`setting-soa-refresh-default`
* :ref:`setting-soa-retry-default`

Replace them with :ref:`setting-default-soa-content`, but be aware that this will only be used at zone creation time.
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

Deprecated settings
^^^^^^^^^^^^^^^^^^^

- :ref:`setting-local-ipv6` has been deprecated and will be removed in 4.5.0. Both IPv4 and IPv6 listen addresses can now be set with :ref:`setting-local-address`. The default for the latter has been changed to ``0.0.0.0, ::``.

Changed defaults
^^^^^^^^^^^^^^^^
- :ref:`setting-local-address` now defaults to ``0.0.0.0, ::``.

Schema changes
^^^^^^^^^^^^^^
- The new 'unpublished DNSSEC keys' feature comes with a mandatory schema change for all database backends (including BIND with a DNSSEC database).
  See files named ``4.2.0_to_4.3.0_schema.X.sql`` for your database backend in our Git repo, tarball, or distro-specific documentation path.
  For the LMDB backend, please review :ref:`setting-lmdb-schema-version`.
- If you are upgrading from 4.3.0-beta2 or 4.3.0-rc2, AND ONLY THEN, please read `pull request #8975 <https://github.com/PowerDNS/pdns/pull/8975>`__ very carefully.

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
- Rectification after API changes is now default (:ref:`setting-default-api-rectify`). If you do mutations in large zones, you may notice a slowdown.

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
