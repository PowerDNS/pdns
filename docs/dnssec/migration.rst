Migrating (Signed) Zones to PowerDNS
====================================

This chapter discusses various migration strategies, from existing
PowerDNS setups, from existing unsigned installations and finally from
previous non-PowerDNS DNSSEC deployments.

.. _dnssecfromexisting:

From an existing PowerDNS installation
--------------------------------------

To migrate an existing database-backed PowerDNS installation, ensure you
are running at least PowerDNS 3.3.3 and preferably 3.4 or newer.

If you run an older version of PowerDNS, please upgrade to 3.4 and apply
all the changes in database schemas as shown in the :doc:`upgrade documentation <../upgrading>`.

.. warning::
  Once the relevant ``backend-dnssec`` switch has been set,
  stricter rules apply for filling out the database! The short version is:
  run ``pdnsutil rectify-all-zones``, even those not secured with DNSSEC!
  For more information, see the :ref:`generic-sql-handling-dnssec-signed-zones`.

To deliver a correctly signed zone with the :ref:`dnssec-pdnsutil-dnssec-defaults`, invoke:

.. code-block:: shell

    pdnsutil secure-zone ZONE

To view the DS records for this zone (to transfer to the parent zone),
run

.. code-block:: shell

    pdnsutil show-zone ZONE

For a more traditional setup with a KSK and a ZSK, use the following
sequence of commands:

.. code-block:: shell

    pdnsutil add-zone-key ZONE ksk 2048 active rsasha256
    pdnsutil add-zone-key ZONE zsk 1024 active rsasha256
    pdnsutil add-zone-key ZONE zsk 1024 inactive rsasha256

This will add a 2048-bit RSA Key Signing Key and two 1024-bit RSA Zone
Signing Keys. One of the ZSKs is inactive and can be rolled to if
needed.

From existing non-DNSSEC, non-PowerDNS setups
---------------------------------------------

It is recommended to :doc:`migrate to PowerDNS <../migration>` before
securing your zones. After that, see the instructions
:ref:`above <dnssecfromexisting>`.

.. _dnssec-migration-presigned:

From existing DNSSEC non-PowerDNS setups, pre-signed
----------------------------------------------------

Industry standard signed zones can be served natively by PowerDNS,
without changes. In such cases, signing happens externally to PowerDNS,
possibly via OpenDNSSEC, ldns-sign or dnssec-sign.

PowerDNS needs to know if a zone should receive DNSSEC processing. To
configure, run ``pdnsutil set-presigned ZONE``.

If you import presigned zones into your database, please do not import
the NSEC or NSEC3 records. PowerDNS will synthesize these itself.
Putting them in the database might cause duplicate records in responses.
:ref:`zone2sql <migration-zone2sql>` filters NSEC and NSEC3
automatically.

.. warning::
  Right now, you will also need to configure NSEC(3) settings
  for pre-signed zones using ``pdnsutil set-nsec3``. Default is NSEC, in
  which case no further configuration is necessary.

From existing DNSSEC non-PowerDNS setups, live signing
------------------------------------------------------

The ``pdnsutil`` tool features the option to import zone keys in the
industry standard private key format, version 1.2. To import an existing
KSK, use

.. code-block:: shell

    pdnsutil import-zone-key ZONE FILENAME ksk

replace 'ksk' by 'zsk' for a Zone Signing Key.

If all keys are imported using this tool, a zone will serve mostly
identical records to before, with the important change that the RRSIG
inception dates will be different.

.. note::
  Within PowerDNS, the 'algorithm' for RSASHA1 keys is modulated
  based on the NSEC3 setting. So if an algorithm=7 key is imported in a
  zone with no configured NSEC3, it will appear as algorithm 5!

Secure transfers
----------------

PowerDNS supports secure DNSSEC transfers as described in
`draft-koch-dnsop-dnssec-operator-change <https://datatracker.ietf.org/doc/draft-koch-dnsop-dnssec-operator-change/>`__.
If the :ref:`setting-direct-dnskey` option is
enabled the foreign DNSKEY records stored in the database are added to
the keyset and signed with the KSK. Without the :ref:`setting-direct-dnskey` option
DNSKEY records in the database are silently ignored.
