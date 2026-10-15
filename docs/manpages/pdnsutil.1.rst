pdnsutil
========

Synopsis
--------

:program:`pdnsutil` [OPTION]... *COMMAND*

Description
-----------

:program:`pdnsutil` (formerly ``pdnssec``) is a powerful command that is the
operator-friendly gateway into DNSSEC and zone management for PowerDNS.
Behind the scenes, :program:`pdnsutil` manipulates a PowerDNS backend database,
which also means that for many databases, :program:`pdnsutil` can be run
remotely, and can configure key material on different servers.

Options
-------

.. option:: -h, --help

   Show summary of options

.. option:: -v, --verbose

   Be more verbose

.. option:: -f, --force

   Force an action

.. option:: -q, --quiet

   Be quiet

.. option:: -s, --sort

   Sort output when applicable

.. option:: --config-name <NAME>

   Virtual configuration name

.. option:: --config-dir <DIR>

   Location of pdns.conf. Default is /etc/powerdns.

Commands
--------

There are many available commands. Most commands follow the pattern
``pdnsutil <object> <action> [arguments...]``, where ``<object>`` is a noun and ``<action>`` is a verb; a few commands which do not apply to any particular object
kind use only the verb.

AUTOPRIMARY COMMANDS
--------------------

.. option:: autoprimary add <IP> <NAMESERVER> [ACCOUNT]

    Add an autoprimary entry into the backend. This enables receiving zone
    updates from other servers.

.. option:: autoprimary list

    List all autoprimaries.

.. option:: autoprimary remove *IP* *NAMESERVER*

    Remove an autoprimary from backend. Not supported by BIND backend.

CATALOG ZONE COMMANDS
---------------------

.. option:: catalog list-members *CATALOG*

    List all members of catalog zone *CATALOG*"

.. option:: catalog set *ZONE* [*CATALOG*]

    Change the catalog of *ZONE* to *CATALOG*. If *CATALOG* is omitted,
    removes *ZONE* from the catalog it is in.

ZONE METADATA COMMANDS
----------------------

.. option:: metadata add <ZONE> <KIND> <VALUE> [VALUE]...

    Append *VALUE* to the existing *KIND* metadata for *ZONE*.
    Will return an error if *KIND* does not support multiple values, use
    ``metadata set`` for these values.

.. option:: metadata get <ZONE> [KIND]...

    Get zone metadata. If no *KIND* given, lists all known.

.. option:: metadata set <ZONE> <KIND> [VALUE]...

    Set zone metadata *KIND* for *ZONE* to *VALUE*, replacing all existing
    values of *KIND*. An omitted value clears it.

NETWORK COMMANDS
----------------

.. option:: network list

    List all defined networks with their chosen views.

.. option:: network set <NET> [VIEW]

    Set the *VIEW* for a the *NET* network, or delete if no *VIEW* argument.

ZONE RECORD COMMANDS
--------------------

In these commands, the ``rrset`` object name may also be written as ``record``.

The three commands modifying zone contents (add, delete, replace) will *NOT*
perform an automatic zone rectification, unless the ``--rectify`` option is
passed to the command.

.. option:: rrset add <ZONE> <NAME> <TYPE> [TTL] <CONTENT>

    Add one or more records of *NAME* and *TYPE* to *ZONE* with *CONTENT*
    and optional *TTL*. If *TTL* is not set, the configured *default-ttl* will be used.
    *NAME* must be absolute.

.. option:: rrset delete <ZONE> <NAME> <TYPE>

    Delete named RRSET from zone.
    *NAME* must be absolute.

.. option:: rrset hash <ZONE> <RNAME>

    This convenience command hashes the name *RNAME* according to the
    NSEC3 settings of *ZONE*. Refuses to hash for zones with no NSEC3
    settings.

.. option:: rrset replace <ZONE> <NAME> <TYPE> [TTL] <CONTENT> [CONTENT]...

    Replace existing *NAME* in zone *ZONE* with a new set.

TSIG RELATED COMMANDS
---------------------

These commands manipulate TSIG key information in the database. Some
commands require an *ALGORITHM*, which can be any of the following:

- hmac-md5
- hmac-sha1
- hmac-sha224
- hmac-sha256
- hmac-sha384
- hmac-sha512

.. option:: tsigkey activate <ZONE> <NAME> <primary|secondary|producer|consumer>

    Enable TSIG authenticated AXFR using the key *NAME* for zone *ZONE*.
    This sets the ``TSIG-ALLOW-AXFR`` (primary/producer) or ``AXFR-MASTER-TSIG``
    (secondary/consumer) zone metadata.

.. option:: tsigkey deactivate <ZONE> <NAME> <primary|secondary|producer|consumer>

    Disable TSIG authenticated AXFR using the key *NAME* for zone
    *ZONE*.

.. option:: tsigkey delete <NAME>

    Delete the TSIG key *NAME*. Warning: this does not deactivate said key.

.. option:: tsigkey generate <NAME> <ALGORITHM>

    Generate new TSIG key with name *NAME* and the specified algorithm.

.. option:: tsigkey import <NAME> <ALGORITHM> <KEY>

    Import *KEY* of the specified algorithm as *NAME*.

.. option:: tsigkey list

    Show a list of all configured TSIG keys.

VIEWS COMMANDS
--------------

.. option:: views add-zone <VIEW> <ZONE..VARIANT>

    Add the given *ZONE* *VARIANT* to a *VIEW*.

.. option:: views del-zone *VIEW* *ZONE..VARIANT*

    Remove a *ZONE* *VARIANT* from a *VIEW*.

.. option:: views list *VIEW*

    List all zones within *VIEW*.

.. option:: views list-all

    List all view names.

ZONE MANIPULATION COMMANDS
--------------------------

.. option:: zone check <ZONE>

    Check zone *ZONE* for correctness.

.. option:: zone check-all [exit-on-error]

    Check all zones for correctness, aborting upon finding the first error
    in any zone if "exit-on-error" is specified.

.. option:: zone clear <ZONE>

    Clear the records in zone *ZONE*, but leave actual zone and
    settings unchanged.

.. option:: zone copy <ZONE> <NEW-ZONE>

    Copies the contents of *ZONE* (records, comments, metadata, keys) to a
    new zone *NEW-ZONE*. The new zone must not exist and gets created as
    part of the copy, in the same backend as *ZONE*.
    Note that the *ZONE* options and catalog memberships, if any, are
    not copied.

.. option:: zone create <ZONE>

    Create an empty zone named *ZONE*.

.. option:: zone delete <ZONE>

    Delete the zone named *ZONE*.

.. option:: zone edit <ZONE>

    Opens *ZONE* in zonefile format (regardless of backend it was loaded
    from) in the editor set in the environment variable **EDITOR**. if
    **EDITOR** is empty, *pdnsutil* falls back to using *editor*.

.. option:: zone increase-serial <ZONE>

    Increases the SOA-serial by 1. Uses SOA-EDIT.

.. option:: zone list <ZONE>

    Show all records for *ZONE*. Passing --sort or -s will sort the records
    according to their name, but may require a lot of memory and processor
    time on huge zones.

.. option:: zone list-all <KIND>

    List all active zone names of the given *KIND* (primary, secondary,
    native, producer, consumer), or all if none given. Passing --verbose or
    -v will also include disabled or empty zones.

.. option:: zone load <ZONE> <FILE>

    Load records for *ZONE* from *FILE*. If *ZONE* already exists, all
    records are overwritten, this operation is atomic. If *ZONE* doesn't
    exist, it is created.

.. option:: zone set-account <ZONE> <ACCOUNT>

    Change the account (owner) of *ZONE* to *ACCOUNT*.

.. option:: zone set-kind <ZONE> <KIND>

    Change the kind of *ZONE* to *KIND* (primary, secondary, native, producer,
    consumer).

.. option:: zone set-option <ZONE> [producer|consumer] [coo|unique|group] <VALUE> [VALUE]...

    Set or remove an option for *ZONE*. Providing an empty value removes
    an option.

.. option:: zone set-options-json <ZONE> <JSONFILE>

    Change the options of *ZONE* to the contents of *JSONFILE*.

.. option:: zone zonemd-verify-file <ZONE> <FILE>

    Validate ZONEMD for *ZONE* read from *FILE*.

SECONDARY ZONE COMMANDS
-----------------------

.. option:: zone change-primary <ZONE> <PRIMARY> [PRIMARY]...

    Change the primaries for secondary zone *ZONE* to new primaries *PRIMARY*. All
    *PRIMARY*\ s need to to be space-separated IP addresses with an optional port.

.. option:: zone create-secondary <ZONE> <PRIMARY> [PRIMARY]...

    Create a new secondary zone *ZONE* with primaries *PRIMARY*. All *PRIMARY*\ s
    need to to be space-separated IP addresses with an optional port.

DNSSEC-RELATED COMMANDS
-----------------------

Several commands manipulate the DNSSEC keys and options for zones. Some
of these commands require an *ALGORITHM* to be set. The following
algorithms are supported:

-  rsasha1
-  rsasha1-nsec3-sha1
-  rsasha256
-  rsasha512
-  ecdsa256
-  ecdsa384
-  ed25519
-  ed448

.. note::
  ed25519 and ed448 algorithms will only be available if adequate cryptographic
  libraries have been available while compiling PowerDNS on your particular
  system.

In addition to the algorithm, some commands below may ask for a key size in
bits. The key size may be omitted for the ECC algorithms, which support only
one valid size per algorithm; for ECDSA256 and ED25519, it is 256;
for ECDSA384, it is 384; and for ED448, it is... 456.

.. option:: zone dnssec-disable <ZONE>

    Deactivate all keys and unset PRESIGNED in *ZONE*.

.. option:: zone export-dnskey <ZONE> <KEY_ID>

    Export DNSKEY and DS of key with key id *KEY_ID* within zone *ZONE* to
    standard output.

.. option:: zone export-ds <ZONE>

    Export all KSK DS records for *ZONE* to standard output.

.. option:: zone list-keys [ZONE]

    List DNSSEC information for all keys or for *ZONE* only. Passing
    --verbose or -v will also include the keys for disabled or empty zones.

.. option:: zone rectify <ZONE>

    Calculates the 'ordername' and 'auth' fields for a zone called
    *ZONE* so they comply with DNSSEC settings. Can be used to fix up
    migrated data.

.. option:: zone rectify-all

    Calculates the 'ordername' and 'auth' fields for all zones so they
    comply with DNSSEC settings. Can be used to fix up migrated data.

.. option:: zone secure <ZONE> [ZONE]...

    Configures a zone called *ZONE* with reasonable DNSSEC settings, and
    performs a zone rectification.

.. option:: zone secure-all [increase-serial]

    Configures all zones that are not currently signed with reasonable
    DNSSEC settings. Setting **increase-serial** will increase the
    serial of those zones too. You should manually run 'pdnsutil
    zone rectify-all' afterwards.

.. option:: zone set-nsec3 <ZONE> ['HASH-ALGORITHM FLAGS ITERATIONS SALT'] [narrow]

    Sets NSEC3 parameters for this zone. The quoted parameters are 4
    values that are used for the NSEC3PARAM record and decide how
    NSEC3 records are created. The NSEC3 parameters must be quoted on
    the command line. *HASH-ALGORITHM* must be 1 (SHA-1). Setting
    *FLAGS* to 1 enables NSEC3 opt-out operation. Only do this if you
    know you need it. For *ITERATIONS*, please consult
    :rfc:`RFC 5155<5155#section-10.3>`.

    And be aware that a high number might overload validating
    resolvers and that a limit can be set with ``max-nsec3-iterations``
    in ``pdns.conf``. The *SALT* is a hexadecimal string encoding the bits
    for the salt, or - to use no salt.

    Setting **narrow** will make PowerDNS send out "white lies" (:rfc:`7129`)
    about the next secure record to prevent zone enumeration. Instead of
    looking it up in the database, it will send out the hash + 1 as the next
    secure record. Narrow mode requires online signing capabilities by the
    nameserver and therefore zone transfers are denied.

    If only the zone is provided as argument, the 4-parameter quoted string
    defaults to ``'1 0 0 -'``, as recommended by :rfc:`9276`.

    A sample commandline would be:

    ``pdnsutil zone set-nsec3 powerdnssec.org '1 1 1 ab' narrow``

    .. warning ::
       If running in RSASHA1 mode (algorithm 5 or 7), switching
       from NSEC to NSEC3 will require a DS update in the parent zone.

.. option:: zone set-presigned <ZONE>

    Switches *ZONE* to presigned operation, utilizing in-zone RRSIGs.

.. option:: zone set-publish-cdnskey <ZONE> [delete]

    Set *ZONE* to publish CDNSKEY records. Add 'delete' to publish a CDNSKEY
    with a DNSSEC delete algorithm.

.. option:: zone set-publish-cds <ZONE> [DIGESTALGOS]

    Set *ZONE* to respond to queries for its CDS records. the optional
    argument *DIGESTALGOS* should be a comma-separated list of DS
    algorithms to use. By default, this is 2 (SHA-256). 0 will publish a
    CDS with a DNSSEC delete algorithm.

.. option:: zone show <ZONE>

    Shows various details of the zone called *ZONE*, including its
    DNSSEC related settings.

.. option:: zone unset-nsec3 <ZONE>

    Converts *ZONE* to NSEC operations. **WARNING**: If running in
    RSASHA1 mode (algorithm 5 or 7), switching from NSEC to NSEC3 will
    require a DS update at the parent zone!

.. option:: zone unset-presigned <ZONE>

    Disables presigned operation for *ZONE*.

.. option:: zone unset-publish-cdnskey <ZONE>

    Set *ZONE* to stop publishing CDNSKEY records.

.. option:: zone unset-publish-cds <ZONE>

    Set *ZONE* to stop responding to queries for its CDS records.

ZONE KEY COMMANDS
-----------------

.. option:: zone activate-key <ZONE> <KEY_ID>

    Activate a key with id *KEY_ID* within a zone called *ZONE*.

.. option:: zone add-key <ZONE> [KSK|ZSK] [active|inactive] [published|unpublished] <ALGORITHM> [KEYBITS]

    Create a new key for zone *ZONE*, and make it a KSK (default) or a ZSK, with
    the specified *ALGORITHM* and *KEYBITS*. If *KEYBITS* is omitted, the value
    of :ref:`setting-default-ksk-size` or :ref:`setting-default-zsk-size` are
    used.

    The key is inactive by default, set it to **active** to immediately use it
    to sign *ZONE*. The key is published in the zone by default, set it to
    **unpublished** to keep it from being returned in a DNSKEY query, which is
    useful for algorithm rollovers.

    Prints the id of the added key.

.. option:: zone deactivate-key <ZONE> <KEY_ID>

    Deactivate a key with id KEY_ID within a zone called *ZONE*.

.. option:: zone export-key <ZONE> <KEY_ID>

    Export full (private) key with key id *KEY_ID* within zone *ZONE* to
    standard output. The format used is compatible with BIND and NSD/LDNS.

.. option:: zone export-key-pem <ZONE> <KEY_ID>

    Export full (private) key with key id *KEY_ID* within zone *ZONE* to
    standard output in the PEM file format. The format is compatible with
    many non-DNS software products.

.. option:: zone generate-key <KSK|ZSK> [ALGORITHM] [KEYBITS]

    Generate a ZSK or KSK with specified algorithm and bits and print it
    on standard output. If *ALGORITHM* is not set, ECDSA256 is used.
    If *KEYBITS* is not set, an appropriate keysize is selected
    for *ALGORITHM*: for RSA keys, 2048 bits for KSK and 1024 bits for ZSK;
    for ECC keys, the algorithm-required size as mentioned above.

.. option:: zone import-key <ZONE> <FILE> [KSK|ZSK] [active|inactive] [published|unpublished]

    Import from *FILE* a full (private) key for the zone *ZONE*. The
    format used is compatible with BIND and NSD/LDNS. **KSK** or **ZSK**
    specifies the flags this key should have on import. Defaults to KSK,
    active and published. Prints the id of the added key.

.. option:: zone import-key-pem <ZONE> <FILE> <ALGORITHM> {KSK|ZSK}

    Import from PEM *FILE* a full (private) key for the zone *ZONE* with a
    specified *ALGORITHM*. The format used is compatible with many non-DNS
    software products. **KSK** or **ZSK** specifies the flags this key should
    have on import. Prints the id of the added key.

.. option:: zone publish-key <ZONE> <KEY_ID>

    Publish the key with id *KEY_ID* within zone *ZONE*.

.. option:: zone remove-key <ZONE> <KEY_ID>

    Remove a key with id *KEY_ID* from zone *ZONE*.

.. option:: zone unpublish-key <ZONE> <KEY_ID>

    Unpublish the key with id *KEY_ID* within zone *ZONE*.

OTHER/MISCELLANEOUS COMMANDS
----------------------------

.. option:: b2b-migrate <OLD> <NEW>

    Migrate data from one backend to another.
    Needs ``launch=OLD,NEW`` in the configuration.

.. option:: backend-cmd <BACKEND> <CMD> [CMD]...

    Send a text command to a backend for execution. GSQL backends will
    take SQL commands, other backends may take different things. Be
    careful!

.. option:: backend-lookup <BACKEND> <NAME> [TYPE [CLIENT_IP_SUBNET]]

    Perform a backend record lookup.

.. option:: bench-db [FILE]

    Perform a benchmark of the backend-database.
    *FILE* can be a file with a list, one per line, of zone names to use for this.
    If *FILE* is not specified, powerdns.com is used.

.. option:: create-bind-db <FILENAME>

    Create DNSSEC database (sqlite3) at *FILENAME* for the BIND backend.
    Remember to set ``bind-dnssec-db=*FILE*`` in your ``pdns.conf``.

.. option:: hash-password [WORK_FACTOR]

    This convenience command reads a password (not echoed) from standard
    input and returns a hashed and salted version, for use as a webserver
    password or api key.
    An optional scrypt work factor can be specified, in powers of two,
    otherwise it defaults to 1024.

.. option:: ipdecrypt <IP_ADDRESS> PASSPHRASE_OR_KEY [key]

    Decrypt an IP address according to the 'ipcipher' standard. If the
    passphrase is a base64 key, add the word "key" after it.

.. option:: ipencrypt <IP_ADDRESS> PASSPHRASE_OR_KEY [key]

    Encrypt an IP address according to the 'ipcipher' standard. If the
    passphrase is a base64 key, add the word "key" after it.

.. option:: list-algorithms [with-backend]

    List all DNSSEC algorithms supported, optionally also listing the
    cryptographic library used if "with-backend" is specified.

.. option:: test-schema <ZONE>

    Test database schema, this creates the zone *ZONE*

.. option:: raw-lua-from-content <TYPE> <CONTENT>

    Display record contents in a form suitable for dnsdist's `SpoofRawAction`.

See also
--------

pdns\_server (1), pdns\_control (1)
