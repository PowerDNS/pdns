% PDNSUTIL(1) PowerDNS DNSSEC command and control
% Matthijs Möhlmann <matthijs@cacholong.nl>
% November 2011

# NAME
pdnsutil - PowerDNS dnssec command and control

# SYNOPSIS
pdnsutil [OPTION]... *COMMAND*

# DESCRIPTION
**pdnsutil** (formerly pdnssec) is a powerful command that is the operator-friendly
gateway into DNSSEC and zone management for PowerDNS. Behind the scenes, **pdnsutil**
manipulates a PowerDNS backend database, which also means that for many databases,
**pdnsutil** can be run remotely, and can configure key material on different servers.

# OPTIONS
-h | -help
:    Show summary of options

-v | --verbose
:    Be more verbose.

--force
:    force an action

--config-name *NAME*
:    Virtual configuration name

--config-dir *DIR*
:    Location of pdns.conf. Default is /etc/powerdns.

# COMMANDS
There are many available commands, this section splits them up into their
respective uses

## DNSSEC RELATED COMMANDS
Several commands manipulate the DNSSEC keys and options for zones. Some of these
commands require an *ALGORITHM* to be set. The following algorithms are
supported:

 * rsasha1
 * rsasha256
 * rsasha512
 * gost
 * ecdsa256
 * ecdsa384

activate-zone-key *ZONE* *KEY-ID*
:    Activate a key with id *KEY-ID* within a zone called *ZONE*.

add-zone-key *ZONE* {**KSK**,**ZSK**} [**active**,**inactive**] *KEYBITS* *ALGORITHM*
:   Create a new key for zone *ZONE*, and make it a KSK or a ZSK, with the
    specified algorithm. The key is inactive by default, set it to **active** to
    immediately use it to sign *ZONE*. Prints the id of the added key.

create-bind-db *FILE*
:    Create DNSSEC database (sqlite3) at *FILE* for the BIND backend.
     Remember to set `bind-dnssec-db=*FILE*` in your `pdns.conf`.

deactivate-zone-key *ZONE* *KEY-ID*
:    Deactivate a key with id KEY-ID within a zone called *ZONE*.

disable-dnssec *ZONE*
:    Deactivate all keys and unset PRESIGNED in *ZONE*.

export-zone-dnskey *ZONE* *KEY-ID*
:    Export to standard output DNSKEY and DS of key with key id *KEY-ID* within
     zone called *ZONE*.

export-zone-key *ZONE* *KEY-ID*
:    Export to standard output full (private) key with key id *KEY-ID* within
     zone called *ZONE*. The format used is compatible with BIND and NSD/LDNS.

generate-zone-key {**KSK**,**ZSK**} [*ALGORITHM*] [*KEYBITS*]
:    Generate a ZSK or KSK to stdout with specified algorithm and bits and print
     it on STDOUT. If *ALGORITHM* is not set, RSASHA512 is used. If *KEYBITS* is
     not set, an appropriate keysize is selected for *ALGORITHM*.

import-zone-key *ZONE* *FILE* {**KSK**,**ZSK**}
:    Import from *FILE* a full (private) key for zone called *ZONE*. The format
     used is compatible with BIND and NSD/LDNS. **KSK** or **ZSK** specifies the
     flags this key should have on import. Prints the id of the added key.

remove-zone-key *ZONE* *KEY-ID*
:    Remove a key with id *KEY-ID* from a zone called *ZONE*.

set-nsec3 *ZONE* '*HASH-ALGORITHM* *FLAGS* *ITERATIONS* *SALT*' [**narrow**]
:    Sets NSEC3 parameters for this zone. The quoted parameters are 4 values
     that are used for the the NSEC3PARAM record and decide how NSEC3 records
     are created. The NSEC3 parameters must be quoted on the command line.<br><br>
     *HASH-ALGORITHM* must be 1 (SHA-1).<br><br>
     Setting *FLAGS* to 1 enables NSEC3 opt-out operation. Only do this if you
     know you need it.<br><br>
     For *ITERATIONS*, please consult RFC 5155, section 10.3. And be aware
     that a high number might overload validating resolvers.<br><br>
     The *SALT* is a hexadecimal string encoding the bits for the salt.<br><br>
     Setting **narrow** will make PowerDNS send out "white lies" about the next
     secure record. Instead of looking it up in the database, it will send out
     the hash + 1 as the next secure record. <br><br>
     A sample commandline is: "pdnsutil set-nsec3 powerdnssec.org '1 1 1 ab' narrow".<br><br>
     **WARNING**: If running in RSASHA1 mode (algorithm 5 or 7), switching from
     NSEC to NSEC3 will require a DS update in the parent zone.

unset-nsec3 *ZONE*
:    Converts *ZONE* to NSEC operations. **WARNING**: If running in RSASHA1 mode
     (algorithm 5 or 7), switching from NSEC to NSEC3 will require a DS update
     at the parent zone!

set-publish-cds *ZONE* [*DIGESTALGOS*]
:    Set *ZONE* to respond to queries for its CDS records. the optional argument
     *DIGESTALGOS* should be a comma-separated list of DS algorithms to use. By
     default, this is 1,2 (SHA1 and SHA2-256).

set-publish-cdnskey *ZONE*
:    Set *ZONE* to publish CDNSKEY records.

unset-publish-cds *ZONE*
:    Set *ZONE* to stop responding to queries for its CDS records.

unset-publish-cdnskey *ZONE*
:    Set *ZONE* to stop publishing CDNSKEY records.

## TSIG RELATED COMMANDS
These commands manipulate TSIG key information in the database. Some commands
require an *ALGORITHM*, the following are available:

 * hmac-md5
 * hmac-sha1
 * hmac-sha224
 * hmac-sha256
 * hmac-sha384
 * hmac-sha512

activate-tsig-key *ZONE* *NAME* {**master**,**slave**}
:    Enable TSIG authenticated AXFR using the key *NAME* for zone *ZONE*.
     This sets the `TSIG-ALLOW-AXFR` (master) or `AXFR-MASTER-TSIG` (slave)
     zone metadata.

deactivate-tsig-key *ZONE* *NAME* {**master**,**slave**}
:    Disable TSIG authenticated AXFR using the key *NAME* for zone *ZONE*.

delete-tsig-key *NAME*
:    Delete the TSIG key *NAME*. Warning, this does not deactivate said key.

generate-tsig-key *NAME* *ALGORITHM*
:    Generate new TSIG key with name *NAME* and the specified algorithm.

import-tsig-key *NAME* *ALGORITHM* *KEY*
:    Import *KEY* of the specified algorithm as *NAME*.

## ZONE MANIPULATION COMMANDS
create-zone *ZONE*
:    Create an empty zone named *ZONE*.

check-all-zones
:    Check all zones for correctness.

check-zone *ZONE*
:    Check zone *ZONE* for correctness.

clear-zone *ZONE*
:    Clear the records in zone *ZONE*, but leave actual domain and settings unchanged

delete-zone *ZONE*:
:    Delete the zone named *ZONE*.

edit-zone *ZONE*
:    Opens *ZONE* in zonefile format (regardless of backend it was loaded from)
     in the editor set in the environment variable **EDITOR**. if **EDITOR** is
     empty, *pdnsutil* falls back to using *editor*.

get-meta *ZONE* [*ATTRIBUTE*]...
:    Get zone metadata. If no *ATTRIBUTE* given, lists all known.

hash-zone-record *ZONE* *RNAME*
:    This convenience command hashes the name *RNAME* according to the NSEC3
     settings of *ZONE*. Refuses to hash for zones with no NSEC3 settings.

list-keys [*ZONE*]
:    List DNSSEC information for all keys or for *ZONE*.

list-all-zones:
:    List all zone names.

list-zone *ZONE*
:    Show all records for *ZONE*.

load-zone *ZONE* *FILE*
:    Load records for *ZONE* from *FILE*. If *ZONE* already exists, all records
     are overwritten, this operation is atomic. If *ZONE* doesn't exist, it is
     created.

rectify-zone *ZONE*
:    Calculates the 'ordername' and 'auth' fields for a zone called *ZONE* so
     they comply with DNSSEC settings. Can be used to fix up migrated data. Can
     always safely be run, it does no harm.

rectify-all-zones
:    Calculates the 'ordername' and 'auth' fields for all zones so they comply 
     with DNSSEC settings. Can be used to fix up migrated data. Can always safely 
     be run, it does no harm.

secure-zone *ZONE*
:    Configures a zone called *ZONE* with reasonable DNSSEC settings. You should
     manually run 'pdnsutil rectify-zone' afterwards.

secure-all-zones [**increase-serial**]
:    Configures all zones that are not currently signed with reasonable DNSSEC
     settings. Setting **increase-serial** will increase the serial of those 
     zones too. You should manually run 'pdnsutil rectify-all-zones' afterwards.

set-kind *ZONE* *KIND*
:    Change the kind of *ZONE* to *KIND* (master, slave, native).

set-account *ZONE* *ACCOUNT*
:    Change the account (owner) of *ZONE* to *ACCOUNT*.

set-meta *ZONE* *ATTRIBUTE* [*VALUE*]
:    Set domainmetadata *ATTRIBUTE* for *ZONE* to *VALUE*. An empty value clears it.

set-presigned *ZONE*
:    Switches *ZONE* to presigned operation, utilizing in-zone RRSIGs.

show-zone *ZONE*
:    Shows all DNSSEC related settings of a zone called *ZONE*.

test-schema *ZONE*
:    Test database schema, this creates the zone *ZONE*

unset-presigned *ZONE*
:    Disables presigned operation for *ZONE*.

## DEBUGGING TOOLS

backend-cmd *BACKEND* *CMD* [*CMD..*]
:    Send a text command to a backend for execution. GSQL backends will take SQL
     commands, other backends may take different things. Be careful!

# SEE ALSO
pdns_server (1), pdns_control (1)
