# Serving authoritative DNSSEC data
PowerDNS contains support for DNSSEC, enabling the easy serving of DNSSEC secured
data, with minimal administrative overhead.

In PowerDNS, DNS and signatures and keys are (usually) treated as separate
entities. The domain & record storage is thus almost completely devoid of DNSSEC
record types.

Instead, keying material is stored separately, allowing operators to focus on the
already complicated task of keeping DNS data correct. In practice, DNSSEC related
material is often stored within the same database, but within separate tables.

If a DNSSEC configuration is found for a domain, the PowerDNS daemon will provide
key records, signatures and (hashed) denials of existence automatically.

As an example, securing an existing zone can be as simple as:

```
$ pdnsutil secure-zone powerdnssec.org
```

Alternatively, PowerDNS can serve pre-signed zones, without knowledge of
private keys.

# A brief introduction to DNSSEC
DNSSEC is a complicated subject, but it is not required to know all the ins and
outs of this protocol to be able to use PowerDNS. In this section, we explain the
core concepts that are needed to operate a PowerDNSSEC installation.

Zone material is enhanced with signatures using 'keys'. Such a signature (called
an RRSIG) is a cryptographic guarantee that the data served is the original data.
DNSSEC keys are asymmetric (RSA, DSA, ECSDA or GOST), the public part is published
in DNS and is called a DNSKEY record, and is used for verification. The private
part is used for signing and is never published.

To make sure that the internet knows that the key that is used for signing is the
authentic key, confirmation can be gotten from the parent zone. This means that
to become operational, a zone operator will have to publish a representation of
the signing key to the parent zone, often a ccTLD or a gTLD. This representation
is called a DS record, and is a shorter (hashed) version of the DNSKEY.

Once the parent zone has the DS, and the zone is signed with the DNSSEC key, we
are done in theory.

However, for a variety of reasons, most DNSSEC operations run with another layer
of keys. The so called 'Key Signing Key' is sent to the parent zone, and this Key
Signing Key is used to sign a new set of keys called the Zone Signing Keys.

This setup allows us to change our keys without having to tell the zone operator
about it.

A final challenge is how to DNSSEC sign the answer 'no such domain'. In the
language of DNS, the way to say 'there is no such domain' (NXDOMAIN) or there is
no such record type is to send an empty answer. Such empty answers are universal,
and can't be signed.

In DNSSEC parlance we therefore sign a record that says 'there are no domains
between A.powerdnssec.org and C.powerdnssec.org'. This securely tells the world
that B.powerdnssec.org does not exist. This solution is called NSEC, and is
simple but has downsides - it also tells the world exactly which records DO exist.

So alternatively, we can say that if a certain mathematical operation (an
'iterated salted hash') is performed on a question, that no valid answers exist
that have as outcome of this operation an answer between two very large numbers.
This leads to the same 'proof of non-existence'. This solution is called NSEC3.

A PowerDNS zone can either be operated in NSEC or in one of two NSEC3 modes
('inclusive' and 'narrow').

# Profile, Supported Algorithms and Record Types
PowerDNS aims to serve unexciting, standards compliant, DNSSEC information. One
goal is to have relevant parts of our output be identical or equivalent to important
fellow-traveller software like NLNetLabs' NSD.

Particularly, if a PowerDNS secured zone is transferred via AXFR, it should be
able to contain the same records as when that zone was signed using `ldns-signzone`
using the same keys and settings.

PowerDNS supports serving pre-signed zones, as well as online ('live') signed
operations. In the last case, Signature Rollover and Key Maintenance are fully
managed by PowerDNS.

## Supported Algorithms
Supported Algorithms (See the [IANA website](http://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml#dns-sec-alg-numbers-1) for more information):

- RSASHA1 (algorithm 5, algorithm 7)
- RSASHA256 (algorithm 8)
- RSASHA512 (algorithm 10)
- ECC-GOST (algorithm 12)
- ECDSA (algorithm 13 and 14)

For the DS records, these [digest algorithms](http://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml#ds-rr-types-1)
are supported:

- SHA-1 (algorithm 1)
- SHA-256 (algorithm 2)
- GOST R 34.11-94 (algorithm 3)
- SHA-384 (algorithm 4)

This corresponds to:
- [RFC 4033](http://tools.ietf.org/html/rfc4033): DNS Security Introduction and Requirements
- [RFC 4034](http://tools.ietf.org/html/rfc4034): Resource Records for the DNS Security Extensions, Protocol Modifications for the DNS Security Extensions
- [RFC 4035](http://tools.ietf.org/html/rfc4035): Protocol Modifications for the DNS Security Extensions
- [RFC 4509](http://tools.ietf.org/html/rfc4509): Use of SHA-256 in DNSSEC Delegation Signer (DS) Resource Records (RRs)
- [RFC 5155](http://tools.ietf.org/html/rfc5155): DNS Security (DNSSEC) Hashed Authenticated Denial of Existence
- [RFC 5702](http://tools.ietf.org/html/rfc5702): Use of SHA-2 Algorithms with RSA in DNSKEY and RRSIG Resource Records for DNSSEC
- [RFC 5933](http://tools.ietf.org/html/rfc5933): Use of GOST Signature Algorithms in DNSKEY and RRSIG Resource Records for DNSSEC
- [RFC 6605](http://tools.ietf.org/html/rfc6605): Elliptic Curve Digital Signature Algorithm (DSA) for DNSSEC

In order to facilitate interoperability with existing technologies, PowerDNS keys
can be imported and exported in industry standard formats.

When using OpenSSL for ECDSA signatures (this is default), starting from OpenSSL
1.1.0, the algorithm used is resilient against PRNG failure, while not
strictly conforming to [RFC 6979](http://tools.ietf.org/html/rfc6979).

**Note**: Actual supported algorithms depend on the crypto-libraries PowerDNS was
compiled against. To check the supported DNSSEC algoritms in your build of PowerDNS,
run `pdnsutil list-algorithms`.

# DNSSEC Modes of Operation
Traditionally, DNSSEC signatures have been added to unsigned zones, and then this
signed zone could be served by any DNSSEC capable authoritative server. PowerDNS
supports this mode fully.

In addition, PowerDNS supports taking care of the signing itself, in which case
PowerDNS operates differently from most tutorials and handbooks. This mode is
easier however.

For relevant tradeoffs, please see [Security](#security) and
[Performance](#performance.html).

## Online Signing
In the simplest situation, there is a single "SQL" database that contains, in
separate tables, all domain data, keying material and other DNSSEC related settings.

This database is then replicated to all PowerDNS instances, which all serve
identical records, keys and signatures.

In this mode of operation, care should be taken that the database replication
occurs over a secure network, or over an encrypted connection. This is because
keying material, if intercepted, could be used to counterfeit DNSSEC data using
the original keys.

Such a single replicated database requires no further attention beyond monitoring
already required during non-DNSSEC operations.

### Records, Keys, signatures, hashes within PowerDNS in online signing mode
Within PowerDNS live signing, keys are stored separately from the zone records.
Zone data are only combined with signatures and keys when requests come in over
the internet.

Each zone can have a number of keys associated with it, with varying key lengths.
Typically 1 or at most 2 of these keys are employed as actual Zone Signing Keys (ZSKs).
During normal operations, this means that only 1 ZSK is 'active', and the other is inactive.

Should it be desired to 'roll over' to a new key, both keys can temporarily be
active (and used for signing), and after a while the old key can be inactivated.
Subsequently it can be removed.

As elucidated above, there are several ways in which DNSSEC can deny the existence
of a record, and this setting too is stored away from zone records, and lives
with the DNSSEC keying material.

### (Hashed) Denial of Existence
PowerDNS supports unhashed secure denial of existence using NSEC records. These
are generated with the help of the (database) backend, which needs to be able
to supply the 'previous' and 'next' records in canonical ordering.

The Generic SQL Backends have fields that allow them to supply these relative
record names.

In addition, hashed secure denial of existence is supported using NSEC3 records,
in two modes, one with help from the database, the other with the help of some
additional calculations.

NSEC3 in 'broad' or 'inclusive' mode works with the aid of the backend, where
the backend should be able to supply the previous and next domain names in hashed
order.

NSEC3 in 'narrow' mode uses additional hashing calculations to provide hashed
secure denial of existence 'on the fly', without further involving the database.

### Signatures
In PowerDNS live signing mode, signatures, as served through RRSIG records, are
calculated on the fly, and heavily cached. All CPU cores are used for the calculation.

RRSIGs have a validity period, in PowerDNS by default this period starts at most
a week in the past, and continues at least a week into the future.

Precisely speaking, the time period used is always from the start of the previous
Thursday until the Thursday two weeks later. This two-week interval jumps with
one-week increments every Thursday.

**Note**: Why Thursday? POSIX-based operating systems count the time since GMT
midnight January 1st of 1970, which was a Thursday. PowerDNS inception/expiration
times are generated based on an integral number of weeks having passed since the
start of the 'epoch'.

PowerDNS also serves the DNSKEY records in live-signing mode. Their TTL is derived
from the SOA records *minimum* field. When using NSEC3, the TTL of the NSEC3PARAM
record is also derived from that field.

## Pre-signed records
In this mode, PowerDNS serves zones that already contain DNSSEC records. Such
zones can either be slaved from a remote master, or can be signed using tools
like OpenDNSSEC, ldns-signzone or dnssec-signzone.

Even in this mode, PowerDNS will synthesize NSEC(3) records itself because of its
architecture. RRSIGs of these NSEC(3) will still need to be imported. See the
[Presigned migration guide](#From-existing-DNSSEC-non-PowerDNS-setups-pre-signed).

## Front-signing
As a special feature, PowerDNS can operate as a signing server which operates as
a slave to an unsigned master.

In this way, if keying material is available for an unsigned zone that is
retrieved from a master server, this keying material will be used when serving
data from this zone.

As part of the zone retrieval, the equivalent of `pdnsutil rectify-zone` is run
to make sure that all DNSSEC-related fields are set correctly.

Signatures and Hashing is similar as described [above](#online-signing)

## BIND-mode operation
Starting with PowerDNS 3.1, the bindbackend can manage keys in an SQLite3 database
without launching a separate gsqlite3 backend.

To use this mode, add [`bind-dnssec-db=/var/db/bind-dnssec-db.sqlite3`](backend-bind.md#bind-dnssec-db)
to pdns.conf, and run `pdnsutil create-bind-db /var/db/bind-dnssec-db.sqlite3`.
Then, restart PowerDNS.

After this, you can use `pdnsutil secure-zone` and all other pdnsutil commands
on your BIND zones without trouble.

## Hybrid BIND-mode operation
**Warning**: This mode is only supported in 3.0, 3.0.1 and 3.4.0 and up! In 3.1
to 3.3.1, the bindbackend always did its own key storage. In 3.4.0 and up hybrid
bind mode operation is optional and enabled with the bindbackend [`hybrid`](backend-bind.md#bind-hybrid)
config option.

PowerDNS can also operate based on 'BIND'-style zone & configuration files. This
'bindbackend' has full knowledge of DNSSEC, but has no native way of storing
keying material.

However, since PowerDNS supports operation with multiple simultaneous backends,
this is not a problem.

In hybrid mode, keying material and zone records are stored in different backends.
This allows for 'bindbackend' operation in full DNSSEC mode.

To benefit from this mode, include at least one database-based backend in the
'launch' statement. The [Generic SQLite backend (gsqlite3)](backend-generic-sqlite.md)
probably complements BIND mode best, since it does not require a database server
process.

**Warning**: For now, it is necessary to execute a manual SQL 'insert' into the
domains table of the backend hosting the keying material. This is needed to
generate a zone-id for the relevant domain. Sample SQL statement: 

```
insert into domains (name, type) values ('powerdnssec.org', 'NATIVE');
```

# `pdnsutil`
`pdnsutil` (previously called `pdnssec`) is a powerful command that is the
operator-friendly gateway into PowerDNS configuration. Behind the scenes,
`pdnsutil` manipulates a PowerDNS backend database, which also means that for
many databases, `pdnsutil` can be run remotely, and can configure key material
on different servers.

For a list of available commands, see the [manpage](../manpages/pdnsutil.1.md).

## DNSSEC Defaults
Since version 4.0, when securing a zone using `pdnsutil secure-zone`, a single
ECDSA (algorithm 13, ECDSAP256SHA256) key is generated that is used as ZSK.
Before 4.0, 3 RSA (algorithm 8) keys were generated, one as the KSK and two ZSKs.
As all keys are online in the database, it made no sense to have this split-key
setup.

The default negative answer strategy is NSEC.

**Note**: not all registrars support algorithm 13.

# Migration
This chapter discusses various migration strategies, from existing PowerDNS setups,
from existing unsigned installations and finally from previous non-PowerDNS
DNSSEC deployments.

## From an existing PowerDNS installation
To migrate an existing database-backed PowerDNS installation, ensure you are
running at least PowerDNS 3.3.3 and preferably 3.4 or newer.

If you run an older version of PowerDNS, please upgrade to 3.4 and apply all the
changes in database schemas as shown in the [upgrade documentation](upgrading.md).

**Warning**: Once the relevant `backend-dnssec` switch has been set, stricter
rules apply for filling out the database! The short version is: run
`pdnsutil rectify-all-zones`, even those not secured with DNSSEC! For more
information, see the [DNSSEC documentation for Generic SQL backends](backend-generic-sql.md#handling-dnssec-signed-zones).

To deliver a correctly signed zone with the [DNSSEC defaults](#dnssec-defaults),
invoke:

```
pdnsutil secure-zone ZONE
```

To view the DS records for this zone (to transfer to the parent zone), run

```
pdnsutil show-zone ZONE
```

For a more traditional setup with a KSK and a ZSK, use the following sequence
of commands:

```
pdnsutil add-zone-key ZONE ksk 2048 active rsasha256
pdnsutil add-zone-key ZONE zsk 1024 active rsasha256
pdnsutil add-zone-key ZONE zsk 1024 inactive rsasha256
```

This will add a 2048-bit RSA Key Signing Key and two 1024-bit RSA Zone Signing Keys.
One of the ZSKs is inactive and can be rolled to if needed.

## From existing non-DNSSEC non-PowerDNS setups
It is recommended to [migrate to PowerDNS](migration.md) before securing your
zones. After that, see the instructions [above](#from-an-existing-PowerDNS-installation).

## From existing DNSSEC non-PowerDNS setups, pre-signed
Industry standard signed zones can be served natively by PowerDNS, without
changes. In such cases, signing happens externally to PowerDNS, possibly via
OpenDNSSEC, ldns-sign or dnssec-sign.

PowerDNS needs to know if a zone should receive DNSSEC processing. To configure,
run `pdnsutil set-presigned ZONE`.

If you import presigned zones into your database, please do not import the NSEC
or NSEC3 records. PowerDNS will synthesize these itself. Putting them in the
database might cause duplicate records in responses. [`zone2sql`](migration.md#zone2sql)
filters NSEC and NSEC3 automatically.

**Warning** Right now, you will also need to configure NSEC(3) settings for
pre-signed zones using `pdnsutil set-nsec3`. Default is NSEC, in which case no
further configuration is necessary.

## From existing DNSSEC non-PowerDNS setups, live signing
The `pdnsutil` tool features the option to import zone keys in the industry
standard private key format, version 1.2. To import an existing KSK, use

```
pdnsutil import-zone-key ZONE FILENAME ksk
```

replace 'ksk' by 'zsk' for a Zone Signing Key.

If all keys are imported using this tool, a zone will serve mostly identical
records to before, with the important change that the RRSIG inception dates will
be different.

**Note**: Within PowerDNS, the 'algorithm' for RSASHA1 keys is modulated based
on the NSEC3 setting. So if an algorithm=7 key is imported in a zone with no
configured NSEC3, it will appear as algorithm 5!

# DNSSEC advice & precautions
DNSSEC is a major change in the way DNS works. Furthermore, there is a bewildering
array of settings that can be configured.

It is well possible to configure DNSSEC in such a way that your domain will not
operate reliably, or even, at all. We advise operators to stick to the keying
defaults of `pdnsutil secure-zone`.

**Note**: GOST may be more widely available in Russia, because it might be
mandatory to implement this regional standard there.

It is possible to operate a zone with different keying algorithms simultaneously,
but it has also been observed that this is not reliable.

Depending on your master/slave setup, you may need to tinker with the
[`SOA-EDIT`](domainmetadata.md#soa-edit) metadata on your master. This is described
in the [operational instructions](#soa-edit) below.

## Packet sizes, fragments, TCP/IP service
DNSSEC answers contain (bulky) keying material and signatures, and are therefore
a lot larger than regular DNS answers. Normal DNS responses almost always fit in
the 'magical' 512 byte limit previously imposed on DNS.

In order to support DNSSEC, operators must make sure that their network allows for:

-   Larger than 512 byte UDP packets on port 53
-   Fragmented UDP packets
-   ICMP packets related to fragmentation
-   TCP queries on port 53
-   EDNS0 queries/responses (filtered by some firewalls)

If any of the conditions outlined above is not met, DNSSEC service will suffer
or be completely unavailable.

In addition, the larger your DNS answers, the more critical the above becomes.
It is therefore advised not to provision too many keys, or keys that are
unnecessarily large.

# Operational instructions
Several How to's describe operational practices with DNSSEC:

* [KSK Rollover](howtos.md#ksk-rollover)
* [ZSK Rollover](howtos.md#zsk-rollover)

Below, frequently used commands are described:

## Publishing a DS
To publish a DS to a parent zone, utilize `pdnsutil show-zone` and take the DS
from its output, and transfer it securely to your parent zone.

## Going insecure
```
pdnsutil disable-dnssec ZONE
```

**Warning**: Going insecure with a zone that has a DS record in the parent zone
will make the zone BOGUS. Make sure the parent zone removes the DS record *before*
going insecure.

## Setting the NSEC modes and parameters
As stated earlier, PowerDNS uses NSEC by default. If you want to use NSEC3 instead,
issue:

```
pdnsutil set-nsec3 ZONE [PARAMETERS]
```

e.g.

```
pdnsutil set-nsec3 example.net '1 0 1 ab'
```

The quoted part is the content of the NSEC3PARAM records, as defined in [RFC 5155
](https://tools.ietf.org/html/rfc5155#section-4), in order:

* Hash algorithm, should always be `1` (SHA1)
* Flags, set to `1` for [NSEC3 Opt-out](https://tools.ietf.org/html/rfc5155#section-6), this best set as `0`
* Number of iterations of the hash function, read [RFC 5155, Section 10.3](https://tools.ietf.org/html/rfc5155#section-10.3) for recommendations
* Salt (in hexadecimal) to apply during hashing

To convert a zone from NSEC3 to NSEC operations, run:

```
pdnsutil unset-nsec3 ZONE
```

**Warning**: Don't change from NSEC to NSEC3 (or the other way around) for zones
with algorithm 5 (RSASHA1), 6 (DSA-NSEC3-SHA1) or 7 (RSASHA1-NSEC3-SHA1).

## SOA-EDIT: ensure signature freshness on slaves
As RRSIGs can expire, slave servers need to know when to re-transfer the zone. In
most implementations (BIND, NSD), this is done by re-signing the full zone outside
of the nameserver, increasing the SOA serial and serving the new zone on the master.

With PowerDNS in Live-signing mode, the SOA serial is not increased by default
when the RRSIG dates are rolled.

For zones that use [native](modes-of-operation.md#native-operation) replication
PowerDNS will serve valid RRSIGs on all servers.

For [master](modes-of-operation.md#master-operation) zones (where replication
happens by means of AXFR), PowerDNS slaves will automatically re-transfer the zone
when it notices the RRSIGs have changed, even when the SOA serial is not increased.
This ensures the zone never serves old signatures.

If your DNS setup uses non-PowerDNS slaves, the slaves need to know when the
signatures have been updated. This can be accomplished by setting the
[SOA-EDIT](domainmetadata.md#soa-edit) metadata for DNSSEC signed zones. This
value controls how the value of the SOA serial is modified by PowerDNS.

**Note**: The SOA serial in the datastore will be untouched, SOA-EDIT is applied
to DNS answers with the SOA record.

The [`default-soa-edit`](settings.md#default-soa-edit) or [`default-soa-edit-signed`](settings.md#default-soa-edit-signed)
configuration options can instead be set to ensure SOA-EDIT is set for every zone.

### Possible SOA-EDIT values
The 'inception' refers to the time the RRSIGs got updated in
[live-signing mode](#online-signing). This happens every week (see [Signatures](#signatures)).
The inception time does not depend on local timezone, but some modes below will
use localtime for representation.

#### INCREMENT-WEEKS
Increments the serial with the number of weeks since the UNIX epoch. This should
work in every setup; but the result won't look like YYYYMMDDSS anymore.

For example: a serial of 12345678 will become 12348079 on Wednesday 13th of January
2016 (2401 weeks after the epoch).

#### INCEPTION-EPOCH
Sets the new SOA serial number to the maximum of the old SOA serial number, and
age in seconds of the last inception. This requires your backend zone to use the
number of seconds since the UNIX epoch as SOA serial. The result is still the age
in seconds of the last change to the zone, either by operator changes to the zone
or the 'addition' of new RRSIGs.

As an example, a serial of 12345678 becomes 1452124800 on Wednesday 13th of January
2016.

#### INCEPTION-INCREMENT
Uses YYYYMMDDSS format for SOA serial numbers. If the SOA serial from the backend
is within two days after inception, it gets incremented by two (the backend should
keep SS below 98). Otherwise it uses the maximum of the backend SOA serial number
and inception time in YYYYMMDD01 format. This requires your backend zone to use
YYYYMMDDSS as SOA serial format. Uses localtime to find the day for inception time.

This changes a serial of 2015120810 to 2016010701 on Wednesday 13th of January
2016.

#### INCEPTION (not recommended)
Sets the SOA serial to the last inception time in YYYYMMDD01 format. Uses localtime
to find the day for inception time.

**Warning**: The SOA serial will only change on inception day, so changes to the
zone will get visible on slaves only on the following inception day.

**Note**: Will be removed in PowerDNS Authoritative Server 4.1.0

#### INCEPTION-WEEK (not recommended)
Sets the SOA serial to the number of weeks since the epoch, which is the last
inception time in weeks.

**Warning**: Same problem as INCEPTION.

**Note**: Will be removed in PowerDNS Authoritative Server 4.1.0

#### EPOCH
Sets the SOA serial to the number of seconds since the epoch.

**Warning**: Don't combine this with AXFR - the slaves would keep refreshing all
the time. If you need fast updates, sync the backend databases directly with
incremental updates (or use the same database server on the slaves)

**Note**: Will be removed in PowerDNS Authoritative Server 4.1.0

#### NONE
Ignore [`default-soa-edit`](settings.md#default-soa-edit) and/or
[`default-soa-edit-signed`](settings.md#default-soa-edit-signed) setings.

# PKCS\#11 support
**Note**: This feature is experimental, and not ready for production. Use at your own risk!
**Note**: As of version 4.0, slot IDs are deprecated, and you are expected to use slot label instead

To enable it, compile PowerDNS Authoritative Server using
`--enable-experimental-pkcs11` flag on configure. This requires you to have
p11-kit libraries and headers.

You can also log on to the tokens after starting server, in this case you need
to edit your PKCS#11 cryptokey record and remove PIN or set it empty. PIN is
required for assigning keys to zone.

## Using with SoftHSM
To test this feature, a software HSM can be used. It is **not recommended** to
use this in production.

Instructions on how to setup SoftHSM to work with the feature after compilation
on ubuntu/debian (tested with Ubuntu 12 and 14).
-   `apt-get install softhsm p11-kit opensc`
-   create directory /etc/pkcs11/modules
-   Add file called 'softhsm' there with (on newer versions, use softhsm.module)
    ```
    module: /home/cmouse/softhsm/lib/softhsm/libsofthsm.so
    managed: yes
    ```
-   Verify it works: `p11-kit -l`
-   Create at least two tokens (ksk and zsk) with (slot-number starts from 0)

    ```
    sudo softhsm --init-token --slot slot-number --label zone-ksk|zone-zsk --pin some-pin --so-pin another-pin
    ```

-   Using pkcs11-tool, initialize your new keys.

    ```
    sudo pkcs11-tool --module=/home/cmouse/softhsm/lib/softhsm/libsofthsm.so -l -p some-pin -k --key-type RSA:2048 -a zone-ksk|zone-zsk --slot-index slot-number
    ```

-   Assign the keys using (note that token label is not necessarely same as object label, see p11-kit -l)

    ```
    pdnsutil hsm assign zone rsasha256 ksk|zsk softhsm token-label pin zone-ksk|zsk
    ```

-   Verify that everything worked, you should see valid data there

    ```
    pdnsutil show-zone zone
    ```

-   SoftHSM signatures are fast enough to be used in live environment.

## Using CryptAS
Instructions on how to use CryptAS [`Athena IDProtect Key USB Token V2J`](http://www.cryptoshop.com/products/smartcards/idprotect-key-j-laser.html)
Smart Card token on Ubuntu 14.
-   install the manufacturer`s support software on your system and initialize the Smart Card token as per instructions (do not use PIV).
-   apt-get install p11-kit opensc
-   create directory /etc/pkcs11/modules
-   Add file called 'athena.module' with content

    ```
    module: /lib64/libASEP11.so
    managed: yes
    ```

-   Verify it worked, it should resemble output below. do not continue if this does not show up.

    ```
    $ p11-kit -l
    athena: /lib64/libASEP11.so
        library-description: ASE Cryptoki
        library-manufacturer: Athena Smartcard Solutions
        library-version: 3.1
        token: IDProtect#0A50123456789
            manufacturer: Athena Smartcard Solutions
            model: IDProtect
            serial-number: 0A50123456789
            hardware-version: 1.0
            firmware-version: 1.0
            flags:
                   rng
                   login-required
                   user-pin-initialized
                   token-initialized
    ```
-   Using pkcs11-tool, initialize your new keys. After this IDProtect Manager no longer can show your token certificates and keys, at least on version v6.23.04.

    ```
    pkcs11-tool --module=/home/cmouse/softhsm/lib/softhsm/libsofthsm.so -l -p some-pin -k --key-type RSA:2048 -a zone-ksk
    pkcs11-tool --module=/home/cmouse/softhsm/lib/softhsm/libsofthsm.so -l -p some-pin -k --key-type RSA:2048 -a zone-zsk
    ```

-   Verify that keys are there.

    ```
    $ pkcs11-tool --module=/lib64/libASEP11.so -l -p some-pin -O
    Using slot 0 with a present token (0x0)
    Public Key Object; RSA 2048 bits
      label:      zone-ksk
      Usage:      encrypt, verify, wrap
    Public Key Object; RSA 2048 bits
      label:      zone-zsk
      Usage:      encrypt, verify, wrap
    Private Key Object; RSA
      label:      zone-ksk
      Usage:      decrypt, sign, unwrap
    Private Key Object; RSA
      label:      zone-zsk
      Usage:      decrypt, sign, unwrap
    ```

-   Assign the keys using

    ```
    pdnsutil hsm assign zone rsasha256 ksk|zsk athena IDProtect#0A50123456789 pin zone-ksk|zsk
    ```

-   Verify that everything worked, you should see valid data there.

    ```
    pdnsutil show-zone zone
    ```

-   Note that the physical token is pretty slow, so you have to use it as hidden master. It has been observed to produce about 1.5signatures/second.

# Secure transfers
From 3.3.1 and up, PowerDNS support secure DNSSEC transfers as described in
[draft-koch-dnsop-dnssec-operator-change](https://datatracker.ietf.org/doc/draft-koch-dnsop-dnssec-operator-change/).
If the [`direct-dnskey`](settings.md#direct-dnskey) option is enabled the foreign
DNSKEY records stored in the database are added to the keyset and signed with the
KSK. Without the direct-dnskey option DNSKEY records in the database are silently
ignored.

# Security
During typical PowerDNS operation, the private part of the signing keys are
'online', which can be compared to operating an HTTPS server, where the
private key is available on the webserver for cryptographic purposes.

In some settings, having such (private) keying material available online is
considered undesirable. In this case, consider running in pre-signed mode.

# Performance
DNSSEC has a performance impact, mostly measured in terms of additional memory
used for the signature caches. In addition, on startup or AXFR-serving, a lot of
signing needs to happen.

Most best practices are documented in [RFC 6781](https://tools.ietf.org/html/rfc6781).

# Thanks to, acknowledgements
PowerDNS DNSSEC has been made possible by the help & contributions of many people.
We would like to thank:

- Peter Koch (DENIC)
- Olaf Kolkman (NLNetLabs)
- Wouter Wijngaards (NLNetLabs)
- Marco Davids (SIDN)
- Markus Travaille (SIDN)
- Antoin Verschuren (SIDN)
- Olafur Guðmundsson (IETF)
- Dan Kaminsky (Recursion Ventures)
- Roy Arends (Nominet)
- Miek Gieben
- Stephane Bortzmeyer (AFNIC)
- Michael Braunoeder (nic.at)
- Peter van Dijk
- Maik Zumstrull
- Jose Arthur Benetasso Villanova
- Stefan Schmidt (CCC ;-))
- Roland van Rijswijk (Surfnet)
- Paul Bakker (Brainspark/Fox-IT)
- Mathew Hennessy
- Johannes Kuehrer (Austrian World4You GmbH)
- Marc van de Geijn (bHosted.nl)
- Stefan Arentz
- Martin van Hensbergen (Fox-IT)
- Christoph Meerwald
- Leen Besselink
- Detlef Peeters
- Christof Meerwald
- Jack Lloyd
- Frank Altpeter
- Fredrik Danerklint
- Vasiliy G Tolstov
- Brielle Bruns
- Evan Hunt (ISC)
- Ralf van der Enden
- Jan-Piet Mens
- Justin Clift
- Kees Monshouwer
- Aki Tuomi
- Ruben Kerkhof
- Christian Hofstaedtler
- Ruben d'Arco
- Morten Stevens
- Pieter Lexis
-   .. this list is far from complete yet ..
