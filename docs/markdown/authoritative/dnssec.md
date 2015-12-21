# Serving authoritative DNSSEC data
(only available in PowerDNS 3.0 and beyond, not yet available in the PowerDNS Recursor)

PowerDNS contains support for DNSSEC, enabling the easy serving of DNSSEC secured data, with minimal administrative overhead.

In PowerDNSSEC, DNS and signatures and keys are (usually) treated as separate entities. The domain & record storage is thus almost completely devoid of DNSSEC record types.

Instead, keying material is stored separately, allowing operators to focus on the already complicated task of keeping DNS data correct. In practice, DNSSEC related material is often stored within the same database, but within separate tables.

If a DNSSEC configuration is found for a domain, the PowerDNS daemon will provide keys, signatures and (hashed) denials of existence automatically.

As an example, securing an existing zone can be as simple as:

```
$ pdnsutil secure-zone powerdnssec.org
$ pdnsutil rectify-zone powerdnssec.org
```

Alternatively, PowerDNS can serve pre-signed zones, without knowledge of private keys.

# A brief introduction to DNSSEC
DNSSEC is a complicated subject, but it is not required to know all the ins and outs of this protocol to be able to use PowerDNSSEC. In this section, we explain the core concepts that are needed to operate a PowerDNSSEC installation.

Zone material is enhanced with signatures using 'keys'. Such a signature (called an RRSIG) is a cryptographic guarantee that the data served is the original data. DNSSEC keys are asymmetric (RSA, DSA or GOST), the public part is published over DNS and is called a DNSKEY record, and is used for verification. The private part is used for signing and is never published.

To make sure that the internet knows that the key that is used for signing is the authentic key, confirmation can be gotten from the parent zone. This means that to become operational, a zone operator will have to publish a representation of the signing key to the parent zone, often a ccTLD or a gTLD. This representation is called a DS record, and is a shorter (hashed) version of the DNSKEY.

Once the parent zone has the DS, and the zone is signed with the DNSSEC key, we are done in theory.

However, for a variety of reasons, most DNSSEC operations run with another layer of keys. The so called 'Key Signing Key' is sent to the parent zone, and this Key Signing Key is used to sign a new set of keys called the Zone Signing Keys.

This setup allows us to change our keys without having to tell the zone operator about it.

A final challenge is how to DNSSEC sign the answer 'no such domain'. In the language of DNS, the way to say 'there is no such domain' (NXDOMAIN) or there is no such record type is to send an empty answer. Such empty answers are universal, and can't be signed.

In DNSSEC parlance we therefore sign a record that says 'there are no domains between A.powerdnssec.org and C.powerdnssec.org'. This securely tells the world that B.powerdnssec.org does not exist. This solution is called NSEC, and is simple but has downsides - it also tells the world exactly which records DO exist.

So alternatively, we can say that if a certain mathematical operation (an 'iterated salted hash') is performed on a question, that no valid answers exist that have as outcome of this operation an answer between two very large numbers. This leads to the same 'proof of non-existence'. This solution is called NSEC3.

A PowerDNSSEC zone can either be operated in NSEC or in one of two NSEC3 modes ('inclusive' and 'narrow').

# Profile, Supported Algorithms, Record Types & Modes of operation
PowerDNSSEC aims to serve unexciting, standards compliant, DNSSEC information. One goal is to have relevant parts of our output be identical or equivalent to important fellow-traveller software like NLNetLabs' NSD.

Particularly, if a PowerDNSSEC secured zone is transferred via AXFR, it should be able to contain the same records as when that zone was signed using `ldns-signzone` using the same keys and settings.

PowerDNS supports serving pre-signed zones, as well as online ('live') signed operations. In the last case, Signature Rollover and Key Maintenance are fully managed by PowerDNS.

## Supported Algorithms
Supported Algorithms (See the [IANA website](http://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml#dns-sec-alg-numbers-1) for more information):
-   DS records (algorithm 1, 2, 3)
-   RSASHA1 (algorithm 5, algorithm 7)
-   RSASHA256 (algorithm 8)
-   RSASHA512 (algorithm 10)
-   ECC-GOST (algorithm 12)
-   ECDSA (algorithm 13 and 14)

This corresponds to:
-   [RFC 4033](http://tools.ietf.org/html/rfc4033): DNS Security Introduction and Requirements
-   [RFC 4034](http://tools.ietf.org/html/rfc4034): Resource Records for the DNS Security Extensions, Protocol Modifications for the DNS Security Extensions
-   [RFC 4035](http://tools.ietf.org/html/rfc4035): Protocol Modifications for the DNS Security Extensions
-   [RFC 4509](http://tools.ietf.org/html/rfc4509): Use of SHA-256 in DNSSEC Delegation Signer (DS) Resource Records (RRs)
-   [RFC 5155](http://tools.ietf.org/html/rfc5155): DNS Security (DNSSEC) Hashed Authenticated Denial of Existence
-   [RFC 5702](http://tools.ietf.org/html/rfc5702): Use of SHA-2 Algorithms with RSA in DNSKEY and RRSIG Resource Records for DNSSEC
-   [RFC 5933](http://tools.ietf.org/html/rfc5933): Use of GOST Signature Algorithms in DNSKEY and RRSIG Resource Records for DNSSEC
-   [RFC 6605](http://tools.ietf.org/html/rfc6605): Elliptic Curve Digital Signature Algorithm (DSA) for DNSSEC

# DNSSEC Modes of Operation
Traditionally, DNSSEC signatures have been added to unsigned zones, and then this signed zone could be served by any DNSSEC capable authoritative server. PowerDNS supports this mode fully.

In addition, PowerDNS supports taking care of the signing itself, in which case PowerDNS operates differently from most tutorials and handbooks. This mode is easier however.

For relevant tradeoffs, please see [Security](#security) and [Performance](#performance.html).

PowerDNSSEC can operate in several modes. In the simplest situation, there is a single "SQL" database that contains, in separate tables, all domain data, keying material and other DNSSEC related settings.

This database is then replicated to all PowerDNS instances, which all serve identical records, keys and signatures.

In this mode of operation, care should be taken that the database replication occurs over a secure network, or over an encrypted connection. This is because keying material, if intercepted, could be used to counterfeit DNSSEC data using the original keys.

Such a single replicated database requires no further attention beyond monitoring already required during non-DNSSEC operations.

## PowerDNSSEC Pre-signed records
In this mode, PowerDNS serves zones that already contain DNSSEC records. Such zones can either be slaved from a remote master, or can be signed using tools like OpenDNSSEC, ldns-signzone or dnssec-signzone.

## PowerDNSSEC Front-signing
As a special feature, PowerDNSSEC can operate as a signing server which operates as a slave to an unsigned master.

In this way, if keying material is available for an unsigned zone that is retrieved from a master server, this keying material will be used when serving data from this zone.

As part of the zone retrieval, the equivalent of 'pdnsutil rectify-zone' is run to make sure that all DNSSEC-related fields are set correctly.

## PowerDNSSEC BIND-mode operation
Starting with PowerDNS 3.1, the bindbackend can manage keys in an SQLite3 database without launching a separate gsqlite3 backend.

To use this mode, add "bind-dnssec-db=/var/db/bind-dnssec-db.sqlite3" to pdns.conf, and run "pdnsutil create-bind-db /var/db/bind-dnssec-db.sqlite3". Then, restart PowerDNS.

After this, you can use "pdnsutil secure-zone" and all other pdnsutil commands on your BIND zones without trouble.

## PowerDNSSEC hybrid BIND-mode operation
**Warning**: This mode is only supported in 3.0, 3.0.1 and 3.4.0 and up! In 3.1 to 3.3.1, the bindbackend always did its own key storage. In 3.4.0 and up hybrid bind mode operation is optional and enabled with the bindbackend `hybrid` config option.

PowerDNS can also operate based on 'BIND'-style zone & configuration files. This 'bindbackend' has full knowledge of DNSSEC, but has no native way of storing keying material.

However, since PowerDNS supports operation with multiple simultaneous backends, this is not a problem.

In hybrid mode, keying material and zone records are stored in different backends. This allows for 'bindbackend' operation in full DNSSEC mode.

To benefit from this mode, include at least one database-based backend in the 'launch' statement. The Generic SQLite backend version 3 (gsqlite3) probably complements BIND mode best, since it does not require a database server process.

**Warning**: For now, it is necessary to execute a manual SQL 'insert' into the domains table of the backend hosting the keying material. This is needed to generate a zone-id for the relevant domain. Sample SQL statement: **insert into domains (name, type) values ('powerdnssec.org', 'NATIVE');**.

## Rules for filling out fields in database backends
**Note**: The BIND Backend automates all the steps outlined below, and does not need 'manual' help

In PowerDNS 3.0 and up, two additional fields are important: 'auth' and 'ordername'. These fields are set correctly on an incoming zone transfer, and also by running `pdnsutil rectify-zone`. zone2sql with the --dnssec flag aims to do this too but there are minor bugs in there, so please run `pdnsutil rectify-zone` after `zone2sql`.

The 'auth' field should be set to '1' for data for which the zone itself is authoritative, which includes the SOA record and its own NS records.

The 'auth' field should be 0 however for NS records which are used for delegation, and also for any glue (A, AAAA) records present for this purpose. Do note that the DS record for a secure delegation should be authoritative!

The 'ordername' field needs to be filled out depending on the NSEC/NSEC3 mode. When running in NSEC3 'Narrow' mode, the ordername field is ignored and best left empty. In NSEC/NSEC3 mode, the ordername field should be NULL for any glue but filled in for all delegation NS records and all authoritative records. In NSEC3 opt-out mode, ordername is NULL for any glue and insecure delegation NS records, but filled in for secure delegation NS records and all authoritative records.

In 'NSEC' mode, it should contain the *relative* part of a domain name, in reverse order, with dots replaced by spaces. So 'www.uk.powerdnssec.org' in the 'powerdnssec.org' zone should have 'uk www' as its ordername.

In 'NSEC3' non-narrow mode, the ordername should contain a lowercase base32hex encoded representation of the salted & iterated hash of the full record name. **pdnsutil hash-zone-record zone record** can be used to calculate this hash.

In addition, from 3.2 and up, PowerDNS fully supports empty non-terminals. If you have a zone example.com, and a host a.b.c.example.com in it, rectify-zone (and the AXFR client code) will insert b.c.example.com and c.example.com in the records table with type NULL (SQL NULL, not 'NULL'). Having these entries provides several benefits. We no longer reply NXDOMAIN for these shorter names (this was an RFC violation but not one that caused trouble). But more importantly, to do NSEC3 correctly, we need to be able to prove existence of these shorter names. The type=NULL records entry gives us a place to store the NSEC3 hash of these names.

If your frontend does not add empty non-terminal names to records, you will get DNSSEC replies of 3.1-quality, which has served many people well, but we suggest you update your code as soon as possible!

If you import presigned zones into your database, please do not import the NSEC or NSEC3 records. PowerDNS will synthesize these itself. Putting them in the database might cause duplicate records in responses. zone2sql filters NSEC and NSEC3 automatically.

# Migration
This chapter discusses various migration strategies, from existing PowerDNS setups, from existing unsigned installations and finally from previous non-PowerDNS DNSSEC deployments.

## From an existing PowerDNS installation
To migrate an existing database-backed PowerDNS installation, a few changes must be made to the database schema. First, the records table gains two new fields: 'auth' and 'ordername'. Some data in a zone, like glue records, should not be signed, and this is signified by setting 'auth' to 0.

**Warning**: Once the database schema has been updated, and the relevant `gsql-dnssec` switch has been set, stricter rules apply for filling out the database! The short version is: run `pdnsutil rectify-all-zones`, even those not secured with DNSSEC!

Additionally, NSEC and NSEC3 in non-narrow mode require ordering data in order to perform (hashed) denial of existence. The 'ordername' field is used for this purpose.

Finally, two new tables are needed. DNSSEC keying material is stored in the 'cryptokeys' table (in a portable standard format). Domain metadata is stored in the 'domainmetadata' table. This includes NSEC3 settings.

Once the database schema has been changed for DNSSEC usage (see the relevant backend chapters or [the PowerDNSSEC wiki](http://wiki.powerdns.com/trac/wiki/PDNSUTIL) for the update statements), the `pdnsutil` tool can be used to fill out keying details, and 'rectify' the auth and ordername fields.

In short, `pdnsutil secure-zone powerdnssec.org ; pdnsutil rectify-zone powerdnssec.org` will deliver a correctly NSEC signed zone.

In addition, so will the [`zone2sql`](migration.md#zone2sql) import tool when run with the `--dnssec` flag.

## From existing non-DNSSEC non-PowerDNS setups

TBD, see [Migration](migration.md).

## From existing DNSSEC non-PowerDNS setups, pre-signed
Industry standard signed zones can be served natively by PowerDNS, without changes. In such cases, signing happens externally to PowerDNS, possibly via OpenDNSSEC, ldns-sign or dnssec-sign.

PowerDNS needs to know if a zone should receive DNSSEC processing. To configure, run `pdnsutil set-presigned zone`.

**Warning** Right now, you will also need to configure NSEC(3) settings for pre-signed zones using `pdnsutil set-nsec3`. Default is NSEC, in which case no further configuration is necessary.

## From existing DNSSEC non-PowerDNS setups, live signing
The `pdnsutil` tool features the option to import zone keys in the industry standard private key format, version 1.2. To import an existing KSK, use `pdnsutil import-zone-key zonename filename KSK`, replace KSK by ZSK for a Zone Signing Key.

If all keys are imported using this tool, a zone will serve mostly identical records to before, with the important change that the RRSIG inception dates will be different.

**Note**: Within PowerDNS, the 'algorithm' for RSASHA1 keys is modulated based on the NSEC3 setting. So if an algorithm=7 key is imported in a zone with no configured NSEC3, it will appear as algorithm 5!

# Records, Keys, signatures, hashes within PowerDNSSEC in online signing mode
Within PowerDNSSEC live signing, keys are stored separately from the zone records. Zone data are only combined with signatures and keys when requests come in over the internet.

Each zone can have a number of keys associated with it, with varying key lengths. Typically 1 or at most 2 of these keys are employed as actual Zone Signing Keys (ZSKs). During normal operations, this means that only 1 ZSK is 'active', and the other is inactive.

Should it be desired to 'roll over' to a new key, both keys can temporarily be active (and used for signing), and after a while the old key can be inactivated. Subsequently it can be removed.

As elucidated above, there are several ways in which DNSSEC can deny the existence of a record, and this setting too is stored away from zone records, and lives with the DNSSEC keying material.

In order to facilitate interoperability with existing technologies, PowerDNSSEC keys can be imported and exported in industry standard formats.

Keys and hashes are configured using the 'pdnsutil' tool, which is described next.

## (Hashed) Denial of Existence

PowerDNS supports unhashed secure denial of existence using NSEC records. These are generated with the help of the (database) backend, which needs to be able to supply the 'previous' and 'next' records in canonical ordering.

The Generic SQL Backends have fields that allow them to supply these relative record names.

In addition, hashed secure denial of existence is supported using NSEC3 records, in two modes, one with help from the database, the other with the help of some additional calculations.

NSEC3 in 'broad' or 'inclusive' mode works with the aid of the backend, where the backend should be able to supply the previous and next domain names in hashed order.

NSEC3 in 'narrow' mode uses additional hashing calculations to provide hashed secure denial of existence 'on the fly', without further involving the database.

## Signatures
In PowerDNS live signing mode, signatures, as served through RRSIG records, are calculated on the fly, and heavily cached. All CPU cores are used for the calculation.

RRSIGs have a validity period, in PowerDNS by default this period starts at most a week in the past, and continues at least a week into the future.

Precisely speaking, the time period used is always from the start of the previous Thursday until the Thursday two weeks later. This two-week interval jumps with one-week increments every Thursday.

**Note**: Why Thursday? POSIX-based operating systems count the time since GMT midnight January 1st of 1970, which was a Thursday. PowerDNS inception/expiration times are generated based on an integral number of weeks having passed since the start of the 'epoch'.

PowerDNS also serves the DNSKEY records in live-signing mode. Their TTL is derived
from the SOA records *minimum* field. When using NSEC3, the TTL of the NSEC3PARAM
record is also derived from that field.

# `pdnsutil`
`pdnsutil` (previously called `pdnssec`) is a powerful command that is the operator-friendly gateway into PowerDNSSEC configuration. Behind the scenes, `pdnsutil` manipulates a PowerDNS backend database, which also means that for many databases, `pdnsutil` can be run remotely, and can configure key material on different servers.

For a list of available commands, see the [manpage](../manpages/pdnsutil.1.md).

# DNSSEC advice & precautions
DNSSEC is a major change in the way DNS works. Furthermore, there is a bewildering array of settings that can be configured.

It is well possible to configure DNSSEC in such a way that your domain will not operate reliably, or even, at all.

We advise operators to stick to the keying defaults of `pdnsutil secure-zone`: RSASHA256 (algorithm 8), 1 Key Signing Key of 2048 bits and 1 active Zone Signing Key of 1024 bits.

While the 'GOST' and 'ECDSA' algorithms are better choices in theory, not many DNSSEC resolvers can validate answers signed with such keys. Much the same goes for RSASHA512, except that it does not offer better performance either.

**Note**: GOST may be more widely available in Russia, because it might be mandatory to implement this regional standard there.

It is possible to operate a zone with different keying algorithms simultaneously, but it has also been observed that this is not reliable.

Depending on your master/slave setup, you may need to tinker with SOA-EDIT on your master.

## Packet sizes, fragments, TCP/IP service
DNSSEC answers contain (bulky) keying material and signatures, and are therefore a lot larger than regular DNS answers. Normal DNS responses almost always fit in the 'magical' 512 byte limit previously imposed on DNS.

In order to support DNSSEC, operators must make sure that their network allows for:

-   &gt;512 byte UDP packets on port 53
-   Fragmented UDP packets
-   ICMP packets related to fragmentation
-   TCP queries on port 53
-   EDNS0 queries/responses (filtered by some firewalls)

If any of the conditions outlined above is not met, DNSSEC service will suffer or be completely unavailable.

In addition, the larger your DNS answers, the more critical the above becomes. It is therefore advised not to provision too many keys, or keys that are unnecessarily large.

# Operational instructions
In this chapter various DNSSEC transitions are discussed, and how to execute them within PowerDNSSEC.

## Publishing a DS
To publish a DS to a parent zone, utilize 'pdnsutil show-zone' and take the DS from its output, and transfer it securely to your parent zone.

## ZSK rollover
```
$ pdnsutil activate-zone-key ZONE next-key-id
$ pdnsutil deactivate-zone-key ZONE prev-key-id
$ pdnsutil remove-zone-key ZONE prev-key-id
```

## KSK rollover
```
pdnsutil add-zone-key ZONE ksk
pdnsutil show-zone ZONE
```

Communicate duplicate DS

```
pdnsutil activate-zone-key ZONE next-key-id
pdnsutil deactivate-zone-key ZONE prev-key-id
pdnsutil remove-zone-key ZONE prev-key-id
```

## Going insecure
`pdnsutil disable-dnssec ZONE`

## NSEC(3) change
This section describes how to change NSEC(3) parameters when they are already set.

**Warning**: The following instructions might not be correct or complete!
```
pdnsutil set-nsec3 ZONE 'parameters'
pdnsutil show-zone ZONE
```

Communicate duplicate DS.

For further details, please see [the `pdnsutil`](#pdnsutil) documentation.

# PKCS\#11 support
**Note**: This feature is experimental, and not ready for production. Use at your own risk!
**Note**: As of version 4.0, slot IDs are deprecated, and you are expected to use slot label instead

To enable it, compile PowerDNS Authoritative Server using --enable-experimental-pkcs11 flag on configure. This requires you to have p11-kit libraries and headers.

You can also log on to the tokens after starting server, in this case you need to edit your PKCS#11 cryptokey record and remove PIN or set it empty. PIN is required
for assigning keys to zone.

Instructions on how to setup SoftHSM to work with the feature after compilation on ubuntu/debian (tested with Ubuntu 12 and 14).
-   apt-get install softhsm p11-kit opensc
-   create directory /etc/pkcs11/modules
-   Add file called 'softhsm' there with (on newer versions, use softhsm.module)

    ```
    module: /home/cmouse/softhsm/lib/softhsm/libsofthsm.so
    managed: yes
    ```

-   Verify it works

    ```
    p11-kit -l
    ```

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

Instructions on how to use CryptAS [`Athena IDProtect Key USB Token V2J`](http://www.cryptoshop.com/products/smartcards/idprotect-key-j-laser.html) Smart Card token on Ubuntu 14.
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
From 3.3.1 and up, PowerDNS support secure DNSSEC transfers as described in [draft-koch-dnsop-dnssec-operator-change](https://datatracker.ietf.org/doc/draft-koch-dnsop-dnssec-operator-change/). If the [`direct-dnskey`](settings.md#direct-dnskey) option is enabled the foreign DNSKEY records stored in the database are added to the keyset and signed with the KSK. Without the direct-dnskey option DNSKEY records in the database are silently ignored.

# Security
During typical PowerDNSSEC operation, the private part of the signing keys are 'online', which can be compared to operating an HTTPS server, where the certificate is available on the webserver for cryptographic purposes.

In some settings, having such (private) keying material available online is considered undesirable. In this case, consider running in pre-signed mode.

# Performance
DNSSEC has a performance impact, mostly measured in terms of additional memory used for the signature caches. In addition, on startup or AXFR-serving, a lot of signing needs to happen.

Please see [Large Scale DNSSEC Best Current Practices](http://wiki.powerdns.com/trac/wiki/LargeScaleDNSSECBCP) for the most up to date information.

# Thanks to, acknowledgements
PowerDNSSEC has been made possible by the help & contributions of many people. We would like to thank:

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
