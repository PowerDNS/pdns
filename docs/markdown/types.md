# Supported Record Types
This chapter lists all record types PowerDNS supports, and how they are stored in
backends. The list is mostly alphabetical but some types are grouped.

**Warning**: Host names and the MNAME of a SOA records are NEVER terminated with
a '.' in PowerDNS storage! If a trailing '.' is present it will inevitably cause
problems, problems that may be hard to debug. Use [`pdnsutil check-zone`](authoritative/dnssec.md#pdnsutil)
to validate your zone data.

**Note**: Whenever the storage format is mentioned, this relates only to the way
the record should be stored in one of the [generic SQL](authoritative/backend-generic-sql.md)
backends. The other backends should use their *native* format.

The PowerDNS Recursor can serve and store all record types, regardless of whether
these are explicitly supported.

## A
The A record contains an IP address. It is stored as a decimal dotted quad
string, for example: '203.0.113.210'.

## AAAA
The AAAA record contains an IPv6 address. An example: '2001:DB8:2000:bf0::1'.

## AFSDB
A specialised record type for the 'Andrew Filesystem'. Stored as: '\#subtype hostname',
where subtype is a number.

## ALIAS
Since 4.0.0, the ALIAS pseudo-record type is supported to provide CNAME-like
mechanisms on a zone's apex. See the [howto](authoritative/howtos.md#using-alias-records)
for information on how to configure PowerDNS to serve records synthesized from
ALIAS records.

## CAA
Since 4.0.0. The "Certification Authority Authorization" record, specified in
[RFC 6844](https://tools.ietf.org/html/rfc6844), is used to specify Certificate
Authorities that may issue certificates for a domain.

## CERT
Specialised record type for storing certificates, defined in
[RFC 2538](http://tools.ietf.org/html/rfc2538).

## CDNSKEY
Since 4.0.0. The CDNSKEY ([Child DNSKEY](https://tools.ietf.org/html/rfc7344#section-3.2))
type is supported.

## CDS
Since 4.0.0. The CDS ([Child DS](https://tools.ietf.org/html/rfc7344#section-3.1))
type is supported.

## CNAME
The CNAME record specifies the canonical name of a record. It is stored plainly.
Like all other records, it is not terminated by a dot. A sample might be
'webserver-01.yourcompany.com'.

## DNSKEY
The DNSKEY DNSSEC record type is fully supported, as described in [RFC 4034](https://tools.ietf.org/html/rfc4034).
Enabling DNSSEC for domains can be done with [`pdnsutil`](authoritative/dnssec.md#pdnsutil "'pdnsutil' for PowerDNS command & control").

## DNAME
The DNAME record, as specified in [RFC 6672](http://tools.ietf.org/html/rfc6672)
is supported. However, [`dname-processing`](authoritative/settings.md#dname-processing) has
to be set to `yes` for PowerDNS to process these records.

## DS
The DS DNSSEC record type is fully supported, as described in [RFC 4034](https://tools.ietf.org/html/rfc4034).
Enabling DNSSEC for domains can be done with [`pdnsutil`](authoritative/dnssec.md#pdnsutil "'pdnsutil' for PowerDNS command & control").

## HINFO
Hardware Info record, used to specify CPU and operating system. Stored with a
single space separating these two, example: 'i386 Linux'.

## KEY
The KEY record is fully supported. For its syntax, see [RFC 2535](http://tools.ietf.org/html/rfc2535).

## LOC
The LOC record is fully supported. For its syntax, see [RFC 1876](http://tools.ietf.org/html/rfc1876).
A sample content would be: `51 56 0.123 N 5 54 0.000 E 4.00m 1.00m 10000.00m 10.00m`

## MX
The MX record specifies a mail exchanger host for a domain. Each mail exchanger
also has a priority or preference. For example `10 mx.example.net`. In the generic
SQL backends, the `10` should go in the 'priority field'.

## NAPTR
Naming Authority Pointer, [RFC 2915](http://tools.ietf.org/html/rfc2915). Stored as follows:

```
'100  50  "s"  "z3950+I2L+I2C"     ""  _z3950._tcp.gatech.edu'.
```

The fields are: order, preference, flags, service, regex, replacement.
Note that the replacement is not enclosed in quotes, and should not be. The
replacement may be omitted, in which case it is empty. See also [RFC 2916](http://tools.ietf.org/html/rfc2916)
for how to use NAPTR for ENUM (E.164) purposes.

## NS
Nameserver record. Specifies nameservers for a domain. Stored plainly:
`ns1.powerdns.com`, as always without a terminating dot.

## NSEC, NSEC3, NSEC3PARAM
The NSEC, NSEC3 and NSEC3PARAM DNSSEC record type are fully supported, as described
in [RFC 4034](http://tools.ietf.org/html/rfc4034). To enable DNSSEC, use
[`pdnsutil`](authoritative/dnssec.md#pdnsutil "'pdnsutil' for PowerDNS command & control").

## OPENPGPKEY
Since 3.4.7. The OPENPGPKEY records, specified in [RFC TBD](https://tools.ietf.org/html/draft-ietf-dane-openpgpkey-06),
are used to bind OpenPGP certificates to email addresses.

## PTR
Reverse pointer, used to specify the host name belonging to an IP or IPv6 address.
Name is stored plainly: `www.powerdns.com`. As always, no terminating dot.

## RP
Responsible Person record, as described in [RFC 1183](http://tools.ietf.org/html/rfc1183).
Stored with a single space between the mailbox name and the more-information pointer.
Example: `peter.powerdns.com peter.people.powerdns.com`, to indicate that
`peter@powerdns.com` is responsible and that more information about peter is
available by querying the TXT record of peter.people.powerdns.com.

## RRSIG
The RRSIG DNSSEC record type is fully supported, as described in [RFC 4034](http://tools.ietf.org/html/rfc4034).
To enable DNSSEC processing, use [pdnsutil](authoritative/dnssec.md#pdnsutil).

## SOA
The Start of Authority record is one of the most complex available. It specifies
a lot about a domain: the name of the master nameserver ('the primary'), the
hostmaster and a set of numbers indicating how the data in this domain expires
and how often it needs to be checked. Further more, it contains a serial number
which should rise on each change of the domain.

The stored format is:

```
 primary hostmaster serial refresh retry expire default_ttl
```

Besides the primary and the hostmaster, all fields are numerical. PowerDNS has a set of default values:

 * primary: [`default-soa-name`](authoritative/settings.md#default-soa-name) configuration option
 * hostmaster: `hostmaster@domain-name`
 * serial: 0
 * refresh: 10800 (3 hours)
 * retry: 3600 (1 hour)
 * expire: 604800 (1 week)
 * default\_ttl: 3600 (1 hour)

The fields have complicated and sometimes controversial meanings. The 'serial'
field is special. If left at 0, the default, PowerDNS will perform an internal list
of the domain to determine highest change\_date field of all records within the
zone, and use that as the zone serial number. This means that the serial number
is always raised when changes are made to the zone, as long as the change\_date
field is being set. Make sure to check whether your backend of choice supports
Autoserial.

## SPF
SPF records can be used to store Sender Policy Framework details
([RFC 4408](http://tools.ietf.org/html/rfc4408)).

## SSHFP
The SSHFP record type, used for storing Secure Shell (SSH) fingerprints, is
fully supported. A sample from [RFC 4255](http://tools.ietf.org/html/rfc4255) is:
`2 1 123456789abcdef67890123456789abcdef67890`.

## SRV
SRV records can be used to encode the location and port of services on a domain
name. When encoding, the priority field is used to encode the priority. For example,
`_ldap._tcp.dc._msdcs.conaxis.ch SRV 0 100 389 mars.conaxis.ch` would be encoded
with `0` in the priority field and `100 389 mars.conaxis.ch` in the content field.

## TKEY, TSIG
The TKEY ([RFC 2930](http://tools.ietf.org/html/rfc2930)) and TSIG records
([RFC 2845](http://tools.ietf.org/html/rfc2845), used for key-exchange and
authenticated AXFRs, are supported. See the
[Modes of operation](authoritative/modes-of-operation.md#tsig-shared-secret-authorization-and-authentication)
and [DNS update](authoritative/dnsupdate.md) documentation for more information.

## TLSA
Since 3.0. The TLSA records, specified in [RFC 6698](http://tools.ietf.org/html/rfc6698),
are used to bind SSL/TLS certificate to named hosts and ports.

## SMIMEA
Since 4.1. The SMIMEA record type, specified in [RFC 8162](http://tools.ietf.org/html/rfc8162), is used to bind S/MIME certificates to domains.

## TXT
The TXT field can be used to attach textual data to a domain. Text is stored
plainly, PowerDNS understands content not enclosed in quotes. However, all quotes
characters (`"`) in the TXT content must be preceded with a backslash (`\`).:

```
"This \"is\" valid"
```

For a literal backslash in the TXT record, escape it:

```
"This is also \\ valid"
```

Unicode characters can be added in two ways, either by adding the character itself
or the escaped variant to the content field. e.g. `"ç"` is equal to `"\195\167"`.

When a TXT record is longer than 255 characters/bytes (excluding possible enclosing
quotes), PowerDNS will cut up the content into 255 character/byte chunks for
transmission to the client.

## URI
The URI record, specified in [RFC 7553](http://tools.ietf.org/html/rfc7553), is
used to publish mappings from hostnames to URIs.

## Other types
The following, rarely used or obsolete record types, are also supported:

* A6 ([RFC 2874](http://tools.ietf.org/html/rfc2874), obsolete)
* DHCID ([RFC 4701](http://tools.ietf.org/html/rfc4701))
* DLV ([RFC 4431](http://tools.ietf.org/html/rfc4431))
* EUI48/EUI64 ([RFC 7043](http://tools.ietf.org/html/rfc7043))
* IPSECKEY ([RFC 4025](http://tools.ietf.org/html/rfc4024))
* KEY ([RFC 2535](http://tools.ietf.org/html/rfc2535), obsolete)
* KX ([RFC 2230](http://tools.ietf.org/html/rfc2230))
* MAILA ([RFC 1035](http://tools.ietf.org/html/rfc1035))
* MAILB ([RFC 1035](http://tools.ietf.org/html/rfc1035))
* MINFO ([RFC 1035](http://tools.ietf.org/html/rfc1035))
* MR ([RFC 1035](http://tools.ietf.org/html/rfc1035))
* RKEY ([draft-reid-dnsext-rkey-00.txt](https://tools.ietf.org/html/draft-reid-dnsext-rkey-00))
* SIG ([RFC 2535](http://tools.ietf.org/html/rfc2535), obsolete)
* WKS ([RFC 1035](http://tools.ietf.org/html/rfc1035))
