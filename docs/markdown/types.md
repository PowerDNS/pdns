# Supported Record Types
This chapter lists all record types PDNS supports, and how they are stored in backends. The list is mostly alphabetical but some types are grouped.

**Warning**: Host names and the MNAME of a SOA records are NEVER terminated with a '.' in PowerDNS storage! If a trailing '.' is present it will inevitably cause problems, problems that may be hard to debug.

The PowerDNS Recursor can serve and store all record types, regardless of whether these are explicitly supported.

## A
The A record contains an IP address. It is stored as a decimal dotted quad string, for example: '203.0.113.210'.

## AAAA
The AAAA record contains an IPv6 address. An example: '2001:DB8:2000:bf0::1'.

## AFSDB
Since 2.9.21. Specialised record type for the 'Andrew Filesystem'. Stored as: '\#subtype hostname', where subtype is a number.

## CERT
Since 2.9.21. Specialised record type for storing certificates, defined in [RFC 2538](http://tools.ietf.org/html/rfc2538).

## CNAME
The CNAME record specifies the canonical name of a record. It is stored plainly. Like all other records, it is not terminated by a dot. A sample might be 'webserver-01.yourcompany.com'.

## DNSKEY
Since 2.9.21. The DNSKEY DNSSEC record type is fully supported, as described in RFC 3757. Before 3.0 PowerDNS didn't do any DNSSEC processing, since 3.0 PowerDNS is able to fully process DNSSEC. This can be done with [`pdnssec`](authoritative/dnssec.md#pdnssec "'pdnssec' for PowerDNSSEC command & control").

## DS
Since 2.9.21, The DS DNSSEC record type is fully supported, as described in RFC 3757. Before 3.0 PowerDNS didn't do any DNSSEC processing, since 3.0 PowerDNS is able to fully process DNSSEC. This can be done with [`pdnssec`](authoritative/dnssec.md#pdnssec "'pdnssec' for PowerDNSSEC command & control").

## HINFO
Hardware Info record, used to specify CPU and operating system. Stored with a single space separating these two, example: 'i386 Linux'.

## KEY
Since 2.9.21. The KEY record is fully supported. For its syntax, see [RFC 2535](http://tools.ietf.org/html/rfc2535).

## LOC
The LOC record is fully supported. For its syntax, see [RFC 1876](http://tools.ietf.org/html/rfc1876). A sample content would be: '51 56 0.123 N 5 54 0.000 E 4.00m 1.00m 10000.00m 10.00m'

## MX
The MX record specifies a mail exchanger host for a domain. Each mail exchanger also has a priority or preference. This should be specified in the separate field dedicated for that purpose, often called 'prio'.

## NAPTR
Naming Authority Pointer, [RFC 2915](http://tools.ietf.org/html/rfc2915). Stored as follows:

```
'100  50  "s"  "z3950+I2L+I2C"     ""  _z3950._tcp.gatech.edu'.
```

The fields are: order, preference, flags, service, regex, replacement. Note that the replacement is not enclosed in quotes, and should not be. The replacement may be omitted, in which case it is empty. See also RFC 2916 for how to use NAPTR for ENUM (E.164) purposes.

## NS
Nameserver record. Specifies nameservers for a domain. Stored plainly: 'ns1.powerdns.com', as always without a terminating dot.

## NSEC
Since 2.9.21. The NSEC DNSSEC record type is fully supported, as described in [RFC 3757](http://tools.ietf.org/html/rfc3757). Before 3.0 PowerDNS didn't do any DNSSEC processing, since 3.0 PowerDNS is able to fully process DNSSEC. This can be done with [`pdnssec`](authoritative/dnssec.md#pdnssec "'pdnssec' for PowerDNSSEC command & control").

## PTR
Reverse pointer, used to specify the host name belonging to an IP or IPv6 address. Name is stored plainly: 'www.powerdns.com'. As always, no terminating dot.

## RP
Responsible Person record, as described in [RFC 1183](http://tools.ietf.org/html/rfc1183). Stored with a single space between the mailbox name and the more-information pointer. Example 'peter.powerdns.com peter.people.powerdns.com', to indicate that `peter@powerdns.com` is responsible and that more information about peter is available by querying the TXT record of peter.people.powerdns.com.

## RRSIG
Since 2.9.21. The RRSIG DNSSEC record type is fully supported, as described in RFC 3757. Before 3.0 PowerDNS didn't do any DNSSEC prcessing, since 3.0 PowerDNS is able to fully process DNSSEC. This can be done with [pdnssec](authoritative/dnssec.md#pdnssec).

## SOA
The Start of Authority record is one of the most complex available. It specifies a lot about a domain: the name of the master nameserver ('the primary'), the hostmaster and a set of numbers indicating how the data in this domain expires and how often it needs to be checked. Further more, it contains a serial number which should rise on each change of the domain.

The stored format is:

```
 primary hostmaster serial refresh retry expire default_ttl
```

Besides the primary and the hostmaster, all fields are numerical. PDNS has a set of default values:

 * primary: [`default-soa-name`](authoritative/settings.md#default-soa-name) configuration option
 * hostmaster: `hostmaster@domain-name`
 * serial: 0
 * refresh: 10800 (3 hours)
 * retry: 3600 (1 hour)
 * expire: 604800 (1 week)
 * default\_ttl: 3600 (1 hour)

The fields have complicated and sometimes controversial meanings. The 'serial' field is special. If left at 0, the default, PDNS will perform an internal list of the domain to determine highest change\_date field of all records within the zone, and use that as the zone serial number. This means that the serial number is always raised when changes are made to the zone, as long as the change\_date field is being set. Make sure to check whether your backend of choice supports Autoserial.

## SPF
Since 2.9.21. SPF records can be used to store Sender Policy Framework details ([RFC 4408](http://tools.ietf.org/html/rfc4408)).

## SSHFP
Since 2.9.21. The SSHFP record type, used for storing Secure Shell (SSH) fingerprints, is fully supported. A sample from [RFC 4255](http://tools.ietf.org/html/rfc4255) is: '2 1 123456789abcdef67890123456789abcdef67890'.

## SRV
SRV records can be used to encode the location and port of services on a domain name. When encoding, the priority field is used to encode the priority. For example, '\_ldap.\_tcp.dc.\_msdcs.conaxis.ch SRV 0 100 389 mars.conaxis.ch' would be encoded with 0 in the priority field and '100 389 mars.conaxis.ch' in the content field.

## TLSA
Since 3.0. The TLSA record, specified in [RFC 6698](http://tools.ietf.org/html/rfc6698), are used to bind SSL/TLS certificate to named hosts and ports.

## TXT
The TXT field can be used to attach textual data to a domain. Text is stored plainly.
