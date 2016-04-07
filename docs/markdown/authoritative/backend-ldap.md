# LDAP backend

As of PowerDNS Authoritative Server 4.0.0, the LDAP backend is fully supported.

**Warning**: Grégory Oestreicher has forked the LDAP backend shortly before our 3.2 release, after which a lot of development happened in a short time. We are working to upstream this work.

The original author for this module is Norbert Sendetzky. This page is based on the content from his [LDAPbackend wiki section](http://wiki.linuxnetworks.de/index.php/PowerDNS_ldapbackend) as copied in February 2016, and edited from there.

**Warning**: Host names and the MNAME of a SOA records are NEVER terminated with a '.' in PowerDNS storage! If a trailing '.' is present it will inevitably cause problems, problems that may be hard to debug.

|&nbsp;|&nbsp;|
|:--|:--|
|Native|Yes|
|Master|No|
|Slave|No|
|Superslave|No|
|Autoserial|No|
|DNSSEC|No|




# Introduction

Rationale
---------

This HOWTO documents the steps necessary to build and use the LDAP DNS
backend I've written for PowerDNS, an extremely versatile name server.
This backend enables PowerDNS to retrieve DNS information from any
standard compliant LDAP server. This is extremely handy if you have
already stored information about your hosts in your LDAP tree.

Schemas
-------

The schema is based on the 'uninett' dnszone schema, with a few types
added by number as designed in that schema.

```
!!include=../modules/ldapbackend/dnsdomain2.schema
```

The LDAP dnsdomain2 schema contains the additional object descriptions
which are required by the LDAP server to check the validity of entries
when they are added. Please consult the documentation of your LDAP
server to find out how to add this schema to the server.


# Installation

Configuration options
---------------------

There are a few options through the LDAP DNS backend can be configured
for your environment. Add them to the pdns.conf file located in
/etc/powerdns or /usr/local/etc/ (depends on your configuration while
compiling):

`launch=ldap`

You'll have to add the LDAP DNS backend to the PowerDNS backends first
by altering the `launch` declaration in the pdns.conf file. Otherwise the
options below won't have any effect.

ldap-host (default "ldap://127.0.0.1:389/") : The values assigned to this parameter can be LDAP URIs (e.g. <ldap://127.0.0.1/> or <ldaps://127.0.0.1/>) describing the connection to the LDAP server. There can be multiple LDAP URIs specified for load balancing and high availability if they are separated by spaces. In case the used LDAP client library doesn't support LDAP URIs as connection parameter, use plain host names or IP addresses instead (both may optionally be followed by a colon and the port).

## `ldap-starttls`
(default "no") : Use TLS encrypted connections to the LDAP server. This is only allowed if ldap-host is a <ldap://> URI or a host name / IP address.


## `ldap-basedn`
(default "") : The PowerDNS LDAP DNS backend searches below this path for objects containing the specified DNS information. The retrieval of attributes is limited to this subtree. This option must be set to the path according to the layout of your LDAP tree, e.g. ou=hosts,o=linuxnetworks,c=de is the DN to my objects containing the DNS information.

## `ldap-binddn`
(default "") : Path to the object to authenticate against. Should only be used, if the LDAP server doesn't support anonymous binds.

## `ldap-secret`
(default "") : Password for authentication against the object specified by ldap-binddn

## `ldap-method`
(default "simple") :

-   `simple`: Search the requested domain by comparing the associatedDomain
    attributes with the domain string in the question.

-   `tree`: Search entires by translating the domain string into a LDAP dn. Your
    LDAP tree must be designed in the same way as your DNS LDAP tree.
    The question for "myhost.linuxnetworks.de" would translate into
    "dc=myhost,dc=linuxnetworks,dc=de,ou=hosts=..." and the entry where
    this dn points to would be evaluated for dns records.

-   `strict`: Like simple, but generates PTR records from aRecords or aAAARecords.
    Using "strict", you won't be able to do zone transfers for
    reverse zones.

## `ldap-filter-axfr`
(default "(:target:)" ) : LDAP filter for limiting AXFR results (zone transfers), e.g. (&(:target:)(active=yes)) for returning only entries whose attribute "active" is set to "yes".

<!-- -->

## `ldap-filter-lookup`
(default "(:target:)" ) : LDAP filter for limiting IP or name lookups, e.g. (&(:target:)(active=yes)) for returning only entries whose attribute "active" is set to "yes".

# Example

Tree design
-----------

The DNS LDAP tree should be designed carefully to prevent mistakes,
which are hard to correct afterwards. The best solution is to create a
subtree for all host entries which will contain the DNS records. You can
do this the simple way or in a tree style.

DN of a simple style example record (e.g. myhost.linuxnetworks.de):

`dn: dc=myhost,dc=linuxnetworks,ou=hosts,...`

DN of a tree style example record (e.g. myhost.test.linuxnetworks.de):

`dn: dc=myhost,dc=test,dc=linuxnetworks,dc=de,ou=hosts,...`

Basic objects
-------------

Each domain (or zone for BIND users) must include one object containing
a SOA (Start Of Authority) record. This object can also contain the
attribute for a MX (Mail eXchange) and a NS (Name Server) record. These
attributes allow one or more values, e.g. for a backup mail or name
server:

```
dn: dc=linuxnetworks,ou=hosts,o=linuxnetworks,c=de
objectclass: top
objectclass: dcobject
objectclass: dnsdomain
objectclass: domainrelatedobject
dc: linuxnetworks
soarecord: ns.linuxnetworks.de me@linuxnetworks.de 1 1800 3600 86400 7200
nsrecord: ns.linuxnetworks.de
mxrecord: 10 mail.linuxnetworks.de
mxrecord: 20 mail2.linuxnetworks.de
associateddomain: linuxnetworks.de
```

A simple mapping between name and IP address can be specified by an
object containing an arecord and an associateddomain. You don't have to
bother about a reverse mapping (ip address to name) if you don't want
to, because this can be done automagically by the LDAP DNS backend if
you set ldap-method=strict in pdns.conf.

```
dn: dc=server,dc=linuxnetworks,ou=hosts,o=linuxnetworks,c=de
objectclass: top
objectclass: dnsdomain
objectclass: domainrelatedobject
dc: server
arecord: 10.1.0.1
arecord: 192.168.0.1
associateddomain: server.linuxnetworks.de
```

Be aware of the fact that these examples work if ldap-method is simple
or strict. For tree mode you have to modify all DNs according to the
algorithm described in the section above.

Wildcards
---------

Wild-card domains are possible by using the asterisk in the
associatedDomain value like it is used in the bind zone files. The "dc"
attribute can be set to any value in simple or strict mode - this
doesn't matter.

dn: dc=any,dc=linuxnetworks,ou=hosts,o=linuxnetworks,c=de
objectclass: top
objectclass: dnsdomain
objectclass: domainrelatedobject
dc: any
arecord: 192.168.0.1
associateddomain: *.linuxnetworks.de

In tree mode wild-card entries has to look like this instead:

```
dn: dc=*,dc=linuxnetworks,dc=de,ou=hosts,o=linuxnetworks,c=de
objectclass: top
objectclass: dnsdomain
objectclass: domainrelatedobject
dc: *
arecord: 192.168.0.1
associateddomain: *.linuxnetworks.de
```

Aliases
-------

Aliases for an existing DNS object have to be defined in a separate LDAP
object. You can create one object per alias (this is a must in tree
mode) or add all aliases (as values of associateddomain) to one object.
The only thing which is not allowed is to create loops by using the same
name in associateddomain and in cnamerecord

```
dn: dc=server-aliases,dc=linuxnetworks,ou=hosts,o=linuxnetworks,c=de
objectclass: top
objectclass: dnsdomain
objectclass: domainrelatedobject
dc: server-aliases
cnamerecord: server.linuxnetworks.de
associateddomain: proxy.linuxnetworks.de
associateddomain: mail2.linuxnetworks.de
associateddomain: ns.linuxnetworks.de
```

Aliases are optional. You can also add all alias domains to the
associateddomain attribute. The only difference is that these additional
domains aren't recognized as aliases anymore, but instead as a normal
arecord:

```
dn: dc=server,dc=linuxnetworks,ou=hosts,o=linuxnetworks,c=de
objectclass: top
objectclass: dnsdomain
objectclass: domainrelatedobject
dc: server
arecord: 10.1.0.1
associateddomain: server.linuxnetworks.de
associateddomain: proxy.linuxnetworks.de
associateddomain: mail2.linuxnetworks.de
associateddomain: ns.linuxnetworks.de
```

Reverse lookups
---------------

Currently you have two options: Either reverse lookups handled by the
code automagically or you have to add PTR records to your LDAP
directory. If you want to derive PTR records from A records, you have
set "ldap-method" to "strict". Otherwise add objects like below to your
directory:

```
dn: dc=1.10.in-addr.arpa,ou=hosts,o=linuxnetworks,c=de
objectclass: top
objectclass: dnsdomain2
objectclass: domainrelatedobject
dc: 1.10.in-addr.arpa
soarecord: ns.linuxnetworks.de me@linuxnetworks.de 1 1800 3600 86400 7200
nsrecord: ns.linuxnetworks.de
associateddomain: 1.10.in-addr.arpa
```

```
dn: dc=1.0,dc=1.10.in-addr.arpa,ou=hosts,o=linuxnetworks,c=de
objectclass: top
objectclass: dnsdomain2
objectclass: domainrelatedobject
dc: 1.0
ptrrecord: server.linuxnetworks.de
associateddomain: 1.0.1.10.in-addr.arpa
```

Tree mode requires each component to be a dc element of its own:

```
dn: dc=1,dc=0,dc=1,dc=10,dc=in-addr,dc=arpa,ou=hosts,o=linuxnetworks,c=de
objectclass: top
objectclass: dnsdomain2
objectclass: domainrelatedobject
dc: 1
ptrrecord: server.linuxnetworks.de
associateddomain: 1.0.1.10.in-addr.arpa
```

To use this kind of record, you also have to add the dnsdomain2 schema
to the configuration of your LDAP server.

**CAUTION:**

You can't use "ldap-method=strict" if you need zone transfers (AXFR) to
other name servers. Distributing zones can only be done directly via
LDAP replication in this case, because for a full zone transfer the
reverse records are missing

# Migration

BIND zone files
---------------

There is a small utility in the PowerDNS distribution available called
"zone2ldap", which can convert zone files used by BIND to the ldif
format. Ldif is a text file format containing information about LDAP
objects and can be read by every standard compliant LDAP server.
Zone2ldap needs the BIND named.conf (usually located in /etc) as input
and writes the dns record entries in ldif format to stdout:

Usage:

```
zone2ldap
   --basedn=`<your-basedn
   --named-conf=`<file
   --resume
   > zones.ldif
```

Alternatively zone2ldap can be used to convert only single zone files
instead all zones:

Usage:

```
zone2ldap
   --basedn=`<your-basedn
   --zone-file=`<file
   --zone-name=`<file
   --resume
   > zone.ldif
```

See [its manpage](../manpages/zone2ldap.1.md) for a complete list of options.

Bind LDAP backend
-----------------

If you are using the [Bind LDAP sdb
backend](http://bind9-ldap.bayour.com/), you can keep the records in the
LDAP tree also for the PowerDNS LDAP backend. The schemas both backends
utilize is almost the same except for one important thing: Domains for
PowerDNS are stored in the attribute "associatedDomain" whereas Bind
stores them split in "relativeDomainName" and "zoneName".

There is a [migration
script](http://www.linuxnetworks.de/pdnsldap/bind2pdns-ldap) which
creates a file in LDIF format with the necessary LDAP updates including
the "associatedDomain" and "dc" attributes. The utility is executed on
the command line by:

```
./bind2pdns-ldap
 --host=<host name or IP>
 --basedn=<subtree dn>
 --binddn=<admin dn>
 > update.ldif
```

The parameter "host" and "basedn" are mandatory, "binddn" is optional.
If "binddn" is given, you will be asked for a password, otherwise an
anonymous bind is executed. The updates in LDIF format are written to
stdout and can be redirected to a file.

The script requires Perl and the Perl Net::LDAP module and can be
downloaded from
[/pdnsldap/bind2pdns-ldap](http://www.linuxnetworks.de/pdnsldap/bind2pdns-ldap).

Updating the entries in the LDAP tree requires to make the dnsdomain2
schema known to the LDAP server. Unfortunately, both schemas (dnsdomain2
and dnszone) share the same record types and use the same OIDs so the
LDAP server can't use both schemas at the same time. The solution is to
add the [dnsdomain2
schema](http://www.linuxnetworks.de/pdnsldap/dnsdomain2.schema) and
replace the dnszone schema by the [dnszone-migrate
schema](http://www.linuxnetworks.de/pdnsldap/dnszone-migrate.schema).
After restarting the LDAP server you can use attributes from both
schemas and updating the objects in the LDAP tree using the LDIF file
generated from bind2pdns-ldap will work without errors.

Other name server
-----------------

The easiest way for migrating DNS records is to use the output of a zone
transfer (AXFR). Save the output of the "dig" program provided by bind
into a file and call zone2ldap with the file name as option to the
--zone-file parameter. This will generate you an appropriate ldif file,
which you can import into your LDAP tree. The bash script except below
automates this for you.

```
DNSSERVER=127.0.0.1
DOMAINS="linuxnetworks.de 10.10.in-addr.arpa"

for DOMAIN in $DOMAINS; do
   dig @$DNSSERVER $DOMAIN AXFR> $DOMAIN.zone;
   zone2ldap --zone-name=$DOMAIN --zone-file=$DOMAIN.zone> $DOMAIN.ldif;
done
```

# Optimization

LDAP indices
------------

To improve performance, you can tell the LDAP server to maintain indices
on certain attributes. This leads to much faster searches for these type
of attributes.

The LDAP DNS backend mainly searches for values in associatedDomain, so
maintaining an index (pres,eq,sub) on this attribute is a big
performance improvement:

`index associatedDomain pres,eq,sub`

Furthermore if you set ldap-method=strict, it uses the aRecord and
aAAARecord attribute for reverse mapping of IP addresses to names. To
maintain an index (pres,eq) on these attributes also improves
performance of the LDAP server:

```
index aAAARecord pres,eq
index aRecord pres,eq
```

All other attributes than associatedDomain, aRecord or aAAARecord are
only read if the object matches the specified criteria. Thus,
maintaining an index on these attributes is useless.

If you've inserted your entries before adding these statements to your
slapd.conf, you have to stop your LDAP server and call slapindex on the
command line. This will generate the indices for already existing
attributes

dNSTTL attribute
----------------

Converting the string in the dNSTTL attribute to an integer is a time
consuming task. If you don't use a separate TTL value for each entry and
use the default-ttl parameter in pdns.conf instead, you will gain a
approx. 7% better performance for entries that aren't cached. You can
still add a dNSTTL attribute to entries that should have a different TTL
than the default TTL

Access method
-------------

The method of accessing the entries in the directory affects the
performance too. By default, the "simple" method is used search for
entries by using their associatedDomain attribute. Alternatively you can
choose the "tree" method, whereby the search is done along the directory
tree, e.g. "host.example.dom" is translated into
"dc=host,dc=example,dc=dom,...". This requires your LDAP DNS subtree
layout to be 1:1 to the DNS tree, but then you will gain additional 7%
better performance values.

# Troubleshooting

No reverse zone transfer
------------------------

Your LDAP tree must contain a separate subtree of PTR records (e.g. for
1.1.10.10.in-addr.arpa) and you can't set "ldap-method" to "strict".

IPv6 reverse lookup doesn't work in strict mode
-----------------------------------------------

For automatically generated reverse IPv6 records your aAAARecord entries
must follow two restrictions: They have to be fully expanded ("FFFF::1"
is not allowed and it must be "FFFF:0:0:0:0:0:0:1" instead) and they
must not contain leading zeros, e.g. an entry containing "002A" is
incorrect - use "2A" without zeros instead. These restrictions are due
to the fact that LDAP DNS AAAA entries are pure text and doesn't allow
searching by wild-cards.

Bad search filter
-----------------

The release of PowerDNS 2.9.20 contains a bug in
ldap-filter-{axfr,lookup}. A user provided string with ":target:" is
replaced with "(associatedDomain=QUERYDATA)" and braces ARE added. So if
you create some filter like

`ldap-filter-lookup=(&(:target:)(active=yes))`

it will result as

`ldap-filter-lookup=(&((associatedDomain=QUERYDATA))(active=yes))`

which results with bad search filter. To circumvent the bug temporarily
you can add instead

`ldap-filter-lookup=(&:target:(active=yes))`

The bug will be fixed in version 2.9.21 and later versions.

------------------------------------------------------------------------

**Feel free to add your own tips**

# Future

DNS notification support
------------------------

As soon as the LDAP server implementations begin to provide the features
of the LDAP client update protocol (LCUP, [RFC
3928](http://www.ietf.org/rfc/rfc3928.txt)), it will be possible to
support the DNS notification feature for the [LDAP DNS
backend](PowerDNS_LDAP_Backend "wikilink") in case a record in the LDAP
directory was changed.

SASL support
------------

Support for more authentication methods would be handy. Anyone
interested and willing to contribute?
