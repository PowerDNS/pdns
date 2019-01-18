Supported Record Types
======================

This chapter lists all record types PowerDNS supports, and how they are
stored in backends. The list is mostly alphabetical but some types are
grouped.

.. warning::
  Host names and the MNAME of a SOA records are NEVER
  terminated with a '.' in PowerDNS storage! If a trailing '.' is present
  it will inevitably cause problems, problems that may be hard to debug.
  Use ``pdnsutil check-zone`` to validate your zone data.

.. note::
  Whenever the storage format is mentioned, this relates only to
  the way the record should be stored in one of the :doc:`generic SQL <../backends/generic-sql>` backends. The other
  backends should use their *native* format.

The PowerDNS Recursor can serve and store all record types, regardless
of whether these are explicitly supported.

.. _types-a:

A
-

The A record contains an IP address. It is stored as a decimal dotted
quad string, for example: '203.0.113.210'.

.. _types-aaaa:

AAAA
----

The AAAA record contains an IPv6 address. An example:
'2001:DB8:2000:bf0::1'.

.. _types-afsdb:

AFSDB
-----

A specialised record type for the 'Andrew Filesystem'. Stored as:
'#subtype hostname', where subtype is a number.

.. _types-alias:

ALIAS
-----

.. versionadded:: 4.0.0

The ALIAS pseudo-record type is supported to provide
CNAME-like mechanisms on a zone's apex. See the :doc:`howto <../guides/alias>` for information
on how to configure PowerDNS to serve records synthesized from ALIAS
records.

.. _types-caa:

CAA
---

.. versionadded:: 4.0.0

The "Certification Authority Authorization" record,
specified in :rfc:`6844`, is used
to specify Certificate Authorities that may issue certificates for a
domain.

.. _types-cert:

CERT
----

Specialised record type for storing certificates, defined in :rfc:`2538`.

.. _types-cdnskey:

CDNSKEY
-------

.. versionadded:: 4.0.0

The CDNSKEY (:rfc:`Child DNSKEY <7344#section-3.2>`) type is supported.

.. _types-cds:

CDS
---

.. versionadded:: 4.0.0

The CDS (:rfc:`Child DS <7344#section-3.1>`) type is supported.

.. _types-cname:

CNAME
-----

The CNAME record specifies the canonical name of a record. It is stored
plainly. Like all other records, it is not terminated by a dot. A sample
might be 'webserver-01.yourcompany.com'.

.. _types-dnskey:

DNSKEY
------

The DNSKEY DNSSEC record type is fully supported, as described in :rfc:`4034`.
Enabling DNSSEC for domains can be done with :doc:`pdnsutil <../dnssec/pdnsutil>`.

.. _types-dname:

DNAME
-----

The DNAME record, as specified in :rfc:`6672` is supported. However,
:ref:`setting-dname-processing` has to be set to ``yes`` for PowerDNS to process these records.

.. _types-ds:

DS
--

The DS DNSSEC record type is fully supported, as described in :rfc:`4034`.
Enabling DNSSEC for domains can be done with :doc:`pdnsutil <../dnssec/pdnsutil>`.

.. _types-hinfo:

HINFO
-----

Hardware Info record, used to specify CPU and operating system. Stored
with a single space separating these two, example: 'i386 Linux'.

.. _types-key:

KEY
---

The KEY record is fully supported. For its syntax, see :rfc:`2535`.

.. _types-loc:

LOC
---

The LOC record is fully supported. For its syntax, see :rfc:`1876`.
A sample content would be: ``51 56 0.123 N 5 54 0.000 E 4.00m 1.00m 10000.00m 10.00m``

.. _types-mx:

MX
--

The MX record specifies a mail exchanger host for a domain. Each mail
exchanger also has a priority or preference. For example
``10 mx.example.net``. In the generic SQL backends, the ``10`` should go
in the 'priority field'.

.. _types-naptr:

NAPTR
-----

Naming Authority Pointer, :rfc:`2915`. Stored as follows:

::

    '100  50  "s"  "z3950+I2L+I2C"     ""  _z3950._tcp.gatech.edu'.

The fields are: order, preference, flags, service, regex, replacement.
Note that the replacement is not enclosed in quotes, and should not be.
The replacement may be omitted, in which case it is empty. See also :rfc:`2916`
for how to use NAPTR for ENUM (E.164) purposes.

.. _types-ns:

NS
--

Nameserver record. Specifies nameservers for a domain. Stored plainly:
``ns1.powerdns.com``, as always without a terminating dot.

NSEC, NSEC3, NSEC3PARAM
-----------------------

The NSEC, NSEC3 and NSEC3PARAM DNSSEC record type are fully supported,
as described in :rfc:`4034`.
Enabling DNSSEC for domains can be done with :doc:`pdnsutil <../dnssec/pdnsutil>`.

.. _types-openpgpkey:

OPENPGPKEY
----------

The OPENPGPKEY records, specified in :rfc:`7929`, are
used to bind OpenPGP certificates to email addresses.

.. _types-ptr:

PTR
---

Reverse pointer, used to specify the host name belonging to an IP or
IPv6 address. Name is stored plainly: ``www.powerdns.com``. As always,
no terminating dot.

.. _types-rp:

RP
--

Responsible Person record, as described in :rfc:`1183`. Stored with a single space
between the mailbox name and the more-information pointer. Example:
``peter.powerdns.com peter.people.powerdns.com``, to indicate that
``peter@powerdns.com`` is responsible and that more information about
peter is available by querying the TXT record of
peter.people.powerdns.com.

.. _types-rrsig:

RRSIG
-----

The RRSIG DNSSEC record type is fully supported, as described in :rfc:`4034`.

.. _types-soa:

SOA
---

The Start of Authority record is one of the most complex available. It
specifies a lot about a domain: the name of the master nameserver ('the
primary'), the hostmaster and a set of numbers indicating how the data
in this domain expires and how often it needs to be checked. Further
more, it contains a serial number which should rise on each change of
the domain.

The stored format is:

::

     primary hostmaster serial refresh retry expire default_ttl

Besides the primary and the hostmaster, all fields are numerical.
PowerDNS has a set of default values:

-  primary: :ref:`setting-default-soa-name`
   configuration option
-  hostmaster: ``hostmaster@domain-name``
-  serial: 0
-  refresh: 10800 (3 hours)
-  retry: 3600 (1 hour)
-  expire: 604800 (1 week)
-  default_ttl: 3600 (1 hour)

The fields have complicated and sometimes controversial meanings. The
'serial' field is special. If left at 0, the default, PowerDNS will
perform an internal list of the domain to determine highest change_date
field of all records within the zone, and use that as the zone serial
number. This means that the serial number is always raised when changes
are made to the zone, as long as the change_date field is being set.
Make sure to check whether your backend of choice supports Autoserial.

.. _types-spf:

SPF
---

SPF records can be used to store Sender Policy Framework details (:rfc:`4408`).

.. _types-sshfp:

SSHFP
-----

The SSHFP record type, used for storing Secure Shell (SSH) fingerprints,
is fully supported. A sample from :rfc:`4255` is::

  2 1 123456789abcdef67890123456789abcdef67890

.. _types-srv:

SRV
---

SRV records can be used to encode the location and port of services on a
domain name. When encoding, the priority field is used to encode the
priority. For example,
``_ldap._tcp.dc._msdcs.conaxis.ch SRV 0 100 389 mars.conaxis.ch`` would
be encoded with ``0`` in the priority field and
``100 389 mars.conaxis.ch`` in the content field.

TKEY, TSIG
----------

The TKEY (:rfc:`2930`) and TSIG records (:rfc:`2845`), used for
key-exchange and authenticated AXFRs, are supported. See the :doc:`../tsig`
and `DNS update <../dnsupdate>` documentation for more information.

.. _types-tlsa:

TLSA
----

Since 3.0. The TLSA records, specified in :rfc:`6698`, are used to bind SSL/TLS
certificate to named hosts and ports.

.. _types-smimea:

SMIMEA
------

Since 4.1. The SMIMEA record type, specified in :rfc:`8162`, is used to bind S/MIME
certificates to domains.

.. _types-txt:

TXT
---

The TXT field can be used to attach textual data to a domain. Text is
stored plainly, PowerDNS understands content not enclosed in quotes.
However, all quotes characters (``"``) in the TXT content must be
preceded with a backslash (``\``).:

::

    "This \"is\" valid"

For a literal backslash in the TXT record, escape it:

::

    "This is also \\ valid"

Unicode characters can be added in two ways, either by adding the
character itself or the escaped variant to the content field. e.g.
``"ç"`` is equal to ``"\195\167"``.

When a TXT record is longer than 255 characters/bytes (excluding
possible enclosing quotes), PowerDNS will cut up the content into 255
character/byte chunks for transmission to the client.

.. _types-uri:

URI
---

The URI record, specified in :rfc:`7553`, is used to publish
mappings from hostnames to URIs.

Other types
-----------

The following, rarely used or obsolete record types, are also supported:

-  A6 (:rfc:`2874`, obsolete)
-  DHCID (:rfc:`4701`)
-  DLV (:rfc:`4431`)
-  EUI48/EUI64 (:rfc:`7043`)
-  IPSECKEY (:rfc:`4025`)
-  KEY (:rfc:`2535`, obsolete)
-  KX (:rfc:`2230`)
-  MAILA (:rfc:`1035`)
-  MAILB (:rfc:`1035`)
-  MINFO (:rfc:`1035`)
-  MR (:rfc:`1035`)
-  RKEY (`draft-reid-dnsext-rkey-00.txt <https://tools.ietf.org/html/draft-reid-dnsext-rkey-00>`__)
-  SIG (:rfc:`2535`, obsolete)
-  WKS (:rfc:`1035`)
