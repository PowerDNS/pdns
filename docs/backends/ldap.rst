LDAP backend
============

* Native: Yes
* Master: No
* Slave: No
* Superslave: No
* Autoserial: No
* DNSSEC: No
* Disabled data: No
* Comments: No
* Module name: ldap
* Launch name: ``ldap``

Introduction
------------
As of PowerDNS Authoritative Server 4.0.0, the LDAP backend is fully
supported.

The original author for this module is Norbert Sendetzky. This page is
based on the content from his `LDAPbackend wiki
section <http://wiki.linuxnetworks.de/index.php/PowerDNS_ldapbackend>`__
as copied in February 2016, and edited from there.

.. warning::
  Host names and the MNAME of a SOA records are NEVER
  terminated with a '.' in PowerDNS storage! If a trailing '.' is present
  it will inevitably cause problems, problems that may be hard to debug.


Rationale
^^^^^^^^^

The LDAP backend enables PowerDNS to retrieve DNS information from any
standard compliant LDAP server. This is extremely handy if information
about hosts is already stored in an LDAP tree.

Schemas
^^^^^^^

The schema is based on the 'uninett' dnszone schema, with a few types
added by number as designed in that schema:

.. literalinclude:: ../../modules/ldapbackend/dnsdomain2.schema

The LDAP dnsdomain2 schema contains the additional object descriptions
which are required by the LDAP server to check the validity of entries
when they are added. Please consult the documentation of the LDAP server
to find out how to add this schema to the server.

Installation
------------

The LDAP backend can be compiled by adding ``ldap`` to either the
``--with-modules`` or ``--with-dynmodules`` ``configure`` options.

When using packages, the ``pdns-backend-ldap`` package should be
installed.

Configuration options
---------------------

There are a few options through the LDAP DNS backend can be configured.
Add them to the ``pdns.conf`` file.

To launch the ldap backend:

.. code-block:: ini

    launch=ldap

.. _setting-ldap-host:

``ldap-host``
^^^^^^^^^^^^^

(default "``ldap://127.0.0.1:389/``") : The values assigned to this
parameter can be LDAP URIs (e.g. ``ldap://127.0.0.1/`` or
``ldaps://127.0.0.1/``) describing the connection to the LDAP server.
There can be multiple LDAP URIs specified for load balancing and high
availability if they are separated by spaces. In case the used LDAP
client library doesn't support LDAP URIs as connection parameter, use
plain host names or IP addresses instead (both may optionally be
followed by a colon and the port).

.. _setting-ldap-starttls:

``ldap-starttls``
^^^^^^^^^^^^^^^^^

(default "no") : Use TLS encrypted connections to the LDAP server. This
is only allowed if ldap-host is an ``ldap://`` URI or a host name / IP
address.

.. _setting-ldap-timeout:

``ldap-timeout``
^^^^^^^^^^^^^^^^

(default: "5") : The number of seconds to wait for LDAP operations to
complete.

.. _setting-ldap-reconnect-attempts:

``ldap-reconnect-attempts``
^^^^^^^^^^^^^^^^^^^^^^^^^^^

(default: "5") : The number of attempts to make to re-establish a lost
connection to the LDAP server.

.. _setting-ldap-authmethod:

``ldap-authmethod``
^^^^^^^^^^^^^^^^^^^

(default: "simple") : How to authenticate to the LDAP server. Actually
only two methods are supported: "simple", which uses the classical DN /
password, or "gssapi", which requires a Kerberos keytab.

.. _setting-ldap-binddn:

``ldap-binddn``
^^^^^^^^^^^^^^^

(default "") : Path to the object to authenticate against. Should only
be used, if the LDAP server doesn't support anonymous binds and with the
"simple" authmethod.

.. _setting-ldap-secret:

``ldap-secret``
^^^^^^^^^^^^^^^

(default "") : Password for authentication against the object specified
by ldap-binddn. Only used when "authmethod" is "simple".

.. _setting-ldap-krb5-keytab:

``ldap-krb5-keytab``
^^^^^^^^^^^^^^^^^^^^

(default: "") : Full path to the keytab file to use to authenticate.
This is only used when "authmethod" is set to "gssapi". The keytab must,
ideally, contain only one principal (or to put it otherwise, only the
first principal found in the keytab will be used).

.. _setting-ldap-krb5-ccache:

``ldap-krb5-ccache``
^^^^^^^^^^^^^^^^^^^^

(default: "") : Full path to the Kerberos credential cache file to use.
Actually only files are supported, and the "FILE:" prefix must not be
set. The PowerDNS process must be able to write to this file and it
*must* be the only one able to read it.

.. _setting-ldap-basedn:

``ldap-basedn``
^^^^^^^^^^^^^^^

(default "") : The PowerDNS LDAP DNS backend searches below this path
for objects containing the specified DNS information. The retrieval of
attributes is limited to this subtree. This option must be set to the
path according to the layout of your LDAP tree, e.g.
ou=hosts,o=linuxnetworks,c=de is the DN to my objects containing the DNS
information.

.. _setting-ldap-method:

``ldap-method``
^^^^^^^^^^^^^^^

(default "simple") :

-  ``simple``: Search the requested domain by comparing the
   associatedDomain attributes with the domain string in the question.
-  ``tree``: Search entires by translating the domain string into a LDAP
   dn. Your LDAP tree must be designed in the same way as the DNS LDAP
   tree. The question for "myhost.linuxnetworks.de" would translate into
   "dc=myhost,dc=linuxnetworks,dc=de,ou=hosts=..." and the entry where
   this dn points to would be evaluated for dns records.
-  ``strict``: Like simple, but generates PTR records from aRecords or
   aAAARecords. Using "strict", zone transfers for reverse zones are not
   possible.

.. _setting-ldap-filter-axfr:

``ldap-filter-axfr``
^^^^^^^^^^^^^^^^^^^^

(default "(:target:)" ) : LDAP filter for limiting AXFR results (zone
transfers), e.g. (&(:target:)(active=yes)) for returning only entries
whose attribute "active" is set to "yes".

.. _setting-ldap-filter-lookup:

``ldap-filter-lookup``
^^^^^^^^^^^^^^^^^^^^^^

(default "(:target:)" ) : LDAP filter for limiting IP or name lookups,
e.g. (&(:target:)(active=yes)) for returning only entries whose
attribute "active" is set to "yes".

Master Mode
-----------

Schema update
^^^^^^^^^^^^^

First off adding master support to the LDAP backend needs a schema
update. This is required as some metadata must be stored by PowerDNS,
such as the last successful transfer to slaves. The new schema is
available in schema/pdns-domaininfo.schema.

Once the schema is loaded the zones for which you want to be a master
must be modified. The dn of the SOA record *must* have the object class
``PdnsDomain``, and thus the ``PdnsDomainId`` attribute. This attribute
is an integer that *must* be unique across all zones served by the
backend. Furthermore the ``PdnsDomainType`` must be equal to 'master'
(lower case).

Example
^^^^^^^

Here is an example LDIF of a zone that's ready for master operation
(assuming the 'tree' style):

::

    dn: dc=example,dc=com,ou=dns,dc=mycompany,dc=com
    objectClass: top
    objectClass: domainRelatedObject
    objectClass: dNSDomain2
    objectClass: PdnsDomain
    dc: example
    associatedDomain: example.com
    nSRecord: ns1.example.com
    sOARecord: ns1.example.com. hostmaster.example.com. 2013031101 1800 600 1209600 600
    mXRecord: 10 mx1.example.com
    PdnsDomainId: 1
    PdnsDomainType: master
    PdnsDomainMaster: 192.168.0.2

You should have one attribute ``PdnsDomainMaster`` per master serving
this zone.

Example
-------

Tree design
^^^^^^^^^^^

The DNS LDAP tree should be designed carefully to prevent mistakes,
which are hard to correct afterwards. The best solution is to create a
subtree for all host entries which will contain the DNS records. This
can be done the simple way or in a tree style.

DN of a simple style example record (e.g. myhost.example.com):

``dn:dc=myhost,dc=example,ou=hosts,...``

DN of a tree style example record (e.g. myhost.test.example.com):

``dn:dc=myhost,dc=test,dc=example,dc=com,ou=hosts,...``

Basic objects
^^^^^^^^^^^^^

Each domain (or zone for BIND users) must include one object containing
a SOA (Start Of Authority) record. This requirement applies to both
forward and reverse zones. This object can also contain the attribute
for a MX (Mail eXchange) and one or more NS (Name Server) records. These
attributes allow one or more values, e.g. for a backup mail or name
server:

::

    dn:dc=example,ou=hosts,o=example,c=com
    objectclass:top
    objectclass:dcobject
    objectclass:dnsdomain
    objectclass:domainrelatedobject
    dc:example
    soarecord:ns.example.com me@example.com 1 1800 3600 86400 7200
    nsrecord:ns.example.com
    mxrecord:10 mail.example.com
    mxrecord:20 mail2.example.com
    associateddomain:example.com

A simple mapping between name and IP address can be specified by an
object containing an ``arecord`` and an ``associateddomain``.

::

    dn:dc=server,dc=example,ou=hosts,o=example,c=de
    objectclass:top
    objectclass:dnsdomain
    objectclass:domainrelatedobject
    dc:server
    arecord:10.1.0.1
    arecord:192.168.0.1
    associateddomain:server.example.com

Be aware of the fact that these examples work if ``ldap-method`` is
``simple`` or ``strict``. For tree mode, all DNs will have to be
modified according to the algorithm described in the section above.

Wildcards
^^^^^^^^^

Wild-card domains are possible by using the asterisk in the
``associatedDomain`` value like it is used in the BIND zone files. The
"dc" attribute can be set to any value in simple or strict mode - this
doesn't matter.

::

    dn:dc=any,dc=example,ou=hosts,o=example,c=de
    objectclass:top
    objectclass:dnsdomain
    objectclass:domainrelatedobject
    dc:any
    arecord:192.168.0.1
    associateddomain:*.example.com

In tree mode wild-card entries has to look like this instead:

::

    dn:dc=*,dc=example,dc=de,ou=hosts,o=example,c=de
    objectclass:top
    objectclass:dnsdomain
    objectclass:domainrelatedobject
    dc:*
    arecord:192.168.0.1
    associateddomain:*.example.com

Aliases
^^^^^^^

Aliases for an existing DNS object have to be defined in a separate LDAP
object. One object should be create per alias (this is a must in tree
mode) or add all aliases (as values of ``associateddomain``) to one
object. The only thing which is not allowed is to create loops by using
the same name in ``associateddomain`` and in ``cnamerecord``.

::

    dn:dc=server-aliases,dc=example,ou=hosts,o=example,c=de
    objectclass:top
    objectclass:dnsdomain
    objectclass:domainrelatedobject
    dc:server-aliases
    cnamerecord:server.example.com
    associateddomain:proxy.example.com
    associateddomain:mail2.example.com
    associateddomain:ns.example.com

Aliases are optional. All alias domains can also be added to the
associateddomain attribute. The only difference is that these additional
domains aren't recognized as aliases anymore, but instead as a normal
``arecord``:

::

    dn:dc=server,dc=example,ou=hosts,o=example,c=de
    objectclass:top
    objectclass:dnsdomain
    objectclass:domainrelatedobject
    dc:server
    arecord:10.1.0.1
    associateddomain:server.example.com
    associateddomain:proxy.example.com
    associateddomain:mail2.example.com
    associateddomain:ns.example.com

Reverse lookups
^^^^^^^^^^^^^^^

Currently there are two options: Set ``ldap-method`` to ``strict`` to
have the code automatically derive PTR records from A and AAAA records
in the tree. Or, in ``simple`` and ``tree`` modes, create additional
objects explictly mapping each address to a PTR record.

For ``strict`` or ``simple`` modes, first create an object with an SOA
record for the reverse-lookup zone(s) corresponding to the A and AAAA
records that will be served:

::

    dn:dc=1.10.in-addr.arpa,ou=hosts,o=example,c=de
    objectclass:top
    objectclass:dnsdomain2
    objectclass:domainrelatedobject
    dc:1.10.in-addr.arpa
    soarecord:ns.example.com me@example.com 1 1800 3600 86400 7200
    nsrecord:ns.example.com
    associateddomain:1.10.in-addr.arpa

In ``strict`` mode, no other objects are required -- reverse queries
that correspond to an arecord or aaaarecord of an existing object will
be automagically serviced using the associateddomain entry of that
object.

In ``simple`` mode, you must then create objects for each reverse
mapping:

::

    dn:dc=1.0,dc=1.10.in-addr.arpa,ou=hosts,o=example,c=de
    objectclass:top
    objectclass:dnsdomain2
    objectclass:domainrelatedobject
    dc:1.0
    ptrrecord:server.example.com
    associateddomain:1.0.1.10.in-addr.arpa

Tree mode requires each component to be a dc element of its own:

::

    dn:dc=1,dc=0,dc=1,dc=10,dc=in-addr,dc=arpa,ou=hosts,o=example,c=de
    objectclass:top
    objectclass:dnsdomain2
    objectclass:domainrelatedobject
    dc:1
    ptrrecord:server.example.com
    associateddomain:1.0.1.10.in-addr.arpa

To use this kind of record, add the dnsdomain2 schema to the
configuration of ther LDAP server.

**CAUTION:** ``ldap-method=strict`` can not be used if zone transfers
(AXFR) are needed to other name servers. Distributing zones can only be
done directly via LDAP replication in this case, because for a full zone
transfer the reverse records are missing.

Migration
---------

BIND zone files
^^^^^^^^^^^^^^^

There is a small utility in the PowerDNS distribution available called
:doc:`../manpages/zone2ldap.1`, which can convert zone
files used by BIND to the ldif format. Ldif is a text file format
containing information about LDAP objects and can be read by every
standard compliant LDAP server. ``zone2ldap`` needs the BIND
``named.conf`` (usually located in /etc) as input and writes the dns
record entries in ldif format to stdout:

.. code-block:: shell

    zone2ldap
       --basedn=YOUR_BASE_DN \
       --named-conf=PATH_TO_NAMED_CONF \
       --resume > zones.ldif

Alternatively zone2ldap can be used to convert only single zone files
instead all zones:

.. code-block:: shell

    zone2ldap
       --basedn=YOUR_BASE_DN \
       --zone-file=PATH_TO_ZONE_FILE \
       --zone-name=NAME_OF_ZONE \
       --resume > zone.ldif

See :doc:`its manpage <../manpages/zone2ldap.1>` for a complete list of
options.

BIND LDAP backend
^^^^^^^^^^^^^^^^^

When coming from the `BIND LDAP sdb
backend <http://bind9-ldap.bayour.com/>`__, the records can be kept in
the LDAP tree also for the PowerDNS LDAP backend. The schemas both
backends utilize is almost the same except for one important thing:
Domains for PowerDNS are stored in the attribute "associatedDomain"
whereas BIND stores them split in "relativeDomainName" and "zoneName".

There is a `migration
script <http://www.linuxnetworks.de/pdnsldap/bind2pdns-ldap>`__ which
creates a file in LDIF format with the necessary LDAP updates including
the "associatedDomain" and "dc" attributes. The utility is executed on
the command line by:

.. code-block:: shell

    ./bind2pdns-ldap
       --host=HOSTNAME_OR_IP \
       --basedn=YOUR_BASE_DN \
       --binddn=ADMIN_DN > update.ldif

The parameter "host" and "basedn" are mandatory, "binddn" is optional.
If "binddn" is given, the script will prompt for a password, otherwise
an anonymous bind is executed. The updates in LDIF format are written to
stdout and can be redirected to a file.

The script requires Perl and the Perl Net::LDAP module and can be
downloaded
`here <http://www.linuxnetworks.de/pdnsldap/bind2pdns-ldap>`__.

Updating the entries in the LDAP tree requires to make the dnsdomain2
schema known to the LDAP server. Unfortunately, both schemas (dnsdomain2
and dnszone) share the same record types and use the same OIDs so the
LDAP server can't use both schemas at the same time. The solution is to
add the `dnsdomain2
schema <http://www.linuxnetworks.de/pdnsldap/dnsdomain2.schema>`__ and
replace the dnszone schema by the `dnszone-migrate
schema <http://www.linuxnetworks.de/pdnsldap/dnszone-migrate.schema>`__.
After restarting the LDAP server attributes from both schemas can be
used and updating the objects in the LDAP tree using the LDIF file
generated from ``bind2pdns-ldap`` will work without errors.

Other name server
^^^^^^^^^^^^^^^^^

The easiest way for migrating DNS records is to use the output of a zone
transfer (AXFR). Save the output of the ``dig`` program provided by BIND
into a file and call ``zone2ldap`` with the file name as option to the
``--zone-file`` parameter. This will generate the appropriate ldif file,
which can be imported into the LDAP tree. The bash script except below
automates this:

.. code-block:: shell

    DNSSERVER=127.0.0.1
    DOMAINS="example.com 10.10.in-addr.arpa"

    for DOMAIN in $DOMAINS; do
      dig @$DNSSERVER $DOMAIN AXFR> $DOMAIN.zone;
      zone2ldap --zone-name=$DOMAIN --zone-file=$DOMAIN.zone> $DOMAIN.ldif;
    done

Optimization
------------

LDAP indices
^^^^^^^^^^^^

To improve performance, the LDAP server can maintain indices on certain
attributes. This leads to much faster searches for these type of
attributes.

The LDAP DNS backend mainly searches for values in ``associatedDomain``,
so maintaining an index (pres,eq,sub) on this attribute is a big
performance improvement:

::

    indexassociatedDomain pres,eq,sub

Furthermore, if ``ldap-method=strict`` is set, it uses the aRecord and
aAAARecord attribute for reverse mapping of IP addresses to names. To
maintain an index (pres,eq) on these attributes also improves
performance of the LDAP server:

::

    indexaAAARecord pres,eq
    indexaRecord pres,eq

All other attributes than associatedDomain, aRecord or aAAARecord are
only read if the object matches the specified criteria. Thus,
maintaining an index on these attributes is useless.

If the DNS-entries were added before adding these statements to
``slapd.conf``, the LDAP server will have to be stopped and
``slapindex`` should be used on the command line. This will generate the
indices for already existing attributes.

dNSTTL attribute
^^^^^^^^^^^^^^^^

Converting the string in the dNSTTL attribute to an integer is a time
consuming task. If no separate TTL value for each entry is requires, use
the :ref:`setting-default-ttl` parameter in
``pdns.conf`` instead. This will gain a 7% improvement in performance
for entries that aren't cached. A dNSTTL attribute can still be added to
entries that should have a different TTL than the default TTL

Access method
^^^^^^^^^^^^^

The method of accessing the entries in the directory affects the
performance too. By default, the "simple" method is used search for
entries by using their associatedDomain attribute. Alternatively, the
"tree" method can be used, whereby the search is done along the
directory tree, e.g. "host.example.com" is translated into
"dc=host,dc=example,dc=com,...". This requires the LDAP DNS subtree
layout to be 1:1 to the DNS tree, this will gain an additional 7%
performance improvement.

Troubleshooting
---------------

No reverse zone transfer
^^^^^^^^^^^^^^^^^^^^^^^^

The LDAP tree must contain a separate subtree of PTR records (e.g. for
1.1.10.10.in-addr.arpa) and ``ldap-method`` can't be set to "strict".

IPv6 reverse lookup doesn't work in strict mode
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For automatically generated reverse IPv6 records the aAAARecord entries
must follow two restrictions: They have to be fully expanded ("FFFF::1"
is not allowed and it must be "FFFF:0:0:0:0:0:0:1" instead) and they
must not contain leading zeros, e.g. an entry containing "002A" is
incorrect - use "2A" without zeros instead. These restrictions are due
to the fact that LDAP DNS AAAA entries are pure text and doesn't allow
searching by wild-cards.

Future
------

DNS notification support
^^^^^^^^^^^^^^^^^^^^^^^^

As soon as the LDAP server implementations begin to provide the features
of the LDAP client update protocol (LCUP, :rfc:`3928`), it will be possible
to support the DNS notification feature for the LDAP DNS backend in case
a record in the LDAP directory was changed.

SASL support
^^^^^^^^^^^^

Support for more authentication methods would be handy. Anyone
interested may `contribute <https://github.com/PowerDNS/pdns>`__.
