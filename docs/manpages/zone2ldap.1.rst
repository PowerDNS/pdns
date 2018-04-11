zone2ldap
=========

Synopsis
--------

:program:`zone2ldap` {**--named-conf=**\ *PATH*,\ **--zone-file=**\ *PATH* **--zone-name=**\ *NAME*} [*OPTION*]...

Description
-----------

:program:`zone2ldap` is a program that converts bind zonefiles to ldif format
which can be inserted to an LDAP server.
Optionally it can add PowerDNS specific LDAP attributes to manage the domains
with pdnsutil.

Options
-------

--help                          Show summary of options.
--basedn=<DN>                   Base DN to store objects below
--dnsttl                        Add dnsttl attribute to every entry
--domain-id                     ID of the first zone found, auto-incremented for each one
--layout=<layout>               How to arrange entries in the directory ("simple" or "tree")
--named-conf=<PATH>             Path to a Bind named.conf to parse
--resume                        Continue after errors
--verbose                       Verbose comments on operation
--zone-file=<PATH>              Zone file to parse
--zone-name=<NAME>              Specify a zone name if zone is set
--pdns-info                     Add the PowerDNS attributes to the SOA entry

See also
--------

pdns_server(1)
