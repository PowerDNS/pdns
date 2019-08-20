zone2ldap
=========

Synopsis
--------

:program:`zone2ldap` {**--named-conf=**\ *PATH*,\ **--zone-file=**\ *PATH* **--zone-name=**\ *NAME*} [*OPTION*]...

Description
-----------

:program:`zone2ldap` is a program that converts BIND zonefiles to ldif format
which can inserted to an LDAP server.

Options
-------

--help                          Show summary of options.
--basedn=<DN>                   Base DN to store objects below
--dnsttl                        Add dnsttl attribute to every entry
--layout=<layout>               How to arrange entries in the directory ("simple" or "tree")
--named-conf=<PATH>             Path to a BIND named.conf to parse
--resume                        Continue after errors
--verbose                       Verbose comments on operation
--zone-file=<PATH>              Zone file to parse
--zone-name=<NAME>              Specify a zone name if zone is set

See also
--------

pdns_server(1)
