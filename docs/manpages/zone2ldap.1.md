% ZONE2LDAP(1)
% Matthijs Möhlmann <matthijs@cacholong.nl>
% November 2004

# NAME
**zone2ldap** - convert zonefiles to ldif

# SYNOPSIS
**zone2ldap** {**--named-conf=***PATH*,**--zone-file=***PATH*
**--zone-name=***NAME*} [*OPTION*]...

# DESCRIPTION
**zone2ldap** is a program that converts bind zonefiles to ldif format which can
inserted to an LDAP server.
Optionally it can add PowerDNS specific LDAP attributes to manage the domains
with pdnsutil.

# OPTIONS
--help
:    Show summary of options.

--basedn=*DN*
:    Base DN to store objects below

--domainid=*ID*
:    The ID of the first zone found, incremented by one for each zone in the
:    current source. This option only has an effect when used with --pdns-info.
:    Defaults to 1.

--dnsttl
:    Add dnsttl attribute to every entry

--layout={**simple,tree**}
:    How to arrange entries in the directory (simple or as tree)

--named-conf=*PATH*
:    Path to a Bind 8 named.conf to parse

--pdns-info
:    Add the PowerDNS attributes to the SOA LDAP entry. The schema provided
:    in pdns-domaininfo.schema must be loaded for this to work.

--resume
:    Continue after errors

--verbose
:    verbose comments on operation

--zone-file=*PATH*
:    Zone file to parse

--zone-name=*NAME*
:    Specify a zone name if zone is set

# SEE ALSO
pdns_server(1)
