% DNSDIST(1)
% PowerDNS.com BV
% 2013 - 2016

# NAME
**dnsdist** - tool to balance DNS queries over downstream servers

# SYNOPSIS
dnsdist [*OPTION*]... *ADDRESS*...

# DESCRIPTION
**dnsdist** receives DNS queries and relays them to one or more downstream
servers. It subsequently sends back responses to the original requestor.

dnsdist operates over TCP and UDP, and strives to deliver very high
performance over both.

Currently, queries are sent to the downstream server with the least
outstanding queries. This effectively implies load balancing, making sure
that slower servers get less queries.

If a reply has not come in after a few seconds, it is removed from the
queue, but in the short term, timeouts do cause a server to get less
traffic.

IPv4 and IPv6 operation can be mixed and matched, in other words, queries
coming in over IPv6 could be forwarded to IPv4 and vice versa.

**dnsdist** is scriptable in Lua, see the dnsdist documentation for more
information on this.

# SCOPE
dnsdist does not 'think' about DNS queries, it restricts itself to measuring
response times and error codes and routing questions accordingly. It comes with 
a very high performance packet-cache.

The goal for dnsdist is to remain simple. If more powerful loadbalancing is
required, dedicated hardware or software is recommended. Linux Virtual
Server for example is often mentioned.

# OPTIONS
-a,--acl *NETMASK*
:    Add *NETMASK* to the ACL.

-C,--config *FILE*
:    Load configuration from *FILE*.

--check-config
:    Test the configuration file (which may be set with **--config** or **-C**)
     for errors. dnsdist will show the errors and exit with a non-zero exit-code
     when errors are found.

-c,--client [*ADDRESS*[:*PORT*]]
:    Operate as a client, connect to dnsdist. This will read the dnsdist configuration
     for the **controlSocket** statement and connect to it. When *ADDRESS* (with
     optional *PORT*) is set, dnsdist will connect to that instead.

-k,--setkey *KEY*
:    When operating as a client(**-c**, **--client**), use *KEY* as shared secret
     to connect to dnsdist. This should be the same key that is used on the
     server (set with **setKey()**). Note that this will leak the key into your
     shell's history. Only available when dnsdist is compiled with libsodium support.

-d,--daemon
:    Operate as a daemon.

-e,--execute *CMD*
:    Connect to dnsdist and execute *CMD*.

-h,--help
:    Display a helpful message and exit.

-l,--local *ADDRESS*
:    Bind to *ADDRESS*, Supply as many addresses (using multiple **--local**
     statements) to listen on as required. Specify IPv4 as 0.0.0.0:53 and IPv6
     as [::]:53.

--supervised
:    Run in foreground, but do not spawn a console. Use this switch to run
     dnsdist inside a supervisor (use with e.g. systemd and daemontools).

--disable-syslog
:    Disable logging to syslog. Use this when running inside a supervisor that
     handles logging (like systemd). Do not use in combination with **--daemon**.

-p,--pidfile *FILE*
:    Write a pidfile to *FILE*, works only with **--daemon**.

-u,--uid *UID*
:    Change the process user to *UID* after binding sockets. *UID* can be a name
     or number.

-g,--gid *GID*
:    Change the process group to *GID* after binding sockets. *GID* Can be a
     name or number.

-V,--version
:    Show the dnsdist version and exit.

-v,--verbose
:    Be verbose.

ADDRESS
:    Any number of downstream DNS servers, in the same syntax as used with
     **--local**. If the port is not specified, 53 is used.

# BUGS
Right now, the TCP support has some rather arbitrary limits.

# RESOURCES
Website: https://dnsdist.org
