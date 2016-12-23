% PDNS_SERVER(1)
% PowerDNS.COM BV
% December 2012

# NAME
**pdns_server** - The PowerDNS Authoritative Namserver

# SYNOPSIS
**pdns_server** [*OPTION*]

# DESCRIPTION
The PowerDNS Authoritative Server is a versatile nameserver which supports a
large number of backends. These backends can either be plain zone files or be
more dynamic in nature. Please see the online documentation for more
information.

# OPTIONS
See the online documentation for all options

--daemon={**yes**,**no**}
:    Indicate if the server should run in the background as a real daemon,
     or in the foreground.

--guardian={**yes**,**no**}
:    Run **pdns_server** inside a guardian. This guardian monitors the performance
     of the inner **pdns_server** instance. It is also this guardian that
     **pdns_control**(8) talks to.

--control-console
:    Run the server in a special monitor mode. This enables detailed logging
     and exposes the raw control socket.

--loglevel=*LEVEL*
:    Set the logging level.

--help
To view more options that are available use this program.

# SEE ALSO
pdns_control(1), pdnsutil(1), http://doc.powerdns.com/md/authoritative/
