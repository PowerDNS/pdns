% DNSSCOPE(1)
% Joerg Jungermann (jj+debian At borkum.net)
% September 2012

# NAME
**dnsscope** - A PowerDNS nameserver debugging tool

# SYNOPSIS
**dnsscope** [*OPTION*]... *INFILE*

# DESCRIPTION
**dnsscope** takes an *INFILE* in PCAP format. It generates some simple
statistics outputs these to STDOUT.

# OPTIONS
INFILE
:     Path to a PCAP file.

-h | --help
:    Show the help.

--rd
:    Only process packets in *INFILE* with the RD (Recursion Desired) flag set.
     By default, we process all DNS packets in *INFILE*.

--ipv4
:    Process IPv4 packets. On by default, disable with **--ipv4 false**.

--ipv6
:    Process IPv6 packets. On by default, disable with **--ipv6 false**.

--servfail-tree
:    Figure out subtrees that generate servfails.

-l | --load-stats
:    Emit per-second load statistics (questions, answers, outstanding).

-w | --write-failures *FILENAME*
:    Write weird packets to a PCAP file at *FILENAME*.

-v | --verbose
:    Be more verbose.

# SEE ALSO
pcap(3PCAP), tcpdump(8)
