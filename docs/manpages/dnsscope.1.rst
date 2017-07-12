dnsscope
========

:program:`dnsscope` - A PowerDNS nameserver debugging tool

Synopsis
--------

:program:`dnsscope` [*OPTION*]... *INFILE*

Description
-----------

:program:`dnsscope` takes an *INFILE* in PCAP format. It generates some simple
statistics outputs these to STDOUT.

Options
-------

INFILE
    Path to a PCAP file.

-h, --help                             Show the help.
--rd                                   Only process packets in *INFILE* with the RD (Recursion Desired)
                                       flag set. By default, we process all DNS packets in *INFILE*.
--ipv4=<state>                         Process IPv4 packets. On by default, disable with **--ipv4 false**.
--ipv6=<state>                         Process IPv6 packets. On by default, disable with **--ipv6 false**.
--servfail-tree                        Figure out subtrees that generate servfails.
-l, --load-stats                       Emit per-second load statistics (questions, answers, outstanding).
-w <file>, --write-failures <file>     Write weird packets to a PCAP file at *FILENAME*.
-v, --verbose                          Be more verbose.

See also
--------

pcap(3PCAP), tcpdump(8)
