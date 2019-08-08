dnsscope
========

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
-f, --filter-name=<domain>             Only process packets within this domain 
--full-histogram <msec>                Write out histogram with specified bin-size to 'full-histogram'
--log-histogram                        Write out a log-histogram of response times to 'log-histogram'
--no-servfail-stats                    Remove servfail responses from latency statistics
--servfail-tree                        Figure out subtrees that generate servfails.
--stats-dir <directory>                Drop statistics files in this directory. Defaults to ./
-l, --load-stats                       Emit per-second load statistics (questions, answers, outstanding).
-w <file>, --write-failures <file>     Write weird packets to a PCAP file at *FILENAME*.
-v, --verbose                          Be more verbose.

See also
--------

pcap(3PCAP), tcpdump(8)
