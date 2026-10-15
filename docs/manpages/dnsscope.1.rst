dnsscope
========

Synopsis
--------

:program:`dnsscope` [OPTION]... <INFILE>

Description
-----------

:program:`dnsscope` takes an *INFILE* in PCAP format. It generates some simple
statistics outputs these to STDOUT.

Options
-------

.. option:: INFILE

   Path to a PCAP file.

.. option:: -h, --help

   Show the help.

.. option:: --rd

   Only process packets in *INFILE* with the RD (Recursion Desired)
   flag set. By default, we process all DNS packets in *INFILE*.

.. option:: --ipv4=<STATE>

   Process IPv4 packets. On by default, disable with ``--ipv4 false``.

.. option:: --ipv6=<STATE>

   Process IPv6 packets. On by default, disable with ``--ipv6 false``.

.. option:: -f <DOMAIN>, --filter-name=<DOMAIN>

   Only process packets within this domain 

.. option:: --full-histogram <MSEC>

   Write out histogram with specified bin-size to 'full-histogram'

.. option:: --log-histogram

   Write out a log-histogram of response times to 'log-histogram'

.. option:: --no-servfail-stats

   Remove servfail responses from latency statistics

.. option:: --port <PORT>

   The source and destination port to consider. Default is looking at packets from and to ports 53 and 5300.

.. option:: --servfail-tree

   Figure out subtrees that generate servfails.

.. option:: --stats-dir <DIRECTORY>

   Drop statistics files in this directory. Defaults to ``./``.

.. option:: -l, --load-stats

   Emit per-second load statistics (questions, answers, outstanding).

.. option:: -w <FILE>, --write-failures <FILE>

   Write weird packets to a PCAP file at *FILE*.

.. option:: -v, --verbose

   Be more verbose.

See also
--------

pcap(3PCAP), tcpdump(8)
