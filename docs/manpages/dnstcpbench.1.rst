dnstcpbench
===========

Synopsis
--------

:program:`dnstcpbench` [*OPTION*]... *REMOTE-ADDRESS* [*REMOTE-PORT*]

Description
-----------

:program:`dnstcpbench` reads DNS queries (by default from standard input) and
sends them out in parallel to a remote nameserver. By default TCP/IP is
used, but optionally, UDP is tried first, which allows for the
benchmarking of TCP/IP fallback.

The program reports both mean and median numbers for queries per second
and UDP and TCP latency. Each query only counts once, even if it is
tried over UDP first. This effectively means that passing '-u' can lower
query rates if many queries get shunted to TCP.

The input format is one query per line: qname single-space qtype. An
example::

  www.powerdns.com ANY

When benchmarking extended runs, it may be necessary to enable
TIME\_WAIT recycling, as TCP/IP port tuples may otherwise run out. On
Linux this is performed by running::

  echo 1 > /proc/sys/net/ipv4/tcp_tw_recycle

The equivalent for IPv6 is not known.

Options
-------

-f, <FILENAME>, --file <FILENAME>       *FILENAME* from which to read queries. Defaults to standard input if unspecified.
-h, --help                              Provide a helpful message.
--timeout-msec <MSEC>                   *MSEC* milliseconds to wait for an answer.
-u, --udp-first                         Attempt resolution via UDP first, only do TCP if truncated answer is received.
-v, --verbose                           Be wordy on what the program is doing.
--workers <NUM>                         Use *NUM* parallel worker threads.

*REMOTE-ADDRESS*: IPv4 or IPv6 to test against.

*REMOTE-PORT*: Port to test against, defaults to 53.

Bugs
----

Currently the timeout code does not actually perform non-blocking
connects or writes. So a slow connect or slow writes will still cause
low performance and delays.

Median queries per second statistics are reported as 0 for sub-second
runs.
