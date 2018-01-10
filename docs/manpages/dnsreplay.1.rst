dnsreplay
=========

Synopsis
--------

:program:`dnsreplay` [*OPTION*]... *FILENAME* *ADDRESS* [*PORT*]

Description
-----------

This program takes recorded questions and answers and replays them to
the specified nameserver and reporting afterwards which percentage of
answers matched, were worse or better.

dnsreplay compares the answers and some other metrics with the actual
ones with those found in the dumpfile.

By default it only replay queries with recursion-desired flag set.

Options
-------

FILENAME
    is expected to be an PCAP file. The queries are send to the DNS
    server specified as *ADDRESS* and *PORT*.
ADDRESS
    IPv4 or IPv6 address of the nameserver to replay *FILENAME* to.
PORT
    if omitted, 53 will be used.

--help, -h               Show summary of options.
--ecs-mask <VAL>         When EDNS forwarding an IP address, mask out first octet with this value
--ecs-stamp <FLAG>       Add original IP address as EDNS Client Subnet Option when 
                         forwarding to reference server
--pcap-dns-port <VAL>    Look at packets from or to this port in the PCAP. Default is 53.
--packet-limit <NUM>     Stop after replaying *NUM* packets. Default for *NUM* is 0, which
                         means no limit.
--quiet <FLAG>           If *FLAG* is set to 1. dnsreplay will not be very noisy with its
                         output. This is the default.
--recursive <FLAG>       If *FLAG* is set to 1. dnsreplay will only replay queries with
                         recursion desired flag set. This is the default.
--speedup <FACTOR>       Replay queries with this speedup *FACTOR*. Default is 1.
--timeout-msec <MSEC>    Wait at least *MSEC* milliseconds for a reply. Default is 500.

Bugs
----

dnsreplay has no certain handling for timeouts. It handles around at
most 65536 outstanding answers.

See also
--------

pcap(3PCAP), tcpdump(8), dnswasher(1)
