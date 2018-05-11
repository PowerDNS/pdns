calidns
=======

Synopsis
--------

:program:`calidns` [*OPTIONS*] *QUERY\_FILE* *DESTINATION* *INITIAL_QPS* *HITRATE*

Description
-----------

:program:`calidns` reads queries from *QUERY_FILE* and sends them as a
recursive query to *DESTINATION* (an IPv4 or IPv6 address, optionally
with a port number), starting at INITIAL_QPS queries per second and
aims to have a cache hitrate of *HITRATE* percent.

It will then try to determine the maximum amount of queries per second
the recursor can handle with the aforementioned *HITRATE*.

QUERY_FILE format
------------------

The format of the *QUERY_FILE* is very simple, it should contain
"QNAME QTYPE" tuples, one per line. For example::

  powerdns.com A
  powerdns.com AAAA
  google.com A

This is similar to Alexa top 1 million list.

Options
-------

--ecs <SUBNET>                 Add EDNS Client Subnet option to outgoing queries using random
                               addresses from the specified *SUBNET* range (IPv4 only).
--ecs-from-file                Read IP or subnet values from the query file and add them as EDNS
                               Client Subnet option to outgoing queries.
--increment <NUM>              On every subsequent run, multiply the number of queries per second
                               by *NUM*. By default, this is 1.1.
--maximum-qps <NUM>            Stop incrementing once this rate has been reached, to provide a
                               stable load.
--minimum-success-rate <NUM>   Stop the test as soon as the success rate drops below this value,
                               in percent.
--plot-file <FILE>             Write results to the specified file.
--quiet                        Whether to run quietly, outputting only the maximum QPS reached.
                               This option is mostly useful when used with --minimum-success-rate.
--want-recursion               Set this flag to send queries with the Recursion Desired flag set.
