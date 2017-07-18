calidns
=======

:program:`calidns` - A DNS recursor testing tool

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

--increment <NUM>        On every subsequent run, multiply the number of queries per second
                         by *NUM*. By default, this is 1.1.
--want-recursion         Set this flag to send queries with the Recursion Desired flag set.
