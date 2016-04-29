% CALIDNS(1)
% PowerDNS.com BV
% April 2016

# NAME
**calidns** - A DNS recursor testing tool

# SYNOPSIS
**calidns** *QUERY_FILE* *DESTINATION* *INITIAL_QPS* *HITRATE*

# DESCRIPTION
**calidns** reads queries from *QUERY_FILE* and sends them as a recursive query to
*DESTINATION* (an IPv4 or IPv6 address, optionally with a port number), starting
at INITIAL_QPS queries per second and aims to have a cache hitrate of *HITRATE*
percent.

It will then try to determine the maximum amount of queries per second the recursor
can handle with the aforementioned *HITRATE*.

# QUERY_FILE format
The format of the *QUERY_FILE* is very simple, it should contain "QNAME<space>QTYPE"
tuples, one per line. For example:

powerdns.com A
powerdns.com AAAA
google.com A

This is similar to Alexa top 1 million list.

# OPTIONS
None
