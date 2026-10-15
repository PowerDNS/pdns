sdig
====

Synopsis
--------

:program:`sdig` <IP-ADDRESS-OR-DOH-URL> <PORT> <QNAME> <QTYPE> [OPTION]...

Description
-----------

:program:`sdig` sends a DNS query to *IP-ADDRESS-OR-DOH-URL* on port *PORT* and displays the answer in a formatted way.
If the address starts with an ``h``, it is assumed to be a DoH endpoint, and *PORT* is ignored.
If qname and qtype are both ``-`` and tcp is used, multiple lines are read from stdin, where each line contains a qname and a type.
If the address is ``stdin``, a DNS packet is read from stdin instead of from the network, and *PORT* is ignored.
All input is literal and case-sensitive.
Queries need option ``recurse`` to expect a resource record reply if the query target is not known to be the authoritative server for that record.

Options
-------

These options can be added to the commandline in any order.

.. option:: class <CLASSNUM>

    Send the query in the numbered class (like 3 for CHAOS) instead of the default 1 (for IN).

.. option:: dnssec

    Set the DO bit to request DNSSEC information.

.. option:: ednssubnet <SUBNET>

    Send *SUBNET* in the edns-client-subnet option. If this option is not set, no edns-client-subnet option is set in the query.

.. option:: hidesoadetails

    Don't show the SOA serial in the response.

.. option:: hidettl

    Replace TTLs with ``[ttl]`` in the response.

.. option:: proxy <TCP_OR_UDP> <SRC> <DST>

    Wrap query in PROXYv2 protocol with these parameters. The first parameter accepts 0 for UDP and 1 for TCP. The second and third take IP addresses and port.

.. option:: recurse

    Set the RD bit in the question.

.. option:: showflags

    Show the NSEC3 flags in the response (they are hidden by default).

.. option:: dumpluaraw

    Display record contents in a form suitable for dnsdist's ``SpoofRawAction``.

.. option:: tcp

    Use TCP instead of UDP to send the query.

.. option:: dot

    use DoT instead of UDP to send a query. Implies tcp.

.. option:: insecure

    when using DoT, do not validate the server certificate.

.. option:: fastOpen

    when using TCP or, DoT, enable TCP Fast Open

.. option:: subjectName <NAME>

    when using DoT, verify the server certificate is issued for *NAME*. The ``openssl`` provider will accept an empty name and still
    make sure the certificate is issued by a trusted CA, ``gnutls`` will only do the validation if a name is given.
    Default is the empty name. Also, note that older provide libraries might not validate at all.

.. option:: caStore <FILE>

    when using DoT, read the trusted CA certificates from *FILE*. Default is to use the system provided CA store.

.. option:: tlsProvider <NAME>

    when using DoT, use TLS provider *NAME*. Currently supported (if compiled in): ``openssl`` and ``gnutls``. Default is ``openssl`` if available.

.. option:: opcode <OPNUM>

    Use opcode *OPNUM* instead of 0 (Query). For example, ``sdig 192.0.2.1 53 example.com SOA opcode 4`` sends a ``NOTIFY``.

.. option:: cookie <COOKIE>

    if *COOKIE* is ``-`` send a random client cookie. Otherwise, send the given cookie, which should be a hex string received from a server earlier.

.. option:: traceid <TRACEID>

    include a TraceID and an empty SpanID value into the EDNS data. If *TRACEID* is ``-``, a random TraceID is generated; otherwise, it is a hex string.
    
Examples
--------

Simple queries to local resolvers::

    sdig 127.0.0.1 53 example.com AAAA recurse

    sdig ::1 53 example.com A recurse

Query to a DNS-over-HTTPS server requesting dnssec and recursion::

    sdig https://dns.example.net/dns-query 443 example.com A dnssec recurse
