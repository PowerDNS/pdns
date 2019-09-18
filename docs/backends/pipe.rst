Pipe Backend
============

* Native: Yes
* Master: No
* Slave: No
* Superslave: No
* Autoserial: No
* Case: Depends
* DNSSEC: Partial, no delegation, no key storage
* Disabled data: No
* Comments: No
* Module name: pipe
* Launch name: ``pipe``

The PipeBackend allows for easy dynamic resolution based on a
'Coprocess' which can be written in any programming language that can
read a question on standard input and answer on standard output.

The number of distributor (backend) threads (``distributor-threads``) to start
per receiver thread is low by default. This can impact the performance if
you have latency-bound application as backend. You should increase the
number of ``distributor-threads`` in such cases. See :doc:`performance`.

The PipeBackend is primarily meant for allowing rapid development of new
backends without tight integration with PowerDNS. It allows end-users to
write PowerDNS backends in any language, a perl sample is provided. The
PipeBackend is also very well suited for dynamic resolution of queries.
Example applications include DNS based load balancing, geo-direction,
DNS-based failover with low TTLs.

.. note::
  The :doc:`Remote Backend <remote>` offers a superset of the functionality of the PipeBackend.

.. note::
  Please do read the :doc:`Backend Writer's guide <../appendices/backend-writers-guide>` carefully. The
  PipeBackend, like all other backends, must not do any DNS thinking, but
  answer all questions (INCLUDING THE ANY QUESTION) faithfully.
  Specifically, the queries that the PipeBackend receives will not
  correspond to the queries that arrived over DNS. So, a query for an AAAA
  record may turn into a backend query for an ANY record. There is nothing
  that can or should be done about this.

Configuration Parameters
------------------------

.. _setting-pipe-abi-version:

``pipe-abi-version``
^^^^^^^^^^^^^^^^^^^^

- Integer
- Default: 1

This is the version of the question format that is sent to the
co-process (:ref:`setting-pipe-command`) for the pipe backend.

If not set the default :ref:`setting-pipe-abi-version` is 1. When set to 2, the
local-ip-address field is added after the remote-ip-address, the
local-ip-address refers to the IP address the question was received on.
When set to 3, the real remote IP/subnet is added based on edns-subnet
support (this also requires enabling :ref:`setting-edns-subnet-processing`).
When set to 4 it sends zone name in AXFR request. See also :ref:`PipeBackend Protocol <pipebackend-protocol>` below.

.. _setting-pipe-command:

``pipe-command``
^^^^^^^^^^^^^^^^

- String
- Mandatory

Command to launch as backend or the path to a unix domain socket file.
The socket should already be open and listening before PowerDNS starts.

.. _setting-pipe-timeout:

``pipe-timeout``
^^^^^^^^^^^^^^^^

- Integer
- Default: 2000

Number of milliseconds to wait for an answer from the backend. If this
time is ever exceeded, the backend is declared dead and a new process is
spawned.

.. _setting-pipe-regex:

``pipe-regex``
^^^^^^^^^^^^^^

- String (a regular expression)

If set, only questions matching this regular expression are even sent to
the backend. This makes sure that most of PowerDNS does not slow down if
you deploy a slow backend. A query for 'www.powerdns.com' would be
presented to the regex as 'www.powerdns.com', a matching regex would be
``^www\.powerdns\.com$``. **Note**: to match the root domain, use a dot,
e.g. ``^\.$``

.. _pipebackend-protocol:

PipeBackend protocol
--------------------

Questions come in over a file descriptor, by default standard input.
Answers are sent out over another file descriptor, standard output by
default. Questions and answers are terminated by single newline (``\n``)
characters. Fields in lines must be separated by tab (``\t``)
characters.

Handshake
^^^^^^^^^

PowerDNS sends out ``HELO\t1``, indicating that it wants to speak the
protocol as defined in this document, version 1. For abi-version 2 or 3,
PowerDNS sends ``HELO\t2`` or ``HELO\t3``. A PowerDNS Coprocess must
then send out a banner, prefixed by ``OK\t``, indicating it launched
successfully. If it does not support the indicated version, it should
respond with ``FAIL``, but not exit. Suggested behaviour is to try and
read a further line, and wait to be terminated.

.. note::
  Fields are separated by a tab (``\t``) character,
  even though they are displayed with spaces in this document.

``Q``: Regular queries for data
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

The question format, for type Q questions.

pipe-abi-version = 1 [default]
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

::

    Q qname       qclass  qtype   id  remote-ip-address

pipe-abi-version = 2
~~~~~~~~~~~~~~~~~~~~

::

    Q   qname       qclass  qtype   id  remote-ip-address   local-ip-address

pipe-abi-version = 3
~~~~~~~~~~~~~~~~~~~~

::

    Q   qname       qclass  qtype   id  remote-ip-address   local-ip-address    edns-subnet-address

Fields are tab separated, and terminated with a single ``\n``. The
``remote-ip-address`` is the IP address of the nameserver asking the
question, the ``local-ip-address`` is the IP address on which the
question was received.

Type is the tag above, ``qname`` is the domain the question is about.
``qclass`` is always 'IN' currently, denoting an INternet question.
``qtype`` is the kind of information desired, the record type, like A,
CNAME or AAAA. ``id`` can be specified to help your backend find an
answer if the ``id`` is already known from an earlier query. You can
ignore it unless you want to support ``AXFR``.

``edns-subnet-address`` is the actual client subnet as provided via
edns-subnet support. Note that for the SOA query that precedes an AXFR,
edns-subnet is always set to 0.0.0.0/0.

**Note**: Queries for wildcard names should be answered literally,
without expansion. So, if a backend gets a question for
"\*.powerdns.com", it should only answer with data if there is an actual
"\*.powerdns.com" name.

**Note**: In some (broken) network setups, the ``remote-ip-address``
and/or ``local-ip-address``, when it is an IPv6 address, may be suffixed
with a ``%`` and the name of the network interface (e.g. ``%eth1``).
Keep this in mind when checking the IP addresses.

``AXFR``: List an entire zone
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

AXFR-queries look like this:

::

    AXFR    id  zone-name

The ``id`` is gathered from the answer to a SOA query. ``zone-name`` is
given in ABI version 4.

Answers
^^^^^^^

Each answer starts with a tag, possibly followed by a TAB and more data.

-  ``DATA``: Indicating a successful line of DATA.
-  ``END``: Indicating the end of an answer - no further data.
-  ``FAIL``: Indicating a lookup failure. Also serves as 'END'. No
   further data.
-  ``LOG``: For specifying things that should be logged. Can only be
   sent after a query and before an END line. After the tab, the message
   to be logged.

ABI version 1 and 2
~~~~~~~~~~~~~~~~~~~

So, letting it be known that there is no data consists of sending 'END'
without anything else. The answer format (for abi-version 1 and 2):

::

    DATA    qname       qclass  qtype   ttl id  content

Again, all fields are tab-separated.

``content`` is as specified in :doc:`../appendices/types`. For MX and SRV,
content consists of the priority, followed by a tab, followed by the
actual content.

A sample dialogue may look like this (note that in reality, almost all
queries will actually be for the ANY qtype):

::

    Q   www.example.org IN  CNAME   -1  203.0.113.210
    DATA    www.example.org IN  CNAME   3600    1 ws1.example.org
    END
    Q   ws1.example.org IN  CNAME   -1  203.0.113.210
    END
    Q   wd1.example.org IN  A   -1  203.0.113.210
    DATA    ws1.example.org IN  A   3600    1   192.0.2.4
    DATA    ws1.example.org IN  A   3600    1   192.0.2.5
    DATA    ws1.example.org IN  A   3600    1   192.0.2.6
    END

This would correspond to a remote webserver 203.0.113.210 wanting to
resolve the IP address of www.example.org, and PowerDNS traversing the
CNAMEs to find the IP addresses of ws1.example.org. Another dialogue
might be:

::

    Q   example.org     IN  SOA -1  203.0.113.210
    DATA    example.org     IN  SOA 86400   1 ahu.example.org ...
    END
    AXFR    1
    DATA    example.org     IN  SOA 86400   1 ahu.example.org ...
    DATA    example.org     IN  NS  86400   1 ns1.example.org
    DATA    example.org     IN  NS  86400   1 ns2.example.org
    DATA    ns1.example.org IN  A   86400   1 203.0.113.210
    DATA    ns2.example.org IN  A   86400   1 63.123.33.135
    .
    .
    END

This is a typical zone transfer.

ABI version 3 and higher
~~~~~~~~~~~~~~~~~~~~~~~~

For abi-version 3, DATA-responses get two extra fields:

::

    DATA    scopebits   auth    qname       qclass  qtype   ttl id  content

``scopebits`` indicates how many bits from the subnet provided in the
question (originally from edns-subnet) were used in determining this
answer. This can aid caching (although PowerDNS does not currently use
this value).

The ``auth`` field indicates whether this response is authoritative,
this is for DNSSEC. The ``auth`` field should be set to '1' for data for
which the zone itself is authoritative, which includes the SOA record
and its own NS records. The ``auth`` field should be 0 for NS records
which are used for delegation, and also for any glue (A, AAAA) records
present for this purpose. Do note that the DS record for a secure
delegation should be authoritative!

For abi-versions 1 and 2, the two new fields fall back to default
values. The default value for scopebits is 0. The default for auth is 1
(meaning authoritative).

Direct backend commands
^^^^^^^^^^^^^^^^^^^^^^^

With abi-version 5 you can use :doc:`backend-cmd <../dnssec/pdnsutil>` for
executing commands on your backend. PowerDNS will use the following
query/answer format:

::

    CMD     Whatever you wrote
    Answer goes here
    And can be multiple lines
    until we see
    END

Sample backends
---------------

ABI version 1
^^^^^^^^^^^^^

.. literalinclude:: ../../modules/pipebackend/backend.pl
  :language: perl

ABI version 3
^^^^^^^^^^^^^

.. literalinclude:: ../../modules/pipebackend/backend-v3.pl
  :language: perl

ABI version 5
^^^^^^^^^^^^^

.. literalinclude:: ../../modules/pipebackend/backend-v5.pl
  :language: perl
