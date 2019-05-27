dumresp
=======

Synopsis
--------

**dumresp** *LOCAL-ADDRESS* *LOCAL-PORT* *NUMBER-OF-PROCESSES* [tcp]

Description
-----------

:program:`dumresp` accepts DNS packets on *LOCAL-ADDRESS*:*LOCAL-PORT* and
simply replies with the same query, with the QR bit set. When
*NUMBER-OF-PROCESSES* is set to anything but 1, :program:`dumresp` will spawn
*NUMBER-OF-PROCESSES* forks and use the SO\_REUSEPORT option to bind to
the port.

Options
-------

tcp: Whether to listen and accept TCP connections in addition to
UDP packets. Defaults to false.

See also
--------

socket(7)
