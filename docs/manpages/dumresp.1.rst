dumresp
=======

Synopsis
--------

**dumresp** *LOCAL-ADDRESS* *LOCAL-PORT* *NUMBER-OF-PROCESSES*

Description
-----------

:program:`dumresp` accepts DNS packets on *LOCAL-ADDRESS*:*LOCAL-PORT* and
simply replies with the same query, with the QR bit set. When
*NUMBER-OF-PROCESSES* is set to anything but 1, :program:`dumresp` will spawn
*NUMBER-OF-PROCESSES* forks and use the SO\_REUSEPORT option to bind to
the port.

Options
-------

None

See also
--------

socket(7)
