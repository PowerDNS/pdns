.. _DNSHeader:

DNSHeader (``dh``) object
^^^^^^^^^^^^^^^^^^^^^^^^^

.. class:: DNSHeader

  This object holds a representation of a DNS packet's header.

  .. method:: DNSHeader:getRD() -> bool

    Get recursion desired flag.

  .. method:: DNSHeader:getCD() -> bool

    Get checking disabled flag.

  .. method:: DNSHeader:getID() -> bool

    Get header's ID

  .. method:: DNSHeader:getTC() -> bool

    Truncated message bit

  .. method:: DNSHeader:getRA() -> bool

    Recursion available

  .. method:: DNSHeader:getAD() -> bool

    Authenticated data from named

  .. method:: DNSHeader:getAA() -> bool

    Authoritative answer

  .. method:: DNSHeader:getRCODE() -> int

    Response code

  .. method:: DNSHeader:getOPCODE() -> int

    Purpose of message

  .. method:: DNSHeader:getQDCOUNT() -> int

    Number of question entries

  .. method:: DNSHeader:getANCOUNT() -> int

    Number of answer entries

  .. method:: DNSHeader:getNSCOUNT() -> int

    Number of authority entries

  .. method:: DNSHeader:getARCOUNT() -> int

    Number of resource entries
