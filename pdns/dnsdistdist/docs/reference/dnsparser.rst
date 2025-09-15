DNS Parser
==========

Since 1.8.0, dnsdist contains a limited DNS parser class that can be used to inspect
the content of DNS queries and responses in Lua.

The first step is to get the content of the DNS payload into a Lua string,
for example using :meth:`DNSQuestion:getContent`, or :meth:`DNSResponse:getContent`,
and then to create a :class:`DNSPacketOverlay` object:

.. code-block:: lua

  function dumpPacket(dq)
    local packet = dq:getContent()
    local overlay = newDNSPacketOverlay(packet)
    print(overlay.qname)
    print(overlay.qtype)
    print(overlay.qclass)
    local count = overlay:getRecordsCountInSection(DNSSection.Answer)
    print(count)
    for idx=0, count-1 do
      local record = overlay:getRecord(idx)
      print(record.name)
      print(record.type)
      print(record.class)
      print(record.ttl)
      print(record.place)
      print(record.contentLength)
      print(record.contentOffset)
    end
    return DNSAction.None
  end

  addAction(AllRule(), LuaAction(dumpPacket))


.. function:: newDNSPacketOverlay(packet) -> DNSPacketOverlay

  .. versionadded:: 1.8.0

  Returns a DNSPacketOverlay

  :param str packet: The DNS payload


.. function:: parseARecord(packet, record) -> ComboAddress

  .. versionadded:: 2.1.0

  Returns the address from a record, as a :ref:`ComboAddress`, if the record's type is A.
  Nil is returned otherwise.

  :param str packet: The DNS payload.
  :param DNSRecord record: The record to parse, obtained via :meth:`DNSPacketOverlay:getRecord`.


.. function:: parseAAAARecord(packet, record) -> ComboAddress

  .. versionadded:: 2.1.0

  Returns the address from a record, as a :ref:`ComboAddress`, if the record's type is AAAA.
  Nil is returned otherwise.

  :param str packet: The DNS payload.
  :param DNSRecord record: The record to parse, obtained via :meth:`DNSPacketOverlay:getRecord`.


.. function:: parseAddressRecord(packet, record) -> ComboAddress

  .. versionadded:: 2.1.0

  Returns the address from a record, as a :ref:`ComboAddress`, if the record's type is A or AAAA.
  Nil is returned otherwise.

  :param str packet: The DNS payload.
  :param DNSRecord record: The record to parse, obtained via :meth:`DNSPacketOverlay:getRecord`.


.. function:: parseCNAMERecord(packet, record) -> DNSName

  .. versionadded:: 2.1.0

  Returns the name from a record, as a :ref:`DNSName`, if the record's type is CNAME.
  Nil is returned otherwise.

  :param str packet: The DNS payload.
  :param DNSRecord record: The record to parse, obtained via :meth:`DNSPacketOverlay:getRecord`.

.. _DNSPacketOverlay:

DNSPacketOverlay
----------------

.. class:: DNSPacketOverlay

  .. versionadded:: 1.8.0

  The DNSPacketOverlay object has several attributes, all of them read-only:

  .. attribute:: DNSPacketOverlay.qname

    The qname of this packet, as a :ref:`DNSName`.

  .. attribute:: DNSPacketOverlay.qtype

    The type of the query in this packet.

  .. attribute:: DNSPacketOverlay.qclass

    The class of the query in this packet.

  .. attribute:: DNSPacketOverlay.dh

  It also supports the following methods:

  .. method:: DNSPacketOverlay:getRecordsCountInSection(section) -> int

    Returns the number of records in the ANSWER (1), AUTHORITY (2) and
    ADDITIONAL (3) :ref:`DNSSection` of this packet. The number of records in the
    QUESTION (0) is always set to 0, look at the dnsheader if you need
    the actual qdcount.

    :param int section: The section, see above

  .. method:: DNSPacketOverlay:getRecord(idx) -> DNSRecord

    Get the record at the requested position. The records in the
    QUESTION sections are not taken into account, so the first record
    in the answer section would be at position 0.

    :param int idx: The position of the requested record


.. _DNSRecord:

DNSRecord object
==================

.. class:: DNSRecord

  .. versionadded:: 1.8.0

  This object represents an unparsed DNS record, as returned by the :ref:`DNSPacketOverlay` class. It has several attributes, all of them read-only:

  .. attribute:: DNSRecord.name

    The name of this record, as a :ref:`DNSName`.

  .. attribute:: DNSRecord.type

    The type of this record.

  .. attribute:: DNSRecord.class

    The class of this record.

  .. attribute:: DNSRecord.ttl

    The TTL of this record.

  .. attribute:: DNSRecord.place

    The place (section) of this record.

  .. attribute:: DNSRecord.contentLength

    The length, in bytes, of the rdata content of this record.

  .. attribute:: DNSRecord.contentOffset

    The offset since the beginning of the DNS payload, in bytes, at which the
    rdata content of this record starts.
