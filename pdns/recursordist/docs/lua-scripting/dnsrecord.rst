DNS Record
==========

DNS record objects are returned by :meth:`DNSQuestion:getRecords`.

.. class:: DNSRecord

  Represents a single DNS record.

.. attribute:: DNSRecord.name -> DNSName

  The name of the record.

.. attribute:: DNSRecord.place -> int

  The place where the record is located,
  - 1 for the answer section
  - 2 for the authority section
  - 3 for the additional section

.. attribute:: DNSRecord.ttl -> int

  The TTL of the record

.. attribute:: DNSRecord.type -> int

  The type of the record, for example pdns.A

.. classmethod:: DNSRecord:changeContent(newcontent)

  Replace the record content with ``newcontent``.
  The type and class cannot be changed.

  :param str newcontent: The replacing content

.. classmethod:: DNSRecord:getCA() -> ComboAddress

  If the record type is A or AAAA, a :class:`ComboAddress` representing the content is returned, nil otherwise.

.. classmethod:: DNSRecord:getContent() -> str

  Return a string representation of the record content.
