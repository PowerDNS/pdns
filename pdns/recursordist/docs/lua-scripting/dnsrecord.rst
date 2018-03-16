DNS Record
==========

DNS record objects are returned by :meth:`DNSQuestion:getRecords`.

.. class:: DNSRecord

  Represents a single DNS record.
  It has these attributes:

  .. attribute:: DNSRecord.name

    The name of the record. A :class:`DNSName`.

  .. attribute:: DNSRecord.place

    The place where the record is located,

    - 0 for the question section
    - 1 for the answer section
    - 2 for the authority section
    - 3 for the additional section

  .. attribute:: DNSRecord.ttl

    The TTL of the record

  .. attribute:: DNSRecord.type

    The type of the record (as an integer). Can for example be compared to ``pdns.A``.

  And the following methods:

  .. method:: DNSRecord:changeContent(newcontent)

    Replace the record content with ``newcontent``.
    The type and class cannot be changed.

    :param str newcontent: The replacing content

  .. method:: DNSRecord:getCA() -> ComboAddress

    If the record type is A or AAAA, a :class:`ComboAddress` representing the content is returned, nil otherwise.

  .. method:: DNSRecord:getContent() -> str

    Return a string representation of the record content.
