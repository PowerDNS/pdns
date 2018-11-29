.. _DNSRecord:

DNSRecord objects
^^^^^^^^^^^^^^^^^^^^^^^^^

A :class:`DNSRecord` object represents a record.
Creating a ``DNSRecord`` is done with the :func:`newDR`.

.. todo
   Add a lua example and some useful things to do with that.

Functions and methods of a ``DNSRecord``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. function:: newDR(name, type, ttl, content, place) -> DNSRecord

  Returns a new :class:`DNSRecord` object.

  :param DNSName name: The name to the new record
  :param string type: The type of the record
  :param int ttl: The TTL of the record
  :param string content: The content of the record
  :param int place: The place where the record is located (as an integer, see :class:`DNSRecord.place`)

.. class:: DNSRecord

  A ``DNSRecord`` object represents a DNS record.

  .. attribute:: DNSRecord.name

    The name of the record. A :class:`DNSName`.

  .. attribute:: DNSRecord.place

    The place where the record is located, you can use the following constants

    - `pdns.place.QUESTION` for the question section
    - `pdns.place.ANSWER` for the answer section
    - `pdns.place.AUTHORITY` for the authority section
    - `pdns.place.ADDITIONAL` for the additional section

  .. attribute:: DNSRecord.ttl

    The TTL of the record

  .. attribute:: DNSRecord.type

    The type of the record (as an integer). Can for example be compared to ``pdns.A``

  .. method:: DNSRecord:getContent() -> string

    Return a string representation of the record content

  .. method:: DNSRecord:getCA() -> ComboAddress

    If the record type is A or AAAA, a :class:`ComboAddress` representing the content is returned, nil otherwise

  .. method:: DNSRecord:changeContent(newcontent)

    Replace the record content with ``newcontent``.
    The type and class cannot be changed.

    :param str newcontent: The replacing content
