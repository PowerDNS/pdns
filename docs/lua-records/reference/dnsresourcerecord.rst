.. _DNSResourceRecord:

DNSResourceRecord objects
^^^^^^^^^^^^^^^^^^^^^^^^^

A :class:`DNSResourceRecord` object represents a resource record in the DNS.
Creating a ``DNSResourceRecord`` is done with the :func:`newDRR`.

.. todo
   Add a lua example and some useful things to do with that.

Functions and methods of a ``DNSResourceRecord``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. function:: newDRR(name, type, ttl, content[, domainId[, auth]]) -> DNSResourceRecord

  Returns a new :class:`DNSResourceRecord` object.
  .. todo describe the auth param

  :param DNSName name: The name to the new record
  :param string type: The name to create a DNSName for
  :param int ttl: The TTL of the record
  :param string content: The content of the record
  :param int domainId: The optional domain ID of the zone the record belongs to
  :param int auth: ?

  .. todo complete LUA example bellow
  .. code-block:: lua

    name = newDN("www.example.org.")
    rr = new DRR(name, "IN", 3600, )

.. class:: DNSResourceRecord

  A ``DNSResourceRecord`` object represents a DNS record.

  .. method:: DNSResourceRecord:toString() -> string

    Returns the full content of the record as a string

  .. method:: DNSResourceRecord:qname() -> DNSName

    Returns the name of the record

  .. method:: DNSResourceRecord:wildcardName() -> DNSName

    Returns the wildcard name of the record the record was matched against

  .. method:: DNSResourceRecord:content() -> string

    Returns what the record points to

  .. method:: DNSResourceRecord:lastModified() -> int

    If unzero, last time this record was changed

  .. method:: DNSResourceRecord:ttl() -> int

    TTL (Time To Live) of this record

  .. method:: DNSResourceRecord:signttl() -> int

    If non-zero, TTL that will be used in the RRSIG of the record

  .. method:: DNSResourceRecord:domainId() -> int

    Backend related domain ID of the zone the record belongs to

  .. method:: DNSResourceRecord:qtype() -> int

    Type of the record (A, CNAME, MX, ...)

  .. method:: DNSResourceRecord:qclass() -> int

    Class of the record (IN, CH, ...)

  .. method:: DNSResourceRecord:scopeMask() -> int

    .. todo

  .. method:: DNSResourceRecord:auth() -> bool

    .. auth

  .. method:: DNSResourceRecord:disabled() -> bool

    .. todo
