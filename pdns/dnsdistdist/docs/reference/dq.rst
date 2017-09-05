.. _DNSQuestion:

The DNSQuestion (``dq``) object
===============================

A DNSQuestion or ``dq`` object is available in several hooks and Lua actions.
This object contains details about the current state of the question.
This state can be modified from the various hooks.

The DNSQuestion object has several attributes, many of them read-only:

.. class:: DNSQuestion

.. attribute:: DNSQuestion.dh

  The :ref:`DNSHeader` of this query.

.. attribute:: DNSQuestion.ecsOverride

  Whether an existing ECS value should be overridden, settable.

.. attribute:: DNSQuestion.ecsPrefixLength

   The ECS prefix length to use, settable.

.. attribute:: DNSQuestion.len

  The length of the :attr:`qname <DNSQuestion.qname>`.

.. attribute:: DNSQuestion.localaddr

  :ref:`ComboAddress` of the local bind this question was received on.

.. attribute:: DNSQuestion.opcode

  Integer describing the OPCODE of the packet. Can be matched against :ref:`DNSOpcode`.

.. attribute:: DNSQuestion.qclass

  QClass (as an unsigned integer) of this question.
  Can be compared against :ref:`DNSQClass`.

.. attribute:: DNSQuestion.qname

  :class:`DNSName` of this question.

.. attribute:: DNSQuestion.qtype

  QType (as an unsigned integer) of this question.
  Can be compared against the pre-defined :ref:`constants <DNSQType>` like ``DNSQType.A``, DNSQType.AAAA``.

.. attribute:: DNSQuestion.remoteaddr

  :ref:`ComboAddress` of the remote client.

.. attribute:: DNSQuestion.rcode

  RCode (as an unsigned integer) of this question.
  Can be compared against :ref:`DNSRCode`

.. attribute:: DNSQuestion.size

  The total size of the buffer starting at :attr:`DNSQuestion.dh`.

.. attribute:: DNSQuestion.skipCache

  Whether to skip cache lookup / storing the answer for this question, settable.

.. attribute:: DNSQuestion.tcp

  Whether the query have been received over TCP.

.. attribute:: DNSQuestion.useECS

  Whether to send ECS to the backend, settable.

It also supports the following methods:

.. classmethod:: DNSQuestion:getDO() -> bool

  .. versionadded:: 1.2.0

  Get the value of the DNSSEC OK bit.

  :returns: true if the DO bit was set, false otherwise

.. classmethod:: DNSQuestion:getTag(key) -> string

  .. versionadded:: 1.2.0

  Get the value of a tag stored into the DNSQuestion object.

  :param string key: The tag's key
  :returns: A table of tags, using strings as keys and values

.. classmethod:: DNSQuestion:getTagArray() -> table

  .. versionadded:: 1.2.0

  Get all the tags stored into the DNSQuestion object.

  :returns: The tag's value if it was set, an empty string otherwise

.. classmethod:: DNSQuestion:sendTrap(reason)

  .. versionadded:: 1.2.0

  Send an SNMP trap.

  :param string reason: An optional string describing the reason why this trap was sent

.. classmethod:: DNSQuestion:setTag(key, value)

  .. versionadded:: 1.2.0

  Set a tag into the DNSQuestion object.

  :param string key: The tag's key
  :param string value: The tag's value

.. classmethod:: DNSQuestion:setTagArray(tags)

  .. versionadded:: 1.2.0

  Set an array of tags into the DNSQuestion object.

  :param table tags: A table of tags, using strings as keys and values

.. _DNSResponse:

DNSResponse object
==================

.. class:: DNSResponse

  This object has all the functions and members of a :ref:`DNSQuestion <DNSQuestion>` and some more

.. classmethod:: DNSResponse:editTTLs(func)

  The function ``func`` is invoked for every entry in the answer, authority and additional section.

  ``func`` points to a function with the following prototype: ``myFunc(section, qclass, qtype, ttl)``

  All parameters to ``func`` are integers:

  - ``section`` is the section in the packet and can be compared to :ref:`DNSSection`
  - ``qclass`` is the QClass of the record. Can be compared to :ref:`DNSQClass`
  - ``qtype`` is the QType of the record. Can be e.g. compared to ``DNSQType.A``, ``DNSQType.AAAA`` :ref:`constants <DNSQType>` and the like.
  - ``ttl`` is the current TTL

  This function must return an integer with the new TTL.
  Setting this TTL to 0 to leaves it unchanged

  :param string func: The function to call to edit TTLs.

.. _DNSHeader:

DNSHeader (``dh``) object
=========================

.. class:: DNSHeader

  This object holds a representation of a DNS packet's header.

.. classmethod:: DNSHeader:getRD() -> bool

  Get recursion desired flag.

.. classmethod:: DNSHeader:setRD(rd)

  Set recursion desired flag.

  :param bool rd: State of the RD flag

.. classmethod:: DNSHeader:setTC(tc)

  Set truncation flag (TC).

  :param bool tc: State of the TC flag

.. classmethod:: DNSHeader:setQR(qr)

  Set Query/Response flag.
  Setting QR to true means "This is an answer packet".

  :param bool qr: State of the QR flag

.. classmethod:: DNSHeader:getCD() -> bool

  Get checking disabled flag.

.. classmethod:: DNSHeader:setCD(cd)

  Set checking disabled flag.

  :param bool cd: State of the CD flag
