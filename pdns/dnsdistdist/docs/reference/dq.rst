.. _DNSQuestion:

The DNSQuestion (``dq``) object
===============================

A DNSQuestion or ``dq`` object is available in several hooks and Lua actions.
This object contains details about the current state of the question.
This state can be modified from the various hooks.

.. class:: DNSQuestion

  The DNSQuestion object has several attributes, many of them read-only:

  .. attribute:: DNSQuestion.dh

    The :ref:`DNSHeader` of this query.

  .. attribute:: DNSQuestion.ecsOverride

    Whether an existing ECS value should be overridden, settable.

  .. attribute:: DNSQuestion.ecsPrefixLength

     The ECS prefix length to use, settable.

  .. attribute:: DNSQuestion.len

    The length of the data starting at :attr:`DNSQuestion.dh`, including any trailing bytes following the DNS message.

  .. attribute:: DNSQuestion.localaddr

    :ref:`ComboAddress` of the local bind this question was received on.

  .. attribute:: DNSQuestion.opcode

    Integer describing the OPCODE of the packet. Can be matched against :ref:`DNSOpcode`.

  .. attribute:: DNSQuestion.qclass

    QClass (as an unsigned integer) of this question.
    Can be compared against :ref:`DNSClass`.

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

    Whether the query was received over TCP.

  .. attribute:: DNSQuestion.useECS

    Whether to send ECS to the backend, settable.

  It also supports the following methods:

  .. method:: DNSQuestion:getDO() -> bool

    .. versionadded:: 1.2.0

    Get the value of the DNSSEC OK bit.

    :returns: true if the DO bit was set, false otherwise

  .. method:: DNSQuestion:getEDNSOptions() -> table

    .. versionadded:: 1.3.3

    Return the list of EDNS Options, if any.

    :returns: A table of EDNSOptionView objects, indexed on the ECS Option code

  .. method:: DNSQuestion:getHTTPHeaders() -> table

    .. versionadded:: 1.4.0

    Return the HTTP headers for a DoH query, as a table whose keys are the header names and values the header values.

    :returns: A table of HTTP headers

  .. method:: DNSQuestion:getHTTPHost() -> string

    .. versionadded:: 1.4.0

    Return the HTTP Host for a DoH query, which may or may not contain the port.

    :returns: The host of the DoH query

  .. method:: DNSQuestion:getHTTPPath() -> string

    .. versionadded:: 1.4.0

    Return the HTTP path for a DoH query.

    :returns: The path part of the DoH query URI

  .. method:: DNSQuestion:getHTTPQueryString() -> string

    .. versionadded:: 1.4.0

    Return the HTTP query string for a DoH query.

    :returns: The query string part of the DoH query URI

  .. method:: DNSQuestion:getHTTPScheme() -> string

    .. versionadded:: 1.4.0

    Return the HTTP scheme for a DoH query.

    :returns: The scheme of the DoH query, for example ''http'' or ''https''

  .. method:: DNSQuestion:getServerNameIndication() -> string

    .. versionadded:: 1.4.0

    Return the TLS Server Name Indication (SNI) value sent by the client over DoT or DoH, if any. See :func:`SNIRule`
    for more information, especially about the availability of SNI over DoH.

    :returns: A string containing the TLS SNI value, if any

  .. method:: DNSQuestion:getTag(key) -> string

    .. versionadded:: 1.2.0

    Get the value of a tag stored into the DNSQuestion object.

    :param string key: The tag's key
    :returns: The tag's value if it was set, an empty string otherwise

  .. method:: DNSQuestion:getTagArray() -> table

    .. versionadded:: 1.2.0

    Get all the tags stored into the DNSQuestion object.

    :returns: A table of tags, using strings as keys and values

  .. method:: DNSQuestion:getTrailingData() -> string

    .. versionadded:: 1.4.0

    Get all data following the DNS message.

    :returns: The trailing data as a null-safe string

  .. method:: DNSQuestion:sendTrap(reason)

    .. versionadded:: 1.2.0

    Send an SNMP trap.

    :param string reason: An optional string describing the reason why this trap was sent

  .. method:: DNSQuestion:setHTTPResponse(status, body, contentType="")

    .. versionadded:: 1.4.0

    Set the HTTP status code and content to immediately send back to the client.
    For HTTP redirects (3xx), the string supplied in ''body'' should be the URL to redirect to.
    For 200 responses, the value of the content type header can be specified via the ''contentType'' parameter.
    In order for the response to be sent, the QR bit should be set before returning and the function should return Action.HeaderModify.

    :param int status: The HTTP status code to return
    :param string body: The body of the HTTP response, or a URL if the status code is a redirect (3xx)
    :param string contentType: The HTTP Content-Type header to return for a 200 response, ignored otherwise. Default is ''application/dns-message''.

  .. method:: DNSQuestion:setTag(key, value)

    .. versionadded:: 1.2.0

    Set a tag into the DNSQuestion object.

    :param string key: The tag's key
    :param string value: The tag's value

  .. method:: DNSQuestion:setTagArray(tags)

    .. versionadded:: 1.2.0

    Set an array of tags into the DNSQuestion object.

    :param table tags: A table of tags, using strings as keys and values

  .. method:: DNSQuestion:setTrailingData(tail) -> bool

    .. versionadded:: 1.4.0

    Set the data following the DNS message, overwriting anything already present.

    :param string tail: The new data
    :returns: true if the operation succeeded, false otherwise

.. _DNSResponse:

DNSResponse object
==================

.. class:: DNSResponse

  This object has all the functions and members of a :ref:`DNSQuestion <DNSQuestion>` and some more

  .. method:: DNSResponse:editTTLs(func)

    The function ``func`` is invoked for every entry in the answer, authority and additional section.

    ``func`` points to a function with the following prototype: ``myFunc(section, qclass, qtype, ttl)``

    All parameters to ``func`` are integers:

    - ``section`` is the section in the packet and can be compared to :ref:`DNSSection`
    - ``qclass`` is the QClass of the record. Can be compared to :ref:`DNSClass`
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

  .. method:: DNSHeader:getRD() -> bool

    Get recursion desired flag.

  .. method:: DNSHeader:setRD(rd)

    Set recursion desired flag.

    :param bool rd: State of the RD flag

  .. method:: DNSHeader:setTC(tc)

    Set truncation flag (TC).

    :param bool tc: State of the TC flag

  .. method:: DNSHeader:setQR(qr)

    Set Query/Response flag.
    Setting QR to true means "This is an answer packet".

    :param bool qr: State of the QR flag

  .. method:: DNSHeader:getCD() -> bool

    Get checking disabled flag.

  .. method:: DNSHeader:setCD(cd)

    Set checking disabled flag.

    :param bool cd: State of the CD flag

.. _EDNSOptionView:

EDNSOptionView object
=====================

.. class:: EDNSOptionView

  .. versionadded:: 1.3.3

  An object that represents the values of a single EDNS option received in a query.

  .. method:: EDNSOptionView:count()

    The number of values for this EDNS option.

  .. method:: EDNSOptionView:getValues()

    Return a table of NULL-safe strings values for this EDNS option.
