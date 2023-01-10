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
    Can be compared against the pre-defined :ref:`constants <DNSQType>` like ``DNSQType.A``, ``DNSQType.AAAA``.

  .. attribute:: DNSQuestion.remoteaddr

    :ref:`ComboAddress` of the remote client.

  .. attribute:: DNSQuestion.rcode

    RCode (as an unsigned integer) of this question.
    Can be compared against :ref:`DNSRCode`

  .. attribute:: DNSQuestion.size

    The total size of the buffer starting at :attr:`DNSQuestion.dh`.

  .. attribute:: DNSQuestion.skipCache

    Whether to skip cache lookup / storing the answer for this question, settable.

  .. attribute:: DNSQuestion.tempFailureTTL
  
    On a SERVFAIL or REFUSED from the backend, cache for this amount of seconds, settable.

  .. attribute:: DNSQuestion.tcp

    Whether the query was received over TCP.

  .. attribute:: DNSQuestion.useECS

    Whether to send ECS to the backend, settable.

  It also supports the following methods:

  .. method:: DNSQuestion:addProxyProtocolValue(type, value)

    .. versionadded:: 1.6.0

    Add a proxy protocol TLV entry of type ``type`` and ``value`` to the current query.

    :param int type: The type of the new value, ranging from 0 to 255 (both included)
    :param str value: The binary-safe value

  .. method:: DNSQuestion:getContent() -> str

    .. versionadded:: 1.8.0

    Get the content of the DNS packet as a string

  .. method:: DNSQuestion:getDO() -> bool

    Get the value of the DNSSEC OK bit.

    :returns: true if the DO bit was set, false otherwise

  .. method:: DNSQuestion:getEDNSOptions() -> table

    Return the list of EDNS Options, if any.

    :returns: A table of EDNSOptionView objects, indexed on the ECS Option code

  .. method:: DNSQuestion:getHTTPHeaders() -> table

    .. versionadded:: 1.4.0
    .. versionchanged:: 1.8.0
       see ``keepIncomingHeaders`` on :func:`addDOHLocal`

    Return the HTTP headers for a DoH query, as a table whose keys are the header names and values the header values.
    Since 1.8.0 it is necessary to set the ``keepIncomingHeaders`` option to true on :func:`addDOHLocal` to be able to use this method.

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

    :returns: The scheme of the DoH query, for example ``http`` or ``https``

  .. method:: DNSQuestion:getProtocol() -> string

    .. versionadded:: 1.7.0

    Return the transport protocol this query was received over, as a string. The possible values are:

    * "Do53 UDP"
    * "Do53 TCP"
    * "DNSCrypt UDP"
    * "DNSCrypt TCP"
    * "DNS over TLS"
    * "DNS over HTTPS"

    :returns: A string

  .. method:: DNSQuestion:getProxyProtocolValues() -> table

    .. versionadded:: 1.6.0

    Return a table of the Proxy Protocol values currently set for this query.

    :returns: A table whose keys are types and values are binary-safe strings

  .. method:: DNSQuestion:getQueryTime -> timespec

    .. versionadded:: 1.8.0

    Return the time at which the current query has been received, in whole seconds and nanoseconds since epoch, as a :ref:`timespec` object.

    :returns: A :ref:`timespec` object

  .. method:: DNSQuestion:getServerNameIndication() -> string

    .. versionadded:: 1.4.0

    Return the TLS Server Name Indication (SNI) value sent by the client over DoT or DoH, if any. See :func:`SNIRule`
    for more information, especially about the availability of SNI over DoH.

    :returns: A string containing the TLS SNI value, if any

  .. method:: DNSQuestion:getTag(key) -> string

    Get the value of a tag stored into the DNSQuestion object.

    :param string key: The tag's key
    :returns: The tag's value if it was set, an empty string otherwise

  .. method:: DNSQuestion:getTagArray() -> table

    Get all the tags stored into the DNSQuestion object.

    :returns: A table of tags, using strings as keys and values

  .. method:: DNSQuestion:getTrailingData() -> string

    .. versionadded:: 1.4.0

    Get all data following the DNS message.

    :returns: The trailing data as a null-safe string

  .. method:: DNSQuestion:sendTrap(reason)

    Send an SNMP trap.

    :param string reason: An optional string describing the reason why this trap was sent

  .. method:: DNSQuestion:setContent(data)

    .. versionadded:: 1.8.0

    Replace the DNS payload of the query with the supplied data, and adjusts the ID in the DNS header to the existing query.

    :param string data: The raw DNS payload

  .. method:: DNSQuestion:setEDNSOption(code, data)

    .. versionadded:: 1.8.0

    Add arbitrary EDNS option and data to the query. Any existing EDNS content with the same option code will be overwritten.

    :param int code: The EDNS option code
    :param string data: The EDNS option raw data

  .. method:: DNSQuestion:setHTTPResponse(status, body, contentType="")

    .. versionadded:: 1.4.0

    Set the HTTP status code and content to immediately send back to the client.
    For HTTP redirects (3xx), the string supplied in ``body`` should be the URL to redirect to.
    For 200 responses, the value of the content type header can be specified via the ``contentType`` parameter.
    In order for the response to be sent, the QR bit should be set before returning and the function should return Action.HeaderModify.

    :param int status: The HTTP status code to return
    :param string body: The body of the HTTP response, or a URL if the status code is a redirect (3xx)
    :param string contentType: The HTTP Content-Type header to return for a 200 response, ignored otherwise. Default is ``application/dns-message``.

  .. method:: DNSQuestion:setNegativeAndAdditionalSOA(nxd, zone, ttl, mname, rname, serial, refresh, retry, expire, minimum)

    .. versionadded:: 1.5.0

    Turn a question into a response, either a NXDOMAIN or a NODATA one based on ``nxd``, setting the QR bit to 1 and adding a SOA record in the additional section.

    :param bool nxd: Whether the answer is a NXDOMAIN (true) or a NODATA (false)
    :param string zone: The owner name for the SOA record
    :param int ttl: The TTL of the SOA record
    :param string mname: The mname of the SOA record
    :param string rname: The rname of the SOA record
    :param int serial: The value of the serial field in the SOA record
    :param int refresh: The value of the refresh field in the SOA record
    :param int retry: The value of the retry field in the SOA record
    :param int expire: The value of the expire field in the SOA record
    :param int minimum: The value of the minimum field in the SOA record

  .. method:: DNSQuestion:setProxyProtocolValues(values)

    .. versionadded:: 1.5.0

    Set the Proxy-Protocol Type-Length values to send to the backend along with this query.

    :param table values: A table of types and values to send, for example: ``{ [0x00] = "foo", [0x42] = "bar" }``. Note that the type must be an integer. Try to avoid these values: 0x01 - 0x05, 0x20 - 0x25, 0x30 as those are predefined in https://www.haproxy.org/download/2.3/doc/proxy-protocol.txt (search for `PP2_TYPE_ALPN`)

  .. method:: DNSQuestion:setTag(key, value)

    .. versionchanged:: 1.7.0
      Prior to 1.7.0 calling :func:`DNSQuestion:setTag` would not overwrite an existing tag value if already set.

    Set a tag into the DNSQuestion object. Overwrites the value if any already exists.
  
    :param string key: The tag's key
    :param string value: The tag's value

  .. method:: DNSQuestion:setTagArray(tags)

    .. versionchanged:: 1.7.0
      Prior to 1.7.0 calling :func:`DNSQuestion:setTagArray` would not overwrite existing tag values if already set.

    Set an array of tags into the DNSQuestion object. Overwrites the values if any already exist.
  
    :param table tags: A table of tags, using strings as keys and values

  .. method:: DNSQuestion:setTrailingData(tail) -> bool

    .. versionadded:: 1.4.0

    Set the data following the DNS message, overwriting anything already present.

    :param string tail: The new data
    :returns: true if the operation succeeded, false otherwise

  .. method:: DNSQuestion:spoof(ip|ips|raw|raws)

    .. versionadded:: 1.6.0

    Forge a response with the specified record data as raw bytes. If you specify list of raws (it is assumed they match the query type), all will get spoofed in.

    :param ComboAddress ip: The `ComboAddress` to be spoofed, e.g. `newCA("192.0.2.1")`.
    :param table ComboAddresses ips: The `ComboAddress`es to be spoofed, e.g. `{ newCA("192.0.2.1"), newCA("192.0.2.2") }`.
    :param string raw: The raw string to be spoofed, e.g. `"\\192\\000\\002\\001"`.
    :param table raws: The raw strings to be spoofed, e.g. `{ "\\192\\000\\002\\001", "\\192\\000\\002\\002" }`.

  .. method:: DNSQuestion:suspend(asyncID, queryID, timeoutMS) -> bool

    .. versionadded:: 1.8.0

    Suspend the processing for the current query, making it asynchronous. The query is then placed into memory, in a map called the Asynchronous Holder, until it is either resumed or the supplied timeout kicks in. The object is stored under a key composed of the tuple (`asyncID`, `queryID`) which is needed to retrieve it later, which can be done via :func:`getAsynchronousObject`.
    Note that the DNSQuestion object should NOT be accessed after successfully calling this method.
    Returns true on success and false on failure, indicating that the query has not been suspended and the normal processing will continue.

    :param int asyncID: A numeric identifier used to identify the suspended query for later retrieval
    :param int queryID: A numeric identifier used to identify the suspended query for later retrieval. This ID does not have to match the query ID present in the initial DNS header. A given (asyncID, queryID) tuple should be unique at a given time.
    :param int timeoutMS: The maximum duration this query will be kept in the asynchronous holder before being automatically resumed,  in milliseconds.

.. _DNSResponse:

DNSResponse object
==================

.. class:: DNSResponse

  This object has almost all the functions and members of a :ref:`DNSQuestion <DNSQuestion>`, except for the following ones which are not available on a response:

  - ``addProxyProtocolValue``
  - ``ecsOverride``
  - ``ecsPrefixLength``
  - ``getProxyProtocolValues``
  - ``getHTTPHeaders``
  - ``getHTTPHost``
  - ``getHTTPPath``
  - ``getHTTPQueryString``
  - ``setHTTPResponse``
  - ``getHTTPScheme``
  - ``getServerNameIndication``
  - ``setNegativeAndAdditionalSOA``
  - ``setProxyProtocolValues``
  - ``spoof``
  - ``tempFailureTTL``
  - ``useECS``

  If the value is really needed while the response is being processed, it is possible to set a tag while the query is processed, as tags will be passed to the response object.
  It also has one additional method:

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

  .. method:: DNSHeader:getAA() -> bool

    Get authoritative answer flag.

  .. method:: DNSHeader:getAD() -> bool

    Get authentic data flag.

  .. method:: DNSHeader:getCD() -> bool

    Get checking disabled flag.

  .. method:: DNSHeader:getID() -> int

    .. versionadded:: 1.8.0

    Get the ID.

  .. method:: DNSHeader:getRA() -> bool

    Get recursion available flag.

  .. method:: DNSHeader:getRD() -> bool

    Get recursion desired flag.

  .. method:: DNSHeader:setAA(aa)

    Set authoritative answer flag.

    :param bool aa: State of the AA flag

  .. method:: DNSHeader:setAD(ad)

    Set authentic data flag.

    :param bool ad: State of the AD flag

  .. method:: DNSHeader:setCD(cd)

    Set checking disabled flag.

    :param bool cd: State of the CD flag

  .. method:: DNSHeader:setQR(qr)

    Set Query/Response flag.
    Setting QR to true means "This is an answer packet".

    :param bool qr: State of the QR flag

  .. method:: DNSHeader:setRA(ra)

    Set recursion available flag.

    :param bool ra: State of the RA flag

  .. method:: DNSHeader:setRD(rd)

    Set recursion desired flag.

    :param bool rd: State of the RD flag

  .. method:: DNSHeader:setTC(tc)

    Set truncation flag (TC).

    :param bool tc: State of the TC flag

.. _EDNSOptionView:

EDNSOptionView object
=====================

.. class:: EDNSOptionView

  An object that represents the values of a single EDNS option received in a query.

  .. method:: EDNSOptionView:count()

    The number of values for this EDNS option.

  .. method:: EDNSOptionView:getValues()

    Return a table of NULL-safe strings values for this EDNS option.

.. _AsynchronousObject:

AsynchronousObject object
=========================

.. class:: AsynchronousObject

  .. versionadded:: 1.8.0

  This object holds a representation of a DNS query or response that has been suspended.

  .. method:: AsynchronousObject:drop() -> bool

    Drop that object immediately, without resuming it.
    Returns true on success, false on failure.

  .. method:: AsynchronousObject:getDQ() -> DNSQuestion

    Return a DNSQuestion object for the suspended object.

  .. method:: AsynchronousObject:getDR() -> DNSResponse

    Return a DNSResponse object for the suspended object.

  .. method:: AsynchronousObject:resume() -> bool

    Resume the processing of the suspended object.
    For a question, it means first checking whether it was turned into a response,
    and sending the response out it it was. Otherwise do a cache-lookup, select a
    backend and send the query to the backend.
    For a response, it means inserting into the cache if needed and sending the
    response to the backend.
    Note that the AsynchronousObject object should NOT be accessed after successfully calling this method.
    Returns true on success, false on failure.

  .. method:: AsynchronousObject:setRCode(rcode, clearRecords) -> bool

    Set the response code in the DNS header of the current object to the supplied value,
    optionally removing all records from the existing payload, if any.
    Returns true on success, false on failure.

    :param int code: The response code to set
    :param bool clearRecords: Whether to clear all records from the existing payload, if any

.. function:: getAsynchronousObject(asyncID, queryID) -> AsynchronousObject

  .. versionadded:: 1.8.0

  Retrieves an asynchronous object stored into the Asynchronous holder.

    :param int asyncID: A numeric identifier used to identify the query when it was suspended
    :param int queryID: A numeric identifier used to identify the query when it was suspended
