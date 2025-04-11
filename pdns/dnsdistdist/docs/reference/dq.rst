.. _DNSQuestion:

The DNSQuestion (``dq``) object
===============================

A DNSQuestion or ``dq`` object is available in several hooks and Lua actions.
This object contains details about the current state of the question.
This state can be modified from the various hooks.

.. class:: DNSQuestion

  The DNSQuestion object has several attributes, many of them read-only:

  .. attribute:: DNSQuestion.deviceID

    .. versionadded:: 1.8.0

    The identifier of the remote device, which will be exported via ProtoBuf if set.

  .. attribute:: DNSQuestion.deviceName

    .. versionadded:: 1.8.0

    The name of the remote device, which will be exported via ProtoBuf if set.

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

  .. attribute:: DNSQuestion.pool

    .. versionadded:: 1.8.0

    The pool of servers to which this query will be routed.

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

  .. attribute:: DNSQuestion.requestorID

    .. versionadded:: 1.8.0

    The identifier of the requestor, which will be exported via ProtoBuf if set.

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

  .. method:: DNSQuestion::getElapsedUs -> double

     .. versionadded:: 1.9.8

     Return the amount of time that has elapsed since the query was received.

     :returns: A double indicating elapsed time in microseconds

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

  .. method:: DNSQuestion:getIncomingInterface() -> string

    .. versionadded:: 2.0.0

    Return the name of the network interface this query was received on, but only if the corresponding frontend
    has been bound to a specific network interface via the ``interface`` parameter to :func:`addLocal`, :func:`setLocal`,
    :func:`addTLSLocal`, :func:`addDOHLocal`, :func:`addDOQLocal` or :func:`AddDOH3Local`, or the ``interface`` parameter
    of a :ref:`frontend <yaml-settings-BindConfiguration>` when the YAML format is used. This is useful in Virtual Routing
    and Forwarding (VRF) environments where the destination IP address might not be enough to identify the VRF.

    :returns: The name of the network interface this query was received on, or an empty string.

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

  .. method:: DNSQuestion:changeName(newName) -> bool

    .. versionadded:: 1.8.0

    Change the qname of the current query in the DNS payload.
    The reverse operation will have to be done on the response to set it back to the initial name, or the client will be confused and likely drop the response.
    See :func:`DNSResponse:changeName`.
    Returns false on failure, true on success.

    :param DNSName newName: The new qname to use

  .. method:: DNSQuestion:sendTrap(reason)

    Send an SNMP trap.

    :param string reason: An optional string describing the reason why this trap was sent

  .. method:: DNSQuestion:setContent(data)

    .. versionadded:: 1.8.0

    Replace the whole DNS payload of the query with the supplied data. The new DNS payload must include the DNS header, whose ID will be adjusted to match the one of the existing query.
    For example, this replaces the whole DNS payload of queries for custom.async.tests.powerdns.com and type A, turning it them into ``FORMERR`` responses, including EDNS with the ``DNSSECOK`` bit set and a UDP payload size of 1232:

    .. code-block:: Lua

      function replaceQueryPayload(dq)
        local raw = '\000\000\128\129\000\001\000\000\000\000\000\001\006custom\005async\005tests\008powerdns\003com\000\000\001\000\001\000\000\041\002\000\000\000\128\000\000\\000'
        dq:setContent(raw)
        return DNSAction.Allow
      end
      addAction(AndRule({QTypeRule(DNSQType.A), QNameSuffixRule('custom.async.tests.powerdns.com')}), LuaAction(replaceQueryPayload))

    :param string data: The raw DNS payload

  .. method:: DNSQuestion:setEDNSOption(code, data)

    .. versionadded:: 1.8.0

    Add arbitrary EDNS option and data to the query. Any existing EDNS content with the same option code will be overwritten.

    :param int code: The EDNS option code
    :param string data: The EDNS option raw data

  .. method:: DNSQuestion:setExtendedDNSError(infoCode [, extraText])

    .. versionadded:: 1.9.0

      Set an Extended DNS Error status that will be added to the response corresponding to the current query.

    :param int infoCode: The EDNS Extended DNS Error code
    :param string extraText: The optional EDNS Extended DNS Error extra text

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

  .. method:: DNSQuestion:setRestartable()

    .. versionadded:: 1.8.0

    Make it possible to restart that query after receiving the response, for example to try a different pool of servers after receiving a SERVFAIL or a REFUSED response.
    Under the hood, this tells dnsdist to keep a copy of the initial query around so that we can send it a second time if needed. Copying the initial DNS payload has a small memory and CPU cost and thus is not done by default.
    See also :func:`DNSResponse:restart`.

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

  .. method:: DNSQuestion:spoof(ip|ips|raw|raws [, typeForAny])

    .. versionadded:: 1.6.0

    .. versionchanged:: 1.9.0
      Optional parameter ``typeForAny`` added.

    Forge a response with the specified record data as raw bytes. If you specify list of raws (it is assumed they match the query type), all will get spoofed in.

    :param ComboAddress ip: The `ComboAddress` to be spoofed, e.g. `newCA("192.0.2.1")`.
    :param table ComboAddresses ips: The `ComboAddress`es to be spoofed, e.g. `{ newCA("192.0.2.1"), newCA("192.0.2.2") }`.
    :param string raw: The raw string to be spoofed, e.g. `"\\192\\000\\002\\001"`.
    :param table raws: The raw strings to be spoofed, e.g. `{ "\\192\\000\\002\\001", "\\192\\000\\002\\002" }`.
    :param int typeForAny: The type to use for raw responses when the requested type is ``ANY``, as using ``ANY`` for the type of the response record would not make sense.

  .. method:: DNSQuestion:suspend(asyncID, queryID, timeoutMS) -> bool

    .. versionadded:: 1.8.0

    Suspend the processing for the current query, making it asynchronous. The query is then placed into memory, in a map called the Asynchronous Holder, until it is either resumed or the supplied timeout kicks in. The object is stored under a key composed of the tuple (`asyncID`, `queryID`) which is needed to retrieve it later, which can be done via :func:`getAsynchronousObject`.
    Note that the DNSQuestion object should NOT be accessed after successfully calling this method.
    Returns true on success and false on failure, indicating that the query has not been suspended and the normal processing will continue.

    :param int asyncID: A numeric identifier used to identify the suspended query for later retrieval. Valid values range from 0 to 65535, both included.
    :param int queryID: A numeric identifier used to identify the suspended query for later retrieval. This ID does not have to match the query ID present in the initial DNS header. A given (asyncID, queryID) tuple should be unique at a given time. Valid values range from 0 to 65535, both included.
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
  It also has additional methods:

  .. method:: DNSResponse.getSelectedBackend() -> Server

    .. versionadded:: 1.9.0

    Get the selected backend :class:`Server` or nil

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

  .. method:: DNSResponse:changeName(initialName) -> bool

    .. versionadded:: 1.8.0

    Change, in the DNS payload of the current response, the qname and the owner name of records to the supplied new name, if they are matching exactly the initial qname.
    This only makes if the reverse operation was performed on the query, or the client will be confused and likely drop the response.
    Note that only records whose owner name matches the qname in the initial response will be rewritten, and that only the owner name itself will be altered,
    not the content of the record rdata. For some records this might cause an issue with compression pointers contained in the payload, as they might
    no longer point to the correct position in the DNS payload. To prevent that, the records are checked against a list of supported record types,
    and the rewriting will not be performed if an unsupported type is present. As of 1.8.0 the list of supported types is:
    A, AAAA, DHCID, TXT, OPT, HINFO, DNSKEY, CDNSKEY, DS, CDS, DLV, SSHFP, KEY, CERT, TLSA, SMIMEA, OPENPGPKEY, NSEC, NSEC3, CSYNC, NSEC3PARAM, LOC, NID, L32, L64, EUI48, EUI64, URI, CAA, NS, PTR, CNAME, DNAME, RRSIG, MX, SOA, SRV
    Therefore this functionality only makes sense when the initial query is requesting a very simple type, like A or AAAA.

    See also :func:`DNSQuestion:changeName`.
    Returns false on failure, true on success.

    :param DNSName initialName: The initial qname

  .. method:: DNSResponse:restart()

    .. versionadded:: 1.8.0

    Discard the received response and restart the processing of the query. For this function to be usable, the query should have been made restartable first, via :func:`DNSQuestion:setRestartable`.
    For example, to restart the processing after selecting a different pool of servers:

    .. code-block:: Lua

      function makeQueryRestartable(dq)
        -- make it possible to restart that query later
        -- by keeping a copy of the initial DNS payload around
        dq:setRestartable()
        return DNSAction.None
      end
      function restartOnServFail(dr)
        -- if the query was SERVFAIL and not already tried on the restarted pool
        if dr.rcode == DNSRCode.SERVFAIL and dr.pool ~= 'restarted' then
          -- assign this query to a new pool
          dr.pool = 'restarted'
          -- discard the received response and
          -- restart the processing of the query
          dr:restart()
        end
        return DNSResponseAction.None
      end
      addAction(AllRule(), LuaAction(makeQueryRestartable))
      addResponseAction(AllRule(), LuaResponseAction(restartOnServFail))

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

  .. method:: DNSHeader:getTC() -> bool

    .. versionadded:: 1.8.1

    Get the TC flag.

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
    and sending the response out it it was. Otherwise do a cache-lookup: on a
    cache-hit, the response will be sent immediately. On a cache-miss,
    it means dnsdist will select a backend and send the query to the backend.
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
