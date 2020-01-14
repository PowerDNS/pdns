Protobuf Logging Reference
==========================

.. function:: newRemoteLogger(address [, timeout=2[, maxQueuedEntries=100[, reconnectWaitTime=1]]])

  Create a Remote Logger object, to use with :func:`RemoteLogAction` and :func:`RemoteLogResponseAction`.

  :param string address: An IP:PORT combination where the logger is listening
  :param int timeout: TCP connect timeout in seconds
  :param int maxQueuedEntries: Queue this many messages before dropping new ones (e.g. when the remote listener closes the connection)
  :param int reconnectWaitTime: Time in seconds between reconnection attempts

.. class:: DNSDistProtoBufMessage

  This object represents a single protobuf message as emitted by :program:`dnsdist`.

  .. method:: DNSDistProtoBufMessage:addResponseRR(name, type, class, ttl, blob)

    .. versionadded:: 1.2.0

    Add a response RR to the protobuf message.

    :param string name: The RR name.
    :param int type: The RR type.
    :param int class: The RR class.
    :param int ttl: The RR TTL.
    :param string blob: The RR binary content.

  .. method:: DNSDistProtoBufMessage:setBytes(bytes)

    Set the size of the query

    :param int bytes: Number of bytes in the query.

  .. method:: DNSDistProtoBufMessage:setEDNSSubnet(netmask)

    Set the EDNS Subnet to ``netmask``.

    :param string netmask: The netmask to set to.

  .. method:: DNSDistProtoBufMessage:setQueryTime(sec, usec)

    In a response message, set the time at which the query has been received.

    :param int sec: Unix timestamp when the query was received.
    :param int usec: The microsecond the query was received.

  .. method:: DNSDistProtoBufMessage:setQuestion(name, qtype, qclass)

    Set the question in the protobuf message.

    :param DNSName name: The qname of the question
    :param int qtype: The qtype of the question
    :param int qclass: The qclass of the question

  .. method:: DNSDistProtoBufMessage:setProtobufResponseType(sec, usec)

    .. versionadded:: 1.2.0

    Change the protobuf response type from a query to a response, and optionally set the query time.

    :param int sec: Optional query time in seconds.
    :param int usec: Optional query time in additional micro-seconds.

  .. method:: DNSDistProtoBufMessage:setRequestor(address [, port])

    .. versionchanged:: 1.5.0
      ``port`` optional parameter added.

    Set the requestor's address.

    :param ComboAddress address: The address to set to
    :param int port: The requestor source port

  .. method:: DNSDistProtoBufMessage:setRequestorFromString(address [, port])

    .. versionchanged:: 1.5.0
      ``port`` optional parameter added.

    Set the requestor's address from a string.

    :param string address: The address to set to
    :param int port: The requestor source port

  .. method:: DNSDistProtoBufMessage:setResponder(address [, port])

    .. versionchanged:: 1.5.0
      ``port`` optional parameter added.

    Set the responder's address.

    :param ComboAddress address: The address to set to
    :param int port: The responder port

  .. method:: DNSDistProtoBufMessage:setResponderFromString(address [, port])

    .. versionchanged:: 1.5.0
      ``port`` optional parameter added.

    Set the responder's address.

    :param string address: The address to set to
    :param int port: The responder port

  .. method:: DNSDistProtoBufMessage:setResponseCode(rcode)

    Set the response code of the query.

    :param int rcode: The response code of the answer

  .. method:: DNSDistProtoBufMessage:setServerIdentity(id)

    .. versionadded:: 1.3.3

    Set the server identify field.

    :param string id: The server ID

  .. method:: DNSDistProtoBufMessage:setTag(value)

    .. versionadded:: 1.2.0

    Add a tag to the list of tags.

    :param string value: The tag value

  .. method:: DNSDistProtoBufMessage:setTagArray(valueList)

    .. versionadded:: 1.2.0

    Add a list of tags.

    :param table tags: A list of tags as strings

  .. method:: DNSDistProtoBufMessage:setTime(sec, usec)

    Set the time at which the query or response has been received.

    :param int sec: Unix timestamp when the query was received.
    :param int usec: The microsecond the query was received.

  .. method:: DNSDistProtoBufMessage:toDebugString() -> string

    Return an string containing the content of the message
