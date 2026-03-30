Protobuf Logging Reference
==========================

.. function:: newRemoteLogger(address [, timeout=2[, maxQueuedEntries=100[, reconnectWaitTime=1[, connectionCount=1]]]])

  .. versionchanged:: 2.0.0
    Added the optional ``connectionCount`` parameter.

  Create a Remote Logger object, to use with :func:`RemoteLogAction` and :func:`RemoteLogResponseAction`.

  :param string address: An IP:PORT combination where the logger is listening
  :param int timeout: TCP connect timeout in seconds
  :param int maxQueuedEntries: Queue this many messages before dropping new ones (e.g. when the remote listener closes the connection)
  :param int reconnectWaitTime: Time in seconds between reconnection attempts
  :param int connectionCount: Number of connections to open to the socket

.. class:: DNSDistProtoBufMessage

  This object represents a single protobuf message as emitted by :program:`dnsdist`.

  .. method:: addResponseRR(name, type, class, ttl, blob)

    Add a response RR to the protobuf message.

    :param string name: The RR name.
    :param int type: The RR type.
    :param int class: The RR class.
    :param int ttl: The RR TTL.
    :param string blob: The RR binary content.

  .. method:: setBytes(bytes)

    Set the size of the query

    :param int bytes: Number of bytes in the query.

  .. method:: setEDNSSubnet(netmask)

    Set the EDNS Subnet to ``netmask``.

    :param string netmask: The netmask to set to.

  .. method:: setQueryTime(sec, usec)

    In a response message, set the time at which the query has been received.

    :param int sec: Unix timestamp when the query was received.
    :param int usec: The microsecond the query was received.

  .. method:: setQuestion(name, qtype, qclass)

    Set the question in the protobuf message.

    :param DNSName name: The qname of the question
    :param int qtype: The qtype of the question
    :param int qclass: The qclass of the question

  .. method:: setProtobufResponseType(sec, usec)

    Change the protobuf response type from a query to a response, and optionally set the query time.

    :param int sec: Optional query time in seconds.
    :param int usec: Optional query time in additional micro-seconds.

  .. method:: setRequestor(address [, port])

    .. versionchanged:: 1.5.0
      ``port`` optional parameter added.

    Set the requestor's address.

    :param ComboAddress address: The address to set to
    :param int port: The requestor source port

  .. method:: setRequestorFromString(address [, port])

    .. versionchanged:: 1.5.0
      ``port`` optional parameter added.

    Set the requestor's address from a string.

    :param string address: The address to set to
    :param int port: The requestor source port

  .. method:: setResponder(address [, port])

    .. versionchanged:: 1.5.0
      ``port`` optional parameter added.

    Set the responder's address.

    :param ComboAddress address: The address to set to
    :param int port: The responder port

  .. method:: setResponderFromString(address [, port])

    .. versionchanged:: 1.5.0
      ``port`` optional parameter added.

    Set the responder's address.

    :param string address: The address to set to
    :param int port: The responder port

  .. method:: setResponseCode(rcode)

    Set the response code of the query.

    :param int rcode: The response code of the answer

  .. method:: setServerIdentity(id)

    Set the server identify field.

    :param string id: The server ID

  .. method:: setTag(value)

    Add a tag to the list of tags.

    :param string value: The tag value

  .. method:: setTagArray(valueList)

    Add a list of tags.

    :param table tags: A list of tags as strings

  .. method:: setTime(sec, usec)

    Set the time at which the query or response has been received.

    :param int sec: Unix timestamp when the query was received.
    :param int usec: The microsecond the query was received.

  .. method:: toDebugString() -> string

    Return a string containing the content of the message


Exporting tags
--------------

func:`RemoteLogAction` and :func:`RemoteLogResponseAction` can be configured to include internal tags in the protocol buffer messages that are exported, using the ``exportTags``/``export_tags`` options. The following example exports all internal tags using the special ``*`` value:

.. md-tab-set::

  .. md-tab-item:: YAML

    .. code-block:: yaml

      remote_logging:
        protobuf_loggers:
          - name: "pblog"
            address: "127.0.0.1:5301"
      query_rules:
        - name: Export queries including internal tags
          selector:
            type: All
          action:
            type: RemoteLog
            logger_name: "pblog"
            export_tags: "*"

  .. md-tab-item:: Lua

    .. code-block:: lua

      rl = newRemoteLogger('127.0.0.1:5301')
      addAction(AllRule(), RemoteLogAction(rl, nil, {exportTags='*'}))


The ``exportTagsPrefixes``/``export_tags_prefixes`` options can also be used to export all tags whose keys start with a given prefix, and ``exportTagsStripPrefixes``/``export_tags_strip_prefixes`` to remove the specified prefix from the key before inserting into the message. The following example exports all internal tags starting with ``pdns-`` and removes the prefix from the key before adding them to the protocol buffer message:

.. md-tab-set::

  .. md-tab-item:: YAML

    .. code-block:: yaml

      remote_logging:
        protobuf_loggers:
          - name: "pblog"
            address: "127.0.0.1:5301"
      query_rules:
        - name: Export queries including internal tags
          selector:
            type: All
          action:
            type: RemoteLog
            logger_name: "pblog"
            export_tags_prefixes:
              - "pdns-"
            export_tags_strip_prefixes: true

  .. md-tab-item:: Lua

    .. code-block:: lua

      rl = newRemoteLogger('127.0.0.1:5301')
      addAction(AllRule(), RemoteLogAction(rl, nil, {exportTagsPrefixes='pdns-', exportTagsStripPrefixes=true}))
