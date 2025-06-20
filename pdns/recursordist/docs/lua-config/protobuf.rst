Logging DNS messages with Protocol Buffers
==========================================
The PowerDNS Recursor has the ability to emit a stream of protocol buffers messages over TCP, containing information about queries, answers and policy decisions.

Messages contain the IP address of the client initiating the query, the one on which the message was received, whether it was received over UDP or TCP, a timestamp and the qname, qtype and qclass of the question.
In addition, messages related to responses contain the name, type, class and rdata of A, AAAA and CNAME records present in the response, as well as the response code.

Finally, if a RPZ or custom Lua policy has been applied, response messages also contain the applied policy name and some tags.
This is particularly useful to detect and act on infected hosts.

The Protobuf logging stream can include event information in a proprietary format and (starting with version 5.3.0) OpenTelemetry Trace data.
See :ref:`event-tracing` for more information.

Configuring Protocol Buffer logs
--------------------------------
Protobuf export to a server is enabled using the ``protobufServer()`` directive:

.. function:: protobufServer(servers [, options]))

  .. versionadded:: 4.2.0
  .. versionadded:: 5.1.0 Alternative equivalent YAML setting: :ref:`setting-yaml-logging.protobuf_servers`.

  Send protocol buffer messages to one or more servers for incoming queries and/or outgoing responses. The client address may be masked using :func:`setProtobufMasks`, for anonymization purposes.

  :param servers: The IP and port to connect to, or a list of those. If more than one server is configured, all messages are sent to every server.
  :type servers: string or list of strings
  :param table options: A table with ``key=value`` pairs with options.

  Options:

  * ``timeout=2``: int - Time in seconds to wait when sending a message
  * ``maxQueuedEntries=100``: int - How many entries will be kept in memory if the server becomes unreachable
  * ``reconnectWaitTime=1``: int - How long to wait, in seconds, between two reconnection attempts
  * ``taggedOnly=false``: bool - Only entries with a policy or a policy tag set will be sent
  * ``asyncConnect``: bool - When set to false (default) the first connection to the server during startup will block up to ``timeout`` seconds, otherwise the connection is done in a separate thread, after the first message has been queued
  * ``logQueries=true``: bool - Whether to export queries
  * ``logResponses=true``: bool - Whether to export responses
  * ``exportTypes={'A', 'AAAA', 'CNAME'}``: list of strings - The list of record types found in the answer section to export. Record types A, AAAA, CNAME, MX, NS, PTR, SPF, SRV and TXT are supported.

  .. versionchanged:: 4.7.0

  The values in ``exportTypes`` can be numeric as well as strings. Symbolic names from ``pdns`` can be used, e.g.  ``exportTypes = { pdns.A, pdns.AAAA, pdns.CNAME }``

  .. versionadded:: 4.7.0

  * ``logMappedFrom=false``: bool - whether to log the remote address before substitution by :ref:`proxymapping` (the default) or after

  .. versionchanged:: 5.1.0

     Added support for the HTTPS, SVCB and NAPTR record types.

.. function:: protobufServer(server [[[[[[[, timeout=2], maxQueuedEntries=100], reconnectWaitTime=1], maskV4=32], maskV6=128], asyncConnect=false], taggedOnly=false])

  .. deprecated:: 4.2.0

  :param string server: The IP and port to connect to
  :param int timeout: Time in seconds to wait when sending a message
  :param int maxQueuedEntries: How many entries will be kept in memory if the server becomes unreachable
  :param int reconnectWaitTime: How long to wait, in seconds, between two reconnection attempts
  :param int maskV4: network mask to apply to the client IPv4 addresses, for anonymization purposes. The default of 32 means no anonymization.
  :param int maskV6: Same as maskV4, but for IPv6. Defaults to 128.
  :param bool taggedOnly: Only entries with a policy or a policy tag set will be sent.
  :param bool asyncConnect: When set to false (default) the first connection to the server during startup will block up to ``timeout`` seconds, otherwise the connection is done in a separate thread, after the first message has been queued..

.. function:: setProtobufMasks(maskv4, maskV6)

  .. versionadded:: 4.2.0
  .. versionadded:: 5.1.0 Alternative equivalent YAML setting: :ref:`setting-yaml-logging.protobuf_mask_v4` and :ref:`setting-yaml-logging.protobuf_mask_v6`.

  :param int maskV4: network mask to apply to the client IPv4 addresses, for anonymization purposes. The default of 32 means no anonymization.
  :param int maskV6: Same as maskV4, but for IPv6. Defaults to 128.

Logging outgoing queries and responses
--------------------------------------

While :func:`protobufServer` only exports the queries sent to the recursor from clients, with the corresponding responses, ``outgoingProtobufServer()`` can be used to export outgoing queries sent by the recursor to authoritative servers, along with the corresponding responses.

.. function:: outgoingProtobufServer(servers [, options])

  .. versionadded:: 4.2.0
  .. versionadded:: 5.1.0 Alternative equivalent YAML setting: :ref:`setting-yaml-logging.outgoing_protobuf_servers`.

  Send protocol buffer messages to one or more servers for outgoing queries and/or incoming responses.

  :param servers: The IP and port to connect to, or a list of those. If more than one server is configured, all messages are sent to every server.
  :type servers: string or list of strings
  :param table options: A table with ``key=value`` pairs with options.

  Options:

  * ``timeout=2``: int - Time in seconds to wait when sending a message
  * ``maxQueuedEntries=100``: int - How many entries will be kept in memory if the server becomes unreachable
  * ``reconnectWaitTime=1``: int - How long to wait, in seconds, between two reconnection attempts
  * ``asyncConnect``: bool - When set to false (default) the first connection to the server during startup will block up to ``timeout`` seconds, otherwise the connection is done in a separate thread, after the first message has been queued
  * ``logQueries=true``: bool - Whether to export queries
  * ``logResponses=true``: bool - Whether to export responses
  * ``exportTypes={'A', 'AAAA', 'CNAME'}``: list of strings or qtypes - The list of record types found in the answer section to export. Record types A, AAAA, CNAME, MX, NS, PTR, SPF, SRV and TXT are supported

  .. versionchanged:: 4.7.0

  The values in ``exportTypes`` can be numeric as well as strings. Symbolic names from ``pdns`` can be used, e.g.  ``exportTypes = { pdns.A, pdns.AAAA, pdns.CNAME }``

  .. versionchanged:: 5.1.0

     Added support for the HTTPS, SVCB and NAPTR records types.

.. function:: outgoingProtobufServer(server [[[[, timeout=2], maxQueuedEntries=100], reconnectWaitTime=1], asyncConnect=false])

  .. deprecated:: 4.2.0

  :param string server: The IP and port to connect to
  :param int timeout: Time in seconds to wait when sending a message
  :param int maxQueuedEntries: How many entries will be kept in memory if the server becomes unreachable
  :param int reconnectWaitTime: How long to wait, in seconds, between two reconnection attempts
  :param bool asyncConnect: When set to false (default) the first connection to the server during startup will block up to ``timeout`` seconds, otherwise the connection is done in a separate thread, after the first message has been queued..

Protocol Buffers Definition
---------------------------

The protocol buffers message types can be found in the `dnsmessage.proto <https://github.com/PowerDNS/pdns/blob/master/pdns/dnsmessage.proto>`_ file and is included here:

.. literalinclude:: ../../../dnsmessage.proto

Logging in ``dnstap`` format using framestreams
-----------------------------------------------
Define the following function to enable logging of outgoing queries and/or responses in ``dnstap`` format.
The recursor must have been built with configure ``--enable-dnstap`` to make this feature available.

.. function:: dnstapFrameStreamServer(servers, [, options])

  .. versionadded:: 4.3.0
  .. versionadded:: 5.1.0 Alternative equivalent YAML setting: :ref:`setting-yaml-logging.dnstap_framestream_servers`.

  Send dnstap formatted message to one or more framestream servers for outgoing queries and/or incoming responses.

  :param servers: Either a pathname of a unix domain socket starting with a slash or the IP:port to connect to, or a list of those. If more than one server is configured, all messages are sent to every server.
  :type servers: string or list of strings
  :param table options: A table with ``key=value`` pairs with options.

  Options:

  * ``logQueries=true``: bool - log outgoing queries
  * ``logResponses=true``: bool - log incoming responses

  The following options apply to the settings of the `framestream library
  <https://github.com/farsightsec/fstrm>`. Refer to the documentation of that library for the default
  values, exact description and allowable values for these options. For all these options, absence or a zero
  value has the effect of using the library-provided default value.

  * ``bufferHint=0``: unsigned
  * ``flushTimeout=0``: unsigned
  * ``inputQueueSize=0``: unsigned
  * ``outputQueueSize=0``: unsigned
  * ``queueNotifyThreshold=0``: unsigned
  * ``reopenInterval=0``: unsigned

.. function:: dnstapNODFrameStreamServer(servers [, options])

  .. versionadded:: 4.8.0
  .. versionadded:: 5.1.0 Alternative equivalent YAML setting: :ref:`setting-yaml-logging.dnstap_nod_framestream_servers`.

  Send dnstap formatted message for :ref:`Newly Observed Domain` and :ref:`Unique Domain Response`.
  ``Message.type`` will be set to ``CLIENT_QUERY`` for NOD and ``RESOLVER_RESPONSE`` for UDR. The concerned domain name will be attached in the ``Message.query_zone`` field.
  UDR notifications will get the reply attached to the ``response_message`` field.

  :param servers: Either a pathname of a unix domain socket starting with a slash or the IP:port to connect to, or a list of those. If more than one server is configured, all messages are sent to every server.
  :type servers: string or list of strings
  :param table options: A table with ``key=value`` pairs with options.

  Options:

  * ``logNODs=true``: bool - log NODs
  * ``logUDRs=false``: bool - log UDRs

  The following options apply to the settings of the `framestream library
  <https://github.com/farsightsec/fstrm>`. Refer to the documentation of that library for the default
  values, exact description and allowable values for these options. For all these options, absence or a zero
  value has the effect of using the library-provided default value.

  * ``bufferHint=0``: unsigned
  * ``flushTimeout=0``: unsigned
  * ``inputQueueSize=0``: unsigned
  * ``outputQueueSize=0``: unsigned
  * ``queueNotifyThreshold=0``: unsigned
  * ``reopenInterval=0``: unsigned
