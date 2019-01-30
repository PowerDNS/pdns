Logging DNS messages with Protocol Buffers
==========================================
The PowerDNS Recursor has the ability to emit a stream of protocol buffers messages over TCP, containing information about queries, answers and policy decisions.

Messages contain the IP address of the client initiating the query, the one on which the message was received, whether it was received over UDP or TCP, a timestamp and the qname, qtype and qclass of the question.
In addition, messages related to responses contain the name, type, class and rdata of A, AAAA and CNAME records present in the response, as well as the response code.

Finally, if a RPZ or custom Lua policy has been applied, response messages also contain the applied policy name and some tags.
This is particularly useful to detect and act on infected hosts.

Configuring Protocol Buffer logs
--------------------------------
Protobuf export to a server is enabled using the ``protobufServer()`` directive:

.. function:: protobufServer(server [[[[[[[[, timeout=2], maxQueuedEntries=100], reconnectWaitTime=1], maskV4=32], maskV6=128], asyncConnect=false], taggedOnly=false], responsesOnly=false])

  .. versionchanged:: 4.1.11

    The optional ``responsesOnly`` parameter was added.

  :param string server: The IP and port to connect to
  :param int timeout: Time in seconds to wait when sending a message
  :param int maxQueuedEntries: How many entries will be kept in memory if the server becomes unreachable
  :param int reconnectWaitTime: How long to wait, in seconds, between two reconnection attempts
  :param int maskV4: network mask to apply to the client IPv4 addresses, for anonymization purposes. The default of 32 means no anonymization.
  :param int maskV6: Same as maskV4, but for IPv6. Defaults to 128.
  :param bool taggedOnly: Only entries with a policy or a policy tag set will be sent.
  :param bool asyncConnect: When set to false (default) the first connection to the server during startup will block up to ``timeout`` seconds, otherwise the connection is done in a separate thread.
  :param bool responsesOnly: When set to true, protobuf messages will only be generated for responses, instead of being generated for queries and responses.

Logging outgoing queries and responses
--------------------------------------

While :func:`protobufServer` only exports the queries sent to the recursor from clients, with the corresponding responses, ``outgoingProtobufServer()`` can be used to export outgoing queries sent by the recursor to authoritative servers, along with the corresponding responses.

.. function:: outgoingProtobufServer(server [[[[, timeout=2], maxQueuedEntries=100], reconnectWaitTime=1], asyncConnect=false])

  :param string server: The IP and port to connect to
  :param int timeout: Time in seconds to wait when sending a message
  :param int maxQueuedEntries: How many entries will be kept in memory if the server becomes unreachable
  :param int reconnectWaitTime: How long to wait, in seconds, between two reconnection attempts
  :param bool asyncConnect: When set to false (default) the first connection to the server during startup will block up to ``timeout`` seconds, otherwise the connection is done in a separate thread.

Protobol Buffers Definition
---------------------------

The protocol buffers message types can be found in the `dnsmessage.proto <https://github.com/PowerDNS/pdns/blob/master/pdns/dnsmessage.proto>`_ file and is included here:

.. literalinclude:: ../../../dnsmessage.proto
