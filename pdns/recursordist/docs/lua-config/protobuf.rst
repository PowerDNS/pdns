Logging DNS messages with Protocol Buffers
==========================================
The PowerDNS Recursor has the ability to emit a stream of protocol buffers messages over TCP, containing information about queries, answers and policy decisions.

Messages contain the IP address of the client initiating the query, the one on which the message was received, whether it was received over UDP or TCP, a timestamp and the qname, qtype and qclass of the question.
In addition, messages related to responses contain the name, type, class and rdata of A, AAAA and CNAME records present in the response, as well as the response code.

Finally, if a RPZ or custom Lua policy has been applied, response messages also contain the applied policy name and some tags.
This is particularly useful to detect and act on infected hosts.

The protocol buffers message types can be found in the `dnsmessage.proto <https://github.com/PowerDNS/pdns/blob/master/pdns/dnsmessage.proto>`_ file.

Configuring Protocol Buffer logs
--------------------------------
Protobuf export to a server is enabled using the ``protobufServer()`` directive:

.. code-block:: Lua

    protobufServer("192.0.2.1:4242" [[[[[[[, timeout], maxQueuedEntries], reconnectWaitTime], maskV4], maskV6], asyncConnect], taggedOnly])

timeout
^^^^^^^
Time in seconds to wait when sending a message, defaults to 2.

maxQueuedEntries
^^^^^^^^^^^^^^^^
How many entries will be kept in memory if the server becomes unreachable, defaults to 100.

reconnectWaitTime
^^^^^^^^^^^^^^^^^
How long to wait, in seconds, between two reconnection attempts, defaults to 1.

maskV4
^^^^^^
network mask to apply to the client IPv4 addresses, for anonymization purposes.
The default of 32 means no anonymization.

maskV6
^^^^^^
Same as maskV4, but for IPv6. Defaults to 128.

taggedOnly
^^^^^^^^^^
Only entries with a policy or a policy tag set will be sent.

asyncConnect
^^^^^^^^^^^^
When set to false (default) the first connection to the server during startup will block up to ``timeout`` seconds, otherwise the connection is done in a separate thread.

Logging outgoing queries and responses
--------------------------------------

While ``protobufServer()`` only exports the queries sent to the recursor from clients, with the corresponding responses, ``outgoingProtobufServer()`` can be used to export outgoing queries sent by the recursor to authoritative servers, along with the corresponding responses.

.. code-block:: Lua

    outgoingProtobufServer("192.0.2.1:4242" [[[[, timeout], maxQueuedEntries], reconnectWaitTime], asyncConnect])

The optional parameters for ``outgoingProtobufServer()`` are:

timeout
^^^^^^^
Time in seconds to wait when sending a message, defaults to 2.

maxQueuedEntries
^^^^^^^^^^^^^^^^
How many entries will be kept in memory if the server becomes unreachable, defaults to 100.

reconnectWaitTime
^^^^^^^^^^^^^^^^^
How long to wait, in seconds, between two reconnection attempts, defaults to 1.

asyncConnect
^^^^^^^^^^^^
When set to false (default) the first connection to the server during startup will block up to ``timeout`` seconds, otherwise the connection is done in a separate thread.
