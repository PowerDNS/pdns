Using the Proxy Protocol
------------------------

In order to provide the downstream server with the address of the real client, or at least the one talking to dnsdist, the ``useProxyProtocol`` parameter can be used when creating a :func:`new server <newServer>`.
This parameter indicates whether a Proxy Protocol header should be prepended to the query before forwarding it to the backend, over UDP or TCP. This header contains the initial source and destination addresses and ports, and can also contain several custom values in a Type-Length-Value format. More information about the Proxy Protocol can be found at https://www.haproxy.org/download/2.2/doc/proxy-protocol.txt

Custom values can be added to the header via :meth:`DNSQuestion:setProxyProtocolValues` and :func:`SetProxyProtocolValuesAction`.

As of 1.5.0 only outgoing Proxy Protocol support has been implemented, although support for parsing incoming Proxy Protocol headers will likely be implemented in the future.
