Using the Proxy Protocol
------------------------

In order to provide the downstream server with the address of the real client, or at least the one talking to dnsdist, the ``useProxyProtocol`` parameter can be used when creating a :func:`new server <newServer>`.
This parameter indicates whether a Proxy Protocol version 2 (binary) header should be prepended to the query before forwarding it to the backend, over UDP or TCP. This header contains the initial source and destination addresses and ports, and can also contain several custom values in a Type-Length-Value format. More information about the Proxy Protocol can be found at https://www.haproxy.org/download/2.2/doc/proxy-protocol.txt
Such a Proxy Protocol header can also be passed from the client to dnsdist, using :func:`setProxyProtocolACL` to specify which clients to accept it from.
If :func:`setProxyProtocolApplyACLToProxiedClients` is set (default is false), the general ACL will be applied to the source IP address as seen by dnsdist first, but also to the source IP address provided in the Proxy Protocol header.

Custom values can be added to the header via :meth:`DNSQuestion:addProxyProtocolValue`, :meth:`DNSQuestion:setProxyProtocolValues`, :func:`SetAdditionalProxyProtocolValueAction` and :func:`SetProxyProtocolValuesAction`.
Be careful that Proxy Protocol values are sent once at the beginning of the TCP connection for TCP and DoT queries.
That means that values received on an incoming TCP connection will be inherited by subsequent queries received over the same incoming TCP connection, if any, but values set to a query will not be inherited by subsequent queries.
Please also note that the maximum size of a Proxy Protocol header dnsdist is willing to accept is 512 bytes by default, although it can be set via :func:`setProxyProtocolMaximumPayloadSize`.

dnsdist 1.5.0 only supports outgoing Proxy Protocol. Support for parsing incoming Proxy Protocol headers has been implemented in 1.6.0, except for DoH where it does not make sense anyway, since HTTP headers already provide a mechanism for that.
