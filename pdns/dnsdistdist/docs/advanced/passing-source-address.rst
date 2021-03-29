Passing the source address to the backend
=========================================

dnsdist, as a load-balancer, receives the UDP datagrams and terminates the TCP connections with the client. It therefore knows the source IP address and port of that client, as well as the original destination address, port, and protocol.
Very often the backend needs to know that information as well, to pass EDNS Client Subnet to an authoritative server, to do GeoIP-based processing or even custom filtering.

There are several ways to pass that information using dnsdist: EDNS Client Subnet, X-Proxied-For and the Proxy Protocol.

Using EDNS Client Subnet
------------------------

EDNS Client Subnet (ECS) is a standardized EDNS option designed to pass a bit of information about the client from a resolver to authoritative servers. While it was not designed with our use-case in mind, it can be used by dnsdist to send the source IP, but only the source IP, to its backend.

In order to provide the downstream server with the address of the real client, or at least the one talking to dnsdist, the ``useClientSubnet`` parameter can be used when creating a :func:`new server <newServer>`. This parameter indicates whether an EDNS Client Subnet option should be added to the request.

The default source prefix-length is 24 for IPv4 and 56 for IPv6, meaning that for a query received from 192.0.2.42, the EDNS Client Subnet value sent to the backend will be 192.0.2.0.
This can be changed with :func:`setECSSourcePrefixV4` and :func:`setECSSourcePrefixV6`.

If the incoming request already contains an EDNS Client Subnet value, it will not be overridden unless :func:`setECSOverride` is set to ``true``.

In addition to the global settings, rules and Lua bindings can alter this behavior per query:

 * calling :func:`SetDisableECSAction` or setting ``dq.useECS`` to ``false`` prevents the sending of the ECS option.
 * calling :func:`SetECSOverrideAction` or setting ``dq.ecsOverride`` will override the global :func:`setECSOverride` value.
 * calling :func:`SetECSPrefixLengthAction(v4, v6)` or setting ``dq.ecsPrefixLength`` will override the global :func:`setECSSourcePrefixV4()` and :func:`setECSSourcePrefixV6()` values.

In effect this means that for the EDNS Client Subnet option to be added to the request, ``useClientSubnet`` should be set to ``true`` for the backend used (default to ``false``) and ECS should not have been disabled by calling :func:`SetDisableECSAction` or setting ``dq.useECS`` to ``false`` (default to true).

Note that any trailing data present in the incoming query is removed when an OPT (or XPF) record has to be inserted.

In addition to the drawback that it can only pass the source IP address, and the fact that it needs to override any existing ECS option, adding that option requires parsing and editing the query, as well as parsing and editing the response in most cases.

+----------------------------+-------------------------------------------------+
| Payload                    | Required processing                             |
+============================+=================================================+
| Query, no EDNS             | add an OPT record                               |
+----------------------------+-------------------------------------------------+
| Query, EDNS without ECS    | edit the OPT record to add an ECS option        |
+----------------------------+-------------------------------------------------+
| Query, ECS                 | edit the OPT record to overwrite the ECS option |
+----------------------------+-------------------------------------------------+
| Response, no EDNS          | none                                            |
+----------------------------+-------------------------------------------------+
| Response, EDNS without ECS | remove the OPT record if needed                 |
+----------------------------+-------------------------------------------------+
| Response, EDNS with ECS    | remove or edit the ECS option if needed         |
+----------------------------+-------------------------------------------------+

X-Proxied-For
-------------

The experimental XPF record (from `draft-bellis-dnsop-xpf <https://datatracker.ietf.org/doc/draft-bellis-dnsop-xpf/>`_) is an alternative to the use of EDNS Client Subnet which has the advantages of preserving any existing EDNS Client Subnet value sent by the client, and of passing along the original destination address, as well as the initial source and destination ports.

In order to provide the downstream server with the address of the real client, or at least the one talking to dnsdist, the ``addXPF`` parameter can be used when creating a :func:`new server <newServer>`.
This parameter indicates whether an XPF record shall be added to the query. Since that record is experimental, there is currently no option code assigned to it, and therefore one needs to be specified as an argument to the ``addXPF`` parameter.

If the incoming request already contains a XPF record, it will not be overwritten. Instead a new one will be added to the query and the existing one will be preserved.
That might be an issue by allowing clients to spoof their source address by adding a forged XPF record to their query. That can be prevented by using a rule to drop incoming queries containing a XPF record (in that example the 65280 option code has been assigned to XPF):

  addAction(RecordsTypeCountRule(DNSSection.Additional, 65280, 1, 65535), DropAction())

Proxy Protocol
--------------

The Proxy Protocol has been designed by the HAProxy folks for HTTP over TCP, but is generic enough to be used in other places, and is a de-facto standard with implementations in nginx and postfix, for example.
It works by pre-pending a small header at the very beginning of a UDP datagram or TCP connection, which holds the initial source and destination addresses and ports, and can also contain several custom values in a Type-Length-Value format. More information about the Proxy Protocol can be found at https://www.haproxy.org/download/2.2/doc/proxy-protocol.txt

In order to use it in dnsdist, the ``useProxyProtocol`` parameter can be used when creating a :func:`new server <newServer>`.
This parameter indicates whether a Proxy Protocol version 2 (binary) header should be prepended to the query before forwarding it to the backend, over UDP or TCP.
Such a Proxy Protocol header can also be passed from the client to dnsdist, using :func:`setProxyProtocolACL` to specify which clients to accept it from.
If :func:`setProxyProtocolApplyACLToProxiedClients` is set (default is false), the general ACL will be applied to the source IP address as seen by dnsdist first, but also to the source IP address provided in the Proxy Protocol header.

Custom values can be added to the header via :meth:`DNSQuestion:addProxyProtocolValue`, :meth:`DNSQuestion:setProxyProtocolValues`, :func:`SetAdditionalProxyProtocolValueAction` and :func:`SetProxyProtocolValuesAction`.
Be careful that Proxy Protocol values are sent once at the beginning of the TCP connection for TCP and DoT queries.
That means that values received on an incoming TCP connection will be inherited by subsequent queries received over the same incoming TCP connection, if any, but values set to a query will not be inherited by subsequent queries.
Please also note that the maximum size of a Proxy Protocol header dnsdist is willing to accept is 512 bytes by default, although it can be set via :func:`setProxyProtocolMaximumPayloadSize`.

dnsdist 1.5.0 only supports outgoing Proxy Protocol. Support for parsing incoming Proxy Protocol headers has been implemented in 1.6.0, except for DoH where it does not make sense anyway, since HTTP headers already provide a mechanism for that.

Influence on caching
--------------------

When dnsdist's packet cache is in use, it is important to note that the cache lookup is done **after** adding ECS, because it prevents serving the same response to clients from different subnets when ECS is passed to an authoritative server doing GeoIP, or to a backend doing custom filtering.
However that means that passing a narrow ECS source will effectively kill dnsdist's cache ratio, since a given answer will only be a cache hit for clients in the same ECS subnet. Therefore, unless a broad ECS source (greater than 24, for example) is used, it's better to disable caching.

One exception to that rule is the zero-scope feature, which allows dnsdist to detect that a response sent by the backend has a 0-scope ECS value, indicating that the answer is not ECS-specific and can be used for all clients. dnsdist will then store the answer in its packet cache using the initial query, before ECS has been added.
For that feature to work, dnsdist will look up twice into the packet cache when a query arrives, first without and then with ECS. That way, when most of the responses sent by a backend are not ECS-specific and can be served to all clients, dnsdist will still be able to have a great cache-hit ratio for non ECS-specific entries.

That feature is enabled by setting ``disableZeroScope=false`` on :func:`newServer` (default) and ``parseECS=true`` on :func:`newPacketCache` (not the default).


Things are different for XPF and the proxy protocol, because dnsdist then does the cache lookup **before** adding the payload. It means that caching can still be enabled as long as the response is not source-dependant, but should be disabled otherwise.

+------------------+----------+---------------------+----------------+------------------------+
| Protocol         | Standard | Require DNS parsing | Contains ports | Caching                |
+==================+==========+=====================+================+========================+
| ECS              | Yes      | Query and response  | No             | Only with broad source |
+------------------+----------+---------------------+----------------+------------------------+
| ECS (zero-scope) | Yes      | Query and response  | No             | Yes                    |
+------------------+----------+---------------------+----------------+------------------------+
| XPF              | No       | Query               | Yes            | Depends on the backend |
+------------------+----------+---------------------+----------------+------------------------+
| Proxy Protocol   | No       | No                  | Yes            | Depends on the backend |
+------------------+----------+---------------------+----------------+------------------------+
