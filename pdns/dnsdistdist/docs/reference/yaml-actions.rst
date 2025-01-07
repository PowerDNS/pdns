.. THIS IS A GENERATED FILE. DO NOT EDIT. See dnsdist-settings-documentation-generator.py

.. raw:: latex

    \setcounter{secnumdepth}{-1}

.. _yaml-settings-Action:

YAML action reference
=====================

.. _yaml-settings-AllowAction:

AllowAction
-----------

Let these packets go through

Lua equivalent: :func:`AllowAction`

.. _yaml-settings-ContinueAction:

ContinueAction
--------------

Execute the specified action and override its return with None, making it possible to continue the processing. Subsequent rules are processed after this action

Lua equivalent: :func:`ContinueAction`

Parameters:

- **action**: :ref:`Action <yaml-settings-Action>`


.. _yaml-settings-DelayAction:

DelayAction
-----------

Delay the response by the specified amount of milliseconds (UDP-only). Note that the sending of the query to the backend, if needed, is not delayed. Only the sending of the response to the client will be delayed. Subsequent rules are processed after this action

Lua equivalent: :func:`DelayAction`

Parameters:

- **msec**: Unsigned integer


.. _yaml-settings-DnstapLogAction:

DnstapLogAction
---------------

Send the current query to a remote logger as a dnstap message. ``alter-function`` is a callback, receiving a :class:`DNSQuestion` and a :class:`DnstapMessage`, that can be used to modify the message. Subsequent rules are processed after this action

Lua equivalent: :func:`DnstapLogAction`

Parameters:

- **identity**: String
- **logger-name**: String
- **alter-function-name**: String ``("")``
- **alter-function-code**: String ``("")``
- **alter-function-file**: String ``("")``


.. _yaml-settings-DropAction:

DropAction
----------

Drop the packet

Lua equivalent: :func:`DropAction`

.. _yaml-settings-SetEDNSOptionAction:

SetEDNSOptionAction
-------------------

Add arbitrary EDNS option and data to the query. Any existing EDNS content with the same option code will be overwritten. Subsequent rules are processed after this action

Lua equivalent: :func:`SetEDNSOptionAction`

Parameters:

- **code**: Unsigned integer
- **data**: String


.. _yaml-settings-ERCodeAction:

ERCodeAction
------------

Reply immediately by turning the query into a response with the specified EDNS extended rcode

Lua equivalent: :func:`ERCodeAction`

Parameters:

- **rcode**: Unsigned integer
- **vars**: :ref:`ResponseConfig <yaml-settings-ResponseConfig>`


.. _yaml-settings-HTTPStatusAction:

HTTPStatusAction
----------------

Return an HTTP response with a status code of ``status``. For HTTP redirects, ``body`` should be the redirect URL

Lua equivalent: :func:`HTTPStatusAction`

Parameters:

- **status**: Unsigned integer
- **body**: String
- **content-type**: String ``("")``
- **vars**: :ref:`ResponseConfig <yaml-settings-ResponseConfig>`


.. _yaml-settings-KeyValueStoreLookupAction:

KeyValueStoreLookupAction
-------------------------

Does a lookup into the key value store using the key returned by ``lookup-key-name``, and storing the result if any into the tag named ``destination-tag``. The store can be a ``CDB`` or a ``LMDB`` database.  The key can be based on the qname, source IP or the value of an existing tag. Subsequent rules are processed after this action. Note that the tag is always created, even if there was no match, but in that case the content is empty

Lua equivalent: :func:`KeyValueStoreLookupAction`

Parameters:

- **kvs-name**: String
- **lookup-key-name**: String
- **destination-tag**: String


.. _yaml-settings-KeyValueStoreRangeLookupAction:

KeyValueStoreRangeLookupAction
------------------------------

Does a range-based lookup into the key value store using the key returned by ``lookup-key-name``, and storing the result if any into the tag named ``destination-tag``. This assumes that there is a key in network byte order for the last element of the range (for example ``2001:0db8:ffff:ffff:ffff:ffff:ffff:ffff`` for ``2001:db8::/32``) which contains the first element of the range (``2001:0db8:0000:0000:0000:0000:0000:0000``) (optionally followed by any data) as value, also in network byte order, and that there is no overlapping ranges in the database. This requires that the underlying store supports ordered keys, which is true for LMDB but not for CDB

Lua equivalent: :func:`KeyValueStoreRangeLookupAction`

Parameters:

- **kvs-name**: String
- **lookup-key-name**: String
- **destination-tag**: String


.. _yaml-settings-LogAction:

LogAction
---------

Log a line for each query, to the specified file if any, to the console (require verbose) if the empty string is given as filename. If an empty string is supplied in the file name, the logging is done to stdout, and only in verbose mode by default. This can be changed by setting ``verbose-only`` to ``false``. When logging to a file, the ``binary`` parameter specifies whether we log in binary form (default) or in textual form. The ``append`` parameter specifies whether we open the file for appending or truncate each time (default). The ``buffered`` parameter specifies whether writes to the file are buffered (default) or not. Subsequent rules are processed after this action

Lua equivalent: :func:`LogAction`

Parameters:

- **file-name**: String ``("")``
- **binary**: Boolean ``(true)``
- **append**: Boolean ``(false)``
- **buffered**: Boolean ``(false)``
- **verbose-only**: Boolean ``(true)``
- **include-timestamp**: Boolean ``(false)``


.. _yaml-settings-LuaAction:

LuaAction
---------

Invoke a Lua function that accepts a :class:`DNSQuestion`. The function should return a :ref:`DNSAction`. If the Lua code fails, ``ServFail`` is returned

Lua equivalent: :func:`LuaAction`

Parameters:

- **function-name**: String ``("")``
- **function-code**: String ``("")``
- **function-file**: String ``("")``


.. _yaml-settings-LuaFFIAction:

LuaFFIAction
------------

Invoke a Lua function that accepts a pointer to a ``dnsdist_ffi_dnsquestion_t`` object, whose bindings are defined in ``dnsdist-lua-ffi-interface.h``. The function should return a :ref:`DNSAction`. If the Lua code fails, ``ServFail`` is returned

Lua equivalent: :func:`LuaFFIAction`

Parameters:

- **function-name**: String ``("")``
- **function-code**: String ``("")``
- **function-file**: String ``("")``


.. _yaml-settings-LuaFFIPerThreadAction:

LuaFFIPerThreadAction
---------------------

Invoke a Lua function that accepts a pointer to a ``dnsdist_ffi_dnsquestion_t`` object, whose bindings are defined in ``dnsdist-lua-ffi-interface.h``. The function should return a :ref:`DNSAction`. If the Lua code fails, ``ServFail`` is returned. The function will be invoked in a per-thread Lua state, without access to the global Lua state. All constants (:ref:`DNSQType`, :ref:`DNSRCode`, ...) are available in that per-thread context, as well as all FFI functions. Objects and their bindings that are not usable in a FFI context (:class:`DNSQuestion`, :class:`DNSDistProtoBufMessage`, :class:`PacketCache`, ...) are not available.

Lua equivalent: :func:`LuaFFIPerThreadAction`

Parameters:

- **code**: String


.. _yaml-settings-NegativeAndSOAAction:

NegativeAndSOAAction
--------------------

Turn a question into a response, either a ``NXDOMAIN`` or a ``NODATA`` one based on ``nxd``, setting the ``QR`` bit to ``1`` and adding a ``SOA`` record in the additional section

Lua equivalent: :func:`NegativeAndSOAAction`

Parameters:

- **nxd**: Boolean
- **zone**: String
- **ttl**: Unsigned integer
- **mname**: String
- **rname**: String
- **soa-parameters**: :ref:`SOAParams <yaml-settings-SOAParams>`
- **soa-in-authority**: Boolean ``(false)``
- **vars**: :ref:`ResponseConfig <yaml-settings-ResponseConfig>`


.. _yaml-settings-NoneAction:

NoneAction
----------

Does nothing. Subsequent rules are processed after this action

Lua equivalent: :func:`NoneAction`

.. _yaml-settings-PoolAction:

PoolAction
----------

Send the packet into the specified pool. If ``stop-processing`` is set to ``false``, subsequent rules will be processed after this action

Lua equivalent: :func:`PoolAction`

Parameters:

- **pool-name**: String
- **stop-processing**: Boolean ``(true)``


.. _yaml-settings-QPSAction:

QPSAction
---------

Drop a packet if it does exceed the ``limit`` queries per second limit. Letting the subsequent rules apply otherwise

Lua equivalent: :func:`QPSAction`

Parameters:

- **limit**: Unsigned integer


.. _yaml-settings-QPSPoolAction:

QPSPoolAction
-------------

Send the packet into the specified pool only if it does not exceed the ``limit`` queries per second limit. If ``stop-processing`` is set to ``false``, subsequent rules will be processed after this action. Letting the subsequent rules apply otherwise

Lua equivalent: :func:`QPSPoolAction`

Parameters:

- **limit**: Unsigned integer
- **pool-name**: String
- **stop-processing**: Boolean ``(true)``


.. _yaml-settings-RCodeAction:

RCodeAction
-----------

Reply immediately by turning the query into a response with the specified rcode

Lua equivalent: :func:`RCodeAction`

Parameters:

- **rcode**: Unsigned integer
- **vars**: :ref:`ResponseConfig <yaml-settings-ResponseConfig>`


.. _yaml-settings-RemoteLogAction:

RemoteLogAction
---------------

Send the current query to a remote logger as a Protocol Buffer message. ``alter-function`` is a callback, receiving a :class:`DNSQuestion` and a :class:`DNSDistProtoBufMessage`, that can be used to modify the message, for example for anonymization purposes. Subsequent rules are processed after this action

Lua equivalent: :func:`RemoteLogAction`

Parameters:

- **logger-name**: String
- **alter-function-name**: String ``("")``
- **alter-function-code**: String ``("")``
- **alter-function-file**: String ``("")``
- **server-id**: String ``("")``
- **ip-encrypt-key**: String ``("")``
- **export-tags**: Sequence of String
- **metas**: Sequence of :ref:`ProtoBufMetaConfiguration <yaml-settings-ProtoBufMetaConfiguration>`


.. _yaml-settings-SetAdditionalProxyProtocolValueAction:

SetAdditionalProxyProtocolValueAction
-------------------------------------

Add a Proxy-Protocol Type-Length value to be sent to the server along with this query. It does not replace any existing value with the same type but adds a new value. Be careful that Proxy Protocol values are sent once at the beginning of the TCP connection for TCP and DoT queries. That means that values received on an incoming TCP connection will be inherited by subsequent queries received over the same incoming TCP connection, if any, but values set to a query will not be inherited by subsequent queries. Subsequent rules are processed after this action

Lua equivalent: :func:`SetAdditionalProxyProtocolValueAction`

Parameters:

- **proxy-type**: Unsigned integer
- **value**: String


.. _yaml-settings-SetDisableECSAction:

SetDisableECSAction
-------------------

Disable the sending of ECS to the backend. Subsequent rules are processed after this action

Lua equivalent: :func:`SetDisableECSAction`

.. _yaml-settings-SetDisableValidationAction:

SetDisableValidationAction
--------------------------

Set the CD bit in the query and let it go through. Subsequent rules are processed after this action

Lua equivalent: :func:`SetDisableValidationAction`

.. _yaml-settings-SetECSAction:

SetECSAction
------------

Set the ECS prefix and prefix length sent to backends to an arbitrary value. If both IPv4 and IPv6 masks are supplied the IPv4 one will be used for IPv4 clients and the IPv6 one for IPv6 clients. Otherwise the first mask is used for both, and can actually be an IPv6 mask. Subsequent rules are processed after this action

Lua equivalent: :func:`SetECSAction`

Parameters:

- **ipv4**: String
- **ipv6**: String ``("")``


.. _yaml-settings-SetECSOverrideAction:

SetECSOverrideAction
--------------------

Whether an existing EDNS Client Subnet value should be overridden (true) or not (false). Subsequent rules are processed after this action

Lua equivalent: :func:`SetECSOverrideAction`

Parameters:

- **override-existing**: Boolean


.. _yaml-settings-SetECSPrefixLengthAction:

SetECSPrefixLengthAction
------------------------

Set the ECS prefix length. Subsequent rules are processed after this action

Lua equivalent: :func:`SetECSPrefixLengthAction`

Parameters:

- **ipv4**: Unsigned integer
- **ipv6**: Unsigned integer


.. _yaml-settings-SetExtendedDNSErrorAction:

SetExtendedDNSErrorAction
-------------------------

Set an Extended DNS Error status that will be added to the response corresponding to the current query. Subsequent rules are processed after this action

Lua equivalent: :func:`SetExtendedDNSErrorAction`

Parameters:

- **info-code**: Unsigned integer
- **extra-text**: String ``("")``


.. _yaml-settings-SetMacAddrAction:

SetMacAddrAction
----------------

Add the source MAC address to the query as EDNS0 option option. This action is currently only supported on Linux. Subsequent rules are processed after this action

Lua equivalent: :func:`SetMacAddrAction`

Parameters:

- **code**: Unsigned integer


.. _yaml-settings-SetMaxReturnedTTLAction:

SetMaxReturnedTTLAction
-----------------------

Cap the TTLs of the response to the given maximum, but only after inserting the response into the packet cache with the initial TTL value

Lua equivalent: :func:`SetMaxReturnedTTLAction`

Parameters:

- **max**: Unsigned integer


.. _yaml-settings-SetNoRecurseAction:

SetNoRecurseAction
------------------

Strip RD bit from the question, let it go through. Subsequent rules are processed after this action

Lua equivalent: :func:`SetNoRecurseAction`

.. _yaml-settings-SetProxyProtocolValuesAction:

SetProxyProtocolValuesAction
----------------------------

Set the Proxy-Protocol Type-Length values to be sent to the server along with this query to values. Subsequent rules are processed after this action

Lua equivalent: :func:`SetProxyProtocolValuesAction`

Parameters:

- **values**: Sequence of :ref:`ProxyProtocolValueConfiguration <yaml-settings-ProxyProtocolValueConfiguration>`


.. _yaml-settings-SetSkipCacheAction:

SetSkipCacheAction
------------------

Don’t lookup the cache for this query, don’t store the answer. Subsequent rules are processed after this action.

Lua equivalent: :func:`SetSkipCacheAction`

.. _yaml-settings-SetTagAction:

SetTagAction
------------

Associate a tag named ``tag`` with a value of ``value`` to this query, that will be passed on to the response. This function will overwrite any existing tag value. Subsequent rules are processed after this action

Lua equivalent: :func:`SetTagAction`

Parameters:

- **tag**: String
- **value**: String


.. _yaml-settings-SetTempFailureCacheTTLAction:

SetTempFailureCacheTTLAction
----------------------------

Set the cache TTL to use for ServFail and Refused replies. TTL is not applied for successful replies. Subsequent rules are processed after this action

Lua equivalent: :func:`SetTempFailureCacheTTLAction`

Parameters:

- **maxTTL**: Unsigned integer


.. _yaml-settings-SNMPTrapAction:

SNMPTrapAction
--------------

Send an SNMP trap, adding the message string as the query description. Subsequent rules are processed after this action

Lua equivalent: :func:`SNMPTrapAction`

Parameters:

- **reason**: String ``("")``


.. _yaml-settings-SpoofAction:

SpoofAction
-----------

Forge a response with the specified IPv4 (for an A query) or IPv6 (for an AAAA) addresses. If you specify multiple addresses, all that match the query type (A, AAAA or ANY) will get spoofed in

Lua equivalent: :func:`SpoofAction`

Parameters:

- **ips**: Sequence of String
- **vars**: :ref:`ResponseConfig <yaml-settings-ResponseConfig>`


.. _yaml-settings-SpoofCNAMEAction:

SpoofCNAMEAction
----------------

Forge a response with the specified CNAME value. Please be aware that DNSdist will not chase the target of the CNAME, so it will not be present in the response which might be a problem for stub resolvers that do not know how to follow a CNAME

Lua equivalent: :func:`SpoofCNAMEAction`

Parameters:

- **cname**: String
- **vars**: :ref:`ResponseConfig <yaml-settings-ResponseConfig>`


.. _yaml-settings-SpoofPacketAction:

SpoofPacketAction
-----------------

Spoof a raw self-generated answer

Lua equivalent: :func:`SpoofPacketAction`

Parameters:

- **response**: String
- **len**: Unsigned integer


.. _yaml-settings-SpoofRawAction:

SpoofRawAction
--------------

Forge a response with the specified raw bytes as record data

Lua equivalent: :func:`SpoofRawAction`

Parameters:

- **answers**: Sequence of String
- **qtype-for-any**: String ``("")``
- **vars**: :ref:`ResponseConfig <yaml-settings-ResponseConfig>`


.. _yaml-settings-SpoofSVCAction:

SpoofSVCAction
--------------

Forge a response with the specified ``SVC`` record data. If the list contains more than one ``SVC`` parameter, they are all returned, and should have different priorities. The hints provided in the SVC parameters, if any, will also be added as ``A``/``AAAA`` records in the additional section, using the target name present in the parameters as owner name if it’s not empty (root) and the qname instead

Lua equivalent: :func:`SpoofSVCAction`

Parameters:

- **parameters**: Sequence of :ref:`SVCRecordParameters <yaml-settings-SVCRecordParameters>`
- **vars**: :ref:`ResponseConfig <yaml-settings-ResponseConfig>`


.. _yaml-settings-TCAction:

TCAction
--------

Create answer to query with the ``TC`` bit set, and the ``RA`` bit set to the value of ``RD`` in the query, to force the client to TCP

Lua equivalent: :func:`TCAction`

.. _yaml-settings-TeeAction:

TeeAction
---------

Send copy of query to remote, keep stats on responses. If ``add-ecs`` is set to true, EDNS Client Subnet information will be added to the query. If ``add-proxy-protocol`` is set to true, a Proxy Protocol v2 payload will be prepended in front of the query. The payload will contain the protocol the initial query was received over (UDP or TCP), as well as the initial source and destination addresses and ports. If ``lca`` has provided a value like “192.0.2.53”, dnsdist will try binding that address as local address when sending the queries. Subsequent rules are processed after this action

Lua equivalent: :func:`TeeAction`

Parameters:

- **rca**: String
- **lca**: String ``("")``
- **add-ecs**: Boolean ``(false)``
- **add-proxy-protocol**: Boolean ``(false)``


