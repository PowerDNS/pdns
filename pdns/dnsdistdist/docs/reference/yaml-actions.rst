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

- **action**: :ref:`Action <yaml-settings-Action>` - The action to execute


.. _yaml-settings-DelayAction:

DelayAction
-----------

Delay the response by the specified amount of milliseconds (UDP-only). Note that the sending of the query to the backend, if needed, is not delayed. Only the sending of the response to the client will be delayed. Subsequent rules are processed after this action

Lua equivalent: :func:`DelayAction`

Parameters:

- **msec**: Unsigned integer - The amount of milliseconds to delay the response


.. _yaml-settings-DnstapLogAction:

DnstapLogAction
---------------

Send the current query to a remote logger as a dnstap message. ``alter_function`` is a callback, receiving a :class:`DNSQuestion` and a :class:`DnstapMessage`, that can be used to modify the message. Subsequent rules are processed after this action

Lua equivalent: :func:`DnstapLogAction`

Parameters:

- **identity**: String - Server identity to store in the dnstap message
- **logger_name**: String - The name of dnstap logger
- **alter_function_name**: String ``("")`` - The name of the Lua function that will alter the message
- **alter_function_code**: String ``("")`` - The code of the Lua function that will alter the message
- **alter_function_file**: String ``("")`` - The path to a file containing the code of the Lua function that will alter the message


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

- **code**: Unsigned integer - The EDNS option number
- **data**: String - The EDNS0 option raw content


.. _yaml-settings-ERCodeAction:

ERCodeAction
------------

Reply immediately by turning the query into a response with the specified EDNS extended rcode

Lua equivalent: :func:`ERCodeAction`

Parameters:

- **rcode**: Unsigned integer - The RCODE to respond with
- **vars**: :ref:`ResponseConfig <yaml-settings-ResponseConfig>` - The response options


.. _yaml-settings-HTTPStatusAction:

HTTPStatusAction
----------------

Return an HTTP response with a status code of ``status``. For HTTP redirects, ``body`` should be the redirect URL

Lua equivalent: :func:`HTTPStatusAction`

Parameters:

- **status**: Unsigned integer - The HTTP status code to return
- **body**: String - The body of the HTTP response, or a URL if the status code is a redirect (3xx)
- **content_type**: String ``("")`` - The HTTP Content-Type header to return for a 200 response, ignored otherwise. Default is ``application/dns-message``
- **vars**: :ref:`ResponseConfig <yaml-settings-ResponseConfig>` - The response options (deprecated since 2.0.0, do not use)


.. _yaml-settings-KeyValueStoreLookupAction:

KeyValueStoreLookupAction
-------------------------

Does a lookup into the key value store using the key returned by ``lookup_key_name``, and storing the result if any into the tag named ``destination_tag``. The store can be a ``CDB`` or a ``LMDB`` database.  The key can be based on the qname, source IP or the value of an existing tag. Subsequent rules are processed after this action. Note that the tag is always created, even if there was no match, but in that case the content is empty

Lua equivalent: :func:`KeyValueStoreLookupAction`

Parameters:

- **kvs_name**: String - The name of the KV store
- **lookup_key_name**: String - The name of the key to use for the lookup
- **destination_tag**: String - The name of the tag to store the result into


.. _yaml-settings-KeyValueStoreRangeLookupAction:

KeyValueStoreRangeLookupAction
------------------------------

Does a range-based lookup into the key value store using the key returned by ``lookup_key_name``, and storing the result if any into the tag named ``destination_tag``. This assumes that there is a key in network byte order for the last element of the range (for example ``2001:0db8:ffff:ffff:ffff:ffff:ffff:ffff`` for ``2001:db8::/32``) which contains the first element of the range (``2001:0db8:0000:0000:0000:0000:0000:0000``) (optionally followed by any data) as value, also in network byte order, and that there is no overlapping ranges in the database. This requires that the underlying store supports ordered keys, which is true for LMDB but not for CDB

Lua equivalent: :func:`KeyValueStoreRangeLookupAction`

Parameters:

- **kvs_name**: String - The name of the KV store
- **lookup_key_name**: String - The name of the key to use for the lookup
- **destination_tag**: String - The name of the tag to store the result into


.. _yaml-settings-LogAction:

LogAction
---------

Log a line for each query, to the specified file if any, to the console (require verbose) if the empty string is given as filename. If an empty string is supplied in the file name, the logging is done to stdout, and only in verbose mode by default. This can be changed by setting ``verbose_only`` to ``false``. When logging to a file, the ``binary`` parameter specifies whether we log in binary form (default) or in textual form. The ``append`` parameter specifies whether we open the file for appending or truncate each time (default). The ``buffered`` parameter specifies whether writes to the file are buffered (default) or not. Subsequent rules are processed after this action

Lua equivalent: :func:`LogAction`

Parameters:

- **file_name**: String ``("")`` - File to log to. Set to an empty string to log to the normal stdout log, this only works when ``-v`` is set on the command line
- **binary**: Boolean ``(true)`` - Whether to do binary logging
- **append**: Boolean ``(false)`` - Whether to append to an existing file
- **buffered**: Boolean ``(false)`` - Whether to use buffered I/O
- **verbose_only**: Boolean ``(true)`` - Whether to log only in verbose mode when logging to stdout
- **include_timestamp**: Boolean ``(false)`` - Whether to include a timestamp for every entry


.. _yaml-settings-LuaAction:

LuaAction
---------

Invoke a Lua function that accepts a :class:`DNSQuestion`. The function should return a :ref:`DNSAction`. If the Lua code fails, ``ServFail`` is returned

Lua equivalent: :func:`LuaAction`

Parameters:

- **function_name**: String ``("")`` - The name of the Lua function
- **function_code**: String ``("")`` - The code of the Lua function
- **function_file**: String ``("")`` - The path to a file containing the code of the Lua function


.. _yaml-settings-LuaFFIAction:

LuaFFIAction
------------

Invoke a Lua function that accepts a pointer to a ``dnsdist_ffi_dnsquestion_t`` object, whose bindings are defined in ``dnsdist-lua-ffi-interface.h``. The function should return a :ref:`DNSAction`. If the Lua code fails, ``ServFail`` is returned

Lua equivalent: :func:`LuaFFIAction`

Parameters:

- **function_name**: String ``("")`` - The name of the Lua function
- **function_code**: String ``("")`` - The code of the Lua function
- **function_file**: String ``("")`` - The path to a file containing the code of the Lua function


.. _yaml-settings-LuaFFIPerThreadAction:

LuaFFIPerThreadAction
---------------------

Invoke a Lua function that accepts a pointer to a ``dnsdist_ffi_dnsquestion_t`` object, whose bindings are defined in ``dnsdist-lua-ffi-interface.h``. The function should return a :ref:`DNSAction`. If the Lua code fails, ``ServFail`` is returned. The function will be invoked in a per-thread Lua state, without access to the global Lua state. All constants (:ref:`DNSQType`, :ref:`DNSRCode`, ...) are available in that per-thread context, as well as all FFI functions. Objects and their bindings that are not usable in a FFI context (:class:`DNSQuestion`, :class:`DNSDistProtoBufMessage`, :class:`PacketCache`, ...) are not available.

Lua equivalent: :func:`LuaFFIPerThreadAction`

Parameters:

- **code**: String - The code of the Lua function


.. _yaml-settings-NegativeAndSOAAction:

NegativeAndSOAAction
--------------------

Turn a question into a response, either a ``NXDOMAIN`` or a ``NODATA`` one based on ``nxd``, setting the ``QR`` bit to ``1`` and adding a ``SOA`` record in the additional section

Lua equivalent: :func:`NegativeAndSOAAction`

Parameters:

- **nxd**: Boolean - Whether the answer is a NXDOMAIN (true) or a NODATA (false)
- **zone**: String - The owner name for the SOA record
- **ttl**: Unsigned integer - The TTL of the SOA record
- **mname**: String - The mname of the SOA record
- **rname**: String - The rname of the SOA record
- **soa_parameters**: :ref:`SOAParams <yaml-settings-SOAParams>` - The fields of the SOA record
- **soa_in_authority**: Boolean ``(false)`` - Whether the SOA record should be the authority section for a complete NXDOMAIN/NODATA response that works as a cacheable negative response, rather than the RPZ-style response with a purely informational SOA in the additional section. Default is false (SOA in additional section)
- **vars**: :ref:`ResponseConfig <yaml-settings-ResponseConfig>` - Response options


.. _yaml-settings-NoneAction:

NoneAction
----------

Does nothing. Subsequent rules are processed after this action

Lua equivalent: :func:`NoneAction`

.. _yaml-settings-PoolAction:

PoolAction
----------

Send the packet into the specified pool. If ``stop_processing`` is set to ``false``, subsequent rules will be processed after this action

Lua equivalent: :func:`PoolAction`

Parameters:

- **pool_name**: String - The name of the pool
- **stop_processing**: Boolean ``(true)`` - Whether subsequent rules should be executed after this one


.. _yaml-settings-QPSAction:

QPSAction
---------

Drop a packet if it does exceed the ``limit`` queries per second limit. Letting the subsequent rules apply otherwise

Lua equivalent: :func:`QPSAction`

Parameters:

- **limit**: Unsigned integer - The QPS limit


.. _yaml-settings-QPSPoolAction:

QPSPoolAction
-------------

Send the packet into the specified pool only if it does not exceed the ``limit`` queries per second limit. If ``stop-processing`` is set to ``false``, subsequent rules will be processed after this action. Letting the subsequent rules apply otherwise

Lua equivalent: :func:`QPSPoolAction`

Parameters:

- **limit**: Unsigned integer - The QPS limit
- **pool_name**: String - The name of the pool
- **stop_processing**: Boolean ``(true)`` - Whether subsequent rules should be executed after this one


.. _yaml-settings-RCodeAction:

RCodeAction
-----------

Reply immediately by turning the query into a response with the specified rcode

Lua equivalent: :func:`RCodeAction`

Parameters:

- **rcode**: Unsigned integer - The response code
- **vars**: :ref:`ResponseConfig <yaml-settings-ResponseConfig>` - Response options


.. _yaml-settings-RemoteLogAction:

RemoteLogAction
---------------

Send the current query to a remote logger as a Protocol Buffer message. ``alter_function`` is a callback, receiving a :class:`DNSQuestion` and a :class:`DNSDistProtoBufMessage`, that can be used to modify the message, for example for anonymization purposes. Subsequent rules are processed after this action

Lua equivalent: :func:`RemoteLogAction`

Parameters:

- **logger_name**: String - The name of the protocol buffer logger
- **alter_function_name**: String ``("")`` - The name of the Lua function
- **alter_function_code**: String ``("")`` - The code of the Lua function
- **alter_function_file**: String ``("")`` - The path to a file containing the code of the Lua function
- **server_id**: String ``("")`` - Set the Server Identity field
- **ip_encrypt_key**: String ``("")`` - A key, that can be generated via the :func:`makeIPCipherKey` function, to encrypt the IP address of the requestor for anonymization purposes. The encryption is done using ipcrypt for IPv4 and a 128-bit AES ECB operation for IPv6
- **export_tags**: Sequence of String ``("")`` - The comma-separated list of keys of internal tags to export into the ``tags`` Protocol Buffer field, as ``key:value`` strings. Note that a tag with an empty value will be exported as ``<key>``, not ``<key>:``. An empty string means that no internal tag will be exported. The special value ``*`` means that all tags will be exported
- **metas**: Sequence of :ref:`ProtoBufMetaConfiguration <yaml-settings-ProtoBufMetaConfiguration>` - A list of ``name``=``key`` pairs, for meta-data to be added to Protocol Buffer message


.. _yaml-settings-SetAdditionalProxyProtocolValueAction:

SetAdditionalProxyProtocolValueAction
-------------------------------------

Add a Proxy-Protocol Type-Length value to be sent to the server along with this query. It does not replace any existing value with the same type but adds a new value. Be careful that Proxy Protocol values are sent once at the beginning of the TCP connection for TCP and DoT queries. That means that values received on an incoming TCP connection will be inherited by subsequent queries received over the same incoming TCP connection, if any, but values set to a query will not be inherited by subsequent queries. Subsequent rules are processed after this action

Lua equivalent: :func:`SetAdditionalProxyProtocolValueAction`

Parameters:

- **proxy_type**: Unsigned integer - The proxy protocol type
- **value**: String - The value


.. _yaml-settings-SetDisableECSAction:

SetDisableECSAction
-------------------

Disable the sending of ECS to the backend. This does not remove any existing EDNS Client Subnet value sent by the client, please have a look at :ref:`yaml-settings-SetEDNSOptionAction` instead. Subsequent rules are processed after this action

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

- **ipv4**: String - The IPv4 netmask, for example 192.0.2.1/32
- **ipv6**: String ``("")`` - The IPv6 netmask, if any


.. _yaml-settings-SetECSOverrideAction:

SetECSOverrideAction
--------------------

Whether an existing EDNS Client Subnet value should be overridden (true) or not (false). Subsequent rules are processed after this action

Lua equivalent: :func:`SetECSOverrideAction`

Parameters:

- **override_existing**: Boolean - Whether to override an existing EDNS Client Subnet value


.. _yaml-settings-SetECSPrefixLengthAction:

SetECSPrefixLengthAction
------------------------

Set the ECS prefix length. Subsequent rules are processed after this action

Lua equivalent: :func:`SetECSPrefixLengthAction`

Parameters:

- **ipv4**: Unsigned integer - The IPv4 netmask length
- **ipv6**: Unsigned integer - The IPv6 netmask length


.. _yaml-settings-SetExtendedDNSErrorAction:

SetExtendedDNSErrorAction
-------------------------

Set an Extended DNS Error status that will be added to the response corresponding to the current query. Subsequent rules are processed after this action

Lua equivalent: :func:`SetExtendedDNSErrorAction`

Parameters:

- **info_code**: Unsigned integer - The EDNS Extended DNS Error code
- **extra_text**: String ``("")`` - The optional EDNS Extended DNS Error extra text


.. _yaml-settings-SetMacAddrAction:

SetMacAddrAction
----------------

Add the source MAC address to the query as an EDNS0 option. This action is currently only supported on Linux. Subsequent rules are processed after this action

Lua equivalent: :func:`SetMacAddrAction`

Parameters:

- **code**: Unsigned integer - The EDNS option code


.. _yaml-settings-SetMaxReturnedTTLAction:

SetMaxReturnedTTLAction
-----------------------

Cap the TTLs of the response to the given maximum, but only after inserting the response into the packet cache with the initial TTL value

Lua equivalent: :func:`SetMaxReturnedTTLAction`

Parameters:

- **max**: Unsigned integer - The TTL cap


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

- **values**: Sequence of :ref:`ProxyProtocolValueConfiguration <yaml-settings-ProxyProtocolValueConfiguration>` - List of proxy protocol values


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

- **tag**: String - The tag name
- **value**: String - The tag value


.. _yaml-settings-SetTempFailureCacheTTLAction:

SetTempFailureCacheTTLAction
----------------------------

Set the cache TTL to use for ServFail and Refused replies. TTL is not applied for successful replies. Subsequent rules are processed after this action

Lua equivalent: :func:`SetTempFailureCacheTTLAction`

Parameters:

- **ttl**: Unsigned integer - The TTL to use


.. _yaml-settings-SNMPTrapAction:

SNMPTrapAction
--------------

Send an SNMP trap, adding the message string as the query description. Subsequent rules are processed after this action

Lua equivalent: :func:`SNMPTrapAction`

Parameters:

- **reason**: String ``("")`` - The SNMP trap reason


.. _yaml-settings-SpoofAction:

SpoofAction
-----------

Forge a response with the specified IPv4 (for an A query) or IPv6 (for an AAAA) addresses. If you specify multiple addresses, all that match the query type (A, AAAA or ANY) will get spoofed in

Lua equivalent: :func:`SpoofAction`

Parameters:

- **ips**: Sequence of String - List of IP addresses to spoof
- **vars**: :ref:`ResponseConfig <yaml-settings-ResponseConfig>` - Response options


.. _yaml-settings-SpoofCNAMEAction:

SpoofCNAMEAction
----------------

Forge a response with the specified CNAME value. Please be aware that DNSdist will not chase the target of the CNAME, so it will not be present in the response which might be a problem for stub resolvers that do not know how to follow a CNAME

Lua equivalent: :func:`SpoofCNAMEAction`

Parameters:

- **cname**: String - The CNAME to use in the response
- **vars**: :ref:`ResponseConfig <yaml-settings-ResponseConfig>` - Response options


.. _yaml-settings-SpoofPacketAction:

SpoofPacketAction
-----------------

Spoof a raw self-generated answer

Lua equivalent: :func:`SpoofPacketAction`

Parameters:

- **response**: String - The DNS packet
- **len**: Unsigned integer - The length of the DNS packet


.. _yaml-settings-SpoofRawAction:

SpoofRawAction
--------------

Forge a response with the specified raw bytes as record data
.. code-block:: Lua

  -- select queries for the 'raw.powerdns.com.' name and TXT type, and answer with both a "aaa" "bbbb" and "ccc" TXT record:
  addAction(AndRule({QNameRule('raw.powerdns.com.'), QTypeRule(DNSQType.TXT)}), SpoofRawAction({"\003aaa\004bbbb", "\003ccc"}))
  -- select queries for the 'raw-srv.powerdns.com.' name and SRV type, and answer with a '0 0 65535 srv.powerdns.com.' SRV record, setting the AA bit to 1 and the TTL to 3600s
  addAction(AndRule({QNameRule('raw-srv.powerdns.com.'), QTypeRule(DNSQType.SRV)}), SpoofRawAction("\000\000\000\000\255\255\003srv\008powerdns\003com\000", { aa=true, ttl=3600 }))
  -- select reverse queries for '127.0.0.1' and answer with 'localhost'
  addAction(AndRule({QNameRule('1.0.0.127.in-addr.arpa.'), QTypeRule(DNSQType.PTR)}), SpoofRawAction("\009localhost\000"))
  -- rfc8482: Providing Minimal-Sized Responses to DNS Queries That Have QTYPE=ANY via HINFO of value "rfc8482"
  addAction(QTypeRule(DNSQType.ANY), SpoofRawAction("\007rfc\056\052\056\050\000", { typeForAny=DNSQType.HINFO }))

:func:`DNSName:toDNSString` is convenient for converting names to wire format for passing to ``SpoofRawAction``.

``sdig dumpluaraw`` and ``pdnsutil raw-lua-from-content`` from PowerDNS can generate raw answers for you:

.. code-block:: Shell

  $ pdnsutil raw-lua-from-content SRV '0 0 65535 srv.powerdns.com.'
  "\000\000\000\000\255\255\003srv\008powerdns\003com\000"
  $ sdig 127.0.0.1 53 open-xchange.com MX recurse dumpluaraw
  Reply to question for qname='open-xchange.com.', qtype=MX
  Rcode: 0 (No Error), RD: 1, QR: 1, TC: 0, AA: 0, opcode: 0
  0 open-xchange.com. IN  MX  "\000c\004mx\049\049\012open\045xchange\003com\000"
  0 open-xchange.com. IN  MX  "\000\010\003mx\049\012open\045xchange\003com\000"
  0 open-xchange.com. IN  MX  "\000\020\003mx\050\012open\045xchange\003com\000"


Lua equivalent: :func:`SpoofRawAction`

Parameters:

- **answers**: Sequence of String - A list of DNS record content entries to use in the response
- **qtype_for_any**: String ``("")`` - The type to use for ANY queries
- **vars**: :ref:`ResponseConfig <yaml-settings-ResponseConfig>` - Response options


.. _yaml-settings-SpoofSVCAction:

SpoofSVCAction
--------------

Forge a response with the specified ``SVC`` record data. If the list contains more than one ``SVC`` parameter, they are all returned, and should have different priorities. The hints provided in the SVC parameters, if any, will also be added as ``A``/``AAAA`` records in the additional section, using the target name present in the parameters as owner name if it’s not empty (root) and the qname instead

Lua equivalent: :func:`SpoofSVCAction`

Parameters:

- **parameters**: Sequence of :ref:`SVCRecordParameters <yaml-settings-SVCRecordParameters>` - List of SVC record parameters
- **vars**: :ref:`ResponseConfig <yaml-settings-ResponseConfig>` - Response options


.. _yaml-settings-TCAction:

TCAction
--------

Create answer to query with the ``TC`` bit set, and the ``RA`` bit set to the value of ``RD`` in the query, to force the client to TCP

Lua equivalent: :func:`TCAction`

.. _yaml-settings-TeeAction:

TeeAction
---------

Send copy of query to remote, keep stats on responses. If ``add_ecs`` is set to true, EDNS Client Subnet information will be added to the query. If ``add_proxy_protocol`` is set to true, a Proxy Protocol v2 payload will be prepended in front of the query. The payload will contain the protocol the initial query was received over (UDP or TCP), as well as the initial source and destination addresses and ports. If ``lca`` has provided a value like “192.0.2.53”, dnsdist will try binding that address as local address when sending the queries. Subsequent rules are processed after this action

Lua equivalent: :func:`TeeAction`

Parameters:

- **rca**: String - The address and port of the remote server
- **lca**: String ``("")`` - The source address to use to send packets to the remote server
- **add_ecs**: Boolean ``(false)`` - Whether to add EDNS Client Subnet to the query
- **add_proxy_protocol**: Boolean ``(false)`` - Whether to add a proxy protocol payload to the query


