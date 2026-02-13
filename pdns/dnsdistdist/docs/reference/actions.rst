Rule Actions
============

:doc:`selectors` need to be combined with an action for them to actually do something with the matched packets.
This page describes the ``Lua`` versions of these actions, for the ``YAML`` version please see :doc:`yaml-actions` and :doc:`yaml-response-actions`.

Some actions allow further processing of rules, this is noted in their description. Most of these start with 'Set' with a few exceptions, mostly for logging actions. These exceptions are:

- :func:`ClearRecordTypesResponseAction`
- :func:`KeyValueStoreLookupAction`
- :func:`DnstapLogAction`
- :func:`DnstapLogResponseAction`
- :func:`LimitTTLResponseAction`
- :func:`LogAction`
- :func:`LogResponseAction`
- :func:`NoneAction`
- :func:`RemoteLogAction`
- :func:`RemoteLogResponseAction`
- :func:`SNMPTrapAction`
- :func:`SNMPTrapResponseAction`
- :func:`TeeAction`

The following actions exist.

.. function:: AllowAction()

  Let these packets go through.

.. function:: AllowResponseAction()

  Let these packets go through.

.. function:: ClearRecordTypesResponseAction(types)

  .. versionadded:: 1.8.0

  Removes given type(s) records from the response. Beware you can accidentally turn the answer into a NODATA response
  without a SOA record in the additional section in which case you may want to use :func:`NegativeAndSOAAction` to generate an answer,
  see example below.
  Subsequent rules are processed after this action.

  .. code-block:: Lua

    -- removes any HTTPS record in the response
    addResponseAction(
            QNameRule('www.example.com.'),
            ClearRecordTypesResponseAction(DNSQType.HTTPS)
    )
    -- reply directly with NODATA and a SOA record as we know the answer will be empty
    addAction(
            AndRule{QNameRule('www.example.com.'), QTypeRule(DNSQType.HTTPS)},
            NegativeAndSOAAction(false, 'example.com.', 3600, 'ns.example.com.', 'postmaster.example.com.', 1, 1800, 900, 604800, 86400)
    )

  :param int types: a single type or a list of types to remove

.. function:: ContinueAction(action)

  .. versionadded:: 1.4.0

  Execute the specified action and override its return with None, making it possible to continue the processing.
  Subsequent rules are processed after this action.

  :param Action action: Any other action

.. function:: DelayAction(milliseconds)

  Delay the response by the specified amount of milliseconds (UDP-only). Note that the sending of the query to the backend, if needed,
  is not delayed. Only the sending of the response to the client will be delayed.
  Subsequent rules are processed after this action.

  :param int milliseconds: The amount of milliseconds to delay the response

.. function:: DelayResponseAction(milliseconds)

  Delay the response by the specified amount of milliseconds (UDP-only).
  The only difference between this action and  :func:`DelayAction` is that they can only be applied on, respectively, responses and queries.
  Subsequent rules are processed after this action.

  :param int milliseconds: The amount of milliseconds to delay the response

.. function:: DisableECSAction()

  .. deprecated:: 1.6.0

  This function has been deprecated in 1.6.0 and removed in 1.7.0, please use :func:`SetDisableECSAction` instead.

  Disable the sending of ECS to the backend.
  Subsequent rules are processed after this action.

.. function:: DisableValidationAction()

  .. deprecated:: 1.6.0

  This function has been deprecated in 1.6.0 and removed in 1.7.0, please use :func:`SetDisableValidationAction` instead.

  Set the CD bit in the query and let it go through.
  Subsequent rules are processed after this action.

.. function:: DnstapLogAction(identity, logger[, alterFunction])

  Send the current query to a remote logger as a :doc:`dnstap <dnstap>` message.
  ``alterFunction`` is a callback, receiving a :class:`DNSQuestion` and a :class:`DnstapMessage`, that can be used to modify the message.
  Subsequent rules are processed after this action.

  :param string identity: Server identity to store in the dnstap message
  :param logger: The :func:`FrameStreamLogger <newFrameStreamUnixLogger>` or :func:`RemoteLogger <newRemoteLogger>` object to write to
  :param alterFunction: A Lua function to alter the message before sending

.. function:: DnstapLogResponseAction(identity, logger[, alterFunction])

  Send the current response to a remote logger as a :doc:`dnstap <dnstap>` message.
  ``alterFunction`` is a callback, receiving a :class:`DNSQuestion` and a :class:`DnstapMessage`, that can be used to modify the message.
  Subsequent rules are processed after this action.

  :param string identity: Server identity to store in the dnstap message
  :param logger: The :func:`FrameStreamLogger <newFrameStreamUnixLogger>` or :func:`RemoteLogger <newRemoteLogger>` object to write to
  :param alterFunction: A Lua function to alter the message before sending

.. function:: DropAction()

  Drop the packet.

.. function:: DropResponseAction()

  Drop the packet.

.. function:: ECSOverrideAction(override)

  .. deprecated:: 1.6.0

  This function has been deprecated in 1.6.0 and removed in 1.7.0, please use :func:`SetECSOverrideAction` instead.

  Whether an existing EDNS Client Subnet value should be overridden (true) or not (false).
  Subsequent rules are processed after this action.

  :param bool override: Whether or not to override ECS value

.. function:: ECSPrefixLengthAction(v4, v6)

  .. deprecated:: 1.6.0

  This function has been deprecated in 1.6.0 and removed in 1.7.0, please use :func:`SetECSPrefixLengthAction` instead.

  Set the ECS prefix length.
  Subsequent rules are processed after this action.

  :param int v4: The IPv4 netmask length
  :param int v6: The IPv6 netmask length

.. function:: ERCodeAction(rcode [, options])

  .. versionadded:: 1.4.0

  .. versionchanged:: 1.5.0
    Added the optional parameter ``options``.

  Reply immediately by turning the query into a response with the specified EDNS extended ``rcode``.
  ``rcode`` can be specified as an integer or as one of the built-in :ref:`DNSRCode`.

  :param int rcode: The extended RCODE to respond with.
  :param table options: A table with key: value pairs with options.

  Options:

  * ``aa``: bool - Set the AA bit to this value (true means the bit is set, false means it's cleared). Default is to clear it.
  * ``ad``: bool - Set the AD bit to this value (true means the bit is set, false means it's cleared). Default is to clear it.
  * ``ra``: bool - Set the RA bit to this value (true means the bit is set, false means it's cleared). Default is to copy the value of the RD bit from the incoming query.

.. function:: HTTPStatusAction(status, body, contentType="" [, options])

  .. versionadded:: 1.4.0

  .. versionchanged:: 1.5.0
    Added the optional parameter ``options``.

  .. versionchanged:: 2.0.0
    The ``options`` parameter is now deprecated.

  Return an HTTP response with a status code of ''status''. For HTTP redirects, ''body'' should be the redirect URL.

  :param int status: The HTTP status code to return.
  :param string body: The body of the HTTP response, or a URL if the status code is a redirect (3xx).
  :param string contentType: The HTTP Content-Type header to return for a 200 response, ignored otherwise. Default is ''application/dns-message''.
  :param table options: A table with key: value pairs with options. Deprecated since 2.0.0 as it had unexpected side-effects.

  Options:

  * ``aa``: bool - Set the AA bit to this value (true means the bit is set, false means it's cleared). Default is to clear it.
  * ``ad``: bool - Set the AD bit to this value (true means the bit is set, false means it's cleared). Default is to clear it.
  * ``ra``: bool - Set the RA bit to this value (true means the bit is set, false means it's cleared). Default is to copy the value of the RD bit from the incoming query.

.. function:: KeyValueStoreLookupAction(kvs, lookupKey, destinationTag)

  .. versionadded:: 1.4.0

  Does a lookup into the key value store referenced by 'kvs' using the key returned by 'lookupKey',
  and storing the result if any into the tag named 'destinationTag'.
  The store can be a CDB (:func:`newCDBKVStore`) or a LMDB database (:func:`newLMDBKVStore`).
  The key can be based on the qname (:func:`KeyValueLookupKeyQName` and :func:`KeyValueLookupKeySuffix`),
  source IP (:func:`KeyValueLookupKeySourceIP`) or the value of an existing tag (:func:`KeyValueLookupKeyTag`).
  Subsequent rules are processed after this action.
  Note that the tag is always created, even if there was no match, but in that case the content is empty.

  :param KeyValueStore kvs: The key value store to query
  :param KeyValueLookupKey lookupKey: The key to use for the lookup
  :param string destinationTag: The name of the tag to store the result into

.. function:: KeyValueStoreRangeLookupAction(kvs, lookupKey, destinationTag)

  .. versionadded:: 1.7.0

  Does a range-based lookup into the key value store referenced by 'kvs' using the key returned by 'lookupKey',
  and storing the result if any into the tag named 'destinationTag'.
  This assumes that there is a key in network byte order for the last element of the range (for example 2001:0db8:ffff:ffff:ffff:ffff:ffff:ffff for 2001:db8::/32) which contains the first element of the range (2001:0db8:0000:0000:0000:0000:0000:0000) (optionally followed by any data) as value, also in network byte order, and that there is no overlapping ranges in the database.
  This requires that the underlying store supports ordered keys, which is true for LMDB but not for CDB.

  Subsequent rules are processed after this action.

  :param KeyValueStore kvs: The key value store to query
  :param KeyValueLookupKey lookupKey: The key to use for the lookup
  :param string destinationTag: The name of the tag to store the result into

.. function:: LimitTTLResponseAction(min[, max [, types]])

  .. versionadded:: 1.8.0

  Cap the TTLs of the response to the given boundaries.

  :param int min: The minimum allowed value
  :param int max: The maximum allowed value
  :param table types: The record types to cap the TTL for, as integers. Default is empty which means all records will be capped.

.. function:: LogAction([filename[, binary[, append[, buffered[, verboseOnly[, includeTimestamp]]]]]])

  .. versionchanged:: 1.4.0
    Added the optional parameters ``verboseOnly`` and ``includeTimestamp``, made ``filename`` optional.

  .. versionchanged:: 1.7.0
    Added the ``reload`` method.

  Log a line for each query, to the specified ``file`` if any, to the console (require verbose) if the empty string is given as filename.

  If an empty string is supplied in the file name, the logging is done to stdout, and only in verbose mode by default. This can be changed by setting ``verboseOnly`` to false.

  When logging to a file, the ``binary`` optional parameter specifies whether we log in binary form (default) or in textual form. Before 1.4.0 the binary log format only included the qname and qtype. Since 1.4.0 it includes an optional timestamp, the query ID, qname, qtype, remote address and port.

  The ``append`` optional parameter specifies whether we open the file for appending or truncate each time (default).
  The ``buffered`` optional parameter specifies whether writes to the file are buffered (default) or not.

  Since 1.7.0 calling the ``reload()`` method on the object will cause it to close and re-open the log file, for rotation purposes.

  Subsequent rules are processed after this action.

  :param string filename: File to log to. Set to an empty string to log to the normal stdout log, this only works when ``-v`` is set on the command line.
  :param bool binary: Do binary logging. Default true
  :param bool append: Append to the log. Default false
  :param bool buffered: Use buffered I/O. Default true
  :param bool verboseOnly: Whether to log only in verbose mode when logging to stdout. Default is true
  :param bool includeTimestamp: Whether to include a timestamp for every entry. Default is false

.. function:: LogResponseAction([filename[, append[, buffered[, verboseOnly[, includeTimestamp]]]]]])

  .. versionadded:: 1.5.0

  .. versionchanged:: 1.7.0
    Added the ``reload`` method.

  Log a line for each response, to the specified ``file`` if any, to the console (require verbose) if the empty string is given as filename.

  If an empty string is supplied in the file name, the logging is done to stdout, and only in verbose mode by default. This can be changed by setting ``verboseOnly`` to false.

  The ``append`` optional parameter specifies whether we open the file for appending or truncate each time (default).
  The ``buffered`` optional parameter specifies whether writes to the file are buffered (default) or not.

  Since 1.7.0 calling the ``reload()`` method on the object will cause it to close and re-open the log file, for rotation purposes.

  Subsequent rules are processed after this action.

  :param string filename: File to log to. Set to an empty string to log to the normal stdout log, this only works when ``-v`` is set on the command line.
  :param bool append: Append to the log. Default false
  :param bool buffered: Use buffered I/O. Default true
  :param bool verboseOnly: Whether to log only in verbose mode when logging to stdout. Default is true
  :param bool includeTimestamp: Whether to include a timestamp for every entry. Default is false

.. function:: LuaAction(function)

  Invoke a Lua function that accepts a :class:`DNSQuestion`.

  The ``function`` should return a :ref:`DNSAction`. If the Lua code fails, ServFail is returned.

  :param string function: the name of a Lua function

.. function:: LuaFFIAction(function)

  .. versionadded:: 1.5.0

  Invoke a Lua FFI function that accepts a pointer to a ``dnsdist_ffi_dnsquestion_t`` object, whose bindings are defined in ``dnsdist-lua-ffi-interface.h``.

  The ``function`` should return a :ref:`DNSAction`. If the Lua code fails, ServFail is returned.

  :param string function: the name of a Lua function

.. function:: LuaFFIPerThreadAction(function)

  .. versionadded:: 1.7.0

  Invoke a Lua FFI function that accepts a pointer to a ``dnsdist_ffi_dnsquestion_t`` object, whose bindings are defined in ``dnsdist-lua-ffi-interface.h``.

  The ``function`` should return a :ref:`DNSAction`. If the Lua code fails, ServFail is returned.

  The function will be invoked in a per-thread Lua state, without access to the global Lua state. All constants (:ref:`DNSQType`, :ref:`DNSRCode`, ...) are available in that per-thread context,
  as well as all FFI functions. Objects and their bindings that are not usable in a FFI context (:class:`DNSQuestion`, :class:`DNSDistProtoBufMessage`, :class:`PacketCache`, ...)
  are not available.

  :param string function: a Lua string returning a Lua function

.. function:: LuaFFIPerThreadResponseAction(function)

  .. versionadded:: 1.7.0

  Invoke a Lua FFI function that accepts a pointer to a ``dnsdist_ffi_dnsquestion_t`` object, whose bindings are defined in ``dnsdist-lua-ffi-interface.h``.

  The ``function`` should return a :ref:`DNSResponseAction`. If the Lua code fails, ServFail is returned.

  The function will be invoked in a per-thread Lua state, without access to the global Lua state. All constants (:ref:`DNSQType`, :ref:`DNSRCode`, ...) are available in that per-thread context,
  as well as all FFI functions. Objects and their bindings that are not usable in a FFI context (:class:`DNSQuestion`, :class:`DNSDistProtoBufMessage`, :class:`PacketCache`, ...)
  are not available.

  :param string function: a Lua string returning a Lua function

.. function:: LuaFFIResponseAction(function)

  .. versionadded:: 1.5.0

  Invoke a Lua FFI function that accepts a pointer to a ``dnsdist_ffi_dnsquestion_t`` object, whose bindings are defined in ``dnsdist-lua-ffi-interface.h``.

  The ``function`` should return a :ref:`DNSResponseAction`. If the Lua code fails, ServFail is returned.

  :param string function: the name of a Lua function

.. function:: LuaResponseAction(function)

  Invoke a Lua function that accepts a :class:`DNSResponse`.

  The ``function`` should return a :ref:`DNSResponseAction`. If the Lua code fails, ServFail is returned.

  :param string function: the name of a Lua function

.. function:: MacAddrAction(option)

  .. deprecated:: 1.6.0

  This function has been deprecated in 1.6.0 and removed in 1.7.0, please use :func:`SetMacAddrAction` instead.

  Add the source MAC address to the query as EDNS0 option ``option``.
  This action is currently only supported on Linux.
  Subsequent rules are processed after this action.

  :param int option: The EDNS0 option number

.. function:: NegativeAndSOAAction(nxd, zone, ttl, mname, rname, serial, refresh, retry, expire, minimum [, options])

  .. versionadded:: 1.6.0

  .. versionchanged:: 1.8.0
    Added the ``soaInAuthoritySection`` option.

  Turn a question into a response, either a NXDOMAIN or a NODATA one based on ''nxd'', setting the QR bit to 1 and adding a SOA record in the additional section.
  Note that this function was called :func:`SetNegativeAndSOAAction` before 1.6.0.

  :param bool nxd: Whether the answer is a NXDOMAIN (true) or a NODATA (false)
  :param string zone: The owner name for the SOA record
  :param int ttl: The TTL of the SOA record
  :param string mname: The mname of the SOA record
  :param string rname: The rname of the SOA record
  :param int serial: The value of the serial field in the SOA record
  :param int refresh: The value of the refresh field in the SOA record
  :param int retry: The value of the retry field in the SOA record
  :param int expire: The value of the expire field in the SOA record
  :param int minimum: The value of the minimum field in the SOA record
  :param table options: A table with key: value pairs with options

  Options:

  * ``aa``: bool - Set the AA bit to this value (true means the bit is set, false means it's cleared). Default is to clear it.
  * ``ad``: bool - Set the AD bit to this value (true means the bit is set, false means it's cleared). Default is to clear it.
  * ``ra``: bool - Set the RA bit to this value (true means the bit is set, false means it's cleared). Default is to copy the value of the RD bit from the incoming query.
  * ``soaInAuthoritySection``: bool - Place the SOA record in the authority section for a complete NXDOMAIN/NODATA response that works as a cacheable negative response, rather than the RPZ-style response with a purely informational SOA in the additional section. Default is false (SOA in additional section).

.. function:: NoneAction()

  Does nothing.
  Subsequent rules are processed after this action.

.. function:: NoRecurseAction()

  .. deprecated:: 1.6.0

  This function has been deprecated in 1.6.0 and removed in 1.7.0, please use :func:`SetNoRecurseAction` instead.

  Strip RD bit from the question, let it go through.
  Subsequent rules are processed after this action.

.. function:: PoolAction(poolname [, stop])

  .. versionchanged:: 1.8.0
    Added the ``stop`` optional parameter.

  Send the packet into the specified pool. If ``stop`` is set to false, subsequent rules will be processed after this action.

  :param string poolname: The name of the pool
  :param bool stop: Whether to stop processing rules after this action. Default is true, meaning the remaining rules will not be processed.

.. function:: QPSAction(maxqps)

  Drop a packet if it does exceed the ``maxqps`` queries per second limits.
  Letting the subsequent rules apply otherwise.

  :param int maxqps: The QPS limit

.. function:: QPSPoolAction(maxqps, poolname [, stop])

  .. versionchanged:: 1.8.0
    Added the ``stop`` optional parameter.

  Send the packet into the specified pool only if it does not exceed the ``maxqps`` queries per second limits. If ``stop`` is set to false, subsequent rules will be processed after this action.
  Letting the subsequent rules apply otherwise.

  :param int maxqps: The QPS limit for that pool
  :param string poolname: The name of the pool
  :param bool stop: Whether to stop processing rules after this action. Default is true, meaning the remaining rules will not be processed.

.. function:: RCodeAction(rcode [, options])

  .. versionchanged:: 1.5.0
    Added the optional parameter ``options``.

  Reply immediately by turning the query into a response with the specified ``rcode``.
  ``rcode`` can be specified as an integer or as one of the built-in :ref:`DNSRCode`.

  :param int rcode: The RCODE to respond with.
  :param table options: A table with key: value pairs with options.

  Options:

  * ``aa``: bool - Set the AA bit to this value (true means the bit is set, false means it's cleared). Default is to clear it.
  * ``ad``: bool - Set the AD bit to this value (true means the bit is set, false means it's cleared). Default is to clear it.
  * ``ra``: bool - Set the RA bit to this value (true means the bit is set, false means it's cleared). Default is to copy the value of the RD bit from the incoming query.

.. function:: RemoteLogAction(remoteLogger[, alterFunction [, options [, metas]]])

  .. versionchanged:: 1.4.0
    ``ipEncryptKey`` optional key added to the options table.

  .. versionchanged:: 1.8.0
    ``metas`` optional parameter added.
    ``exportTags`` optional key added to the options table.

  Send the content of this query to a remote logger via Protocol Buffer.
  ``alterFunction`` is a callback, receiving a :class:`DNSQuestion` and a :class:`DNSDistProtoBufMessage`, that can be used to modify the Protocol Buffer content, for example for anonymization purposes.
  Since 1.8.0 it is possible to add configurable meta-data fields to the Protocol Buffer message via the ``metas`` parameter, which takes a list of ``name``=``key`` pairs. For each entry in the list, a new value named ``name``
  will be added to the message with the value corresponding to the ``key``. Available keys are:

  * ``doh-header:<HEADER>``: the content of the corresponding ``<HEADER>`` HTTP header for DoH queries, empty otherwise
  * ``doh-host``: the ``Host`` header for DoH queries, empty otherwise
  * ``doh-path``: the HTTP path for DoH queries, empty otherwise
  * ``doh-query-string``: the HTTP query string for DoH queries, empty otherwise
  * ``doh-scheme``: the HTTP scheme for DoH queries, empty otherwise
  * ``pool``: the currently selected pool of servers
  * ``proxy-protocol-value:<TYPE>``: the content of the proxy protocol value of type ``<TYPE>``, if any
  * ``proxy-protocol-values``: the content of all proxy protocol values as a "<type1>:<value1>", ..., "<typeN>:<valueN>" strings
  * ``b64-content``: the base64-encoded DNS payload of the current query
  * ``sni``: the Server Name Indication value for queries received over DoT or DoH. Empty otherwise.
  * ``tag:<TAG>``: the content of the corresponding ``<TAG>`` if any
  * ``tags``: the list of all tags, and their values, as a "<key1>:<value1>", ..., "<keyN>:<valueN>" strings. Note that a tag with an empty value will be exported as "<key>", not "<key>:".

  Subsequent rules are processed after this action.

  :param string remoteLogger: The :func:`remoteLogger <newRemoteLogger>` object to write to
  :param string alterFunction: Name of a function to modify the contents of the logs before sending
  :param table options: A table with key: value pairs.
  :param table metas: A list of ``name``=``key`` pairs, for meta-data to be added to Protocol Buffer message.

  Options:

  * ``serverID=""``: str - Set the Server Identity field.
  * ``ipEncryptKey=""``: str - A key, that can be generated via the :func:`makeIPCipherKey` function, to encrypt the IP address of the requestor for anonymization purposes. The encryption is done using ipcrypt for IPv4 and a 128-bit AES ECB operation for IPv6.
  * ``exportTags=""``: str - The comma-separated list of keys of internal tags to export into the ``tags`` Protocol Buffer field, as "key:value" strings. Note that a tag with an empty value will be exported as "<key>", not "<key>:". An empty string means that no internal tag will be exported. The special value ``*`` means that all tags will be exported.

.. function:: RemoteLogResponseAction(remoteLogger[, alterFunction[, includeCNAME [, options [, metas [, delay]]]]])

  .. versionchanged:: 1.4.0
    ``ipEncryptKey`` optional key added to the options table.

  .. versionchanged:: 1.8.0
    ``metas`` optional parameter added.
    ``exportTags`` optional key added to the options table.

  .. versionchanged:: 1.9.0
    ``exportExtendedErrorsToMeta`` optional key added to the options table.

  .. versionchanged:: 2.1.0
    ``delay`` optional parameter added.

  Send the content of this response to a remote logger via Protocol Buffer.
  ``alterFunction`` is the same callback that receiving a :class:`DNSResponse` and a :class:`DNSDistProtoBufMessage`, that can be used to modify the Protocol Buffer content, for example for anonymization purposes.
  ``includeCNAME`` indicates whether CNAME records inside the response should be parsed and exported.
  The default is to only exports A and AAAA records.
  Since 1.8.0 it is possible to add configurable meta-data fields to the Protocol Buffer message via the ``metas`` parameter, which takes a list of ``name``=``key`` pairs. See :func:`RemoteLogAction` for the list of available keys.
  Subsequent rules are processed after this action.

  :param string remoteLogger: The :func:`remoteLogger <newRemoteLogger>` object to write to
  :param string alterFunction: Name of a function to modify the contents of the logs before sending
  :param bool includeCNAME: Whether or not to parse and export CNAMEs. Default false
  :param table options: A table with key: value pairs.
  :param table metas: A list of ``name``=``key`` pairs, for meta-data to be added to Protocol Buffer message.
  :param bool delay: Delay sending the protobuf until after the DNS response has been sent to the client. Default false.

  Options:

  * ``serverID=""``: str - Set the Server Identity field.
  * ``ipEncryptKey=""``: str - A key, that can be generated via the :func:`makeIPCipherKey` function, to encrypt the IP address of the requestor for anonymization purposes. The encryption is done using ipcrypt for IPv4 and a 128-bit AES ECB operation for IPv6.
  * ``exportTags=""``: str - The comma-separated list of keys of internal tags to export into the ``tags`` Protocol Buffer field, as "key:value" strings. Note that a tag with an empty value will be exported as "<key>", not "<key>:". An empty string means that no internal tag will be exported. The special value ``*`` means that all tags will be exported.
  * ``exportExtendedErrorsToMeta=""``: str - Export Extended DNS Errors present in the DNS response, if any, into the ``meta`` Protocol Buffer field using the specified ``key``. The EDE info code will be exported as an integer value, and the EDE extra text, if present, as a string value.

.. function:: SetAdditionalProxyProtocolValueAction(type, value)

  .. versionadded:: 1.6.0

  Add a Proxy-Protocol Type-Length value to be sent to the server along with this query. It does not replace any
  existing value with the same type but adds a new value.
  Be careful that Proxy Protocol values are sent once at the beginning of the TCP connection for TCP and DoT queries.
  That means that values received on an incoming TCP connection will be inherited by subsequent queries received over
  the same incoming TCP connection, if any, but values set to a query will not be inherited by subsequent queries.
  Subsequent rules are processed after this action.

  :param int type: The type of the value to send, ranging from 0 to 255 (both included)
  :param str value: The binary-safe value

.. function:: SetDisableECSAction()

  .. versionadded:: 1.6.0

  Disable the addition of EDNS Client Subnet information by :program:`dnsdist` before passing queries to the backend.
  This does not remove any existing EDNS Client Subnet value sent by the client, please have a look at :func:`SetEDNSOptionAction` instead.
  Subsequent rules are processed after this action.
  Note that this function was called :func:`DisableECSAction` before 1.6.0.

.. function:: SetDisableValidationAction()

  .. versionadded:: 1.6.0

  Set the CD bit in the query and let it go through.
  Subsequent rules are processed after this action.
  Note that this function was called :func:`DisableValidationAction` before 1.6.0.

.. function:: SetECSAction(v4 [, v6])

  Set the ECS prefix and prefix length sent to backends to an arbitrary value.
  If both IPv4 and IPv6 masks are supplied the IPv4 one will be used for IPv4 clients
  and the IPv6 one for IPv6 clients. Otherwise, the first mask is used for both, and
  can actually be an IPv6 mask.
  Subsequent rules are processed after this action.

  :param string v4: The IPv4 netmask, for example "192.0.2.1/32"
  :param string v6: The IPv6 netmask, if any

.. function:: SetECSOverrideAction(override)

  .. versionadded:: 1.6.0

  Whether an existing EDNS Client Subnet value should be overridden (true) or not (false).
  Subsequent rules are processed after this action.
  Note that this function was called :func:`ECSOverrideAction` before 1.6.0.

  :param bool override: Whether or not to override ECS value

.. function:: SetECSPrefixLengthAction(v4, v6)

  .. versionadded:: 1.6.0

  Set the ECS prefix length.
  Subsequent rules are processed after this action.
  Note that this function was called :func:`ECSPrefixLengthAction` before 1.6.0.

  :param int v4: The IPv4 netmask length
  :param int v6: The IPv6 netmask length

.. function:: SetEDNSOptionAction(option)

  .. versionadded:: 1.7.0

  Add arbitrary EDNS option and data to the query. Any existing EDNS content with the same option code will be overwritten.
  Subsequent rules are processed after this action.

  :param int option: The EDNS option number
  :param string data: The EDNS0 option raw content

.. function:: SetEDNSOptionResponseAction(option)

  .. versionadded:: 1.9.11

  Add arbitrary EDNS option and data to the response. Any existing EDNS content with the same option code will be replaced.
  Subsequent rules are processed after this action.

  :param int option: The EDNS option number
  :param string data: The EDNS0 option raw content

.. function:: SetExtendedDNSErrorAction(infoCode [, extraText [, clearExistingEntries]])

  .. versionadded:: 1.9.0

  .. versionchanged:: 2.1.0
    ``clearExistingEntries`` optional parameter added.

  Set an Extended DNS Error status that will be added to the response corresponding to the current query.
  Subsequent rules are processed after this action.

  :param int infoCode: The EDNS Extended DNS Error code
  :param string extraText: The optional EDNS Extended DNS Error extra text
  :param bool clearExistingEntries: Whether to clear existing EDNS Extended DNS Error codes, default true

.. function:: SetExtendedDNSErrorResponseAction(infoCode [, extraText [, clearExistingEntries]])

  .. versionadded:: 1.9.0

  .. versionchanged:: 2.1.0
    ``clearExistingEntries`` optional parameter added.

  Set an Extended DNS Error status that will be added to this response.
  Subsequent rules are processed after this action.

  :param int infoCode: The EDNS Extended DNS Error code
  :param string extraText: The optional EDNS Extended DNS Error extra text
  :param bool clearExistingEntries: Whether to clear existing EDNS Extended DNS Error codes, default true

.. function:: SetMacAddrAction(option)

  .. versionadded:: 1.6.0

  Add the source MAC address to the query as EDNS0 option ``option``.
  This action is currently only supported on Linux.
  Subsequent rules are processed after this action.
  Note that this function was called :func:`MacAddrAction` before 1.6.0.

  :param int option: The EDNS0 option number

.. function:: SetMaxReturnedTTLAction(max)

  .. versionadded:: 1.8.0

  Cap the TTLs of the response to the given maximum, but only after inserting the response into the packet cache with the initial TTL values.

  :param int max: The maximum allowed value

.. function:: SetMaxReturnedTTLResponseAction(max)

  .. versionadded:: 1.8.0

  Cap the TTLs of the response to the given maximum, but only after inserting the response into the packet cache with the initial TTL values.

  :param int max: The maximum allowed value

.. function:: SetMaxTTLResponseAction(max)

  .. versionadded:: 1.8.0

  Cap the TTLs of the response to the given maximum.

  :param int max: The maximum allowed value

.. function:: SetMinTTLResponseAction(min)

  .. versionadded:: 1.8.0

  Cap the TTLs of the response to the given minimum.

  :param int min: The minimum allowed value

.. function:: SetNoRecurseAction()

  .. versionadded:: 1.6.0

  Strip RD bit from the question, let it go through.
  Subsequent rules are processed after this action.
  Note that this function was called :func:`NoRecurseAction` before 1.6.0.

.. function:: SetNegativeAndSOAAction(nxd, zone, ttl, mname, rname, serial, refresh, retry, expire, minimum [, options])

  .. versionadded:: 1.5.0

  .. deprecated:: 1.6.0

  This function has been deprecated in 1.6.0 and removed in 1.7.0, please use :func:`NegativeAndSOAAction` instead.

  Turn a question into a response, either a NXDOMAIN or a NODATA one based on ''nxd'', setting the QR bit to 1 and adding a SOA record in the additional section.

  :param bool nxd: Whether the answer is a NXDOMAIN (true) or a NODATA (false)
  :param string zone: The owner name for the SOA record
  :param int ttl: The TTL of the SOA record
  :param string mname: The mname of the SOA record
  :param string rname: The rname of the SOA record
  :param int serial: The value of the serial field in the SOA record
  :param int refresh: The value of the refresh field in the SOA record
  :param int retry: The value of the retry field in the SOA record
  :param int expire: The value of the expire field in the SOA record
  :param int minimum: The value of the minimum field in the SOA record
  :param table options: A table with key: value pairs with options

  Options:

  * ``aa``: bool - Set the AA bit to this value (true means the bit is set, false means it's cleared). Default is to clear it.
  * ``ad``: bool - Set the AD bit to this value (true means the bit is set, false means it's cleared). Default is to clear it.
  * ``ra``: bool - Set the RA bit to this value (true means the bit is set, false means it's cleared). Default is to copy the value of the RD bit from the incoming query.

.. function:: SetProxyProtocolValuesAction(values)

  .. versionadded:: 1.5.0

  Set the Proxy-Protocol Type-Length values to be sent to the server along with this query to ``values``.
  Subsequent rules are processed after this action.

  :param table values: A table of types and values to send, for example: ``{ [0] = foo", [42] = "bar" }``

.. function:: SetReducedTTLResponseAction(percentage)

  .. versionadded:: 1.8.0

  Reduce the TTL of records in a response to a percentage of the original TTL. For example,
  passing 50 means that the original TTL will be cut in half.
  Subsequent rules are processed after this action.

  :param int percentage: The percentage to use

.. function:: SetSkipCacheAction()

  .. versionadded:: 1.6.0

  Don't lookup the cache for this query, don't store the answer.
  Subsequent rules are processed after this action.
  Note that this function was called :func:`SkipCacheAction` before 1.6.0.

.. function:: SetSkipCacheResponseAction()

  .. versionadded:: 1.6.0

  Don't store this answer into the cache.
  Subsequent rules are processed after this action.

.. function:: SetTagAction(name, value)

  .. versionadded:: 1.6.0

  .. versionchanged:: 1.7.0
    Prior to 1.7.0 :func:`SetTagAction` would not overwrite an existing tag value if already set.

  Associate a tag named ``name`` with a value of ``value`` to this query, that will be passed on to the response.
  This function will overwrite any existing tag value.
  Subsequent rules are processed after this action.
  Note that this function was called :func:`TagAction` before 1.6.0.

  :param string name: The name of the tag to set
  :param string value: The value of the tag

.. function:: SetTagResponseAction(name, value)

  .. versionadded:: 1.6.0

  .. versionchanged:: 1.7.0
    Prior to 1.7.0 :func:`SetTagResponseAction` would not overwrite an existing tag value if already set.

  Associate a tag named ``name`` with a value of ``value`` to this response.
  This function will overwrite any existing tag value.
  Subsequent rules are processed after this action.
  Note that this function was called :func:`TagResponseAction` before 1.6.0.

  :param string name: The name of the tag to set
  :param string value: The value of the tag

.. function:: SetTempFailureCacheTTLAction(ttl)

  .. versionadded:: 1.6.0

  Set the cache TTL to use for ServFail and Refused replies. TTL is not applied for successful replies.
  Subsequent rules are processed after this action.
  Note that this function was called :func:`TempFailureCacheTTLAction` before 1.6.0.

  :param int ttl: Cache TTL for temporary failure replies

.. function:: SetTraceAction(value[, use_incoming_traceid[, trace_edns_option]])

  .. versionadded:: 2.1.0

  Enable or disable :doc:`OpenTelemetry tracing <../reference/ottrace>` for this query. Don't forget to use :func:`RemoteLogResponseAction` to actually send the Protobuf with the trace to a collector.
  Subsequent rules are processed after this action.

  Tracing has to be turned on globally as well using :func:`setOpenTelemetryTracing`.

  :param bool value: Whether to enable or disable query tracing.
  :param bool use_incoming_traceid: If the incoming query has a TraceID in its EDNS options, use that instead of generating one, default false.
  :param bool trace_edns_option: The EDNS option number that contains the TraceID, default 65500.

.. function:: SkipCacheAction()

  .. deprecated:: 1.6.0

  This function has been deprecated in 1.6.0 and removed in 1.7.0, please use :func:`SetSkipAction` instead.

  Don't lookup the cache for this query, don't store the answer.
  Subsequent rules are processed after this action.

.. function:: SNMPTrapAction([message])

  Send an SNMP trap, adding the optional ``message`` string as the query description.
  Subsequent rules are processed after this action.

  :param string message: The message to include

.. function:: SNMPTrapResponseAction([message])

  Send an SNMP trap, adding the optional ``message`` string as the query description.
  Subsequent rules are processed after this action.

  :param string message: The message to include

.. function:: SpoofAction(ip [, options])
              SpoofAction(ips [, options])

  .. versionchanged:: 1.5.0
    Added the optional parameter ``options``.

  .. versionchanged:: 1.6.0
    Up to 1.6.0, the syntax for this function was ``SpoofAction(ips[, ip[, options]])``.

  Forge a response with the specified IPv4 (for an A query) or IPv6 (for an AAAA) addresses.
  If you specify multiple addresses, all that match the query type (A, AAAA or ANY) will get spoofed in.

  Note that if you only specify addresses of one type (e.g. only IPv4 addresses), then queries for the other type (in this case AAAA queries), will **not** be spoofed.
  If you want to spoof the request for an A record, but not return an IPv6 address on AAAA requests, you could limit this function to A queries and  :func:`NegativeAndSOAAction()` for AAAA queries.

  :param string ip: An IPv4 and/or IPv6 address to spoof
  :param {string} ips: A table of IPv4 and/or IPv6 addresses to spoof
  :param table options: A table with key: value pairs with options.

  Options:

  * ``aa``: bool - Set the AA bit to this value (true means the bit is set, false means it's cleared). Default is to clear it.
  * ``ad``: bool - Set the AD bit to this value (true means the bit is set, false means it's cleared). Default is to clear it.
  * ``ra``: bool - Set the RA bit to this value (true means the bit is set, false means it's cleared). Default is to copy the value of the RD bit from the incoming query.
  * ``ttl``: int - The TTL of the record.

.. function:: SpoofCNAMEAction(cname [, options])

  .. versionchanged:: 1.5.0
    Added the optional parameter ``options``.

  Forge a response with the specified CNAME value.

  :param string cname: The name to respond with
  :param table options: A table with key: value pairs with options.

  Options:

  * ``aa``: bool - Set the AA bit to this value (true means the bit is set, false means it's cleared). Default is to clear it.
  * ``ad``: bool - Set the AD bit to this value (true means the bit is set, false means it's cleared). Default is to clear it.
  * ``ra``: bool - Set the RA bit to this value (true means the bit is set, false means it's cleared). Default is to copy the value of the RD bit from the incoming query.
  * ``ttl``: int - The TTL of the record.

.. function:: SpoofRawAction(rawAnswer [, options])
              SpoofRawAction(rawAnswers [, options])

  .. versionadded:: 1.5.0

  .. versionchanged:: 1.6.0
    Up to 1.6.0, it was only possible to spoof one answer.

  .. versionchanged:: 1.9.0
    Added the optional parameter ``typeForAny``.

  Forge a response with the specified raw bytes as record data.

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

  :param string rawAnswer: The raw record data
  :param {string} rawAnswers: A table of raw record data to spoof
  :param table options: A table with key: value pairs with options.

  Options:

  * ``aa``: bool - Set the AA bit to this value (true means the bit is set, false means it's cleared). Default is to clear it.
  * ``ad``: bool - Set the AD bit to this value (true means the bit is set, false means it's cleared). Default is to clear it.
  * ``ra``: bool - Set the RA bit to this value (true means the bit is set, false means it's cleared). Default is to copy the value of the RD bit from the incoming query.
  * ``ttl``: int - The TTL of the record.
  * ``typeForAny``: int - The record type to use when responding to queries of type ``ANY``, as using ``ANY`` for the type of the response record would not make sense.

.. function:: SpoofSVCAction(svcParams [, options])

  .. versionadded:: 1.7.0

  Forge a response with the specified SVC record data. If the list contains more than one :class:`SVCRecordParameters` (generated via :func:`newSVCRecordParameters`) object, they are all returned,
  and should have different priorities.
  The hints provided in the SVC parameters, if any, will also be added as A/AAAA records in the additional section, using the target name present in the parameters as owner name if it's not empty (root) and the qname instead.

  :param table svcParams: List of :class:`SVCRecordParameters` from which to generate the record data to return
  :param table options: A table with key: value pairs with options.

  Options:

  * ``aa``: bool - Set the AA bit to this value (true means the bit is set, false means it's cleared). Default is to clear it.
  * ``ad``: bool - Set the AD bit to this value (true means the bit is set, false means it's cleared). Default is to clear it.
  * ``ra``: bool - Set the RA bit to this value (true means the bit is set, false means it's cleared). Default is to copy the value of the RD bit from the incoming query.
  * ``ttl``: int - The TTL of the record.

.. function:: SpoofPacketAction(rawPacket, len)

  .. versionadded:: 1.8.0

  Spoof a raw self-generated answer

  :param string rawPacket: The raw wire-ready DNS answer
  :param int len: The length of the packet

.. function:: TagAction(name, value)

  .. deprecated:: 1.6.0
    This function has been deprecated in 1.6.0 and removed in 1.7.0, please use :func:`SetTagAction` instead.

  Associate a tag named ``name`` with a value of ``value`` to this query, that will be passed on to the response.
  Subsequent rules are processed after this action.

  :param string name: The name of the tag to set
  :param string value: The value of the tag

.. function:: TagResponseAction(name, value)

  .. deprecated:: 1.6.0
    This function has been deprecated in 1.6.0 and removed in 1.7.0, please use :func:`SetTagResponseAction` instead.

  Associate a tag named ``name`` with a value of ``value`` to this response.
  Subsequent rules are processed after this action.

  :param string name: The name of the tag to set
  :param string value: The value of the tag

.. function:: TCAction()

  .. versionchanged:: 1.7.0
    This action is now only performed over UDP transports.

  Create answer to query with the TC bit set, and the RA bit set to the value of RD in the query, to force the client to TCP.
  Before 1.7.0 this action was performed even when the query had been received over TCP, which required the use of :func:`TCPRule` to
  prevent the TC bit from being set over TCP transports.

.. function:: TCResponseAction()

  .. versionadded:: 1.9.0

  Truncate an existing answer, to force the client to TCP. Only applied to answers that will be sent to the client over TCP.
  In addition to the TC bit being set, all records are removed from the answer, authority and additional sections.

.. function:: TeeAction(remote[, addECS[, local [, addProxyProtocol]]])

  .. versionchanged:: 1.8.0
    Added the optional parameter ``local``.

  .. versionchanged:: 1.9.0
    Added the optional parameter ``addProxyProtocol``.

  Send copy of query to ``remote``, keep stats on responses.
  If ``addECS`` is set to true, EDNS Client Subnet information will be added to the query.
  If ``addProxyProtocol`` is set to true, a Proxy Protocol v2 payload will be prepended in front of the query. The payload will contain the protocol that delivered the initial query (UDP or TCP), as well as the initial source and destination addresses and ports.
  If ``local`` has provided a value like "192.0.2.53", :program:`dnsdist` will try binding that address as local address when sending the queries.
  Subsequent rules are processed after this action.

  :param string remote: An IP:PORT combination to send the copied queries to
  :param bool addECS: Whether to add ECS information. Default false.
  :param str local: The local address to use to send queries. The default is to let the kernel pick one.
  :param bool addProxyProtocol: Whether to prepend a proxy protocol v2 payload in front of the query. Default to false.

.. function:: TempFailureCacheTTLAction(ttl)

  .. deprecated:: 1.6.0

  This function has been deprecated in 1.6.0 and removed in 1.7.0, please use :func:`SetTempFailureCacheTTLAction` instead.

  Set the cache TTL to use for ServFail and Refused replies. TTL is not applied for successful replies.
  Subsequent rules are processed after this action.

  :param int ttl: Cache TTL for temporary failure replies

.. function:: UnsetTagAction(name)

  .. versionadded:: 2.1.0

  Remove a tag named ``name``.
  Subsequent rules are processed after this action.

  :param string name: The name of the tag to unset

.. function:: UnsetTagResponseAction(name)

  .. versionadded:: 2.1.0

  Remove a tag named ``name``.
  Subsequent rules are processed after this action.

  :param string name: The name of the tag to unset
