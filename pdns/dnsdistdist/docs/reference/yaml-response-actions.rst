.. THIS IS A GENERATED FILE. DO NOT EDIT. See dnsdist-settings-documentation-generator.py

.. raw:: latex

    \setcounter{secnumdepth}{-1}

.. _yaml-settings-ResponseAction:

YAML response-action reference
==============================

.. _yaml-settings-AllowResponseAction:

AllowResponseAction
-------------------

Let these packets go through.

Lua equivalent: :func:`AllowResponseAction`

.. _yaml-settings-ClearRecordTypesResponseAction:

ClearRecordTypesResponseAction
------------------------------

Removes given type(s) records from the response. Beware you can accidentally turn the answer into a NODATA response without a SOA record in the additional section in which case you may want to use NegativeAndSOAAction() to generate an answer, see example below. Subsequent rules are processed after this action.

Lua equivalent: :func:`ClearRecordTypesResponseAction`

Parameters:

- **types**: Sequence of Unsigned integer - List of types to remove


.. _yaml-settings-DelayResponseAction:

DelayResponseAction
-------------------

Delay the response by the specified amount of milliseconds (UDP-only). Note that the sending of the query to the backend, if needed, is not delayed. Only the sending of the response to the client will be delayed. Subsequent rules are processed after this action

Lua equivalent: :func:`DelayResponseAction`

Parameters:

- **msec**: Unsigned integer - The amount of milliseconds to delay the response


.. _yaml-settings-DnstapLogResponseAction:

DnstapLogResponseAction
-----------------------

Send the current response to a remote logger as a dnstap message. ``alter-function`` is a callback, receiving a :class:`DNSResponse` and a :class:`DnstapMessage`, that can be used to modify the message. Subsequent rules are processed after this action

Lua equivalent: :func:`DnstapLogResponseAction`

Parameters:

- **identity**: String - Server identity to store in the dnstap message
- **logger_name**: String - The name of dnstap logger
- **alter_function_name**: String ``("")`` - The name of the Lua function that will alter the message
- **alter_function_code**: String ``("")`` - The code of the Lua function that will alter the message
- **alter_function_file**: String ``("")`` - The path to a file containing the code of the Lua function that will alter the message


.. _yaml-settings-DropResponseAction:

DropResponseAction
------------------

Drop the packet

Lua equivalent: :func:`DropResponseAction`

.. _yaml-settings-LimitTTLResponseAction:

LimitTTLResponseAction
----------------------

Cap the TTLs of the response to the given boundaries

Lua equivalent: :func:`LimitTTLResponseAction`

Parameters:

- **min**: Unsigned integer - The minimum allowed value
- **max**: Unsigned integer - The maximum allowed value
- **types**: Sequence of Unsigned integer - The record types to cap the TTL for, as integers. Default is empty which means all records will be capped


.. _yaml-settings-LogResponseAction:

LogResponseAction
-----------------

Log a line for each response, to the specified file if any, to the console (require verbose) if the empty string is given as filename. If an empty string is supplied in the file name, the logging is done to stdout, and only in verbose mode by default. This can be changed by setting ``verbose-only`` to ``false``. The ``append`` parameter specifies whether we open the file for appending or truncate each time (default). The ``buffered`` parameter specifies whether writes to the file are buffered (default) or not. Subsequent rules are processed after this action

Lua equivalent: :func:`LogResponseAction`

Parameters:

- **file_name**: String ``("")`` - File to log to. Set to an empty string to log to the normal stdout log, this only works when ``-v`` is set on the command line
- **append**: Boolean ``(false)`` - Whether to append to an existing file
- **buffered**: Boolean ``(false)`` - Whether to use buffered I/O
- **verbose_only**: Boolean ``(true)`` - Whether to log only in verbose mode when logging to stdout
- **include_timestamp**: Boolean ``(false)`` - Whether to include a timestamp for every entry


.. _yaml-settings-LuaResponseAction:

LuaResponseAction
-----------------

Invoke a Lua function that accepts a :class:`DNSResponse`. The function should return a :ref:`DNSResponseAction`. If the Lua code fails, ``ServFail`` is returned

Lua equivalent: :func:`LuaResponseAction`

Parameters:

- **function_name**: String ``("")`` - The name of the Lua function
- **function_code**: String ``("")`` - The code of the Lua function
- **function_file**: String ``("")`` - The path to a file containing the code of the Lua function


.. _yaml-settings-LuaFFIResponseAction:

LuaFFIResponseAction
--------------------

Invoke a Lua function that accepts a pointer to a ``dnsdist_ffi_dnsquestion_t`` object, whose bindings are defined in ``dnsdist-lua-ffi-interface.h``. The function should return a :ref:`DNSResponseAction`. If the Lua code fails, ``ServFail`` is returned

Lua equivalent: :func:`LuaFFIResponseAction`

Parameters:

- **function_name**: String ``("")`` - The name of the Lua function
- **function_code**: String ``("")`` - The code of the Lua function
- **function_file**: String ``("")`` - The path to a file containing the code of the Lua function


.. _yaml-settings-LuaFFIPerThreadResponseAction:

LuaFFIPerThreadResponseAction
-----------------------------

Invoke a Lua function that accepts a pointer to a ``dnsdist_ffi_dnsquestion_t`` object, whose bindings are defined in ``dnsdist-lua-ffi-interface.h``. The function should return a :ref:`DNSResponseAction`. If the Lua code fails, ``ServFail`` is returned. The function will be invoked in a per-thread Lua state, without access to the global Lua state. All constants (:ref:`DNSQType`, :ref:`DNSRCode`, ...) are available in that per-thread context, as well as all FFI functions. Objects and their bindings that are not usable in a FFI context (:class:`DNSQuestion`, :class:`DNSDistProtoBufMessage`, :class:`PacketCache`, ...) are not available.

Lua equivalent: :func:`LuaFFIPerThreadResponseAction`

Parameters:

- **code**: String - The code of the Lua function


.. _yaml-settings-RemoteLogResponseAction:

RemoteLogResponseAction
-----------------------

Send the current response to a remote logger as a Protocol Buffer message. ``alter-function`` is a callback, receiving a :class:`DNSResponse` and a :class:`DNSDistProtoBufMessage`, that can be used to modify the message, for example for anonymization purposes. Subsequent rules are processed after this action

Lua equivalent: :func:`RemoteLogResponseAction`

Parameters:

- **logger_name**: String - The name of the protocol buffer logger
- **alter_function_name**: String ``("")`` - The name of the Lua function
- **alter_function_code**: String ``("")`` - The code of the Lua function
- **alter_function_file**: String ``("")`` - The path to a file containing the code of the Lua function
- **server_id**: String ``("")`` - Set the Server Identity field
- **ip_encrypt_key**: String ``("")`` - A key, that can be generated via the :func:`makeIPCipherKey` function, to encrypt the IP address of the requestor for anonymization purposes. The encryption is done using ipcrypt for IPv4 and a 128-bit AES ECB operation for IPv6
- **include_cname**: Boolean ``(false)`` - Whether or not to parse and export CNAMEs
- **export_tags**: Sequence of String ``("")`` - The comma-separated list of keys of internal tags to export into the ``tags`` Protocol Buffer field, as ``key:value`` strings. Note that a tag with an empty value will be exported as ``<key>``, not ``<key>:``. An empty string means that no internal tag will be exported. The special value ``*`` means that all tags will be exported
- **export_extended_errors_to_meta**: String ``("")`` - Export Extended DNS Errors present in the DNS response, if any, into the ``meta`` Protocol Buffer field using the specified ``key``. The EDE info code will be exported as an integer value, and the EDE extra text, if present, as a string value
- **metas**: Sequence of :ref:`ProtoBufMetaConfiguration <yaml-settings-ProtoBufMetaConfiguration>` - A list of ``name``=``key`` pairs, for meta-data to be added to Protocol Buffer message


.. _yaml-settings-SetEDNSOptionResponseAction:

SetEDNSOptionResponseAction
---------------------------

Add arbitrary EDNS option and data to the response. Any existing EDNS content with the same option code will be replaced. Subsequent rules are processed after this action

Lua equivalent: :func:`SetEDNSOptionResponseAction`

Parameters:

- **code**: Unsigned integer - The EDNS option number
- **data**: String - The EDNS0 option raw content


.. _yaml-settings-SetExtendedDNSErrorResponseAction:

SetExtendedDNSErrorResponseAction
---------------------------------

Set an Extended DNS Error status that will be added to the response. Subsequent rules are processed after this action

Lua equivalent: :func:`SetExtendedDNSErrorResponseAction`

Parameters:

- **info_code**: Unsigned integer - The EDNS Extended DNS Error code
- **extra_text**: String ``("")`` - The optional EDNS Extended DNS Error extra text


.. _yaml-settings-SetMaxReturnedTTLResponseAction:

SetMaxReturnedTTLResponseAction
-------------------------------

Cap the TTLs of the response to the given maximum, but only after inserting the response into the packet cache with the initial TTL values

Lua equivalent: :func:`SetMaxReturnedTTLResponseAction`

Parameters:

- **max**: Unsigned integer - The TTL cap


.. _yaml-settings-SetMaxTTLResponseAction:

SetMaxTTLResponseAction
-----------------------

Cap the TTLs of the response to the given maximum

Lua equivalent: :func:`SetMaxTTLResponseAction`

Parameters:

- **max**: Unsigned integer - The TTL cap


.. _yaml-settings-SetMinTTLResponseAction:

SetMinTTLResponseAction
-----------------------

Cap the TTLs of the response to the given minimum

Lua equivalent: :func:`SetMinTTLResponseAction`

Parameters:

- **min**: Unsigned integer - The TTL cap


.. _yaml-settings-SetReducedTTLResponseAction:

SetReducedTTLResponseAction
---------------------------

Reduce the TTL of records in a response to a percentage of the original TTL. For example, passing 50 means that the original TTL will be cut in half. Subsequent rules are processed after this action

Lua equivalent: :func:`SetReducedTTLResponseAction`

Parameters:

- **percentage**: Unsigned integer - The percentage to use


.. _yaml-settings-SetSkipCacheResponseAction:

SetSkipCacheResponseAction
--------------------------

Don’t store this answer in the cache. Subsequent rules are processed after this action.

Lua equivalent: :func:`SetSkipCacheResponseAction`

.. _yaml-settings-SetTagResponseAction:

SetTagResponseAction
--------------------

Associate a tag named ``tag`` with a value of ``value`` to this response. This function will overwrite any existing tag value. Subsequent rules are processed after this action

Lua equivalent: :func:`SetTagResponseAction`

Parameters:

- **tag**: String - The tag name
- **value**: String - The tag value


.. _yaml-settings-SNMPTrapResponseAction:

SNMPTrapResponseAction
----------------------

Send an SNMP trap, adding the message string as the query description. Subsequent rules are processed after this action

Lua equivalent: :func:`SNMPTrapResponseAction`

Parameters:

- **reason**: String ``("")`` - The SNMP trap reason


.. _yaml-settings-TCResponseAction:

TCResponseAction
----------------

Truncate an existing answer, to force the client to TCP. Only applied to answers that will be sent to the client over TCP. In addition to the TC bit being set, all records are removed from the answer, authority and additional sections

Lua equivalent: :func:`TCResponseAction`

