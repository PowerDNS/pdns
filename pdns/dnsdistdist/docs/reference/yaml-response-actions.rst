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

- **msec**: Unsigned integer


.. _yaml-settings-DnstapLogResponseAction:

DnstapLogResponseAction
-----------------------

Send the current response to a remote logger as a dnstap message. ``alter-function`` is a callback, receiving a :class:`DNSResponse` and a :class:`DnstapMessage`, that can be used to modify the message. Subsequent rules are processed after this action

Lua equivalent: :func:`DnstapLogResponseAction`

Parameters:

- **identity**: String
- **logger-name**: String
- **alter-function_name**: String ``("")``
- **alter-function-code**: String ``("")``
- **alter-function-file**: String ``("")``


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

- **min**: Unsigned integer
- **max**: Unsigned integer
- **types**: Sequence of Unsigned integer


.. _yaml-settings-LogResponseAction:

LogResponseAction
-----------------

Log a line for each response, to the specified file if any, to the console (require verbose) if the empty string is given as filename. If an empty string is supplied in the file name, the logging is done to stdout, and only in verbose mode by default. This can be changed by setting ``verbose-only`` to ``false``. When logging to a file, the ``binary`` parameter specifies whether we log in binary form (default) or in textual form. The ``append`` parameter specifies whether we open the file for appending or truncate each time (default). The ``buffered`` parameter specifies whether writes to the file are buffered (default) or not. Subsequent rules are processed after this action

Lua equivalent: :func:`LogResponseAction`

Parameters:

- **file-name**: String ``("")``
- **append**: Boolean ``(false)``
- **buffered**: Boolean ``(false)``
- **verbose-only**: Boolean ``(true)``
- **include-timestamp**: Boolean ``(false)``


.. _yaml-settings-LuaResponseAction:

LuaResponseAction
-----------------

Invoke a Lua function that accepts a :class:`DNSResponse`. The function should return a :ref:`DNSResponseAction`. If the Lua code fails, ``ServFail`` is returned

Lua equivalent: :func:`LuaResponseAction`

Parameters:

- **function-name**: String ``("")``
- **function-code**: String ``("")``
- **function-file**: String ``("")``


.. _yaml-settings-LuaFFIResponseAction:

LuaFFIResponseAction
--------------------

Invoke a Lua function that accepts a pointer to a ``dnsdist_ffi_dnsquestion_t`` object, whose bindings are defined in ``dnsdist-lua-ffi-interface.h``. The function should return a :ref:`DNSResponseAction`. If the Lua code fails, ``ServFail`` is returned

Lua equivalent: :func:`LuaFFIResponseAction`

Parameters:

- **function-name**: String ``("")``
- **function-code**: String ``("")``
- **function-file**: String ``("")``


.. _yaml-settings-LuaFFIPerThreadResponseAction:

LuaFFIPerThreadResponseAction
-----------------------------

Invoke a Lua function that accepts a pointer to a ``dnsdist_ffi_dnsquestion_t`` object, whose bindings are defined in ``dnsdist-lua-ffi-interface.h``. The function should return a :ref:`DNSResponseAction`. If the Lua code fails, ``ServFail`` is returned. The function will be invoked in a per-thread Lua state, without access to the global Lua state. All constants (:ref:`DNSQType`, :ref:`DNSRCode`, ...) are available in that per-thread context, as well as all FFI functions. Objects and their bindings that are not usable in a FFI context (:class:`DNSQuestion`, :class:`DNSDistProtoBufMessage`, :class:`PacketCache`, ...) are not available.

Lua equivalent: :func:`LuaFFIPerThreadResponseAction`

Parameters:

- **code**: String


.. _yaml-settings-RemoteLogResponseAction:

RemoteLogResponseAction
-----------------------

Send the current response to a remote logger as a Protocol Buffer message. ``alter-function`` is a callback, receiving a :class:`DNSResponse` and a :class:`DNSDistProtoBufMessage`, that can be used to modify the message, for example for anonymization purposes. Subsequent rules are processed after this action

Lua equivalent: :func:`RemoteLogResponseAction`

Parameters:

- **logger-name**: String
- **alter-function-name**: String ``("")``
- **alter-function-code**: String ``("")``
- **alter-function-file**: String ``("")``
- **server-id**: String ``("")``
- **ip-encrypt-key**: String ``("")``
- **include-cname**: Boolean ``(false)``
- **export-tags**: Sequence of String
- **export-extended-errors-to-meta**: String ``("")``
- **metas**: Sequence of :ref:`ProtoBufMetaConfiguration <yaml-settings-ProtoBufMetaConfiguration>`


.. _yaml-settings-SetExtendedDNSErrorResponseAction:

SetExtendedDNSErrorResponseAction
---------------------------------

Set an Extended DNS Error status that will be added to the response. Subsequent rules are processed after this action

Lua equivalent: :func:`SetExtendedDNSErrorResponseAction`

Parameters:

- **info-code**: Unsigned integer
- **extra-text**: String ``("")``


.. _yaml-settings-SetMaxReturnedTTLResponseAction:

SetMaxReturnedTTLResponseAction
-------------------------------

Cap the TTLs of the response to the given maximum, but only after inserting the response into the packet cache with the initial TTL values

Lua equivalent: :func:`SetMaxReturnedTTLResponseAction`

Parameters:

- **max**: Unsigned integer


.. _yaml-settings-SetMaxTTLResponseAction:

SetMaxTTLResponseAction
-----------------------

Cap the TTLs of the response to the given maximum

Lua equivalent: :func:`SetMaxTTLResponseAction`

Parameters:

- **max**: Unsigned integer


.. _yaml-settings-SetMinTTLResponseAction:

SetMinTTLResponseAction
-----------------------

Cap the TTLs of the response to the given minimum

Lua equivalent: :func:`SetMinTTLResponseAction`

Parameters:

- **min**: Unsigned integer


.. _yaml-settings-SetReducedTTLResponseAction:

SetReducedTTLResponseAction
---------------------------

Reduce the TTL of records in a response to a percentage of the original TTL. For example, passing 50 means that the original TTL will be cut in half. Subsequent rules are processed after this action

Lua equivalent: :func:`SetReducedTTLResponseAction`

Parameters:

- **percentage**: Unsigned integer


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

- **tag**: String
- **value**: String


.. _yaml-settings-SNMPTrapResponseAction:

SNMPTrapResponseAction
----------------------

Send an SNMP trap, adding the message string as the query description. Subsequent rules are processed after this action

Lua equivalent: :func:`SNMPTrapResponseAction`

Parameters:

- **reason**: String ``("")``


.. _yaml-settings-TCResponseAction:

TCResponseAction
----------------

Truncate an existing answer, to force the client to TCP. Only applied to answers that will be sent to the client over TCP. In addition to the TC bit being set, all records are removed from the answer, authority and additional sections

Lua equivalent: :func:`TCResponseAction`

