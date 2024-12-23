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

.. _yaml-settings-ClearRecordTypesResponseAction:

ClearRecordTypesResponseAction
------------------------------

Removes given type(s) records from the response. Beware you can accidentally turn the answer into a NODATA response without a SOA record in the additional section in which case you may want to use NegativeAndSOAAction() to generate an answer, see example below. Subsequent rules are processed after this action.

Parameters:

- **types**: Sequence of Unsigned integer - List of types to remove


.. _yaml-settings-DelayResponseAction:

DelayResponseAction
-------------------

Parameters:

- **msec**: Unsigned integer


.. _yaml-settings-DnstapLogResponseAction:

DnstapLogResponseAction
-----------------------

Parameters:

- **identity**: String
- **logger-name**: String
- **alter-function**: String ``("")``


.. _yaml-settings-DropResponseAction:

DropResponseAction
------------------

.. _yaml-settings-LimitTTLResponseAction:

LimitTTLResponseAction
----------------------

Parameters:

- **min**: Unsigned integer
- **max**: Unsigned integer
- **types**: Sequence of Unsigned integer


.. _yaml-settings-LogResponseAction:

LogResponseAction
-----------------

Parameters:

- **file-name**: String ``("")``
- **append**: Boolean ``(false)``
- **buffered**: Boolean ``(false)``
- **verbose-only**: Boolean ``(true)``
- **include-timestamp**: Boolean ``(false)``


.. _yaml-settings-LuaResponseAction:

LuaResponseAction
-----------------

Parameters:

- **function**: String


.. _yaml-settings-LuaFFIResponseAction:

LuaFFIResponseAction
--------------------

Parameters:

- **function**: String


.. _yaml-settings-LuaFFIPerThreadResponseAction:

LuaFFIPerThreadResponseAction
-----------------------------

Parameters:

- **code**: String


.. _yaml-settings-RemoteLogResponseAction:

RemoteLogResponseAction
-----------------------

Parameters:

- **logger-name**: String
- **alter-function**: String ``("")``
- **server-id**: String ``("")``
- **ip-encrypt-key**: String ``("")``
- **include-cname**: Boolean ``(false)``
- **export-tags**: Sequence of String
- **export-extended-errors-to-meta**: String ``("")``
- **metas**: Sequence of :ref:`ProtoBufMetaConfiguration <yaml-settings-ProtoBufMetaConfiguration>`


.. _yaml-settings-SetExtendedDNSErrorResponseAction:

SetExtendedDNSErrorResponseAction
---------------------------------

Parameters:

- **info-code**: Unsigned integer
- **extra-text**: String ``("")``


.. _yaml-settings-SetMinTTLResponseAction:

SetMinTTLResponseAction
-----------------------

Parameters:

- **min**: Unsigned integer


.. _yaml-settings-SetMaxReturnedTTLResponseAction:

SetMaxReturnedTTLResponseAction
-------------------------------

Parameters:

- **max**: Unsigned integer


.. _yaml-settings-SetMaxTTLResponseAction:

SetMaxTTLResponseAction
-----------------------

Parameters:

- **max**: Unsigned integer


.. _yaml-settings-SetReducedTTLResponseAction:

SetReducedTTLResponseAction
---------------------------

Parameters:

- **percentage**: Unsigned integer


.. _yaml-settings-SetSkipCacheResponseAction:

SetSkipCacheResponseAction
--------------------------

.. _yaml-settings-SetTagResponseAction:

SetTagResponseAction
--------------------

Parameters:

- **tag**: String
- **value**: String


.. _yaml-settings-SNMPTrapResponseAction:

SNMPTrapResponseAction
----------------------

Parameters:

- **reason**: String ``("")``


.. _yaml-settings-TCResponseAction:

TCResponseAction
----------------

