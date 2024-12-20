.. THIS IS A GENERATED FILE. DO NOT EDIT. See dnsdist-settings-documentation-generator.py

.. raw:: latex

    \setcounter{secnumdepth}{-1}

.. _yaml-settings-responseaction:

YAML responseaction reference
=============================

.. _yaml-settings-AllowResponseaction:

AllowResponseaction
-------------------

Let these packets go through.
 
.. _yaml-settings-ClearRecordTypesResponseaction:

ClearRecordTypesResponseaction
------------------------------

Removes given type(s) records from the response. Beware you can accidentally turn the answer into a NODATA response without a SOA record in the additional section in which case you may want to use NegativeAndSOAAction() to generate an answer, see example below. Subsequent rules are processed after this action.
 
Parameters:

- **types**: Sequence of Unsigned integer - List of types to remove


.. _yaml-settings-DelayResponseaction:

DelayResponseaction
-------------------

Parameters:

- **msec**: Unsigned integer


.. _yaml-settings-DnstapLogResponseaction:

DnstapLogResponseaction
-----------------------

Parameters:

- **identity**: String
- **logger-name**: String
- **alter-function**: String ``("")``


.. _yaml-settings-DropResponseaction:

DropResponseaction
------------------

.. _yaml-settings-LimitTTLResponseaction:

LimitTTLResponseaction
----------------------

Parameters:

- **min**: Unsigned integer
- **max**: Unsigned integer
- **types**: Sequence of Unsigned integer


.. _yaml-settings-LogResponseaction:

LogResponseaction
-----------------

Parameters:

- **file-name**: String ``("")``
- **append**: Boolean ``(false)``
- **buffered**: Boolean ``(false)``
- **verbose-only**: Boolean ``(true)``
- **include-timestamp**: Boolean ``(false)``


.. _yaml-settings-LuaResponseaction:

LuaResponseaction
-----------------

Parameters:

- **function**: String


.. _yaml-settings-LuaFFIResponseaction:

LuaFFIResponseaction
--------------------

Parameters:

- **function**: String


.. _yaml-settings-LuaFFIPerThreadResponseaction:

LuaFFIPerThreadResponseaction
-----------------------------

Parameters:

- **code**: String


.. _yaml-settings-RemoteLogResponseaction:

RemoteLogResponseaction
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


.. _yaml-settings-SetExtendedDNSErrorResponseaction:

SetExtendedDNSErrorResponseaction
---------------------------------

Parameters:

- **info-code**: Unsigned integer
- **extra-text**: String ``("")``


.. _yaml-settings-SetMinTTLResponseaction:

SetMinTTLResponseaction
-----------------------

Parameters:

- **min**: Unsigned integer


.. _yaml-settings-SetMaxReturnedTTLResponseaction:

SetMaxReturnedTTLResponseaction
-------------------------------

Parameters:

- **max**: Unsigned integer


.. _yaml-settings-SetMaxTTLResponseaction:

SetMaxTTLResponseaction
-----------------------

Parameters:

- **max**: Unsigned integer


.. _yaml-settings-SetReducedTTLResponseaction:

SetReducedTTLResponseaction
---------------------------

Parameters:

- **percentage**: Unsigned integer


.. _yaml-settings-SetSkipCacheResponseaction:

SetSkipCacheResponseaction
--------------------------

.. _yaml-settings-SetTagResponseaction:

SetTagResponseaction
--------------------

Parameters:

- **tag**: String
- **value**: String


.. _yaml-settings-SNMPTrapResponseaction:

SNMPTrapResponseaction
----------------------

Parameters:

- **reason**: String ``("")``


.. _yaml-settings-TCResponseaction:

TCResponseaction
----------------

