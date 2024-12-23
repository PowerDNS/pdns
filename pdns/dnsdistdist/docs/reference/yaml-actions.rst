.. THIS IS A GENERATED FILE. DO NOT EDIT. See dnsdist-settings-documentation-generator.py

.. raw:: latex

    \setcounter{secnumdepth}{-1}

.. _yaml-settings-Action:

YAML action reference
=====================

.. _yaml-settings-AllowAction:

AllowAction
-----------

Let these packets go through.

.. _yaml-settings-DelayAction:

DelayAction
-----------

Parameters:

- **msec**: Unsigned integer


.. _yaml-settings-DnstapLogAction:

DnstapLogAction
---------------

Parameters:

- **identity**: String
- **logger-name**: String
- **alter-function**: String ``("")``


.. _yaml-settings-DropAction:

DropAction
----------

.. _yaml-settings-SetEDNSOptionAction:

SetEDNSOptionAction
-------------------

Parameters:

- **code**: Unsigned integer
- **data**: String


.. _yaml-settings-ERCodeAction:

ERCodeAction
------------

Parameters:

- **rcode**: Unsigned integer
- **vars**: :ref:`ResponseConfig <yaml-settings-ResponseConfig>`


.. _yaml-settings-HTTPStatusAction:

HTTPStatusAction
----------------

Parameters:

- **status**: Unsigned integer
- **body**: String
- **content-type**: String ``("")``
- **vars**: :ref:`ResponseConfig <yaml-settings-ResponseConfig>`


.. _yaml-settings-KeyValueStoreLookupAction:

KeyValueStoreLookupAction
-------------------------

Parameters:

- **kvs-name**: String
- **lookup-key-name**: String
- **destination-tag**: String


.. _yaml-settings-KeyValueStoreRangeLookupAction:

KeyValueStoreRangeLookupAction
------------------------------

Parameters:

- **kvs-name**: String
- **lookup-key-name**: String
- **destination-tag**: String


.. _yaml-settings-LogAction:

LogAction
---------

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

Parameters:

- **function**: String


.. _yaml-settings-LuaFFIAction:

LuaFFIAction
------------

Parameters:

- **function**: String


.. _yaml-settings-LuaFFIPerThreadAction:

LuaFFIPerThreadAction
---------------------

Parameters:

- **code**: String


.. _yaml-settings-NegativeAndSOAAction:

NegativeAndSOAAction
--------------------

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

.. _yaml-settings-PoolAction:

PoolAction
----------

Parameters:

- **pool-name**: String
- **stop-processing**: Boolean ``(true)``


.. _yaml-settings-QPSAction:

QPSAction
---------

Parameters:

- **limit**: Unsigned integer


.. _yaml-settings-QPSPoolAction:

QPSPoolAction
-------------

Parameters:

- **limit**: Unsigned integer
- **pool-name**: String
- **stop-processing**: Boolean ``(true)``


.. _yaml-settings-RCodeAction:

RCodeAction
-----------

Parameters:

- **rcode**: Unsigned integer
- **vars**: :ref:`ResponseConfig <yaml-settings-ResponseConfig>`


.. _yaml-settings-RemoteLogAction:

RemoteLogAction
---------------

Parameters:

- **logger-name**: String
- **alter-function**: String ``("")``
- **server-id**: String ``("")``
- **ip-encrypt-key**: String ``("")``
- **export-tags**: Sequence of String
- **metas**: Sequence of :ref:`ProtoBufMetaConfiguration <yaml-settings-ProtoBufMetaConfiguration>`


.. _yaml-settings-SetAdditionalProxyProtocolValueAction:

SetAdditionalProxyProtocolValueAction
-------------------------------------

Parameters:

- **proxy-type**: Unsigned integer
- **value**: String


.. _yaml-settings-SetDisableECSAction:

SetDisableECSAction
-------------------

.. _yaml-settings-SetDisableValidationAction:

SetDisableValidationAction
--------------------------

.. _yaml-settings-SetECSAction:

SetECSAction
------------

Parameters:

- **ipv4**: String
- **ipv6**: String ``("")``


.. _yaml-settings-SetECSOverrideAction:

SetECSOverrideAction
--------------------

Parameters:

- **override-existing**: Boolean


.. _yaml-settings-SetECSPrefixLengthAction:

SetECSPrefixLengthAction
------------------------

Parameters:

- **ipv4**: Unsigned integer
- **ipv6**: Unsigned integer


.. _yaml-settings-SetExtendedDNSErrorAction:

SetExtendedDNSErrorAction
-------------------------

Parameters:

- **info-code**: Unsigned integer
- **extra-text**: String ``("")``


.. _yaml-settings-SetMacAddrAction:

SetMacAddrAction
----------------

Parameters:

- **code**: Unsigned integer


.. _yaml-settings-SetMaxReturnedTTLAction:

SetMaxReturnedTTLAction
-----------------------

Parameters:

- **max**: Unsigned integer


.. _yaml-settings-SetNoRecurseAction:

SetNoRecurseAction
------------------

.. _yaml-settings-SetSkipCacheAction:

SetSkipCacheAction
------------------

.. _yaml-settings-SetTagAction:

SetTagAction
------------

Parameters:

- **tag**: String
- **value**: String


.. _yaml-settings-SetTempFailureCacheTTLAction:

SetTempFailureCacheTTLAction
----------------------------

Parameters:

- **maxTTL**: Unsigned integer


.. _yaml-settings-SNMPTrapAction:

SNMPTrapAction
--------------

Parameters:

- **reason**: String ``("")``


.. _yaml-settings-SpoofAction:

SpoofAction
-----------

Parameters:

- **ips**: Sequence of String
- **vars**: :ref:`ResponseConfig <yaml-settings-ResponseConfig>`


.. _yaml-settings-SpoofCNAMEAction:

SpoofCNAMEAction
----------------

Parameters:

- **cname**: String
- **vars**: :ref:`ResponseConfig <yaml-settings-ResponseConfig>`


.. _yaml-settings-SpoofPacketAction:

SpoofPacketAction
-----------------

Parameters:

- **response**: String
- **len**: Unsigned integer


.. _yaml-settings-SpoofRawAction:

SpoofRawAction
--------------

Parameters:

- **answers**: Sequence of String
- **qtype-for-any**: String ``("")``
- **vars**: :ref:`ResponseConfig <yaml-settings-ResponseConfig>`


.. _yaml-settings-SpoofSVCAction:

SpoofSVCAction
--------------

Parameters:

- **parameters**: Sequence of :ref:`SVCRecordParameters <yaml-settings-SVCRecordParameters>`
- **vars**: :ref:`ResponseConfig <yaml-settings-ResponseConfig>`


.. _yaml-settings-TCAction:

TCAction
--------

.. _yaml-settings-TeeAction:

TeeAction
---------

Parameters:

- **rca**: String
- **lca**: String ``("")``
- **addECS**: Boolean ``(false)``
- **addProxyProtocol**: Boolean ``(false)``


