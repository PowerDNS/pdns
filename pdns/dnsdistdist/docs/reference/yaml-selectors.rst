.. THIS IS A GENERATED FILE. DO NOT EDIT. See dnsdist-settings-documentation-generator.py

.. raw:: latex

    \setcounter{secnumdepth}{-1}

.. _yaml-settings-selector:

YAML selector reference
=======================

.. _yaml-settings-AllSelector:

AllSelector
-----------

.. _yaml-settings-AndSelector:

AndSelector
-----------

Parameters:

- **selectors**: Sequence of :ref:`Selector <yaml-settings-Selector>`


.. _yaml-settings-ByNameSelector:

ByNameSelector
--------------

Parameters:

- **selector-name**: String


.. _yaml-settings-DNSSECSelector:

DNSSECSelector
--------------

.. _yaml-settings-DSTPortSelector:

DSTPortSelector
---------------

Parameters:

- **port**: Unsigned integer


.. _yaml-settings-EDNSOptionSelector:

EDNSOptionSelector
------------------

Parameters:

- **option-code**: Unsigned integer


.. _yaml-settings-EDNSVersionSelector:

EDNSVersionSelector
-------------------

Parameters:

- **version**: Unsigned integer


.. _yaml-settings-ERCodeSelector:

ERCodeSelector
--------------

Parameters:

- **rcode**: Unsigned integer


.. _yaml-settings-HTTPHeaderSelector:

HTTPHeaderSelector
------------------

Parameters:

- **header**: String
- **expression**: String


.. _yaml-settings-HTTPPathSelector:

HTTPPathSelector
----------------

Parameters:

- **path**: String


.. _yaml-settings-HTTPPathRegexSelector:

HTTPPathRegexSelector
---------------------

Parameters:

- **expression**: String


.. _yaml-settings-KeyValueStoreLookupSelector:

KeyValueStoreLookupSelector
---------------------------

Parameters:

- **kvs-name**: String
- **lookup-key-name**: String


.. _yaml-settings-KeyValueStoreRangeLookupSelector:

KeyValueStoreRangeLookupSelector
--------------------------------

Parameters:

- **kvs-name**: String
- **lookup-key-name**: String


.. _yaml-settings-LuaSelector:

LuaSelector
-----------

Parameters:

- **function**: String


.. _yaml-settings-LuaFFISelector:

LuaFFISelector
--------------

Parameters:

- **function**: String


.. _yaml-settings-LuaFFIPerThreadSelector:

LuaFFIPerThreadSelector
-----------------------

Parameters:

- **code**: String


.. _yaml-settings-MaxQPSSelector:

MaxQPSSelector
--------------

Parameters:

- **qps**: Unsigned integer
- **burst**: Unsigned integer ``(0)``


.. _yaml-settings-MaxQPSIPSelector:

MaxQPSIPSelector
----------------

Parameters:

- **qps**: Unsigned integer
- **ipv4-mask**: Unsigned integer ``(32)``
- **ipv6-mask**: Unsigned integer ``(64)``
- **burst**: Unsigned integer ``(0)``
- **expiration**: Unsigned integer ``(300)``
- **cleanup-delay**: Unsigned integer ``(60)``
- **scan-fraction**: Unsigned integer ``(10)``
- **shards**: Unsigned integer ``(10)``


.. _yaml-settings-NetmaskGroupSelector:

NetmaskGroupSelector
--------------------

Parameters:

- **netmask-group-name**: String ``("")``
- **netmasks**: Sequence of String
- **source**: Boolean ``(true)``
- **quiet**: Boolean ``(false)``


.. _yaml-settings-NotSelector:

NotSelector
-----------

Parameters:

- **selector**: :ref:`Selector <yaml-settings-Selector>`


.. _yaml-settings-OpcodeSelector:

OpcodeSelector
--------------

Parameters:

- **code**: Unsigned integer


.. _yaml-settings-OrSelector:

OrSelector
----------

Parameters:

- **selectors**: Sequence of :ref:`Selector <yaml-settings-Selector>`


.. _yaml-settings-PayloadSizeSelector:

PayloadSizeSelector
-------------------

Parameters:

- **comparison**: String
- **size**: Unsigned integer


.. _yaml-settings-PoolAvailableSelector:

PoolAvailableSelector
---------------------

Parameters:

- **pool**: String


.. _yaml-settings-PoolOutstandingSelector:

PoolOutstandingSelector
-----------------------

Parameters:

- **pool**: String
- **max-outstanding**: Unsigned integer


.. _yaml-settings-ProbaSelector:

ProbaSelector
-------------

Parameters:

- **probability**: Double


.. _yaml-settings-ProxyProtocolValueSelector:

ProxyProtocolValueSelector
--------------------------

Parameters:

- **option-type**: Unsigned integer
- **option-value**: String ``("")``


.. _yaml-settings-QClassSelector:

QClassSelector
--------------

Parameters:

- **qclass**: String ``("")``
- **numeric-value**: Unsigned integer ``(0)``


.. _yaml-settings-QNameSelector:

QNameSelector
-------------

Parameters:

- **qname**: String


.. _yaml-settings-QNameLabelsCountSelector:

QNameLabelsCountSelector
------------------------

Parameters:

- **min-labels-count**: Unsigned integer
- **max-labels-count**: Unsigned integer


.. _yaml-settings-QNameSetSelector:

QNameSetSelector
----------------

Parameters:

- **qnames**: Sequence of String


.. _yaml-settings-QNameSuffixSelector:

QNameSuffixSelector
-------------------

Parameters:

- **suffixes**: Sequence of String
- **quiet**: Boolean ``(false)``


.. _yaml-settings-QNameWireLengthSelector:

QNameWireLengthSelector
-----------------------

Parameters:

- **min**: Unsigned integer
- **max**: Unsigned integer


.. _yaml-settings-QTypeSelector:

QTypeSelector
-------------

Parameters:

- **qtype**: String
- **numeric-value**: Unsigned integer ``(0)``


.. _yaml-settings-RCodeSelector:

RCodeSelector
-------------

Parameters:

- **rcode**: Unsigned integer


.. _yaml-settings-RDSelector:

RDSelector
----------

.. _yaml-settings-RE2Selector:

RE2Selector
-----------

Parameters:

- **expression**: String


.. _yaml-settings-RecordsCountSelector:

RecordsCountSelector
--------------------

Parameters:

- **section**: Unsigned integer
- **minimum**: Unsigned integer
- **maximum**: Unsigned integer


.. _yaml-settings-RecordsTypeCountSelector:

RecordsTypeCountSelector
------------------------

Parameters:

- **section**: Unsigned integer
- **record-type**: Unsigned integer
- **minimum**: Unsigned integer
- **maximum**: Unsigned integer


.. _yaml-settings-RegexSelector:

RegexSelector
-------------

Parameters:

- **expression**: String


.. _yaml-settings-SNISelector:

SNISelector
-----------

Parameters:

- **server-name**: String


.. _yaml-settings-TagSelector:

TagSelector
-----------

Parameters:

- **tag**: String
- **value**: String ``("")``


.. _yaml-settings-TCPSelector:

TCPSelector
-----------

Parameters:

- **tcp**: Boolean


.. _yaml-settings-TrailingDataSelector:

TrailingDataSelector
--------------------

