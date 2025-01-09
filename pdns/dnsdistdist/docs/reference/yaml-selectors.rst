.. THIS IS A GENERATED FILE. DO NOT EDIT. See dnsdist-settings-documentation-generator.py

.. raw:: latex

    \setcounter{secnumdepth}{-1}

.. _yaml-settings-Selector:

YAML selector reference
=======================

.. _yaml-settings-AllSelector:

AllSelector
-----------

Matches all traffic

Lua equivalent: :func:`AllRule`

.. _yaml-settings-AndSelector:

AndSelector
-----------

Matches traffic if all selectors match

Lua equivalent: :func:`AndRule`

Parameters:

- **selectors**: Sequence of :ref:`Selector <yaml-settings-Selector>`


.. _yaml-settings-ByNameSelector:

ByNameSelector
--------------

References an already declared selector by its name

Parameters:

- **selector-name**: String


.. _yaml-settings-DNSSECSelector:

DNSSECSelector
--------------

Matches queries with the DO flag set

Lua equivalent: :func:`DNSSECRule`

.. _yaml-settings-DSTPortSelector:

DSTPortSelector
---------------

Matches questions received to the destination port

Lua equivalent: :func:`DSTPortRule`

Parameters:

- **port**: Unsigned integer


.. _yaml-settings-EDNSOptionSelector:

EDNSOptionSelector
------------------

Matches queries or responses with the specified EDNS option present

Lua equivalent: :func:`EDNSOptionRule`

Parameters:

- **option-code**: Unsigned integer


.. _yaml-settings-EDNSVersionSelector:

EDNSVersionSelector
-------------------

Matches queries or responses with an OPT record whose EDNS version is greater than the specified EDNS version

Lua equivalent: :func:`EDNSVersionRule`

Parameters:

- **version**: Unsigned integer


.. _yaml-settings-ERCodeSelector:

ERCodeSelector
--------------

Matches queries or responses with the specified rcode. The full 16bit RCode will be matched. If no EDNS OPT RR is present, the upper 12 bits are treated as 0

Lua equivalent: :func:`ERCodeRule`

Parameters:

- **rcode**: Unsigned integer


.. _yaml-settings-HTTPHeaderSelector:

HTTPHeaderSelector
------------------

Matches DNS over HTTPS queries with a HTTP header name whose content matches the supplied regular expression. It is necessary to set the ``keepIncomingHeaders`` to :func:`addDOHLocal()` to use this rule

Lua equivalent: :func:`HTTPHeaderRule`

Parameters:

- **header**: String
- **expression**: String


.. _yaml-settings-HTTPPathSelector:

HTTPPathSelector
----------------

Matches DNS over HTTPS queries with a specific HTTP path

Lua equivalent: :func:`HTTPPathRule`

Parameters:

- **path**: String


.. _yaml-settings-HTTPPathRegexSelector:

HTTPPathRegexSelector
---------------------

Matches DNS over HTTPS queries with a path matching the supplied regular expression

Lua equivalent: :func:`HTTPPathRegexRule`

Parameters:

- **expression**: String


.. _yaml-settings-KeyValueStoreLookupSelector:

KeyValueStoreLookupSelector
---------------------------

Matches if the key returned by ``lookup-key-name`` exists in the key value store

Lua equivalent: :func:`KeyValueStoreLookupRule`

Parameters:

- **kvs-name**: String
- **lookup-key-name**: String


.. _yaml-settings-KeyValueStoreRangeLookupSelector:

KeyValueStoreRangeLookupSelector
--------------------------------

Does a range-based lookup into the key value store using the key returned by ``lookup-key-name`` and matches if there is a range covering that key. This assumes that there is a key, in network byte order, for the last element of the range (for example ``2001:0db8:ffff:ffff:ffff:ffff:ffff:ffff`` for ``2001:db8::/32``) which contains the first element of the range (``2001:0db8:0000:0000:0000:0000:0000:0000``) (optionally followed by any data) as value, still in network byte order, and that there is no overlapping ranges in the database. This requires that the underlying store supports ordered keys, which is true for ``LMDB`` but not for ``CDB``

Lua equivalent: :func:`KeyValueStoreRangeLookupRule`

Parameters:

- **kvs-name**: String
- **lookup-key-name**: String


.. _yaml-settings-LuaSelector:

LuaSelector
-----------

Invoke a Lua function that accepts a :class:`DNSQuestion` object. The function should return true if the query matches, or false otherwise. If the Lua code fails, false is returned

Lua equivalent: :func:`LuaRule`

Parameters:

- **function-name**: String ``("")``
- **function-code**: String ``("")``
- **function-file**: String ``("")``


.. _yaml-settings-LuaFFISelector:

LuaFFISelector
--------------

Invoke a Lua FFI function that accepts a pointer to a ``dnsdist_ffi_dnsquestion_t`` object, whose bindings are defined in ``dnsdist-lua-ffi-interface.h``. The function should return true if the query matches, or false otherwise. If the Lua code fails, false is returned

Lua equivalent: :func:`LuaFFIRule`

Parameters:

- **function-name**: String ``("")``
- **function-code**: String ``("")``
- **function-file**: String ``("")``


.. _yaml-settings-LuaFFIPerThreadSelector:

LuaFFIPerThreadSelector
-----------------------

Invoke a Lua FFI function that accepts a pointer to a ``dnsdist_ffi_dnsquestion_t`` object, whose bindings are defined in ``dnsdist-lua-ffi-interface.h``. The function should return true if the query matches, or false otherwise. If the Lua code fails, false is returned.
The function will be invoked in a per-thread Lua state, without access to the global Lua state. All constants (:ref:`DNSQType`, :ref:`DNSRCode`, ...) are available in that per-thread context, as well as all FFI functions. Objects and their bindings that are not usable in a FFI context (:class:`DNSQuestion`, :class:`DNSDistProtoBufMessage`, :class:`PacketCache`, ...) are not available

Lua equivalent: :func:`LuaFFIPerThreadRule`

Parameters:

- **code**: String


.. _yaml-settings-MaxQPSSelector:

MaxQPSSelector
--------------

Matches traffic not exceeding this qps limit. If e.g. this is set to 50, starting at the 51st query of the current second traffic stops being matched. This can be used to enforce a global QPS limit

Lua equivalent: :func:`MaxQPSRule`

Parameters:

- **qps**: Unsigned integer
- **burst**: Unsigned integer ``(0)``


.. _yaml-settings-MaxQPSIPSelector:

MaxQPSIPSelector
----------------

Matches traffic for a subnet specified by the v4 or v6 mask exceeding ``qps`` queries per second up to ``burst`` allowed. This rule keeps track of QPS by netmask or source IP. This state is cleaned up regularly if ``cleanup-delay`` is greater than zero, removing existing netmasks or IP addresses that have not been seen in the last ``expiration`` seconds.

Lua equivalent: :func:`MaxQPSIPRule`

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

Matches traffic from/to the network range specified in either the supplied :class:`NetmaskGroup` object or the list of ``netmasks``. Set the ``source`` parameter to ``false`` to match against destination address instead of source address. This can be used to differentiate between clients

Lua equivalent: :func:`NetmaskGroupRule`

Parameters:

- **netmask-group-name**: String ``("")``
- **netmasks**: Sequence of String
- **source**: Boolean ``(true)``
- **quiet**: Boolean ``(false)``


.. _yaml-settings-NotSelector:

NotSelector
-----------

Matches the traffic if the selector rule does not match

Lua equivalent: :func:`NotRule`

Parameters:

- **selector**: :ref:`Selector <yaml-settings-Selector>`


.. _yaml-settings-OpcodeSelector:

OpcodeSelector
--------------

Matches queries with opcode equals to ``code``

Lua equivalent: :func:`OpcodeRule`

Parameters:

- **code**: Unsigned integer


.. _yaml-settings-OrSelector:

OrSelector
----------

Matches the traffic if one or more of the selectors Rules does match

Lua equivalent: :func:`OrRule`

Parameters:

- **selectors**: Sequence of :ref:`Selector <yaml-settings-Selector>`


.. _yaml-settings-PayloadSizeSelector:

PayloadSizeSelector
-------------------

Matches queries or responses whose DNS payload size fits the given comparison

Lua equivalent: :func:`PayloadSizeRule`

Parameters:

- **comparison**: String
- **size**: Unsigned integer


.. _yaml-settings-PoolAvailableSelector:

PoolAvailableSelector
---------------------

Check whether a pool has any servers available to handle queries

Lua equivalent: :func:`PoolAvailableRule`

Parameters:

- **pool**: String


.. _yaml-settings-PoolOutstandingSelector:

PoolOutstandingSelector
-----------------------

Check whether a pool has total outstanding queries above limit

Lua equivalent: :func:`PoolOutstandingRule`

Parameters:

- **pool**: String
- **max-outstanding**: Unsigned integer


.. _yaml-settings-ProbaSelector:

ProbaSelector
-------------

Matches queries with a given probability. 1.0 means "always"

Lua equivalent: :func:`ProbaRule`

Parameters:

- **probability**: Double


.. _yaml-settings-ProxyProtocolValueSelector:

ProxyProtocolValueSelector
--------------------------

Matches queries that have a proxy protocol TLV value of the specified type. If ``option-value`` is set, the content of the value should also match the content of value

Lua equivalent: :func:`ProxyProtocolValueRule`

Parameters:

- **option-type**: Unsigned integer
- **option-value**: String ``("")``


.. _yaml-settings-QClassSelector:

QClassSelector
--------------

Matches queries with the specified qclass. The class can be specified as a numerical value or as a string

Lua equivalent: :func:`QClassRule`

Parameters:

- **qclass**: String ``("")``
- **numeric-value**: Unsigned integer ``(0)``


.. _yaml-settings-QNameSelector:

QNameSelector
-------------

Matches queries with the specified qname exactly

Lua equivalent: :func:`QNameRule`

Parameters:

- **qname**: String


.. _yaml-settings-QNameLabelsCountSelector:

QNameLabelsCountSelector
------------------------

Matches if the qname has less than ``min-labels-count`` or more than ``max-labels-count`` labels

Lua equivalent: :func:`QNameLabelsCountRule`

Parameters:

- **min-labels-count**: Unsigned integer
- **max-labels-count**: Unsigned integer


.. _yaml-settings-QNameSetSelector:

QNameSetSelector
----------------

Matches if the set contains exact qname. To match subdomain names, see :ref:`yaml-settings-QNameSuffixSelector`

Lua equivalent: :func:`QNameSetRule`

Parameters:

- **qnames**: Sequence of String


.. _yaml-settings-QNameSuffixSelector:

QNameSuffixSelector
-------------------

Matches based on a group of domain suffixes for rapid testing of membership. Pass true to ``quiet`` to prevent listing of all domains matched in the console or the web interface

Lua equivalent: :func:`QNameSuffixRule`

Parameters:

- **suffixes**: Sequence of String
- **quiet**: Boolean ``(false)``


.. _yaml-settings-QNameWireLengthSelector:

QNameWireLengthSelector
-----------------------

Matches if the qname’s length on the wire is less than ``min`` or more than ``max`` bytes.

Lua equivalent: :func:`QNameWireLengthRule`

Parameters:

- **min**: Unsigned integer
- **max**: Unsigned integer


.. _yaml-settings-QTypeSelector:

QTypeSelector
-------------

Matches queries with the specified qtype, which can be supplied as a String or as a numerical value

Lua equivalent: :func:`QTypeRule`

Parameters:

- **qtype**: String
- **numeric-value**: Unsigned integer ``(0)``


.. _yaml-settings-RCodeSelector:

RCodeSelector
-------------

Matches queries or responses with the specified rcode

Lua equivalent: :func:`RCodeRule`

Parameters:

- **rcode**: Unsigned integer


.. _yaml-settings-RDSelector:

RDSelector
----------

Matches queries with the RD flag set

Lua equivalent: :func:`RDRule`

.. _yaml-settings-RE2Selector:

RE2Selector
-----------

Matches the query name against the supplied regex using the RE2 engine

Lua equivalent: :func:`RE2Rule`

Parameters:

- **expression**: String


.. _yaml-settings-RecordsCountSelector:

RecordsCountSelector
--------------------

Matches if there is at least ``minimum`` and at most ``maximum`` records in the ``section`` section. ``section`` is specified as an integer with ``0`` being the question section, ``1`` answer, ``2`` authority and ``3`` additional

Lua equivalent: :func:`RecordsCountRule`

Parameters:

- **section**: Unsigned integer
- **minimum**: Unsigned integer
- **maximum**: Unsigned integer


.. _yaml-settings-RecordsTypeCountSelector:

RecordsTypeCountSelector
------------------------

Matches if there is at least ``minimum`` and at most ``maximum`` records of type ``record-type`` in the section ``section``. ``section`` is specified as an integer with ``0`` being the question section, ``1`` answer, ``2`` authority and ``3`` additional

Lua equivalent: :func:`RecordsTypeCountRule`

Parameters:

- **section**: Unsigned integer
- **record-type**: Unsigned integer
- **minimum**: Unsigned integer
- **maximum**: Unsigned integer


.. _yaml-settings-RegexSelector:

RegexSelector
-------------

Matches the query name against the supplied regular expression

Lua equivalent: :func:`RegexRule`

Parameters:

- **expression**: String


.. _yaml-settings-SNISelector:

SNISelector
-----------

Matches against the TLS Server Name Indication value sent by the client, if any. Only makes sense for DoT or DoH, and for that last one matching on the HTTP Host header using :ref:`yaml-settings-HTTPHeaderSelector` might provide more consistent results

Lua equivalent: :func:`SNIRule`

Parameters:

- **server-name**: String


.. _yaml-settings-TagSelector:

TagSelector
-----------

Matches question or answer with a tag named ``tag`` set. If ``value`` is specified, the existing tag value should match too

Lua equivalent: :func:`TagRule`

Parameters:

- **tag**: String
- **value**: String ``("")``


.. _yaml-settings-TCPSelector:

TCPSelector
-----------

Matches question received over TCP if ``tcp`` is true, over UDP otherwise

Lua equivalent: :func:`TCPRule`

Parameters:

- **tcp**: Boolean


.. _yaml-settings-TrailingDataSelector:

TrailingDataSelector
--------------------

Matches if the query has trailing data

Lua equivalent: :func:`TrailingDataRule`

