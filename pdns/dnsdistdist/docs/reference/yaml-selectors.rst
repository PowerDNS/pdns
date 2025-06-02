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

- **selectors**: Sequence of :ref:`Selector <yaml-settings-Selector>` - List of selectors


.. _yaml-settings-ByNameSelector:

ByNameSelector
--------------

References an already declared selector by its name

Parameters:

- **selector_name**: String


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

- **port**: Unsigned integer - Match destination port


.. _yaml-settings-EDNSOptionSelector:

EDNSOptionSelector
------------------

Matches queries or responses with the specified EDNS option present

Lua equivalent: :func:`EDNSOptionRule`

Parameters:

- **option_code**: Unsigned integer - The option code as an integer


.. _yaml-settings-EDNSVersionSelector:

EDNSVersionSelector
-------------------

Matches queries or responses with an OPT record whose EDNS version is greater than the specified EDNS version

Lua equivalent: :func:`EDNSVersionRule`

Parameters:

- **version**: Unsigned integer - The EDNS version to match on


.. _yaml-settings-ERCodeSelector:

ERCodeSelector
--------------

Matches queries or responses with the specified rcode. The full 16bit RCode will be matched. If no EDNS OPT RR is present, the upper 12 bits are treated as 0

Lua equivalent: :func:`ERCodeRule`

Parameters:

- **rcode**: Unsigned integer - The full 16bit RCode will be matched. If no EDNS OPT RR is present, the upper 12 bits are treated as 0


.. _yaml-settings-HTTPHeaderSelector:

HTTPHeaderSelector
------------------

Matches DNS over HTTPS queries with a HTTP header name whose content matches the supplied regular expression. It is necessary to set the ``keepIncomingHeaders`` to :func:`addDOHLocal()` to use this rule

Lua equivalent: :func:`HTTPHeaderRule`

Parameters:

- **header**: String - The case-insensitive name of the HTTP header to match on
- **expression**: String - A regular expression to match the content of the specified header


.. _yaml-settings-HTTPPathSelector:

HTTPPathSelector
----------------

Matches DNS over HTTPS queries with a specific HTTP path. For example, if the query has been sent to the https://192.0.2.1:443/PowerDNS?dns=... URL, the path would be '/PowerDNS'. Only valid DNS over HTTPS queries are matched. If you want to match all HTTP queries, see :meth:`DOHFrontend:setResponsesMap` instead

Lua equivalent: :func:`HTTPPathRule`

Parameters:

- **path**: String - The exact HTTP path to match on


.. _yaml-settings-HTTPPathRegexSelector:

HTTPPathRegexSelector
---------------------

Matches DNS over HTTPS queries with a path matching the supplied regular expression. For example, if the query has been sent to the https://192.0.2.1:443/PowerDNS?dns=... URL, the path would be '/PowerDNS'.
Only valid DNS over HTTPS queries are matched. If you want to match all HTTP queries, see :meth:`DOHFrontend:setResponsesMap` instead


Lua equivalent: :func:`HTTPPathRegexRule`

Parameters:

- **expression**: String - The regex to match on


.. _yaml-settings-KeyValueStoreLookupSelector:

KeyValueStoreLookupSelector
---------------------------

Matches if the key returned by ``lookup_key_name`` exists in the key value store

Lua equivalent: :func:`KeyValueStoreLookupRule`

Parameters:

- **kvs_name**: String - The key value store to query
- **lookup_key_name**: String - The key to use for the lookup


.. _yaml-settings-KeyValueStoreRangeLookupSelector:

KeyValueStoreRangeLookupSelector
--------------------------------

Does a range-based lookup into the key value store using the key returned by ``lookup_key_name`` and matches if there is a range covering that key. This assumes that there is a key, in network byte order, for the last element of the range (for example ``2001:0db8:ffff:ffff:ffff:ffff:ffff:ffff`` for ``2001:db8::/32``) which contains the first element of the range (``2001:0db8:0000:0000:0000:0000:0000:0000``) (optionally followed by any data) as value, still in network byte order, and that there is no overlapping ranges in the database. This requires that the underlying store supports ordered keys, which is true for ``LMDB`` but not for ``CDB``

Lua equivalent: :func:`KeyValueStoreRangeLookupRule`

Parameters:

- **kvs_name**: String - The key value store to query
- **lookup_key_name**: String - The key to use for the lookup


.. _yaml-settings-LuaSelector:

LuaSelector
-----------

Invoke a Lua function that accepts a :class:`DNSQuestion` object. The function should return true if the query matches, or false otherwise. If the Lua code fails, false is returned

Lua equivalent: :func:`LuaRule`

Parameters:

- **function_name**: String ``("")`` - The name of the Lua function
- **function_code**: String ``("")`` - The code of the Lua function
- **function_file**: String ``("")`` - The path to a file containing the code of the Lua function


.. _yaml-settings-LuaFFISelector:

LuaFFISelector
--------------

Invoke a Lua FFI function that accepts a pointer to a ``dnsdist_ffi_dnsquestion_t`` object, whose bindings are defined in ``dnsdist-lua-ffi-interface.h``. The function should return true if the query matches, or false otherwise. If the Lua code fails, false is returned

Lua equivalent: :func:`LuaFFIRule`

Parameters:

- **function_name**: String ``("")`` - The name of the Lua function
- **function_code**: String ``("")`` - The code of the Lua function
- **function_file**: String ``("")`` - The path to a file containing the code of the Lua function


.. _yaml-settings-LuaFFIPerThreadSelector:

LuaFFIPerThreadSelector
-----------------------

Invoke a Lua FFI function that accepts a pointer to a ``dnsdist_ffi_dnsquestion_t`` object, whose bindings are defined in ``dnsdist-lua-ffi-interface.h``. The function should return true if the query matches, or false otherwise. If the Lua code fails, false is returned.
The function will be invoked in a per-thread Lua state, without access to the global Lua state. All constants (:ref:`DNSQType`, :ref:`DNSRCode`, ...) are available in that per-thread context, as well as all FFI functions. Objects and their bindings that are not usable in a FFI context (:class:`DNSQuestion`, :class:`DNSDistProtoBufMessage`, :class:`PacketCache`, ...) are not available

Lua equivalent: :func:`LuaFFIPerThreadRule`

Parameters:

- **code**: String - The code of the Lua function


.. _yaml-settings-MaxQPSSelector:

MaxQPSSelector
--------------

Matches traffic not exceeding this qps limit. If e.g. this is set to 50, starting at the 51st query of the current second traffic stops being matched. This can be used to enforce a global QPS limit

Lua equivalent: :func:`MaxQPSRule`

Parameters:

- **qps**: Unsigned integer - The number of queries per second allowed, above this number the traffic is **not** matched anymore
- **burst**: Unsigned integer ``(0)`` - The number of burstable queries per second allowed. Default is same as qps


.. _yaml-settings-MaxQPSIPSelector:

MaxQPSIPSelector
----------------

Matches traffic for a subnet specified by the v4 or v6 mask exceeding ``qps`` queries per second up to ``burst`` allowed. This rule keeps track of QPS by netmask or source IP. This state is cleaned up regularly if ``cleanup_delay`` is greater than zero, removing existing netmasks or IP addresses that have not been seen in the last ``expiration`` seconds.

Lua equivalent: :func:`MaxQPSIPRule`

Parameters:

- **qps**: Unsigned integer - The number of queries per second allowed, above this number traffic is matched
- **ipv4_mask**: Unsigned integer ``(32)`` - The IPv4 netmask to match on. Default is 32 (the whole address)
- **ipv6_mask**: Unsigned integer ``(64)`` - he IPv6 netmask to match on
- **burst**: Unsigned integer ``(0)`` - The number of burstable queries per second allowed. Default is same as qps
- **expiration**: Unsigned integer ``(300)`` - How long to keep netmask or IP addresses after they have last been seen, in seconds
- **cleanup_delay**: Unsigned integer ``(60)`` - The number of seconds between two cleanups
- **scan_fraction**: Unsigned integer ``(10)`` - he maximum fraction of the store to scan for expired entries, for example 5 would scan at most 20% of it
- **shards**: Unsigned integer ``(10)`` - How many shards to use, to decrease lock contention between threads. Default is 10 and is a safe default unless a very high number of threads are used to process incoming queries


.. _yaml-settings-NetmaskGroupSelector:

NetmaskGroupSelector
--------------------

Matches traffic from/to the network range specified in either the supplied :class:`NetmaskGroup` object or the list of ``netmasks``. Set the ``source`` parameter to ``false`` to match against destination address instead of source address. This can be used to differentiate between clients

Lua equivalent: :func:`NetmaskGroupRule`

Parameters:

- **netmask_group_name**: String ``("")`` - The name of the netmask group object to use
- **netmasks**: Sequence of String ``("")`` - A list of netmasks to use instead of an existing netmask group object
- **source**: Boolean ``(true)`` - Whether to match source or destination address of the packet. Defaults to true (matches source)
- **quiet**: Boolean ``(false)`` - Do not display the list of matched netmasks in Rules. Default is false.


.. _yaml-settings-NotSelector:

NotSelector
-----------

Matches the traffic if the selector rule does not match

Lua equivalent: :func:`NotRule`

Parameters:

- **selector**: :ref:`Selector <yaml-settings-Selector>` - The list of selectors


.. _yaml-settings-OpcodeSelector:

OpcodeSelector
--------------

Matches queries with opcode equals to ``code``

Lua equivalent: :func:`OpcodeRule`

Parameters:

- **code**: Unsigned integer - The opcode to match


.. _yaml-settings-OrSelector:

OrSelector
----------

Matches the traffic if one or more of the selectors Rules does match

Lua equivalent: :func:`OrRule`

Parameters:

- **selectors**: Sequence of :ref:`Selector <yaml-settings-Selector>` - The list of selectors


.. _yaml-settings-PayloadSizeSelector:

PayloadSizeSelector
-------------------

Matches queries or responses whose DNS payload size fits the given comparison

Lua equivalent: :func:`PayloadSizeRule`

Parameters:

- **comparison**: String - The comparison operator to use. Supported values are: equal, greater, greaterOrEqual, smaller, smallerOrEqual
- **size**: Unsigned integer - The size to compare to


.. _yaml-settings-PoolAvailableSelector:

PoolAvailableSelector
---------------------

Check whether a pool has any servers available to handle queries

Lua equivalent: :func:`PoolAvailableRule`

Parameters:

- **pool**: String - The name of the pool


.. _yaml-settings-PoolOutstandingSelector:

PoolOutstandingSelector
-----------------------

Check whether a pool has total outstanding queries above limit

Lua equivalent: :func:`PoolOutstandingRule`

Parameters:

- **pool**: String - The name of the pool
- **max_outstanding**: Unsigned integer - The maximum number of outstanding queries in that pool


.. _yaml-settings-ProbaSelector:

ProbaSelector
-------------

Matches queries with a given probability. 1.0 means ``always``

Lua equivalent: :func:`ProbaRule`

Parameters:

- **probability**: Double - Probability of a match


.. _yaml-settings-ProxyProtocolValueSelector:

ProxyProtocolValueSelector
--------------------------

Matches queries that have a proxy protocol TLV value of the specified type. If ``option_value`` is set, the content of the value should also match the content of value

Lua equivalent: :func:`ProxyProtocolValueRule`

Parameters:

- **option_type**: Unsigned integer - The type of the value, ranging from 0 to 255 (both included)
- **option_value**: String ``("")`` - The optional binary-safe value to match


.. _yaml-settings-QClassSelector:

QClassSelector
--------------

Matches queries with the specified qclass. The class can be specified as a numerical value or as a string

Lua equivalent: :func:`QClassRule`

Parameters:

- **qclass**: String ``("")`` - The Query Class to match on, as a string
- **numeric_value**: Unsigned integer ``(0)`` - The Query Class to match on, as an integer


.. _yaml-settings-QNameSelector:

QNameSelector
-------------

Matches queries with the specified qname exactly

Lua equivalent: :func:`QNameRule`

Parameters:

- **qname**: String - Qname to match


.. _yaml-settings-QNameLabelsCountSelector:

QNameLabelsCountSelector
------------------------

Matches if the qname has less than ``min_labels_count`` or more than ``max_labels_count`` labels

Lua equivalent: :func:`QNameLabelsCountRule`

Parameters:

- **min_labels_count**: Unsigned integer - Minimum number of labels
- **max_labels_count**: Unsigned integer - Maximum number of labels


.. _yaml-settings-QNameSetSelector:

QNameSetSelector
----------------

Matches if the set contains exact qname. To match subdomain names, see :ref:`yaml-settings-QNameSuffixSelector`

Lua equivalent: :func:`QNameSetRule`

Parameters:

- **qnames**: Sequence of String - List of qnames


.. _yaml-settings-QNameSuffixSelector:

QNameSuffixSelector
-------------------

Matches based on a group of domain suffixes for rapid testing of membership. Pass true to ``quiet`` to prevent listing of all domains matched in the console or the web interface

Lua equivalent: :func:`QNameSuffixRule`

Parameters:

- **suffixes**: Sequence of String - List of suffixes
- **quiet**: Boolean ``(false)`` - Do not display the list of matched domains in Rules


.. _yaml-settings-QNameWireLengthSelector:

QNameWireLengthSelector
-----------------------

Matches if the qname’s length on the wire is less than ``min`` or more than ``max`` bytes.

Lua equivalent: :func:`QNameWireLengthRule`

Parameters:

- **min**: Unsigned integer - Minimum number of bytes
- **max**: Unsigned integer - Maximum number of bytes


.. _yaml-settings-QTypeSelector:

QTypeSelector
-------------

Matches queries with the specified qtype, which can be supplied as a String or as a numerical value

Lua equivalent: :func:`QTypeRule`

Parameters:

- **qtype**: String - The qtype, as a string
- **numeric_value**: Unsigned integer ``(0)`` - The qtype, as a numerical value


.. _yaml-settings-RCodeSelector:

RCodeSelector
-------------

Matches queries or responses with the specified rcode

Lua equivalent: :func:`RCodeRule`

Parameters:

- **rcode**: Unsigned integer - The response code, as a numerical value


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

- **expression**: String - The regular expression to match the QNAME


.. _yaml-settings-RecordsCountSelector:

RecordsCountSelector
--------------------

Matches if there is at least ``minimum`` and at most ``maximum`` records in the ``section`` section. ``section`` is specified as an integer with ``0`` being the question section, ``1`` answer, ``2`` authority and ``3`` additional

Lua equivalent: :func:`RecordsCountRule`

Parameters:

- **section**: Unsigned integer - The section to match on
- **minimum**: Unsigned integer - The minimum number of entries
- **maximum**: Unsigned integer - The maximum number of entries


.. _yaml-settings-RecordsTypeCountSelector:

RecordsTypeCountSelector
------------------------

Matches if there is at least ``minimum`` and at most ``maximum`` records of type ``record_type`` in the section ``section``. ``section`` is specified as an integer with ``0`` being the question section, ``1`` answer, ``2`` authority and ``3`` additional

Lua equivalent: :func:`RecordsTypeCountRule`

Parameters:

- **section**: Unsigned integer - The section to match on
- **record_type**: Unsigned integer - The record type to match on
- **minimum**: Unsigned integer - The minimum number of entries
- **maximum**: Unsigned integer - The maximum number of entries


.. _yaml-settings-RegexSelector:

RegexSelector
-------------

Matches the query name against the supplied regular expression

Lua equivalent: :func:`RegexRule`

Parameters:

- **expression**: String - The regular expression to match the QNAME


.. _yaml-settings-SNISelector:

SNISelector
-----------

Matches against the TLS Server Name Indication value sent by the client, if any. Only makes sense for DoT or DoH, and for that last one matching on the HTTP Host header using :ref:`yaml-settings-HTTPHeaderSelector` might provide more consistent results

Lua equivalent: :func:`SNIRule`

Parameters:

- **server_name**: String - The exact Server Name Indication value


.. _yaml-settings-TagSelector:

TagSelector
-----------

Matches question or answer with a tag named ``tag`` set. If ``value`` is specified, the existing tag value should match too

Lua equivalent: :func:`TagRule`

Parameters:

- **tag**: String - The name of the tag that has to be set
- **value**: String ``("")`` - If set, the value the tag has to be set to
- **empty-as-wildcard**: Boolean ``(true)`` - Because of a limitation in our Rust <-> C++ interoperability layer, ``value`` defaults to an empty string, which makes it impossible to express whether an empty ``value`` means that we should match on all values (so as long as the tag has been set) or only if the value is actually empty. This flag fixes that: if ``value`` is empty and this parameter is set to ``false`` the selector will only match if the actual value of the tag is empty, while if it set to ``true`` (default) it will match as long as the tag is set, regardless of the value


.. _yaml-settings-TCPSelector:

TCPSelector
-----------

Matches question received over TCP if ``tcp`` is true, over UDP otherwise

Lua equivalent: :func:`TCPRule`

Parameters:

- **tcp**: Boolean - Match TCP traffic if true, UDP traffic if false


.. _yaml-settings-TrailingDataSelector:

TrailingDataSelector
--------------------

Matches if the query has trailing data

Lua equivalent: :func:`TrailingDataRule`

