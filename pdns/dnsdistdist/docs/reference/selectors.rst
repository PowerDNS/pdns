Rule selectors
==============

Packets can be matched by selectors, called a ``DNSRule``.

These ``DNSRule``\ s be one of the following items:

  * A string that is either a domain name or netmask
  * A list of strings that are either domain names or netmasks
  * A :class:`DNSName`
  * A list of :class:`DNSName`\ s
  * A (compounded) ``Rule``

This page describes the ``Lua`` versions of these selectors, for the ``YAML`` version please see :doc:`yaml-selectors`.

Selectors can be combined via :func:`AndRule`, :func:`OrRule` and :func:`NotRule`.

.. function:: AllRule()

  Matches all traffic

.. function:: DNSSECRule()

  Matches queries with the DO flag set

.. function:: DSTPortRule(port)

  Matches questions received to the destination port.

  :param int port: Match destination port.

.. function:: EDNSOptionRule(optcode)

  .. versionadded:: 1.4.0

  Matches queries or responses with the specified EDNS option present.
  ``optcode`` is specified as an integer, or a constant such as `EDNSOptionCode.ECS`.

.. function:: EDNSVersionRule(version)

  .. versionadded:: 1.4.0

  Matches queries or responses with an OPT record whose EDNS version is greater than the specified EDNS version.

  :param int version: The EDNS version to match on

.. function:: ERCodeRule(rcode)

  Matches queries or responses with the specified ``rcode``.
  ``rcode`` can be specified as an integer or as one of the built-in :ref:`DNSRCode`.
  The full 16bit RCode will be matched. If no EDNS OPT RR is present, the upper 12 bits are treated as 0.

  :param int rcode: The RCODE to match on

.. function:: HTTPHeaderRule(name, regex)

  .. versionadded:: 1.4.0

  .. versionchanged:: 1.8.0
     see ``keepIncomingHeaders`` on :func:`addDOHLocal`

  Matches DNS over HTTPS queries with a HTTP header ``name`` whose content matches the regular expression ``regex``.
  Since 1.8.0 it is necessary to set the ``keepIncomingHeaders`` option to true on :func:`addDOHLocal` to be able to use this rule.

  :param str name: The case-insensitive name of the HTTP header to match on
  :param str regex: A regular expression to match the content of the specified header

.. function:: HTTPPathRegexRule(regex)

  .. versionadded:: 1.4.0

  Matches DNS over HTTPS queries with a HTTP path matching the regular expression supplied in ``regex``. For example, if the query has been sent to the https://192.0.2.1:443/PowerDNS?dns=... URL, the path would be '/PowerDNS'.
  Only valid DNS over HTTPS queries are matched. If you want to match all HTTP queries, see :meth:`DOHFrontend:setResponsesMap` instead.

  :param str regex: The regex to match on

.. function:: HTTPPathRule(path)

  .. versionadded:: 1.4.0

  Matches DNS over HTTPS queries with a HTTP path of ``path``. For example, if the query has been sent to the https://192.0.2.1:443/PowerDNS?dns=... URL, the path would be '/PowerDNS'.
  Only valid DNS over HTTPS queries are matched. If you want to match all HTTP queries, see :meth:`DOHFrontend:setResponsesMap` instead.

  :param str path: The exact HTTP path to match on

.. function:: KeyValueStoreLookupRule(kvs, lookupKey)

  .. versionadded:: 1.4.0

  Return true if the key returned by 'lookupKey' exists in the key value store referenced by 'kvs'.
  The store can be a CDB (:func:`newCDBKVStore`) or a LMDB database (:func:`newLMDBKVStore`).
  The key can be based on the qname (:func:`KeyValueLookupKeyQName` and :func:`KeyValueLookupKeySuffix`),
  source IP (:func:`KeyValueLookupKeySourceIP`) or the value of an existing tag (:func:`KeyValueLookupKeyTag`).

  :param KeyValueStore kvs: The key value store to query
  :param KeyValueLookupKey lookupKey: The key to use for the lookup

.. function:: KeyValueStoreRangeLookupRule(kvs, lookupKey)

  .. versionadded:: 1.7.0

  Does a range-based lookup into the key value store referenced by 'kvs' using the key returned by 'lookupKey' and returns true if there is a range covering that key.

  This assumes that there is a key, in network byte order, for the last element of the range (for example 2001:0db8:ffff:ffff:ffff:ffff:ffff:ffff for 2001:db8::/32) which contains the first element of the range (2001:0db8:0000:0000:0000:0000:0000:0000) (optionally followed by any data) as value, still in network byte order, and that there is no overlapping ranges in the database.
  This requires that the underlying store supports ordered keys, which is true for LMDB but not for CDB.

  :param KeyValueStore kvs: The key value store to query
  :param KeyValueLookupKey lookupKey: The key to use for the lookup

.. function:: LuaFFIPerThreadRule(function)

  .. versionadded:: 1.7.0

  Invoke a Lua FFI function that accepts a pointer to a ``dnsdist_ffi_dnsquestion_t`` object, whose bindings are defined in ``dnsdist-lua-ffi-interface.h``.

  The ``function`` should return true if the query matches, or false otherwise. If the Lua code fails, false is returned.

  The function will be invoked in a per-thread Lua state, without access to the global Lua state. All constants (:ref:`DNSQType`, :ref:`DNSRCode`, ...) are available in that per-thread context,
  as well as all FFI functions. Objects and their bindings that are not usable in a FFI context (:class:`DNSQuestion`, :class:`DNSDistProtoBufMessage`, :class:`PacketCache`, ...)
  are not available.

  :param string function: a Lua string returning a Lua function

.. function:: LuaFFIRule(function)

  .. versionadded:: 1.5.0

  Invoke a Lua FFI function that accepts a pointer to a ``dnsdist_ffi_dnsquestion_t`` object, whose bindings are defined in ``dnsdist-lua-ffi-interface.h``.

  The ``function`` should return true if the query matches, or false otherwise. If the Lua code fails, false is returned.

  :param string function: the name of a Lua function

.. function:: LuaRule(function)

  .. versionadded:: 1.5.0

  Invoke a Lua function that accepts a :class:`DNSQuestion` object.

  The ``function`` should return true if the query matches, or false otherwise. If the Lua code fails, false is returned.

  :param string function: the name of a Lua function

.. function:: MaxQPSIPRule(qps[, v4Mask[, v6Mask[, burst[, expiration[, cleanupDelay[, scanFraction [, shards]]]]]]])

  .. versionchanged:: 1.8.0
    ``shards`` parameter added

  Matches traffic for a subnet specified by ``v4Mask`` or ``v6Mask`` exceeding ``qps`` queries per second up to ``burst`` allowed.
  This rule keeps track of QPS by netmask or source IP. This state is cleaned up regularly if  ``cleanupDelay`` is greater than zero,
  removing existing netmasks or IP addresses that have not been seen in the last ``expiration`` seconds.

  :param int qps: The number of queries per second allowed, above this number traffic is matched
  :param int v4Mask: The IPv4 netmask to match on. Default is 32 (the whole address)
  :param int v6Mask: The IPv6 netmask to match on. Default is 64
  :param int burst: The number of burstable queries per second allowed. Default is same as qps
  :param int expiration: How long to keep netmask or IP addresses after they have last been seen, in seconds. Default is 300
  :param int cleanupDelay: The number of seconds between two cleanups. Default is 60
  :param int scanFraction: The maximum fraction of the store to scan for expired entries, for example 5 would scan at most 20% of it. Default is 10 so 10%
  :param int shards: How many shards to use, to decrease lock contention between threads. Default is 10 and is a safe default unless a very high number of threads are used to process incoming queries

.. function:: MaxQPSRule(qps)

  Matches traffic **not** exceeding this qps limit. If e.g. this is set to 50, starting at the 51st query of the current second traffic stops being matched.
  This can be used to enforce a global QPS limit.

  :param int qps: The number of queries per second allowed, above this number the traffic is **not** matched anymore

.. function:: NetmaskGroupRule(nmg[, src[, quiet]])

  .. versionchanged:: 1.4.0
    ``quiet`` parameter added

  .. versionchanged:: 1.9.0
    The ``nmg`` parameter now accepts a string or a list of strings in addition to a class:`NetmaskGroup` object.

  Matches traffic from/to the network range specified in the ``nmg``, which can be a string, a list of strings,
  or a :class:`NetmaskGroup` object created via :func:`newNMG`.

  Set the ``src`` parameter to false to match ``nmg`` against destination address instead of source address.
  This can be used to differentiate between clients

  :param NetmaskGroup nmg: The netmasks to match, can be a string, a list of strings or a :class:`NetmaskGroup` object.
  :param bool src: Whether to match source or destination address of the packet. Defaults to true (matches source)
  :param bool quiet: Do not display the list of matched netmasks in Rules. Default is false.

.. function:: OpcodeRule(code)

  Matches queries with opcode ``code``.
  ``code`` can be directly specified as an integer, or one of the :ref:`built-in DNSOpcodes <DNSOpcode>`.

  :param int code: The opcode to match

.. function:: PayloadSizeRule(comparison, size)

  .. versionadded:: 1.9.0

  Matches queries or responses whose DNS payload size fits the given comparison.

  :param str comparison: The comparison operator to use. Supported values are ``equal``, ``greater``, ``greaterOrEqual``, ``smaller`` and ``smallerOrEqual``.
  :param int size: The size to compare to.

.. function:: ProbaRule(probability)

  Matches queries with a given probability. 1.0 means "always"

  :param double probability: Probability of a match

.. function:: ProxyProtocolValueRule(type [, value])

  .. versionadded:: 1.6.0

  Matches queries that have a proxy protocol TLV value of the specified type. If ``value`` is set,
  the content of the value should also match the content of ``value``.

  :param int type: The type of the value, ranging from 0 to 255 (both included)
  :param str value: The optional binary-safe value to match

.. function:: QClassRule(qclass)

  Matches queries with the specified ``qclass``.
  ``class`` can be specified as an integer or as one of the built-in :ref:`DNSClass`.

  :param int qclass: The Query Class to match on

.. function:: QNameRule(qname)

   Matches queries with the specified qname exactly.

   :param string qname: Qname to match

.. function:: QNameSetRule(set)

  .. versionadded:: 1.4.0

   Matches if the set contains exact qname.

   To match subdomain names, see :func:`QNameSuffixRule`.

   :param DNSNameSet set: Set with qnames of type class:`DNSNameSet` created with :func:`newDNSNameSet`.

.. function:: QNameSuffixRule(suffixes [, quiet])

  .. versionadded:: 1.9.0

  Matches based on a group of domain suffixes for rapid testing of membership.
  The first parameter, ``suffixes``, can be a string, list of strings or a class:`SuffixMatchNode` object created with :func:`newSuffixMatchNode`.
  Pass true as second parameter to prevent listing of all domains matched.

  To match domain names exactly, see :func:`QNameSetRule`.

  This rule existed before 1.9.0 but was called :func:`SuffixMatchNodeRule`, only accepting a :class:`SuffixMatchNode` parameter.

  :param suffixes: A string, list of strings, or a :class:`SuffixMatchNode` to match on
  :param bool quiet: Do not display the list of matched domains in Rules. Default is false.

   Matches queries with the specified qname exactly.

   :param string qname: Qname to match

.. function:: QNameLabelsCountRule(min, max)

  Matches if the qname has less than ``min`` or more than ``max`` labels.

  :param int min: Minimum number of labels
  :param int max: Maximum nimber of labels

.. function:: QNameWireLengthRule(min, max)

  Matches if the qname's length on the wire is less than ``min`` or more than ``max`` bytes.

  :param int min: Minimum number of bytes
  :param int max: Maximum nimber of bytes

.. function:: QTypeRule(qtype)

  Matches queries with the specified ``qtype``
  ``qtype`` may be specified as an integer or as one of the built-in QTypes.
  For instance ``DNSQType.A``, ``DNSQType.TXT`` and ``DNSQType.ANY``.

  :param int qtype: The QType to match on

.. function:: RCodeRule(rcode)

  Matches queries or responses with the specified ``rcode``.
  ``rcode`` can be specified as an integer or as one of the built-in :ref:`DNSRCode`.
  Only the non-extended RCode is matched (lower 4bits).

  :param int rcode: The RCODE to match on

.. function:: RDRule()

  Matches queries with the RD flag set.

.. function:: RegexRule(regex)

  Matches the query name against the ``regex``.

  .. code-block:: Lua

    addAction(RegexRule("[0-9]{5,}"), DelayAction(750)) -- milliseconds
    addAction(RegexRule("[0-9]{4,}\\.example$"), DropAction())

  This delays any query for a domain name with 5 or more consecutive digits in it.
  The second rule drops anything with more than 4 consecutive digits within a .EXAMPLE domain.

  Note that the query name is presented without a trailing dot to the regex.
  The regex is applied case-insensitively.

  :param string regex: A regular expression to match the traffic on

.. function:: RecordsCountRule(section, minCount, maxCount)

  Matches if there is at least ``minCount`` and at most ``maxCount`` records in the section ``section``.
  ``section`` can be specified as an integer or as a :ref:`DNSSection`.

  :param int section: The section to match on
  :param int minCount: The minimum number of entries
  :param int maxCount: The maximum number of entries

.. function:: RecordsTypeCountRule(section, qtype, minCount, maxCount)

  Matches if there is at least ``minCount`` and at most ``maxCount`` records of type ``type`` in the section ``section``.
  ``section`` can be specified as an integer or as a :ref:`DNSSection`.
  ``qtype`` may be specified as an integer or as one of the :ref:`built-in QTypes <DNSQType>`, for instance ``DNSQType.A`` or ``DNSQType.TXT``.

  :param int section: The section to match on
  :param int qtype: The QTYPE to match on
  :param int minCount: The minimum number of entries
  :param int maxCount: The maximum number of entries

.. function:: RE2Rule(regex)

  Matches the query name against the supplied regex using the RE2 engine. Note that this rule requires a full match of the query name, meaning that for example the ``powerdns`` expression with match a query name of ``powerdns`` but not ``prefixpowerdns``, ``sub.powerdns``, ``powerdnssuffix`` or ``powerdns.tld``. In short, the expression is treated as if it started with a ``^`` and ended with a ``$``.

  For an example of usage, see :func:`RegexRule`.

  :note: Only available when :program:`dnsdist` was built with libre2 support.

  :param str regex: The regular expression to match the QNAME.

.. function:: SNIRule(name)

  .. versionadded:: 1.4.0

  Matches against the TLS Server Name Indication value sent by the client, if any. Only makes
  sense for DoT or DoH, and for that last one matching on the HTTP Host header using :func:`HTTPHeaderRule`
  might provide more consistent results.
  As of the version 2.3.0-beta of h2o, it is unfortunately not possible to extract the SNI value from DoH
  connections, and it is therefore necessary to use the HTTP Host header until version 2.3.0 is released,
  or ``nghttp2`` is used for incoming DoH instead (1.9.0+).

  :param str name: The exact SNI name to match.

.. function:: SuffixMatchNodeRule(smn[, quiet])

  .. versionchanged:: 1.9.0
    The ``smn`` parameter now accepts a string or a list of strings in addition to a class:`SuffixMatchNode` object.

  Matches based on a group of domain suffixes for rapid testing of membership.
  The first parameter, ``smn``, can be a string, list of strings or a class:`SuffixMatchNode` object created with :func:`newSuffixMatchNode`.
  Pass true as second parameter to prevent listing of all domains matched.

  To match domain names exactly, see :func:`QNameSetRule`.

  Since 1.9.0, this rule can also be used via the alias :func:`QNameSuffixRule`.

  :param SuffixMatchNode smn: A string, list of strings, or a :class:`SuffixMatchNode` to match on
  :param bool quiet: Do not display the list of matched domains in Rules. Default is false.

.. function:: TagRule(name [, value])

  Matches question or answer with a tag named ``name`` set. If ``value`` is specified, the existing tag value should match too.

  :param string name: The name of the tag that has to be set
  :param string value: If set, the value the tag has to be set to. Default is unset

.. function:: TCPRule(tcp)

  Matches question received over TCP if ``tcp`` is true, over UDP otherwise.

  :param bool tcp: Match TCP traffic if true, UDP traffic if false.

.. function:: TrailingDataRule()

  Matches if the query has trailing data.

.. function:: PoolAvailableRule(poolname)

  Check whether a pool has any servers available to handle queries

  .. code-block:: Lua

    --- Send queries to default pool when servers are available
    addAction(PoolAvailableRule(""), PoolAction(""))
    --- Send queries to fallback pool if not
    addAction(AllRule(), PoolAction("fallback"))

  :param string poolname: Pool to check

.. function:: PoolOutstandingRule(poolname, limit)

  .. versionadded:: 1.7.0

  Check whether a pool has total outstanding queries above limit

  .. code-block:: Lua

    --- Send queries to spill over pool if default pool is under pressure
    addAction(PoolOutstandingRule("", 5000), PoolAction("spillover"))

  :param string poolname: Pool to check
  :param int limit: Total outstanding limit

Combining Rules
---------------

.. function:: AndRule(selectors)

  Matches traffic if all ``selectors`` match.

  :param {Rule} selectors: A table of Rules

.. function:: NotRule(selector)

  Matches the traffic if the ``selector`` rule does not match;

  :param Rule selector: A Rule

.. function:: OrRule(selectors)

  Matches the traffic if one or more of the ``selectors`` Rules does match.

  :param {Rule} selector: A table of Rules

Objects
-------

.. class:: DNSDistRuleAction

  .. versionadded:: 1.9.0

  Represents a rule composed of a :class:`DNSRule` selector, to select the queries this applies to,
  and a :class:`DNSAction` action to apply when the selector matches.

  .. method:: DNSDistRuleAction:getAction()

    Return the :class:`DNSAction` action of this rule.

  .. method:: DNSDistRuleAction:getSelector()

    Return the :class:`DNSRule` selector of this rule.

.. class:: DNSDistResponseRuleAction

  .. versionadded:: 1.9.0

  Represents a rule composed of a :class:`DNSRule` selector, to select the responses this applies to,
  and a :class:`DNSResponseAction` action to apply when the selector matches.

  .. method:: DNSDistResponseRuleAction:getAction()

    Return the :class:`DNSResponseAction` action of this rule.

  .. method:: DNSDistResponseRuleAction:getSelector()

    Return the :class:`DNSRule` selector of this rule.

.. class:: DNSRule

  .. versionadded:: 1.9.0

  .. method:: DNSRule:getMatches() -> int

    Return the number of times this selector matched a query or a response. Note that if the same selector is reused for different ``DNSDistRuleAction``
    objects, the counter will be common to all these objects.
