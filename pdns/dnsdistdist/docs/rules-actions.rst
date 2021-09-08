Packet Policies
===============

dnsdist works in essence like any other loadbalancer:

It receives packets on one or several addresses it listens on, and determines whether it will process this packet based on the :doc:`advanced/acl`. Should the packet be processed, dnsdist attempts to match any of the configured rules in order and when one matches, the associated action is performed.

These rule and action combinations are considered policies.

Packet Actions
--------------

Each packet can be:

- Dropped
- Turned into an answer directly
- Forwarded to a downstream server
- Modified and forwarded to a downstream and be modified back
- Be delayed

This decision can be taken at different times during the forwarding process.

Examples
~~~~~~~~

Rules for traffic exceeding QPS limits
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Traffic that exceeds a QPS limit, in total or per IP (subnet) can be matched by a rule.

For example::

  addAction(MaxQPSIPRule(5, 32, 48), DelayAction(100))

This measures traffic per IPv4 address and per /48 of IPv6, and if traffic for such an address (range) exceeds 5 qps, it gets delayed by 100ms. (Please note: :func:`DelayAction` can only delay UDP traffic). 

As another example::

  addAction(MaxQPSIPRule(5), SetNoRecurseAction())

This strips the Recursion Desired (RD) bit from any traffic per IPv4 or IPv6 /64 that exceeds 5 qps.
This means any those traffic bins is allowed to make a recursor do 'work' for only 5 qps.

If this is not enough, try::

  addAction(MaxQPSIPRule(5), DropAction())

or::

  addAction(AndRule{MaxQPSIPRule(5), TCPRule(false)}, TCAction())

This will respectively drop traffic exceeding that 5 QPS limit per IP or range, or return it with TC=1, forcing clients to fall back to TCP.

In that last one, note the use of :func:`TCPRule`.
Without it, clients would get TC=1 even if they correctly fell back to TCP.

To turn this per IP or range limit into a global limit, use ``NotRule(MaxQPSRule(5000))`` instead of :func:`MaxQPSIPRule`.

Regular Expressions
^^^^^^^^^^^^^^^^^^^

:func:`RegexRule` matches a regular expression on the query name, and it works like this::

  addAction(RegexRule("[0-9]{5,}"), DelayAction(750)) -- milliseconds
  addAction(RegexRule("[0-9]{4,}\\.example$"), DropAction())

This delays any query for a domain name with 5 or more consecutive digits in it.
The second rule drops anything with more than 4 consecutive digits within a .example domain.

Note that the query name is presented without a trailing dot to the regex.
The regex is applied case insensitively.

Alternatively, if compiled in, :func:`RE2Rule` provides similar functionality, but against libre2.

Rule Generators
---------------

:program:`dnsdist` contains several functions that make it easier to add actions and rules.

.. function:: addLuaAction(DNSrule, function [, options])

  .. deprecated:: 1.4.0
    Removed in 1.4.0, use :func:`LuaAction` with :func:`addAction` instead.

  Invoke a Lua function that accepts a :class:`DNSQuestion`.
  This function works similar to using :func:`LuaAction`.
  The ``function`` should return both a :ref:`DNSAction` and its argument `rule`. The `rule` is used as an argument
  of the following :ref:`DNSAction`: `DNSAction.Spoof`, `DNSAction.Pool` and `DNSAction.Delay`.
  If the Lua code fails, ServFail is returned.

  :param DNSRule: match queries based on this rule
  :param string function: the name of a Lua function
  :param table options: A table with key: value pairs with options.

  Options:

  * ``uuid``: string - UUID to assign to the new rule. By default a random UUID is generated for each rule.

  ::

    function luaaction(dq)
      if(dq.qtype==DNSQType.NAPTR)
      then
        return DNSAction.Pool, "abuse" -- send to abuse pool
      else
        return DNSAction.None, ""      -- no action
        -- return DNSAction.None       -- as of dnsdist version 1.3.0
      end
    end

    addLuaAction(AllRule(), luaaction)

.. function:: addLuaResponseAction(DNSrule, function [, options])

  .. deprecated:: 1.4.0
    Removed in 1.4.0, use :func:`LuaResponseAction` with :func:`addResponseAction` instead.

  Invoke a Lua function that accepts a :class:`DNSResponse`.
  This function works similar to using :func:`LuaResponseAction`.
  The ``function`` should return both a :ref:`DNSResponseAction` and its argument `rule`. The `rule` is used as an argument
  of the `DNSResponseAction.Delay`.
  If the Lua code fails, ServFail is returned.

  :param DNSRule: match queries based on this rule
  :param string function: the name of a Lua function
  :param table options: A table with key: value pairs with options.

  Options:

  * ``uuid``: string - UUID to assign to the new rule. By default a random UUID is generated for each rule.

Managing Rules
--------------

Active Rules can be shown with :func:`showRules` and removed with :func:`rmRule`::

  > addAction("h4xorbooter.xyz.", QPSAction(10))
  > addAction({"130.161.0.0/16", "145.14.0.0/16"} , QPSAction(20))
  > addAction({"nl.", "be."}, QPSAction(1))
  > showRules()
  #     Matches Rule                                               Action
  0           0 h4xorbooter.xyz.                                   qps limit to 10
  1           0 130.161.0.0/16, 145.14.0.0/16                      qps limit to 20
  2           0 nl., be.                                           qps limit to 1

For Rules related to the incoming query:

.. function:: addAction(DNSrule, action [, options])

  .. versionchanged:: 1.6.0
    Added ``name`` to the ``options``.

  Add a Rule and Action to the existing rules.

  :param DNSrule rule: A DNSRule, e.g. an :func:`AllRule` or a compounded bunch of rules using e.g. :func:`AndRule`
  :param action: The action to take
  :param table options: A table with key: value pairs with options.

  Options:

  * ``uuid``: string - UUID to assign to the new rule. By default a random UUID is generated for each rule.
  * ``name``: string - Name to assign to the new rule.

.. function:: clearRules()

  Remove all current rules.

.. function:: getAction(n) -> Action

  Returns the Action associated with rule ``n``.

  :param int n: The rule number

.. function:: mvRule(from, to)

  Move rule ``from`` to a position where it is in front of ``to``.
  ``to`` can be one larger than the largest rule, in which case the rule will be moved to the last position.

  :param int from: Rule number to move
  :param int to: Location to more the Rule to

.. function:: mvRuleToTop()

  .. versionadded:: 1.6.0

  This function moves the last rule to the first position. Before 1.6.0 this was handled by :func:`topRule`.

.. function:: newRuleAction(rule, action[, options])

  .. versionchanged:: 1.6.0
    Added ``name`` to the ``options``.

  Return a pair of DNS Rule and DNS Action, to be used with :func:`setRules`.

  :param Rule rule: A Rule (see `Matching Packets (Selectors)`_)
  :param Action action: The Action (see `Actions`_) to apply to the matched traffic
  :param table options: A table with key: value pairs with options.

  Options:

  * ``uuid``: string - UUID to assign to the new rule. By default a random UUID is generated for each rule.
  * ``name``: string - Name to assign to the new rule.

.. function:: setRules(rules)

  Replace the current rules with the supplied list of pairs of DNS Rules and DNS Actions (see :func:`newRuleAction`)

  :param [RuleAction] rules: A list of RuleActions

.. function:: showRules([options])

  Show all defined rules for queries, optionally displaying their UUIDs.

  :param table options: A table with key: value pairs with display options.

  Options:

  * ``showUUIDs=false``: bool - Whether to display the UUIDs, defaults to false.
  * ``truncateRuleWidth=-1``: int - Truncate rules output to ``truncateRuleWidth`` size. Defaults to ``-1`` to display the full rule.

.. function:: topRule()

  .. versionchanged:: 1.6.0
    Replaced by :func:`mvRuleToTop`

  Before 1.6.0 this function used to move the last rule to the first position, which is now handled by :func:`mvRuleToTop`.

.. function:: rmRule(id)

  .. versionchanged:: 1.6.0
    ``id`` can now be a string representing the name of the rule.

  Remove rule ``id``.

  :param int id: The position of the rule to remove if ``id`` is numerical, its UUID or name otherwise

For Rules related to responses:

.. function:: addResponseAction(DNSRule, action [, options])

  .. versionchanged:: 1.6.0
    Added ``name`` to the ``options``.

  Add a Rule and Action for responses to the existing rules.

  :param DNSRule: A DNSRule, e.g. an :func:`AllRule` or a compounded bunch of rules using e.g. :func:`AndRule`
  :param action: The action to take
  :param table options: A table with key: value pairs with options.

  Options:

  * ``uuid``: string - UUID to assign to the new rule. By default a random UUID is generated for each rule.
  * ``name``: string - Name to assign to the new rule.

.. function:: mvResponseRule(from, to)

  Move response rule ``from`` to a position where it is in front of ``to``.
  ``to`` can be one larger than the largest rule, in which case the rule will be moved to the last position.

  :param int from: Rule number to move
  :param int to: Location to more the Rule to

.. function:: mvResponseRuleToTop()

  .. versionadded:: 1.6.0

  This function moves the last response rule to the first position. Before 1.6.0 this was handled by :func:`topResponseRule`.

.. function:: rmResponseRule(id)

  .. versionchanged:: 1.6.0
    ``id`` can now be a string representing the name of the rule.

  Remove response rule ``id``.

  :param int id: The position of the rule to remove if ``id`` is numerical, its UUID or name otherwise

.. function:: showResponseRules([options])

  Show all defined response rules, optionally displaying their UUIDs.

  :param table options: A table with key: value pairs with display options.

  Options:

  * ``showUUIDs=false``: bool - Whether to display the UUIDs, defaults to false.
  * ``truncateRuleWidth=-1``: int - Truncate rules output to ``truncateRuleWidth`` size. Defaults to ``-1`` to display the full rule.

.. function:: topResponseRule()

  .. versionchanged:: 1.6.0
    Replaced by :func:`mvResponseRuleToTop`

  Before 1.6.0 this function used to move the last response rule to the first position, which is now handled by :func:`mvResponseRuleToTop`.

Functions for manipulating Cache Hit Response Rules:

.. function:: addCacheHitResponseAction(DNSRule, action [, options])

  .. versionchanged:: 1.6.0
    Added ``name`` to the ``options``.

  Add a Rule and ResponseAction for Cache Hits to the existing rules.

  :param DNSRule: A DNSRule, e.g. an :func:`AllRule` or a compounded bunch of rules using e.g. :func:`AndRule`
  :param action: The action to take
  :param table options: A table with key: value pairs with options.

  Options:

  * ``uuid``: string - UUID to assign to the new rule. By default a random UUID is generated for each rule.
  * ``name``: string - Name to assign to the new rule.

.. function:: mvCacheHitResponseRule(from, to)

  Move cache hit response rule ``from`` to a position where it is in front of ``to``.
  ``to`` can be one larger than the largest rule, in which case the rule will be moved to the last position.

  :param int from: Rule number to move
  :param int to: Location to more the Rule to

.. function:: mvCacheHitResponseRuleToTop()

  .. versionadded:: 1.6.0

  This function moves the last cache hit response rule to the first position. Before 1.6.0 this was handled by :func:`topCacheHitResponseRule`.

.. function:: rmCacheHitResponseRule(id)

  .. versionchanged:: 1.6.0
    ``id`` can now be a string representing the name of the rule.

  :param int id: The position of the rule to remove if ``id`` is numerical, its UUID or name otherwise

.. function:: showCacheHitResponseRules([options])

  Show all defined cache hit response rules, optionally displaying their UUIDs.

  :param table options: A table with key: value pairs with display options.

  Options:

  * ``showUUIDs=false``: bool - Whether to display the UUIDs, defaults to false.
  * ``truncateRuleWidth=-1``: int - Truncate rules output to ``truncateRuleWidth`` size. Defaults to ``-1`` to display the full rule.

.. function:: topCacheHitResponseRule()

  .. versionchanged:: 1.6.0
    Replaced by :func:`mvCacheHitResponseRuleToTop`

  Before 1.6.0 this function used to move the last cache hit response rule to the first position, which is now handled by :func:`mvCacheHitResponseRuleToTop`.

Functions for manipulating Self-Answered Response Rules:

.. function:: addSelfAnsweredResponseAction(DNSRule, action [, options])

  .. versionchanged:: 1.6.0
    Added ``name`` to the ``options``.

  Add a Rule and Action for Self-Answered queries to the existing rules.

  :param DNSRule: A DNSRule, e.g. an :func:`AllRule` or a compounded bunch of rules using e.g. :func:`AndRule`
  :param action: The action to take
  :param table options: A table with key: value pairs with options.

  Options:

  * ``uuid``: string - UUID to assign to the new rule. By default a random UUID is generated for each rule.
  * ``name``: string - Name to assign to the new rule.

.. function:: mvSelfAnsweredResponseRule(from, to)

  Move self answered response rule ``from`` to a position where it is in front of ``to``.
  ``to`` can be one larger than the largest rule, in which case the rule will be moved to the last position.

  :param int from: Rule number to move
  :param int to: Location to more the Rule to

.. function:: mvSelfAnsweredResponseRuleToTop()

  .. versionadded:: 1.6.0

  This function moves the last self-answered response rule to the first position. Before 1.6.0 this was handled by :func:`topSelfAnsweredResponseRule`.

.. function:: rmSelfAnsweredResponseRule(id)

  .. versionchanged:: 1.6.0
    ``id`` can now be a string representing the name of the rule.

  Remove self answered response rule ``id``.

  :param int id: The position of the rule to remove if ``id`` is numerical, its UUID or name otherwise

.. function:: showSelfAnsweredResponseRules([options])

  Show all defined self answered response rules, optionally displaying their UUIDs.

  :param table options: A table with key: value pairs with display options.

  Options:

  * ``showUUIDs=false``: bool - Whether to display the UUIDs, defaults to false.
  * ``truncateRuleWidth=-1``: int - Truncate rules output to ``truncateRuleWidth`` size. Defaults to ``-1`` to display the full rule.

.. function:: topSelfAnsweredResponseRule()

  .. versionchanged:: 1.6.0
    Replaced by :func:`mvSelfAnsweredResponseRuleToTop`

  Before 1.6.0 this function used to move the last cache hit response rule to the first position, which is now handled by :func:`mvSelfAnsweredResponseRuleToTop`.

  Move the last self answered response rule to the first position.

.. _RulesIntro:

Matching Packets (Selectors)
----------------------------

Packets can be matched by selectors, called a ``DNSRule``.
These ``DNSRule``\ s be one of the following items:

  * A string that is either a domain name or netmask
  * A list of strings that are either domain names or netmasks
  * A :class:`DNSName`
  * A list of :class:`DNSName`\ s
  * A (compounded) ``Rule``

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

  Matches DNS over HTTPS queries with a HTTP header ``name`` whose content matches the regular expression ``regex``.

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

  Invoke a Lua FFI function that accepts a pointer to a ``dnsdist_ffi_dnsquestion_t`` object, whose bindings are defined in ``dnsdist-lua-ffi.hh``.

  The ``function`` should return true if the query matches, or false otherwise. If the Lua code fails, false is returned.

  The function will be invoked in a per-thread Lua state, without access to the global Lua state. All constants (:ref:`DNSQType`, :ref:`DNSRCode`, ...) are available in that per-thread context,
  as well as all FFI functions. Objects and their bindings that are not usable in a FFI context (:class:`DNSQuestion`, :class:`DNSDistProtoBufMessage`, :class:`PacketCache`, ...)
  are not available.

  :param string function: a Lua string returning a Lua function

.. function:: LuaFFIRule(function)

  .. versionadded:: 1.5.0

  Invoke a Lua FFI function that accepts a pointer to a ``dnsdist_ffi_dnsquestion_t`` object, whose bindings are defined in ``dnsdist-lua-ffi.hh``.

  The ``function`` should return true if the query matches, or false otherwise. If the Lua code fails, false is returned.

  :param string function: the name of a Lua function

.. function:: LuaRule(function)

  .. versionadded:: 1.5.0

  Invoke a Lua function that accepts a :class:`DNSQuestion` object.

  The ``function`` should return true if the query matches, or false otherwise. If the Lua code fails, false is returned.

  :param string function: the name of a Lua function

.. function:: MaxQPSIPRule(qps[, v4Mask[, v6Mask[, burst[, expiration[, cleanupDelay[, scanFraction]]]]]])

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

.. function:: MaxQPSRule(qps)

  Matches traffic **not** exceeding this qps limit. If e.g. this is set to 50, starting at the 51st query of the current second traffic stops being matched.
  This can be used to enforce a global QPS limit.

  :param int qps: The number of queries per second allowed, above this number the traffic is **not** matched anymore

.. function:: NetmaskGroupRule(nmg[, src[, quiet]])

  .. versionchanged:: 1.4.0
    ``quiet`` parameter added

  Matches traffic from/to the network range specified in ``nmg``.

  Set the ``src`` parameter to false to match ``nmg`` against destination address instead of source address.
  This can be used to differentiate between clients

  :param NetMaskGroup nmg: The NetMaskGroup to match on
  :param bool src: Whether to match source or destination address of the packet. Defaults to true (matches source)
  :param bool quiet: Do not display the list of matched netmasks in Rules. Default is false.

.. function:: OpcodeRule(code)

  Matches queries with opcode ``code``.
  ``code`` can be directly specified as an integer, or one of the :ref:`built-in DNSOpcodes <DNSOpcode>`.

  :param int code: The opcode to match

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

   To match subdomain names, see :func:`SuffixMatchNodeRule`.

   :param DNSNameSet set: Set with qnames.

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
  The regex is applied case insensitively.

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

  Matches the query name against the supplied regex using the RE2 engine.

  For an example of usage, see :func:`RegexRule`.

  :note: Only available when dnsdist was built with libre2 support.

  :param str regex: The regular expression to match the QNAME.

.. function:: SNIRule(name)

  .. versionadded:: 1.4.0

  Matches against the TLS Server Name Indication value sent by the client, if any. Only makes
  sense for DoT or DoH, and for that last one matching on the HTTP Host header using :func:`HTTPHeaderRule`
  might provide more consistent results.
  As of the version 2.3.0-beta of h2o, it is unfortunately not possible to extract the SNI value from DoH
  connections, and it is therefore necessary to use the HTTP Host header until version 2.3.0 is released.

  :param str name: The exact SNI name to match.

.. function:: SuffixMatchNodeRule(smn[, quiet])

  Matches based on a group of domain suffixes for rapid testing of membership.
  Pass true as second parameter to prevent listing of all domains matched.

  To match domain names exactly, see :func:`QNameSetRule`.

  :param SuffixMatchNode smn: The SuffixMatchNode to match on
  :param bool quiet: Do not display the list of matched domains in Rules. Default is false.

.. function:: TagRule(name [, value])

  Matches question or answer with a tag named ``name`` set. If ``value`` is specified, the existing tag value should match too.

  :param bool name: The name of the tag that has to be set
  :param bool value: If set, the value the tag has to be set to. Default is unset

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

Combining Rules
~~~~~~~~~~~~~~~

.. function:: AndRule(selectors)

  Matches traffic if all ``selectors`` match.

  :param {Rule} selectors: A table of Rules

.. function:: NotRule(selector)

  Matches the traffic if the ``selector`` rule does not match;

  :param Rule selector: A Rule

.. function:: OrRule(selectors)

  Matches the traffic if one or more of the the ``selectors`` Rules does match.

  :param {Rule} selector: A table of Rules

Convenience Functions
~~~~~~~~~~~~~~~~~~~~~

.. function:: makeRule(rule)

  Make a :func:`NetmaskGroupRule` or a :func:`SuffixMatchNodeRule`, depending on it is called.
  ``makeRule("0.0.0.0/0")`` will for example match all IPv4 traffic, ``makeRule({"be","nl","lu"})`` will match all Benelux DNS traffic.

  :param string rule: A string to convert to a rule.


Actions
-------

:ref:`RulesIntro` need to be combined with an action for them to actually do something with the matched packets.
Some actions allow further processing of rules, this is noted in their description. Most of these start with 'Set' with a few exceptions, mostly for logging actions. These exceptions are:
- :func:`KeyValueStoreLookupAction`
- :func:`DnstapLogAction`
- :func:`DnstapLogResponseAction`
- :func:`LogAction`
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

.. function:: ContinueAction(action)

  .. versionadded:: 1.4.0

  Execute the specified action and override its return with None, making it possible to continue the processing.
  Subsequent rules are processed after this action.

  :param int action: Any other action

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

  This function has been deprecated in 1.6.0, please use :func:`SetDisableECSAction` instead.

  Disable the sending of ECS to the backend.
  Subsequent rules are processed after this action.

.. function:: DisableValidationAction()

  .. deprecated:: 1.6.0

  This function has been deprecated in 1.6.0, please use :func:`SetDisableValidationAction` instead.

  Set the CD bit in the query and let it go through.
  Subsequent rules are processed after this action.

.. function:: DnstapLogAction(identity, logger[, alterFunction])

  Send the the current query to a remote logger as a :doc:`dnstap <reference/dnstap>` message.
  ``alterFunction`` is a callback, receiving a :class:`DNSQuestion` and a :class:`DnstapMessage`, that can be used to modify the message.
  Subsequent rules are processed after this action.

  :param string identity: Server identity to store in the dnstap message
  :param logger: The :func:`FrameStreamLogger <newFrameStreamUnixLogger>` or :func:`RemoteLogger <newRemoteLogger>` object to write to
  :param alterFunction: A Lua function to alter the message before sending

.. function:: DnstapLogResponseAction(identity, logger[, alterFunction])

  Send the the current response to a remote logger as a :doc:`dnstap <reference/dnstap>` message.
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

  This function has been deprecated in 1.6.0, please use :func:`SetECSOverrideAction` instead.

  Whether an existing EDNS Client Subnet value should be overridden (true) or not (false).
  Subsequent rules are processed after this action.

  :param bool override: Whether or not to override ECS value

.. function:: ECSPrefixLengthAction(v4, v6)

  .. deprecated:: 1.6.0

  This function has been deprecated in 1.6.0, please use :func:`SetECSPrefixLengthAction` instead.

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

  Return an HTTP response with a status code of ''status''. For HTTP redirects, ''body'' should be the redirect URL.

  :param int status: The HTTP status code to return.
  :param string body: The body of the HTTP response, or a URL if the status code is a redirect (3xx).
  :param string contentType: The HTTP Content-Type header to return for a 200 response, ignored otherwise. Default is ''application/dns-message''.
  :param table options: A table with key: value pairs with options.

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

  Invoke a Lua FFI function that accepts a pointer to a ``dnsdist_ffi_dnsquestion_t`` object, whose bindings are defined in ``dnsdist-lua-ffi.hh``.

  The ``function`` should return a :ref:`DNSAction`. If the Lua code fails, ServFail is returned.

  :param string function: the name of a Lua function

.. function:: LuaFFIPerThreadAction(function)

  .. versionadded:: 1.7.0

  Invoke a Lua FFI function that accepts a pointer to a ``dnsdist_ffi_dnsquestion_t`` object, whose bindings are defined in ``dnsdist-lua-ffi.hh``.

  The ``function`` should return a :ref:`DNSAction`. If the Lua code fails, ServFail is returned.

  The function will be invoked in a per-thread Lua state, without access to the global Lua state. All constants (:ref:`DNSQType`, :ref:`DNSRCode`, ...) are available in that per-thread context,
  as well as all FFI functions. Objects and their bindings that are not usable in a FFI context (:class:`DNSQuestion`, :class:`DNSDistProtoBufMessage`, :class:`PacketCache`, ...)
  are not available.

  :param string function: a Lua string returning a Lua function

.. function:: LuaFFIPerThreadResponseAction(function)

  .. versionadded:: 1.7.0

  Invoke a Lua FFI function that accepts a pointer to a ``dnsdist_ffi_dnsquestion_t`` object, whose bindings are defined in ``dnsdist-lua-ffi.hh``.

  The ``function`` should return a :ref:`DNSResponseAction`. If the Lua code fails, ServFail is returned.

  The function will be invoked in a per-thread Lua state, without access to the global Lua state. All constants (:ref:`DNSQType`, :ref:`DNSRCode`, ...) are available in that per-thread context,
  as well as all FFI functions. Objects and their bindings that are not usable in a FFI context (:class:`DNSQuestion`, :class:`DNSDistProtoBufMessage`, :class:`PacketCache`, ...)
  are not available.

  :param string function: a Lua string returning a Lua function

.. function:: LuaFFIResponseAction(function)

  .. versionadded:: 1.5.0

  Invoke a Lua FFI function that accepts a pointer to a ``dnsdist_ffi_dnsquestion_t`` object, whose bindings are defined in ``dnsdist-lua-ffi.hh``.

  The ``function`` should return a :ref:`DNSResponseAction`. If the Lua code fails, ServFail is returned.

  :param string function: the name of a Lua function

.. function:: LuaResponseAction(function)

  Invoke a Lua function that accepts a :class:`DNSResponse`.

  The ``function`` should return a :ref:`DNSResponseAction`. If the Lua code fails, ServFail is returned.

  :param string function: the name of a Lua function

.. function:: MacAddrAction(option)

  .. deprecated:: 1.6.0

  This function has been deprecated in 1.6.0, please use :func:`SetMacAddrAction` instead.

  Add the source MAC address to the query as EDNS0 option ``option``.
  This action is currently only supported on Linux.
  Subsequent rules are processed after this action.

  :param int option: The EDNS0 option number

.. function:: NegativeAndSOAAction(nxd, zone, ttl, mname, rname, serial, refresh, retry, expire, minimum [, options])

  .. versionadded:: 1.6.0

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

.. function:: NoneAction()

  Does nothing.
  Subsequent rules are processed after this action.

.. function:: NoRecurseAction()

  .. deprecated:: 1.6.0

  This function has been deprecated in 1.6.0, please use :func:`SetNoRecurseAction` instead.

  Strip RD bit from the question, let it go through.
  Subsequent rules are processed after this action.

.. function:: PoolAction(poolname)

  Send the packet into the specified pool.

  :param string poolname: The name of the pool

.. function:: QPSAction(maxqps)

  Drop a packet if it does exceed the ``maxqps`` queries per second limits.
  Letting the subsequent rules apply otherwise.

  :param int maxqps: The QPS limit

.. function:: QPSPoolAction(maxqps, poolname)

  Send the packet into the specified pool only if it does not exceed the ``maxqps`` queries per second limits.
  Letting the subsequent rules apply otherwise.

  :param int maxqps: The QPS limit for that pool
  :param string poolname: The name of the pool

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

.. function:: RemoteLogAction(remoteLogger[, alterFunction [, options]])

  .. versionchanged:: 1.4.0
    ``ipEncryptKey`` optional key added to the options table.

  Send the content of this query to a remote logger via Protocol Buffer.
  ``alterFunction`` is a callback, receiving a :class:`DNSQuestion` and a :class:`DNSDistProtoBufMessage`, that can be used to modify the Protocol Buffer content, for example for anonymization purposes.
  Subsequent rules are processed after this action.

  :param string remoteLogger: The :func:`remoteLogger <newRemoteLogger>` object to write to
  :param string alterFunction: Name of a function to modify the contents of the logs before sending
  :param table options: A table with key: value pairs.

  Options:

  * ``serverID=""``: str - Set the Server Identity field.
  * ``ipEncryptKey=""``: str - A key, that can be generated via the :func:`makeIPCipherKey` function, to encrypt the IP address of the requestor for anonymization purposes. The encryption is done using ipcrypt for IPv4 and a 128-bit AES ECB operation for IPv6.

.. function:: RemoteLogResponseAction(remoteLogger[, alterFunction[, includeCNAME [, options]]])

  .. versionchanged:: 1.4.0
    ``ipEncryptKey`` optional key added to the options table.

  Send the content of this response to a remote logger via Protocol Buffer.
  ``alterFunction`` is the same callback that receiving a :class:`DNSQuestion` and a :class:`DNSDistProtoBufMessage`, that can be used to modify the Protocol Buffer content, for example for anonymization purposes.
  ``includeCNAME`` indicates whether CNAME records inside the response should be parsed and exported.
  The default is to only exports A and AAAA records.
  Subsequent rules are processed after this action.

  :param string remoteLogger: The :func:`remoteLogger <newRemoteLogger>` object to write to
  :param string alterFunction: Name of a function to modify the contents of the logs before sending
  :param bool includeCNAME: Whether or not to parse and export CNAMEs. Default false
  :param table options: A table with key: value pairs.

  Options:

  * ``serverID=""``: str - Set the Server Identity field.
  * ``ipEncryptKey=""``: str - A key, that can be generated via the :func:`makeIPCipherKey` function, to encrypt the IP address of the requestor for anonymization purposes. The encryption is done using ipcrypt for IPv4 and a 128-bit AES ECB operation for IPv6.

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

  Disable the sending of ECS to the backend.
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
  and the IPv6 one for IPv6 clients. Otherwise the first mask is used for both, and
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

.. function:: SetMacAddrAction(option)

  .. versionadded:: 1.6.0

  Add the source MAC address to the query as EDNS0 option ``option``.
  This action is currently only supported on Linux.
  Subsequent rules are processed after this action.
  Note that this function was called :func:`MacAddrAction` before 1.6.0.

  :param int option: The EDNS0 option number

.. function:: SetNoRecurseAction()

  .. versionadded:: 1.6.0

  Strip RD bit from the question, let it go through.
  Subsequent rules are processed after this action.
  Note that this function was called :func:`NoRecurseAction` before 1.6.0.

.. function:: SetNegativeAndSOAAction(nxd, zone, ttl, mname, rname, serial, refresh, retry, expire, minimum [, options])

  .. versionadded:: 1.5.0

  .. deprecated:: 1.6.0

  This function has been deprecated in 1.6.0, please use :func:`NegativeAndSOAAction` instead.

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

  Associate a tag named ``name`` with a value of ``value`` to this query, that will be passed on to the response.
  This function will not overwrite an existing tag. If the tag already exists it will keep its original value.
  Subsequent rules are processed after this action.
  Note that this function was called :func:`TagAction` before 1.6.0.

  :param string name: The name of the tag to set
  :param string value: The value of the tag

.. function:: SetTagResponseAction(name, value)

  .. versionadded:: 1.6.0

  Associate a tag named ``name`` with a value of ``value`` to this response.
  This function will not overwrite an existing tag. If the tag already exists it will keep its original value.
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

.. function:: SkipCacheAction()

  .. deprecated:: 1.6.0

  This function has been deprecated in 1.6.0, please use :func:`SetSkipAction` instead.

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

  Forge a response with the specified raw bytes as record data.

  .. code-block:: Lua

    -- select queries for the 'raw.powerdns.com.' name and TXT type, and answer with both a "aaa" "bbbb" and "ccc" TXT record:
    addAction(AndRule({QNameRule('raw.powerdns.com.'), QTypeRule(DNSQType.TXT)}), SpoofRawAction({"\003aaa\004bbbb", "\003ccc"}))
    -- select queries for the 'raw-srv.powerdns.com.' name and SRV type, and answer with a '0 0 65535 srv.powerdns.com.' SRV record, setting the AA bit to 1 and the TTL to 3600s
    addAction(AndRule({QNameRule('raw-srv.powerdns.com.'), QTypeRule(DNSQType.SRV)}), SpoofRawAction("\000\000\000\000\255\255\003srv\008powerdns\003com\000", { aa=true, ttl=3600 }))
    -- select reverse queries for '127.0.0.1' and answer with 'localhost'
    addAction(AndRule({QNameRule('1.0.0.127.in-addr.arpa.'), QTypeRule(DNSQType.PTR)}), SpoofRawAction("\009localhost\000"))

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

.. function:: SpoofSVCAction(svcParams [, options])

  .. versionadded:: 1.7.0

  Forge a response with the specified SVC record data. If the list contains more than one class:`SVCRecordParameters` (generated via :func:`newSVCRecordParameters`) object, they are all returned,
  and should have different priorities.
  The hints provided in the SVC parameters, if any, will also be added as A/AAAA records in the additional section, using the target name present in the parameters as owner name if it's not empty (root) and the qname instead.

  :param list of class:`SVCRecordParameters` svcParams: The record data to return
  :param table options: A table with key: value pairs with options.

  Options:

  * ``aa``: bool - Set the AA bit to this value (true means the bit is set, false means it's cleared). Default is to clear it.
  * ``ad``: bool - Set the AD bit to this value (true means the bit is set, false means it's cleared). Default is to clear it.
  * ``ra``: bool - Set the RA bit to this value (true means the bit is set, false means it's cleared). Default is to copy the value of the RD bit from the incoming query.
  * ``ttl``: int - The TTL of the record.

.. function:: TagAction(name, value)

  .. deprecated:: 1.6.0
    This function has been deprecated in 1.6.0, please use :func:`SetTagAction` instead.

  Associate a tag named ``name`` with a value of ``value`` to this query, that will be passed on to the response.
  Subsequent rules are processed after this action.

  :param string name: The name of the tag to set
  :param string value: The value of the tag

.. function:: TagResponseAction(name, value)

  .. deprecated:: 1.6.0
    This function has been deprecated in 1.6.0, please use :func:`SetTagResponseAction` instead.

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

.. function:: TeeAction(remote[, addECS])

  Send copy of query to ``remote``, keep stats on responses.
  If ``addECS`` is set to true, EDNS Client Subnet information will be added to the query.
  Subsequent rules are processed after this action.

  :param string remote: An IP:PORT combination to send the copied queries to
  :param bool addECS: Whether or not to add ECS information. Default false

.. function:: TempFailureCacheTTLAction(ttl)

  .. deprecated:: 1.6.0

  This function has been deprecated in 1.6.0, please use :func:`SetTempFailureCacheTTLAction` instead.

  Set the cache TTL to use for ServFail and Refused replies. TTL is not applied for successful replies.
  Subsequent rules are processed after this action.

  :param int ttl: Cache TTL for temporary failure replies
