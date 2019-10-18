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

  addAction(MaxQPSIPRule(5), NoRecurseAction())

This strips the Recursion Desired (RD) bit from any traffic per IPv4 or IPv6 /64 that exceeds 5 qps.
This means any those traffic bins is allowed to make a recursor do 'work' for only 5 qps.

If this is not enough, try::

  addAction(MaxQPSIPRule(5), DropAction())

or::

  addAction(MaxQPSIPRule(5), TCAction())

This will respectively drop traffic exceeding that 5 QPS limit per IP or range, or return it with TC=1, forcing clients to fall back to TCP.

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

.. function:: addAnyTCRule()

  .. deprecated:: 1.2.0

  Set the TC-bit (truncate) on ANY queries received over UDP, forcing a retry over TCP.
  This function is deprecated as of 1.2.0 and will be removed in 1.3.0. This is equivalent to doing::

   addAction(AndRule({QTypeRule(DNSQType.ANY), TCPRule(false)}), TCAction())

  .. versionchanged:: 1.4.0
    Before 1.4.0, the QTypes were in the ``dnsdist`` namespace. Use ``dnsdist.ANY`` in these versions.

.. function:: addDelay(DNSrule, delay)

  .. deprecated:: 1.2.0

  Delay the query for ``delay`` milliseconds before sending to a backend.
  This function is deprecated as of 1.2.0 and will be removed in 1.3.0, please use instead:

    addAction(DNSRule, DelayAction(delay))

  :param DNSRule: The DNSRule to match traffic
  :param int delay: The delay time in milliseconds.

.. function:: addDisableValidationRule(DNSrule)

  .. deprecated:: 1.2.0

  Set the CD (Checking Disabled) flag to 1 for all queries matching the DNSRule.
  This function is deprecated as of 1.2.0 and will be removed in 1.3.0. Please use the :func:`DisableValidationAction` action instead.

.. function:: addDomainBlock(domain)

  .. deprecated:: 1.2.0

  Drop all queries for ``domain`` and all names below it.
  Deprecated as of 1.2.0 and will be removed in 1.3.0, please use instead:

    addAction(domain, DropAction())

  :param string domain: The domain name to block

.. function:: addDomainSpoof(domain, IPv4[, IPv6])
              addDomainSpoof(domain, {IP[,...]})

  .. deprecated:: 1.2.0

  Generate answers for A/AAAA/ANY queries.
  This function is deprecated as of 1.2.0 and will be removed in 1.3.0, please use:

    addAction(domain, SpoofAction({IP[,...]}))

  or:

    addAction(domain, SpoofAction(IPv4[, IPv6]))

  :param string domain: Domain name to spoof for
  :param string IPv4: IPv4 address to spoof in the reply
  :param string IPv6: IPv6 address to spoof in the reply
  :param string IP: IP address to spoof in the reply

.. function:: addDomainCNAMESpoof(domain, cname)

  .. deprecated:: 1.2.0

  Generate CNAME answers for queries. This function is deprecated as of 1.2.0 and will be removed in 1.3.0, in favor of using:

    addAction(domain, SpoofCNAMEAction(cname))

  :param string domain: Domain name to spoof for
  :param string cname: Domain name to add CNAME to

.. function:: addLuaAction(DNSrule, function [, options])

  .. versionchanged:: 1.3.0
    Added the optional parameter ``options``.

  .. versionchanged:: 1.3.0
    The second argument returned by the ``function`` can be omitted. For earlier releases, simply return an empty string.

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

    function luarule(dq)
      if(dq.qtype==dnsdist.NAPTR)
      then
        return DNSAction.Pool, "abuse" -- send to abuse pool
      else
        return DNSAction.None, ""      -- no action
        -- return DNSAction.None       -- as of dnsdist version 1.3.0
      end
    end

    addLuaAction(AllRule(), luarule)

.. function:: addLuaResponseAction(DNSrule, function [, options])

  .. versionchanged:: 1.3.0
    Added the optional parameter ``options``.

  .. versionchanged:: 1.3.0
    The second argument returned by the ``function`` can be omitted. For earlier releases, simply return an empty string.

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

.. function:: addNoRecurseRule(DNSrule)

  .. deprecated:: 1.2.0

  Clear the RD flag for all queries matching the rule.
  This function is deprecated as of 1.2.0 and will be removed in 1.3.0, please use:

    addAction(DNSRule, NoRecurseAction())

  :param DNSRule: match queries based on this rule

.. function:: addPoolRule(DNSRule, pool)

  .. deprecated:: 1.2.0

  Send queries matching the first argument to the pool ``pool``.
  e.g.::

    addPoolRule("example.com", "myPool")

  This function is deprecated as of 1.2.0 and will be removed in 1.3.0, this is equivalent to::

    addAction("example.com", PoolAction("myPool"))

  :param DNSRule: match queries based on this rule
  :param string pool: The name of the pool to send the queries to

.. function:: addQPSLimit(DNSrule, limit)

  .. deprecated:: 1.2.0

  Limit queries matching the DNSRule to ``limit`` queries per second.
  All queries over the limit are dropped.
  This function is deprecated as of 1.2.0 and will be removed in 1.3.0, please use:

    addAction(DNSRule, QPSAction(limit))

  :param DNSRule: match queries based on this rule
  :param int limit: QPS limit for this rule

.. function:: addQPSPoolRule(DNSRule, limit, pool)

  .. deprecated:: 1.2.0

  Send at most ``limit`` queries/s for this pool, letting the subsequent rules apply otherwise.
  This function is deprecated as of 1.2.0 and will be removed in 1.3.0, as it is only a convience function for the following syntax::

    addAction("192.0.2.0/24", QPSPoolAction(15, "myPool")

  :param DNSRule: match queries based on this rule
  :param int limit: QPS limit for this rule
  :param string pool: The name of the pool to send the queries to


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

  .. versionchanged:: 1.3.0
    Added the optional parameter ``options``.

  Add a Rule and Action to the existing rules.

  :param DNSrule rule: A DNSRule, e.g. an :func:`AllRule` or a compounded bunch of rules using e.g. :func:`AndRule`
  :param action: The action to take
  :param table options: A table with key: value pairs with options.

  Options:

  * ``uuid``: string - UUID to assign to the new rule. By default a random UUID is generated for each rule.

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

.. function:: newRuleAction(rule, action[, options])

  .. versionchanged:: 1.3.0
    Added the optional parameter ``options``.

  Return a pair of DNS Rule and DNS Action, to be used with :func:`setRules`.

  :param Rule rule: A `Rule <#traffic-matching>`_
  :param Action action: The `Action <#actions>`_ to apply to the matched traffic
  :param table options: A table with key: value pairs with options.

  Options:

  * ``uuid``: string - UUID to assign to the new rule. By default a random UUID is generated for each rule.

.. function:: setRules(rules)

  Replace the current rules with the supplied list of pairs of DNS Rules and DNS Actions (see :func:`newRuleAction`)

  :param [RuleAction] rules: A list of RuleActions

.. function:: showRules([options])

  .. versionchanged:: 1.3.0
    ``options`` optional parameter added

  Show all defined rules for queries, optionally displaying their UUIDs.

  :param table options: A table with key: value pairs with display options.

  Options:

  * ``showUUIDs=false``: bool - Whether to display the UUIDs, defaults to false.
  * ``truncateRuleWidth=-1``: int - Truncate rules output to ``truncateRuleWidth`` size. Defaults to ``-1`` to display the full rule.

.. function:: topRule()

  Move the last rule to the first position.

.. function:: rmRule(id)

  .. versionchanged:: 1.3.0
    ``id`` can now be an UUID.

  Remove rule ``id``.

  :param int id: The UUID of the rule to remove if ``id`` is an UUID, its position otherwise

For Rules related to responses:

.. function:: addResponseAction(DNSRule, action [, options])

  .. versionchanged:: 1.3.0
    Added the optional parameter ``options``.

  Add a Rule and Action for responses to the existing rules.

  :param DNSRule: A DNSRule, e.g. an :func:`AllRule` or a compounded bunch of rules using e.g. :func:`AndRule`
  :param action: The action to take
  :param table options: A table with key: value pairs with options.

  Options:

  * ``uuid``: string - UUID to assign to the new rule. By default a random UUID is generated for each rule.

.. function:: mvResponseRule(from, to)

  Move response rule ``from`` to a position where it is in front of ``to``.
  ``to`` can be one larger than the largest rule, in which case the rule will be moved to the last position.

  :param int from: Rule number to move
  :param int to: Location to more the Rule to

.. function:: rmResponseRule(id)

  .. versionchanged:: 1.3.0
    ``id`` can now be an UUID.

  Remove response rule ``id``.

  :param int id: The UUID of the rule to remove if ``id`` is an UUID, its position otherwise

.. function:: showResponseRules([options])

  .. versionchanged:: 1.3.0
    ``options`` optional parameter added

  Show all defined response rules, optionally displaying their UUIDs.

  :param table options: A table with key: value pairs with display options.

  Options:

  * ``showUUIDs=false``: bool - Whether to display the UUIDs, defaults to false.
  * ``truncateRuleWidth=-1``: int - Truncate rules output to ``truncateRuleWidth`` size. Defaults to ``-1`` to display the full rule.

.. function:: topResponseRule()

  Move the last response rule to the first position.

Functions for manipulating Cache Hit Respone Rules:

.. function:: addCacheHitResponseAction(DNSRule, action [, options])

  .. versionadded:: 1.2.0

  .. versionchanged:: 1.3.0
    Added the optional parameter ``options``.

  Add a Rule and ResponseAction for Cache Hits to the existing rules.

  :param DNSRule: A DNSRule, e.g. an :func:`AllRule` or a compounded bunch of rules using e.g. :func:`AndRule`
  :param action: The action to take
  :param table options: A table with key: value pairs with options.

  Options:

  * ``uuid``: string - UUID to assign to the new rule. By default a random UUID is generated for each rule.

.. function:: mvCacheHitResponseRule(from, to)

  .. versionadded:: 1.2.0

  Move cache hit response rule ``from`` to a position where it is in front of ``to``.
  ``to`` can be one larger than the largest rule, in which case the rule will be moved to the last position.

  :param int from: Rule number to move
  :param int to: Location to more the Rule to

.. function:: rmCacheHitResponseRule(id)

  .. versionadded:: 1.2.0

  .. versionchanged:: 1.3.0
    ``id`` can now be an UUID.

  :param int id: The UUID of the rule to remove if ``id`` is an UUID, its position otherwise

.. function:: showCacheHitResponseRules([options])

  .. versionadded:: 1.2.0

  .. versionchanged:: 1.3.0
    ``options`` optional parameter added

  Show all defined cache hit response rules, optionally displaying their UUIDs.

  :param table options: A table with key: value pairs with display options.

  Options:

  * ``showUUIDs=false``: bool - Whether to display the UUIDs, defaults to false.
  * ``truncateRuleWidth=-1``: int - Truncate rules output to ``truncateRuleWidth`` size. Defaults to ``-1`` to display the full rule.

.. function:: topCacheHitResponseRule()

  .. versionadded:: 1.2.0

  Move the last cache hit response rule to the first position.

Functions for manipulating Self-Answered Response Rules:

.. function:: addSelfAnsweredResponseAction(DNSRule, action [, options])

  .. versionadded:: 1.3.0

  Add a Rule and Action for Self-Answered queries to the existing rules.

  :param DNSRule: A DNSRule, e.g. an :func:`AllRule` or a compounded bunch of rules using e.g. :func:`AndRule`
  :param action: The action to take

.. function:: mvSelfAnsweredResponseRule(from, to)

  .. versionadded:: 1.3.0

  Move self answered response rule ``from`` to a position where it is in front of ``to``.
  ``to`` can be one larger than the largest rule, in which case the rule will be moved to the last position.

  :param int from: Rule number to move
  :param int to: Location to more the Rule to

.. function:: rmSelfAnsweredResponseRule(id)

  .. versionadded:: 1.3.0

  Remove self answered response rule ``id``.

  :param int id: The UUID of the rule to remove if ``id`` is an UUID, its position otherwise

.. function:: showSelfAnsweredResponseRules([options])

  .. versionadded:: 1.3.0

  Show all defined self answered response rules, optionally displaying their UUIDs.

  :param table options: A table with key: value pairs with display options.

  Options:

  * ``showUUIDs=false``: bool - Whether to display the UUIDs, defaults to false.
  * ``truncateRuleWidth=-1``: int - Truncate rules output to ``truncateRuleWidth`` size. Defaults to ``-1`` to display the full rule.

.. function:: topSelfAnsweredResponseRule()

  .. versionadded:: 1.3.0

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

.. versionadded:: 1.2.0
   A DNSRule can also be a :class:`DNSName` or a list of these

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
  Only valid DNS over HTTPS queries are matched. If you want to match all HTTP queries, see :meth:`DOHFrontend.setResponsesMap` instead.

  :param str regex: The regex to match on

.. function:: HTTPPathRule(path)

  .. versionadded:: 1.4.0

  Matches DNS over HTTPS queries with a HTTP path of ``path``. For example, if the query has been sent to the https://192.0.2.1:443/PowerDNS?dns=... URL, the path would be '/PowerDNS'.
  Only valid DNS over HTTPS queries are matched. If you want to match all HTTP queries, see :meth:`DOHFrontend.setResponsesMap` instead.

  :param str path: The exact HTTP path to match on

.. function:: KeyValueStoreLookupRule(kvs, lookupKey)

  .. versionadded:: 1.4.0

  As of 1.4.0, this code is considered experimental.

  Return true if the key returned by 'lookupKey' exists in the key value store referenced by 'kvs'.
  The store can be a CDB (:func:`newCDBKVStore`) or a LMDB database (:func:`newLMDBKVStore`).
  The key can be based on the qname (:func:`KeyValueLookupKeyQName` and :func:`KeyValueLookupKeySuffix`),
  source IP (:func:`KeyValueLookupKeySourceIP`) or the value of an existing tag (:func:`KeyValueLookupKeyTag`).

  :param KeyValueStore kvs: The key value store to query
  :param KeyValueLookupKey lookupKey: The key to use for the lookup

.. function:: MaxQPSIPRule(qps[, v4Mask[, v6Mask[, burst[, expiration[, cleanupDelay[, scanFraction]]]]]])
  .. versionchanged:: 1.3.1
    Added the optional parameters ``expiration``, ``cleanupDelay`` and ``scanFraction``.

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

  .. versionadded:: 1.3.0

  Matches queries with a given probability. 1.0 means "always"

  :param double probability: Probability of a match

.. function:: QClassRule(qclass)

  Matches queries with the specified ``qclass``.
  ``class`` can be specified as an integer or as one of the built-in :ref:`DNSClass`.

  :param int qclass: The Query Class to match on

.. function:: QNameRule(qname)

  .. versionadded:: 1.2.0

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
  For instance ``dnsdist.A``, ``dnsdist.TXT`` and ``dnsdist.ANY``.

  :param int qtype: The QType to match on

.. function:: RCodeRule(rcode)

  Matches queries or responses with the specified ``rcode``.
  ``rcode`` can be specified as an integer or as one of the built-in :ref:`DNSRCode`.
  Only the non-extended RCode is matched (lower 4bits).

  :param int rcode: The RCODE to match on

.. function:: RDRule()

  .. versionadded:: 1.2.0

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

  :param SuffixMatchNode smb: The SuffixMatchNode to match on
  :param bool quiet: Do not display the list of matched domains in Rules. Default is false.

.. function:: TagRule(name [, value])

  .. versionadded:: 1.3.0

  Matches question or answer with a tag named ``name`` set. If ``value`` is specified, the existing tag value should match too.

  :param bool name: The name of the tag that has to be set
  :param bool value: If set, the value the tag has to be set to. Default is unset

.. function:: TCPRule([tcp])

  Matches question received over TCP if ``tcp`` is true, over UDP otherwise.

  :param bool tcp: Match TCP traffic. Default is true.

.. function:: TrailingDataRule()

  Matches if the query has trailing data.

.. function:: PoolAvailableRule(poolname)

  .. versionadded:: 1.3.3

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
Some actions allow further processing of rules, this is noted in their description.
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

  Delay the response by the specified amount of milliseconds (UDP-only).
  Subsequent rules are processed after this action.

  :param int milliseconds: The amount of milliseconds to delay the response

.. function:: DelayResponseAction(milliseconds)

  Delay the response by the specified amount of milliseconds (UDP-only).
  Subsequent rules are processed after this action.

  :param int milliseconds: The amount of milliseconds to delay the response

.. function:: DisableECSAction()

  Disable the sending of ECS to the backend.
  Subsequent rules are processed after this action.

.. function:: DisableValidationAction()

  Set the CD bit in the query and let it go through.

.. function:: DnstapLogAction(identity, logger[, alterFunction])

  .. versionadded:: 1.3.0

  Send the the current query to a remote logger as a :doc:`dnstap <reference/dnstap>` message.
  ``alterFunction`` is a callback, receiving a :class:`DNSQuestion` and a :class:`DnstapMessage`, that can be used to modify the message.
  Subsequent rules are processed after this action.

  :param string identity: Server identity to store in the dnstap message
  :param logger: The :func:`FrameStreamLogger <newFrameStreamUnixLogger>` or :func:`RemoteLogger <newRemoteLogger>` object to write to
  :param alterFunction: A Lua function to alter the message before sending

.. function:: DnstapLogResponseAction(identity, logger[, alterFunction])

  .. versionadded:: 1.3.0

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

  Whether an existing EDNS Client Subnet value should be overridden (true) or not (false).
  Subsequent rules are processed after this action.

  :param bool override: Whether or not to override ECS value

.. function:: ECSPrefixLengthAction(v4, v6)

  Set the ECS prefix length.
  Subsequent rules are processed after this action.

  :param int v4: The IPv4 netmask length
  :param int v6: The IPv6 netmask length


.. function:: ERCodeAction(rcode)

  .. versionadded:: 1.4.0

  Reply immediately by turning the query into a response with the specified EDNS extended ``rcode``.
  ``rcode`` can be specified as an integer or as one of the built-in :ref:`DNSRCode`.

  :param int rcode: The extended RCODE to respond with.

.. function:: HTTPStatusAction(status, body, contentType="")

  .. versionadded:: 1.4.0

  Return an HTTP response with a status code of ''status''. For HTTP redirects, ''body'' should be the redirect URL.

  :param int status: The HTTP status code to return.
  :param string body: The body of the HTTP response, or a URL if the status code is a redirect (3xx).
  :param string contentType: The HTTP Content-Type header to return for a 200 response, ignored otherwise. Default is ''application/dns-message''.

.. function:: KeyValueStoreLookupAction(kvs, lookupKey, destinationTag)

  .. versionadded:: 1.4.0

  As of 1.4.0, this code is considered experimental.

  Does a lookup into the key value store referenced by 'kvs' using the key returned by 'lookupKey',
  and storing the result if any into the tag named 'destinationTag'.
  The store can be a CDB (:func:`newCDBKVStore`) or a LMDB database (:func:`newLMDBKVStore`).
  The key can be based on the qname (:func:`KeyValueLookupKeyQName` and :func:`KeyValueLookupKeySuffix`),
  source IP (:func:`KeyValueLookupKeySourceIP`) or the value of an existing tag (:func:`KeyValueLookupKeyTag`).

  :param KeyValueStore kvs: The key value store to query
  :param KeyValueLookupKey lookupKey: The key to use for the lookup
  :param string destinationTag: The name of the tag to store the result into

.. function:: LogAction([filename[, binary[, append[, buffered[, verboseOnly[, includeTimestamp]]]]]])

  .. versionchanged:: 1.4.0
    Added the optional parameters ``verboseOnly`` and ``includeTimestamp``, made ``filename`` optional.

  Log a line for each query, to the specified ``file`` if any, to the console (require verbose) if the empty string is given as filename.

  If an empty string is supplied in the file name, the logging is done to stdout, and only in verbose mode by default. This can be changed by setting ``verboseOnly`` to true.

  When logging to a file, the ``binary`` optional parameter specifies whether we log in binary form (default) or in textual form. Before 1.4.0 the binary log format only included the qname and qtype. Since 1.4.0 it includes an optional timestamp, the query ID, qname, qtype, remote address and port.

  The ``append`` optional parameter specifies whether we open the file for appending or truncate each time (default).
  The ``buffered`` optional parameter specifies whether writes to the file are buffered (default) or not.

  Subsequent rules are processed after this action.

  :param string filename: File to log to. Set to an empty string to log to the normal stdout log, this only works when ``-v`` is set on the command line.
  :param bool binary: Do binary logging. Default true
  :param bool append: Append to the log. Default false
  :param bool buffered: Use buffered I/O. Default true
  :param bool verboseOnly: Whether to log only in verbose mode when logging to stdout. Default is true
  :param bool includeTimestamp: Whether to include a timestamp for every entry. Default is false

.. function:: LuaAction(function)

  Invoke a Lua function that accepts a :class:`DNSQuestion`.

  The ``function`` should return a :ref:`DNSAction`. If the Lua code fails, ServFail is returned.

  :param string function: the name of a Lua function

.. function:: LuaResponseAction(function)

  Invoke a Lua function that accepts a :class:`DNSResponse`.

  The ``function`` should return a :ref:`DNSResponseAction`. If the Lua code fails, ServFail is returned.

  :param string function: the name of a Lua function

.. function:: MacAddrAction(option)

  Add the source MAC address to the query as EDNS0 option ``option``.
  This action is currently only supported on Linux.
  Subsequent rules are processed after this action.

  :param int option: The EDNS0 option number

.. function:: NoneAction()

  Does nothing.
  Subsequent rules are processed after this action.

.. function:: NoRecurseAction()

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

.. function:: RCodeAction(rcode)

  Reply immediately by turning the query into a response with the specified ``rcode``.
  ``rcode`` can be specified as an integer or as one of the built-in :ref:`DNSRCode`.

  :param int rcode: The RCODE to respond with.

.. function:: RemoteLogAction(remoteLogger[, alterFunction [, options]])

  .. versionchanged:: 1.3.0
    ``options`` optional parameter added.

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

  .. versionchanged:: 1.3.0
    ``options`` optional parameter added.

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

.. function:: SetECSAction(v4 [, v6])

  .. versionadded:: 1.3.1

  Set the ECS prefix and prefix length sent to backends to an arbitrary value.
  If both IPv4 and IPv6 masks are supplied the IPv4 one will be used for IPv4 clients
  and the IPv6 one for IPv6 clients. Otherwise the first mask is used for both, and
  can actually be an IPv6 mask.
  Subsequent rules are processed after this action.

  :param string v4: The IPv4 netmask, for example "192.0.2.1/32"
  :param string v6: The IPv6 netmask, if any

.. function:: SkipCacheAction()

  Don't lookup the cache for this query, don't store the answer.

.. function:: SNMPTrapAction([message])

  Send an SNMP trap, adding the optional ``message`` string as the query description.
  Subsequent rules are processed after this action.

  :param string message: The message to include

.. function:: SNMPTrapResponseAction([message])

  Send an SNMP trap, adding the optional ``message`` string as the query description.
  Subsequent rules are processed after this action.

  :param string message: The message to include

.. function:: SpoofAction(ip[, ip[...]])
              SpoofAction(ips)

  Forge a response with the specified IPv4 (for an A query) or IPv6 (for an AAAA) addresses.
  If you specify multiple addresses, all that match the query type (A, AAAA or ANY) will get spoofed in.

  :param string ip: An IPv4 and/or IPv6 address to spoof
  :param {string} ips: A table of IPv4 and/or IPv6 addresses to spoof

.. function:: SpoofCNAMEAction(cname)

  Forge a response with the specified CNAME value.

  :param string cname: The name to respond with

.. function:: TagAction(name, value)

  .. versionadded:: 1.3.0

  Associate a tag named ``name`` with a value of ``value`` to this query, that will be passed on to the response.
  Subsequent rules are processed after this action.

  :param string name: The name of the tag to set
  :param string value: The value of the tag

.. function:: TagResponseAction(name, value)

  .. versionadded:: 1.3.0

  Associate a tag named ``name`` with a value of ``value`` to this response.
  Subsequent rules are processed after this action.

  :param string name: The name of the tag to set
  :param string value: The value of the tag

.. function:: TCAction()

  Create answer to query with TC and RD bits set, to force the client to TCP.

.. function:: TeeAction(remote[, addECS])

  Send copy of query to ``remote``, keep stats on responses.
  If ``addECS`` is set to true, EDNS Client Subnet information will be added to the query.

  :param string remote: An IP:PORT conbination to send the copied queries to
  :param bool addECS: Whether or not to add ECS information. Default false

.. function:: TempFailureCacheTTLAction(ttl)

  Set the cache TTL to use for ServFail and Refused replies. TTL is not applied for successful replies.

  :param int ttl: Cache TTL for temporary failure replies
