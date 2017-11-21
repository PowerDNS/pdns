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

This measures traffic per IPv4 address and per /48 of IPv6, and if traffic for such an address (range) exceeds 5 qps, it gets delayed by 100ms.

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

    addAction(AndRule({QTypeRule(dnsdist.ANY), TCPRule(false)}), TCAction())

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

.. function:: addLuaAction(DNSrule, function)

  Invoke a Lua function that accepts a :class:`DNSQuestion`.
  This function works similar to using :func:`LuaAction`.

  The ``function`` should return a :ref:`DNSAction`.

  :param DNSRule: match queries based on this rule
  :param string function: the name of a Lua function

.. function:: addLuaResponseAction(DNSrule, function)

  Invoke a Lua function that accepts a :class:`DNSQuestion` on the response.
  This function works similar to using :func:`LuaAction`.

  The ``function`` should return a :ref:`DNSAction`.

  :param DNSRule: match queries based on this rule
  :param string function: the name of a Lua function

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

.. function:: addAction(DNSrule, action)

  Add a Rule and Action to the existing rules.

  :param DNSrule rule: A DNSRule, e.g. an :func:`allRule` or a compounded bunch of rules using e.g. :func:`AndRule`
  :param action: The action to take

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

.. function:: newRuleAction(rule, action)

  Return a pair of DNS Rule and DNS Action, to be used with :func:`setRules`.

  :param Rule rule: A `Rule <#traffic-matching>`_
  :param Action action: The `Action <#actions>`_ to apply to the matched traffic

.. function:: setRules(rules)

  Replace the current rules with the supplied list of pairs of DNS Rules and DNS Actions (see :func:`newRuleAction`)

  :param [RuleAction] rules: A list of RuleActions

.. function:: showRules()

  Show all defined rules for queries.

.. function:: topRule()

  Move the last rule to the first position.

.. function:: rmRule(n)

  Remove rule ``n``.

  :param int n: Rule number to remove

For Rules related to responses:

.. function:: addResponseAction(DNSRule, action)

  Add a Rule and Action for responses to the existing rules.

  :param DNSRule: A DNSRule, e.g. an :func:`allRule` or a compounded bunch of rules using e.g. :func:`AndRule`
  :param action: The action to take

.. function:: mvResponseRule(from, to)

  Move response rule ``from`` to a position where it is in front of ``to``.
  ``to`` can be one larger than the largest rule, in which case the rule will be moved to the last position.

  :param int from: Rule number to move
  :param int to: Location to more the Rule to

.. function:: rmResponseRule(n)

  Remove response rule ``n``.

  :param int n: Rule number to remove

.. function:: showResponseRules()

  Show all defined response rules.

.. function:: topResponseRule()

  Move the last response rule to the first position.

Functions for manipulation Cache Hit Rules:

.. function:: addCacheHitAction(DNSRule, action)

  .. versionadded:: 1.2.0

  Add a Rule and Action for Cache Hits to the existing rules.

  :param DNSRule: A DNSRule, e.g. an :func:`allRule` or a compounded bunch of rules using e.g. :func:`AndRule`
  :param action: The action to take

.. function:: mvCacheHitResponseRule(from, to)

  .. versionadded:: 1.2.0

  Move cache hit response rule ``from`` to a position where it is in front of ``to``.
  ``to`` can be one larger than the largest rule, in which case the rule will be moved to the last position.

  :param int from: Rule number to move
  :param int to: Location to more the Rule to

.. function:: rmCacheHitResponseRule(n)

  .. versionadded:: 1.2.0

  Remove cache hit response rule ``n``.

  :param int n: Rule number to remove

.. function:: showCacheHitResponseRules()

  .. versionadded:: 1.2.0

  Show all defined cache hit response rules.

.. function:: topCacheHitResponseRule()

  .. versionadded:: 1.2.0

  Move the last cache hit response rule to the first position.

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

.. function:: MaxQPSIPRule(qps[, v4Mask[, v6Mask[, burst]]])

  Matches traffic for a subnet specified by ``v4Mask`` or ``v6Mask`` exceeding ``qps`` queries per second up to ``burst`` allowed 

  :param int qps: The number of queries per second allowed, above this number traffic is matched
  :param int v4Mask: The IPv4 netmask to match on. Default is 32 (the whole address)
  :param int v6Mask: The IPv6 netmask to match on. Default is 64
  :param int burst: The number of burstable queries per second allowed. Default is same as qps

.. function:: MaxQPSRule(qps)

  Matches traffic exceeding this qps limit. If e.g. this is set to 50, starting at the 51st query of the current second traffic is matched.
  This can be used to enforce a global QPS limit.

  :param int qps: The number of queries per second allowed, above this number traffic is matched

.. function:: NetmaskGroupRule(nmg[, src])

  Matches traffic from/to the network range specified in ``nmg``.

  Set the ``src`` parameter to false to match ``nmg`` against destination address instead of source address.
  This can be used to differentiate between clients 

  :param NetMaskGroup nmg: The NetMaskGroup to match on
  :param bool src: Whether to match source or destination address of the packet. Defaults to true (matches source)

.. function:: OpcodeRule(code)

  Matches queries with opcode ``code``.
  ``code`` can be directly specified as an integer, or one of the `built-in DNSOpcode <#opcode>`_.

  :param int code: The opcode to match

.. function:: ProbaRule(probability)

  .. versionadded:: 1.3.0

  Matches queries with a given probability. 1.0 means "always"

  :param double probability: Probability of a match

.. function:: QClassRule(qclass)

  Matches queries with the specified ``qclass``.
  ``class`` can be specified as an integer or as one of the built-in `QClass <#qclass>`_.

  :param int qclass: The Query Class to match on

.. function:: QNameRule(qname)

  .. versionadded:: 1.2.0

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
  For instance ``dnsdist.A``, ``dnsdist.TXT`` and ``dnsdist.ANY``.

  :param int qtype: The QType to match on

.. function:: RCodeRule(rcode)

  Matches queries or responses the specified ``rcode``.
  ``rcode`` can be specified as an integer or as one of the built-in `RCode <#rcode>`_.

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
  ``section`` can be specified as an integer or as a ref:`DNSSection`.
  ``qtype`` may be specified as an integer or as one of the built-in QTypes, for instance ``dnsdist.A`` or ``dnsdist.TXT``.

  :param int section: The section to match on
  :param int qtype: The QTYPE to match on
  :param int minCount: The minimum number of entries
  :param int maxCount: The maximum number of entries

.. function:: RE2Rule(regex)

  Matches the query name against the supplied regex using the RE2 engine.

  For an example of usage, see :func:`RegexRule`.

  :note: Only available when dnsdist was built with libre2 support.

  :param str regex: The regular expression to match the QNAME.

.. function:: SuffixMatchNodeRule(smn[, quiet])

  Matches based on a group of domain suffixes for rapid testing of membership.
  Pass true as second parameter to prevent listing of all domains matched.

  :param SuffixMatchNode smb: The SuffixMatchNode to match on
  :param bool quiet: Do not return the list of matched domains. Default is false.

.. function:: TCPRule([tcp])

  Matches question received over TCP if ``tcp`` is true, over UDP otherwise.

  :param bool tcp: Match TCP traffic. Default is true.

.. function:: TrailingDataRule()

  Matches if the query has trailing data.

Combining Rules
~~~~~~~~~~~~~~~

.. function:: andRule(selectors)

  Matches traffic if all ``selectors`` match.

  :param {Rule} selectors: A table of Rules

.. function:: NotRule(selector)

  Matches the traffic if the ``selector`` rule does not match;

  :param Rule selector: A Rule

.. function:: OrRule(selectors)

  Matches the traffic if one or more of the the ``selectors`` Rules does match.

  :param {Rule} selector: A table of Rules

Convience Functions
~~~~~~~~~~~~~~~~~~~

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

.. function:: DelayAction(milliseconds)

  Delay the response by the specified amount of milliseconds (UDP-only).
  Subsequent rules are processed after this rule.

  :param int milliseconds: The amount of milliseconds to delay the response

.. function:: DelayResponseAction(milliseconds)

  Delay the response by the specified amount of milliseconds (UDP-only).
  Subsequent rules are processed after this rule.

  :param int milliseconds: The amount of milliseconds to delay the response

.. function:: DisableECSAction()

  Disable the sending of ECS to the backend.
  Subsequent rules are processed after this rule.

.. function:: DisableValidationAction()

  Set the CD bit in the query and let it go through.

.. function:: DropAction()

  Drop the packet.

.. function:: DropResponseAction()

  Drop the packet.

.. function:: ECSOverrideAction(override)

  Whether an existing EDNS Client Subnet value should be overridden (true) or not (false).
  Subsequent rules are processed after this rule.

  :param bool override: Whether or not to override ECS value

.. function:: ECSPrefixLengthAction(v4, v6)

  Set the ECS prefix length.
  Subsequent rules are processed after this rule.

  :param int v4: The IPv4 netmask length
  :param int v6: The IPv6 netmask length

.. function:: LogAction([filename[, binary[, append[, buffered]]]])

  Log a line for each query, to the specified ``file`` if any, to the console (require verbose) otherwise.
  When logging to a file, the ``binary`` optional parameter specifies whether we log in binary form (default) or in textual form.
  The ``append`` optional parameter specifies whether we open the file for appending or truncate each time (default).
  The ``buffered`` optional parameter specifies whether writes to the file are buffered (default) or not.
  Subsequent rules are processed after this rule.

  :param string filename: File to log to
  :param bool binary: Do binary logging. Default true
  :param bool append: Append to the log. Default false
  :param bool buffered: Use buffered I/O. default true

.. function:: MacAddrAction(option)

  Add the source MAC address to the query as EDNS0 option ``option``.
  This action is currently only supported on Linux.
  Subsequent rules are processed after this rule.

  :param int option: The EDNS0 option number

.. function:: NoneAction()

  Does nothing.
  Subsequent rules are processed after this rule.

.. function:: NoRecurseAction()

  Strip RD bit from the question, let it go through.
  Subsequent rules are processed after this rule.

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

  Reply immediatly by turning the query into a response with the specified ``rcode``.
  ``rcode`` can be specified as an integer or as one of the built-in `RCode <#rcode>`_.

  :param int rcode: The RCODE to respond with.

.. function:: RemoteLogAction(remoteLogger[, alterFunction])

  Send the content of this query to a remote logger via Protocol Buffer.
  ``alterFunction`` is a callback, receiving a :class:`DNSQuestion` and a :class:`DNSDistProtoBufMessage`, that can be used to modify the Protocol Buffer content, for example for anonymization purposes

  :param string remoteLogger: An IP:PORT combo to send the remote log to
  :param string alterFunction: Name of a function to modify the contents of the logs before sending

.. function:: RemoteLogResponseAction(remoteLogger[, alterFunction[, includeCNAME]])

  Send the content of this response to a remote logger via Protocol Buffer.
  ``alterFunction`` is the same callback that receiving a :class:`DNSQuestion` and a :class:`DNSDistProtoBufMessage`, that can be used to modify the Protocol Buffer content, for example for anonymization purposes
  ``includeCNAME`` indicates whether CNAME records inside the response should be parsed and exported.
  The default is to only exports A and AAAA records

  :param string remoteLogger: An IP:PORT combo to send the remote log to
  :param string alterFunction: Name of a function to modify the contents of the logs before sending
  :param bool includeCNAME: Whether or not to parse and export CNAMEs. Default false

.. function:: SkipCacheAction()

  Don't lookup the cache for this query, don't store the answer.

.. function:: SNMPTrapAction([message])

  Send an SNMP trap, adding the optional ``message`` string as the query description.
  Subsequent rules are processed after this rule.

  :param string message: The message to include

.. function:: SNMPTrapResponseAction([message])

  Send an SNMP trap, adding the optional ``message`` string as the query description.
  Subsequent rules are processed after this rule.

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

.. function:: TCAction()

  Create answer to query with TC and RD bits set, to force the client to TCP.

.. function:: TeeAction(remote[, addECS])

  Send copy of query to ``remote``, keep stats on responses.
  If ``addECS`` is set to true, EDNS Client Subnet information will be added to the query.

  :param string remote: An IP:PORT conbination to send the copied queries to
  :param bool addECS: Whether or not to add ECS information. Default false


