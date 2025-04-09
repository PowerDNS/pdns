Rules management
================

Incoming queries
----------------

For Rules related to the incoming query:

.. function:: addAction(DNSrule, action [, options])

  .. versionchanged:: 1.6.0
    Added ``name`` to the ``options``.

  .. versionchanged:: 1.9.0
    Passing a string or list of strings instead of a :class:`DNSRule` is deprecated, use :func:`NetmaskGroupRule` or :func:`QNameSuffixRule` instead

  Add a Rule and Action to the existing rules.
  If a string (or list of) is passed as the first parameter instead of a :class:`DNSRule`, it behaves as if the string or list of strings was passed to :func:`NetmaskGroupRule` or :func:`SuffixMatchNodeRule`.

  :param DNSrule rule: A :class:`DNSRule`, e.g. an :func:`AllRule`, or a compounded bunch of rules using e.g. :func:`AndRule`. Before 1.9.0 it was also possible to pass a string (or list of strings) but doing so is now deprecated.
  :param action: The action to take
  :param table options: A table with key: value pairs with options.

  Options:

  * ``uuid``: string - UUID to assign to the new rule. By default a random UUID is generated for each rule.
  * ``name``: string - Name to assign to the new rule.

.. function:: clearRules()

  Remove all current rules.

.. function:: getAction(n) -> DNSDistRuleAction

  Returns the :class:`DNSDistRuleAction` associated with rule ``n``.

  :param int n: The rule number

.. function:: getRule(selector) -> DNSDistRuleAction

  .. versionadded:: 1.9.0

  Return the rule corresponding to the selector, if any.
  The selector can be the position of the rule in the list, as an integer,
  its name as a string or its UUID as a string as well.

  :param int or str selector: The position in the list, name or UUID of the rule to return.

.. function:: mvRule(from, to)

  Move rule ``from`` to a position where it is in front of ``to``.
  ``to`` can be one larger than the largest rule, in which case the rule will be moved to the last position.

  :param int from: Rule number to move
  :param int to: Location to more the Rule to

.. function:: mvRuleToTop()

  .. versionadded:: 1.6.0

  This function moves the last rule to the first position. Before 1.6.0 this was handled by :func:`topRule`.

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

Cache misses
------------

For Rules related to the incoming query after a cache miss:

.. warning::
  While all selectors and actions are available, some actions will no longer be honored at
  this point. For example changing the backend pool will not trigger a second cache-lookup.
  Switching from a backend pool that has EDNS Client Subnet enabled to one that doesn't
  will result in the EDNS Client Subnet corresponding to the initial server pool to be
  added to the query.

.. function:: addCacheMissAction(DNSrule, action [, options])

  .. versionadded:: 1.10

  Add a Rule and Action to the existing cache miss rules.
  If a string (or list of) is passed as the first parameter instead of a :class:`DNSRule`, it behaves as if the string or list of strings was passed to :func:`NetmaskGroupRule` or :func:`SuffixMatchNodeRule`.

  :param DNSrule rule: A :class:`DNSRule`, e.g. an :func:`AllRule`, or a compounded bunch of rules using e.g. :func:`AndRule`.
  :param action: The action to take
  :param table options: A table with key: value pairs with options.

  Options:

  * ``uuid``: string - UUID to assign to the new rule. By default a random UUID is generated for each rule.
  * ``name``: string - Name to assign to the new rule.

.. function:: clearCacheMissRules()

  .. versionadded:: 1.10

  Remove all current cache miss rules.

.. function:: getCacheMissAction(n) -> DNSDistRuleAction

  .. versionadded:: 1.10

  Returns the :class:`DNSDistRuleAction` associated with cache miss rule ``n``.

  :param int n: The rule number

.. function:: getCacheMissRule(selector) -> DNSDistRuleAction

  .. versionadded:: 1.10

  Return the cache miss rule corresponding to the selector, if any.
  The selector can be the position of the rule in the list, as an integer,
  its name as a string or its UUID as a string as well.

  :param int or str selector: The position in the list, name or UUID of the rule to return.

.. function:: mvCacheMissRule(from, to)

  .. versionadded:: 1.10

  Move cache miss rule ``from`` to a position where it is in front of ``to``.
  ``to`` can be one larger than the largest rule, in which case the rule will be moved to the last position.

  :param int from: Rule number to move
  :param int to: Location to more the Rule to

.. function:: mvCacheMissRuleToTop()

  .. versionadded:: 1.10

  This function moves the last cache miss rule to the first position.

.. function:: setCacheMissRules(rules)

  .. versionadded:: 1.10

  Replace the current cache miss rules with the supplied list of pairs of DNS Rules and DNS Actions (see :func:`newRuleAction`)

  :param [RuleAction] rules: A list of RuleActions

.. function:: showCacheMissRules([options])

  .. versionadded:: 1.10

  Show all defined cache miss rules for queries, optionally displaying their UUIDs.

  :param table options: A table with key: value pairs with display options.

  Options:

  * ``showUUIDs=false``: bool - Whether to display the UUIDs, defaults to false.
  * ``truncateRuleWidth=-1``: int - Truncate rules output to ``truncateRuleWidth`` size. Defaults to ``-1`` to display the full rule.

.. function:: rmCacheMissRule(id)

  .. versionadded:: 1.10

  Remove rule ``id``.

  :param int id: The position of the cache miss rule to remove if ``id`` is numerical, its UUID or name otherwise

Responses
---------

For Rules related to responses:

.. function:: addResponseAction(DNSRule, action [, options])

  .. versionchanged:: 1.6.0
    Added ``name`` to the ``options``.

  .. versionchanged:: 1.9.0
    Passing a string or list of strings instead of a :class:`DNSRule` is deprecated, use :func:`NetmaskGroupRule` or :func:`QNameSuffixRule` instead

  Add a Rule and Action for responses to the existing rules. This won't be triggered if the response is due to a cache hit (see :func:`addCacheHitResponseAction`) or is self generated (see :func:`addSelfAnsweredResponseAction`).
  If a string (or list of) is passed as the first parameter instead of a :class:`DNSRule`, it behaves as if the string or list of strings was passed to :func:`NetmaskGroupRule` or :func:`SuffixMatchNodeRule`.

  :param DNSrule rule: A :class:`DNSRule`, e.g. an :func:`AllRule`, or a compounded bunch of rules using e.g. :func:`AndRule`. Before 1.9.0 it was also possible to pass a string (or list of strings) but doing so is now deprecated.
  :param action: The action to take
  :param table options: A table with key: value pairs with options.

  Options:

  * ``uuid``: string - UUID to assign to the new rule. By default a random UUID is generated for each rule.
  * ``name``: string - Name to assign to the new rule.

.. function:: clearResponseRules()

  .. versionadded:: 1.10

  Remove all current response rules.

.. function:: getResponseRule(selector) -> DNSDistResponseRuleAction

  .. versionadded:: 1.9.0

  Return the response rule corresponding to the selector, if any.
  The selector can be the position of the rule in the list, as an integer,
  its name as a string or its UUID as a string as well.

  :param int or str selector: The position in the list, name or UUID of the rule to return.

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

Cache hits
----------

Functions for manipulating Cache Hit Response Rules:

.. function:: addCacheHitResponseAction(DNSRule, action [, options])

  .. versionchanged:: 1.6.0
    Added ``name`` to the ``options``.

  .. versionchanged:: 1.9.0
    Passing a string or list of strings instead of a :class:`DNSRule` is deprecated, use :func:`NetmaskGroupRule` or :func:`QNameSuffixRule` instead

  Add a Rule and ResponseAction for Cache Hits to the existing rules.
  If a string (or list of) is passed as the first parameter instead of a :class:`DNSRule`, it behaves as if the string or list of strings was passed to :func:`NetmaskGroupRule` or :func:`SuffixMatchNodeRule`.

  :param DNSrule rule: A :class:`DNSRule`, e.g. an :func:`AllRule`, or a compounded bunch of rules using e.g. :func:`AndRule`. Before 1.9.0 it was also possible to pass a string (or list of strings) but doing so is now deprecated.
  :param action: The action to take
  :param table options: A table with key: value pairs with options.

  Options:

  * ``uuid``: string - UUID to assign to the new rule. By default a random UUID is generated for each rule.
  * ``name``: string - Name to assign to the new rule.

.. function:: clearCacheHitResponseRules()

  .. versionadded:: 1.10

  Remove all current cache-hit response rules.

.. function:: getCacheHitResponseRule(selector) -> DNSDistResponseRuleAction

  .. versionadded:: 1.9.0

  Return the cache-hit response rule corresponding to the selector, if any.
  The selector can be the position of the rule in the list, as an integer,
  its name as a string or its UUID as a string as well.

  :param int or str selector: The position in the list, name or UUID of the rule to return.

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

Cache inserted
--------------

Functions for manipulating Cache Inserted Response Rules:

.. function:: addCacheInsertedResponseAction(DNSRule, action [, options])

  .. versionadded:: 1.8.0

  .. versionchanged:: 1.9.0
    Passing a string or list of strings instead of a :class:`DNSRule` is deprecated, use :func:`NetmaskGroupRule` or :func:`QNameSuffixRule` instead

  Add a Rule and ResponseAction that is executed after a cache entry has been inserted to the existing rules.
  If a string (or list of) is passed as the first parameter instead of a :class:`DNSRule`, it behaves as if the string or list of strings was passed to :func:`NetmaskGroupRule` or :func:`SuffixMatchNodeRule`.

  :param DNSrule rule: A :class:`DNSRule`, e.g. an :func:`AllRule`, or a compounded bunch of rules using e.g. :func:`AndRule`. Before 1.9.0 it was also possible to pass a string (or list of strings) but doing so is now deprecated.
  :param action: The action to take
  :param table options: A table with key: value pairs with options.

  Options:

  * ``uuid``: string - UUID to assign to the new rule. By default a random UUID is generated for each rule.
  * ``name``: string - Name to assign to the new rule.

.. function:: clearCacheInsertedResponseRules()

  .. versionadded:: 1.10

  Remove all current cache-inserted response rules.

.. function:: getCacheInsertedResponseRule(selector) -> DNSDistResponseRuleAction

  .. versionadded:: 1.9.0

  Return the cache-inserted response rule corresponding to the selector, if any.
  The selector can be the position of the rule in the list, as an integer,
  its name as a string or its UUID as a string as well.

  :param int or str selector: The position in the list, name or UUID of the rule to return.

.. function:: mvCacheInsertedResponseRule(from, to)

  .. versionadded:: 1.8.0

  Move cache inserted response rule ``from`` to a position where it is in front of ``to``.
  ``to`` can be one larger than the largest rule, in which case the rule will be moved to the last position.

  :param int from: Rule number to move
  :param int to: Location to more the Rule to

.. function:: mvCacheInsertedResponseRuleToTop()

  .. versionadded:: 1.8.0

  This function moves the last cache inserted response rule to the first position.

.. function:: rmCacheInsertedResponseRule(id)

  .. versionadded:: 1.8.0

  :param int id: The position of the rule to remove if ``id`` is numerical, its UUID or name otherwise

.. function:: showCacheInsertedResponseRules([options])

  .. versionadded:: 1.8.0

  Show all defined cache inserted response rules, optionally displaying their UUIDs.

  :param table options: A table with key: value pairs with display options.

  Options:

  * ``showUUIDs=false``: bool - Whether to display the UUIDs, defaults to false.
  * ``truncateRuleWidth=-1``: int - Truncate rules output to ``truncateRuleWidth`` size. Defaults to ``-1`` to display the full rule.

Self-answered responses
-----------------------

Functions for manipulating Self-Answered Response Rules:

.. function:: addSelfAnsweredResponseAction(DNSRule, action [, options])

  .. versionchanged:: 1.6.0
    Added ``name`` to the ``options``.

  .. versionchanged:: 1.9.0
    Passing a string or list of strings instead of a :class:`DNSRule` is deprecated, use :func:`NetmaskGroupRule` or :func:`QNameSuffixRule` instead

  Add a Rule and Action for Self-Answered queries to the existing rules.
  If a string (or list of) is passed as the first parameter instead of a :class:`DNSRule`, it behaves as if the string or list of strings was passed to :func:`NetmaskGroupRule` or :func:`SuffixMatchNodeRule`.

  :param DNSrule rule: A :class:`DNSRule`, e.g. an :func:`AllRule`, or a compounded bunch of rules using e.g. :func:`AndRule`. Before 1.9.0 it was also possible to pass a string (or list of strings) but doing so is now deprecated.
  :param action: The action to take
  :param table options: A table with key: value pairs with options.

  Options:

  * ``uuid``: string - UUID to assign to the new rule. By default a random UUID is generated for each rule.
  * ``name``: string - Name to assign to the new rule.

.. function:: clearSelfAnsweredResponseRules()

  .. versionadded:: 1.10

  Remove all current self-answered response rules.

.. function:: getSelfAnsweredResponseRule(selector) -> DNSDistResponseRuleAction

  .. versionadded:: 1.9.0

  Return the self-answered response rule corresponding to the selector, if any.
  The selector can be the position of the rule in the list, as an integer,
  its name as a string or its UUID as a string as well.

  :param int or str selector: The position in the list, name or UUID of the rule to return.

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

  Before 1.6.0 this function used to move the last self-answered response rule to the first position, which is now handled by :func:`mvSelfAnsweredResponseRuleToTop`.

  Move the last self answered response rule to the first position.

Timeout
-------

For Rules related to timed out queries:

.. function:: addTimeoutResponseAction(DNSRule, action [, options])

  .. versionadded:: 2.0.0

  Add a Rule and Action for timeout triggered from timer expiration or I/O error.

  :param DNSrule rule: A :class:`DNSRule`, e.g. an :func:`AllRule`, or a compounded bunch of rules using e.g. :func:`AndRule`.
  :param action: The action to take
  :param table options: A table with key: value pairs with options.

  Options:

  * ``uuid``: string - UUID to assign to the new rule. By default a random UUID is generated for each rule.
  * ``name``: string - Name to assign to the new rule.

.. function:: clearTimeoutResponseRules()

  .. versionadded:: 2.0.0

  Remove all current timeout response rules.

.. function:: getTimeoutResponseRule(selector) -> DNSDistResponseRuleAction

  .. versionadded:: 2.0.0

  Return the timeout response rule corresponding to the selector, if any.
  The selector can be the position of the rule in the list, as an integer,
  its name as a string or its UUID as a string as well.

  :param int or str selector: The position in the list, name or UUID of the rule to return.

.. function:: getTopTimeoutResponseRule() -> DNSDistResponseRuleAction

  .. versionadded:: 2.0.0

  Return the current top timeout response rule.

.. function:: mvTimeoutResponseRule(from, to)

  .. versionadded:: 2.0.0

  Move timeout response rule ``from`` to a position where it is in front of ``to``.
  ``to`` can be one larger than the largest rule, in which case the rule will be moved to the last position.

  :param int from: Rule number to move
  :param int to: Location to more the Rule to

.. function:: mvTimeoutResponseRuleToTop()

  .. versionadded:: 2.0.0

  This function moves the last timeout response rule to the first position.

.. function:: rmTimeoutResponseRule(id)

  .. versionadded:: 2.0.0
    ``id`` can now be a string representing the name of the rule.

  Remove timeout response rule ``id``.

  :param int id: The position of the rule to remove if ``id`` is numerical, its UUID or name otherwise

.. function:: showTimeoutResponseRules([options])

  .. versionadded:: 2.0.0

  Show all defined timeout response rules, optionally displaying their UUIDs.

  :param table options: A table with key: value pairs with display options.

  Options:

  * ``showUUIDs=false``: bool - Whether to display the UUIDs, defaults to false.
  * ``truncateRuleWidth=-1``: int - Truncate rules output to ``truncateRuleWidth`` size. Defaults to ``-1`` to display the full rule.

.. function:: topTimeoutResponseRules()

  .. versionadded:: 2.0.0

  Show all defined timeout response rules, sorted top-down by match hits.

XFR
---

Functions for manipulating zone transfer (AXFR, IXFR) Response Rules:

.. note::
  Please remember that a zone transfer (XFR) can and will often contain
  several response packets to a single query packet.

.. warning::
  While almost all existing selectors and Response actions should be usable from
  the XFR response rules, it is strongly advised to only inspect the content of
  XFR response packets, and not modify them.
  Logging the content of response packets can be done via:

  - :func:`DnstapLogResponseAction`
  - :func:`LogResponseAction`
  - :func:`RemoteLogResponseAction`

.. function:: addXFRResponseAction(DNSRule, action [, options])

  .. versionadded:: 1.10

  Add a Rule and ResponseAction for zone transfers (XFR) to the existing rules.
  If a string (or list of) is passed as the first parameter instead of a :class:`DNSRule`, it behaves as if the string or list of strings was passed to :func:`NetmaskGroupRule` or :func:`SuffixMatchNodeRule`.

  :param DNSrule rule: A :class:`DNSRule`, e.g. an :func:`AllRule`, or a compounded bunch of rules using e.g. :func:`AndRule`.
  :param action: The action to take
  :param table options: A table with key: value pairs with options.

  Options:

  * ``uuid``: string - UUID to assign to the new rule. By default a random UUID is generated for each rule.
  * ``name``: string - Name to assign to the new rule.

.. function:: mvXFRResponseRule(from, to)

  .. versionadded:: 1.10

  Move XFR response rule ``from`` to a position where it is in front of ``to``.
  ``to`` can be one larger than the largest rule, in which case the rule will be moved to the last position.

  :param int from: Rule number to move
  :param int to: Location to more the Rule to

.. function:: mvXFRResponseRuleToTop()

  .. versionadded:: 1.10

  This function moves the last XFR response rule to the first position.

.. function:: rmXFRResponseRule(id)

  .. versionadded:: 1.10

  :param int id: The position of the rule to remove if ``id`` is numerical, its UUID or name otherwise

.. function:: showXFRResponseRules([options])

  .. versionadded:: 1.10

  Show all defined XFR response rules, optionally displaying their UUIDs.

  :param table options: A table with key: value pairs with display options.

  Options:

  * ``showUUIDs=false``: bool - Whether to display the UUIDs, defaults to false.
  * ``truncateRuleWidth=-1``: int - Truncate rules output to ``truncateRuleWidth`` size. Defaults to ``-1`` to display the full rule.

Convenience Functions
---------------------

.. function:: makeRule(rule)

  .. versionchanged:: 1.9.0
    This function is deprecated, please use :func:`NetmaskGroupRule` or :func:`QNameSuffixRule` instead

  Make a :func:`NetmaskGroupRule` or a :func:`SuffixMatchNodeRule`, depending on how it is called.
  The `rule` parameter can be a string, or a list of strings, that should contain either:

  * netmasks: in which case it will behave as :func:`NetmaskGroupRule`, or
  * domain names: in which case it will behave as :func:`SuffixMatchNodeRule`

  Mixing both netmasks and domain names is not supported, and will result in domain names being ignored!

  ``makeRule("0.0.0.0/0")`` will for example match all IPv4 traffic, ``makeRule({"be","nl","lu"})`` will match all Benelux DNS traffic.

  :param string rule: A string, or list of strings, to convert to a rule.

.. function:: newRuleAction(rule, action[, options])

  .. versionchanged:: 1.6.0
    Added ``name`` to the ``options``.

  Return a pair of DNS Rule and DNS Action, to be used with :func:`setRules`.

  :param Rule rule: A Rule (see :doc:`selectors`)
  :param Action action: The Action (see :doc:`actions`) to apply to the matched traffic
  :param table options: A table with key: value pairs with options.

  Options:

  * ``uuid``: string - UUID to assign to the new rule. By default a random UUID is generated for each rule.
  * ``name``: string - Name to assign to the new rule.
