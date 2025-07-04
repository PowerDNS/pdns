.. _scripting-policyevent:

Policy Events
=============

Since 4.4.0, the Lua hook :func:`policyEventFilter` is called along with a :class:`PolicyEvent` object whenever a filtering policy matches.

PolicyEvent class
------------------

.. class:: PolicyEvent

  Represents an event related to a filtering policy.

  .. method:: PolicyEvent:addPolicyTag(tag)

     Add policyTag ``tag`` to the list of policyTags.

     :param str tag: The tag to add

  .. method:: PolicyEvent:getPolicyTags() -> {str}

      Get the current policy tags as a table of strings.

  .. method:: PolicyEvent:setPolicyTags(tags)

      Set the policy tags to ``tags``, overwriting any existing policy tags.

      :param {str} tags: The policy tags

  .. method:: PolicyEvent:discardPolicy(policyname)

     Skip the filtering policy (for example RPZ) named ``policyname`` for this query.

     :param str policyname: The name of the policy to ignore.

  .. attribute:: PolicyEvent.appliedPolicy

    The decision that was made by the policy engine, see
    :ref:`modifyingpolicydecisions` and :attr:`DNSQuestion.appliedPolicy` for the attributes of :attr:`PolicyEvent.appliedPolicy`.

  .. attribute:: PolicyEvent.qname

      :class:`DNSName` of the name corresponding to the query.

  .. attribute:: PolicyEvent.qtype

      Type the query is for as an integer, can be compared against ``pdns.A``, ``pdns.AAAA``.

  .. attribute:: PolicyEvent.isTcp

      Whether the query was received over TCP.

  .. attribute:: PolicyEvent.remote

      :class:`ComboAddress` of the requestor.

