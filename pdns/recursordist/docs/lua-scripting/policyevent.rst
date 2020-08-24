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

    The decision that was made by the policy engine, see :ref:`modifyingpolicydecisions`.

    .. attribute:: PolicyEvent.appliedPolicy.policyName

      A string with the name of the policy.
      Set by :ref:`policyName <rpz-policyName>` in the :func:`rpzFile` and :func:`rpzMaster` configuration items.
      It is advised to overwrite this when modifying the :attr:`PolicyEvent.appliedPolicy.policyKind`

    .. attribute:: PolicyEvent.appliedPolicy.policyAction

        The action taken by the engine

    .. attribute:: PolicyEvent.appliedPolicy.policyCustom

        The CNAME content for the ``pdns.policyactions.Custom`` response, a string

    .. attribute:: PolicyEvent.appliedPolicy.policyKind

      The kind of policy response, there are several policy kinds:

      -  ``pdns.policykinds.Custom`` will return a NoError, CNAME answer with the value specified in :attr:`PolicyEvent.appliedPolicy.policyCustom`
      -  ``pdns.policykinds.Drop`` will simply cause the query to be dropped
      -  ``pdns.policykinds.NoAction`` will continue normal processing of the query
      -  ``pdns.policykinds.NODATA`` will return a NoError response with no value in the answer section
      -  ``pdns.policykinds.NXDOMAIN`` will return a response with a NXDomain rcode
      -  ``pdns.policykinds.Truncate`` will return a NoError, no answer, truncated response over UDP. Normal processing will continue over TCP

    .. attribute:: PolicyEvent.appliedPolicy.policyTTL

        The TTL in seconds for the ``pdns.policyactions.Custom`` response

  .. attribute:: PolicyEvent.qname

      :class:`DNSName` of the name the query is for.

  .. attribute:: PolicyEvent.qtype

      Type the query is for as an integer, can be compared against ``pdns.A``, ``pdns.AAAA``.

  .. attribute:: PolicyEvent.isTcp

      Whether the query was received over TCP.

  .. attribute:: PolicyEvent.remote

      :class:`ComboAddress` of the requestor.

