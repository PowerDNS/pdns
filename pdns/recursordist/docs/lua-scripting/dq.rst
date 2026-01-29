The DNSQuestion (``dq``) object
===============================
Apart from the :func:`ipfilter`-function, all functions work on a ``dq`` (DNSQuestion) object.
This object contains details about the current state of the question.
This state can be modified from the various hooks.

The DNSQuestion object contains at least the following fields:

.. class:: DNSQuestion

  An object that contains everything about the current query.
  This object has the following attributes:

  .. attribute:: addPaddingToResponse

      .. versionadded:: 4.5.0

      Whether the response will get EDNS Padding. See :ref:`setting-yaml-incoming.edns_padding_from` and :ref:`setting-yaml-incoming.edns_padding_mode`.

  .. attribute:: extendedErrorCode

      .. versionadded:: 4.5.0

      The extended error code, if any. See :ref:`setting-yaml-recursor.extended_resolution_errors`.

  .. attribute:: extendedErrorExtra

      .. versionadded:: 4.5.0

      The extended error extra text, as a string, if any. See :ref:`setting-yaml-recursor.extended_resolution_errors`.

  .. attribute:: qname

      :class:`DNSName` of the name this query is for.

  .. attribute:: qtype

      Type this query is for as an integer, can be compared against ``pdns.A``, ``pdns.AAAA``.

  .. attribute:: rcode

      current DNS Result Code, which can be overridden, including to several magical values.
      Before 4.4.0, the rcode can be set to ``pdns.DROP`` to drop the query, for later versions refer to :ref:`hook-semantics`.
      Other statuses are normal DNS return codes, like ``pdns.NOERROR``, ``pdns.NXDOMAIN`` etc.

  .. attribute:: isTcp

      Whether the query was received over TCP.

  .. attribute:: remoteaddr

      :class:`ComboAddress` of the requestor.
      If the proxy protocol is used, this will contain the source address from the proxy protocol header.

  .. attribute:: localaddr

      :class:`ComboAddress` where this query was received on.
      If the proxy protocol is used, this will contain the destination address from the proxy protocol header.

  .. attribute:: interface_remoteaddr

      Source :class:`ComboAddress` of the packet received by the recursor. If the proxy protocol is not used, the value will match ``remoteaddr``.

  .. attribute:: interface_localaddr

      Destination :class:`ComboAddress` of the packet received by the recursor. If the proxy protocol is not used, the value will match ``localaddr``.

  .. attribute:: variable

      Boolean which, if set, indicates the recursor should not packet cache this answer.
      Honored even when returning false from a hook!
      Important when providing answers that vary over time or based on sender details.

  .. attribute:: followupFunction

      String that signals the nameserver to take one an additional action:

      - followCNAMERecords: When adding a CNAME to the answer, this tells the recursor to follow that CNAME. See :ref:`CNAME Chain Resolution <cnamechainresolution>`
      - getFakeAAAARecords: Get a fake AAAA record, see :doc:`DNS64 <../dns64>`
      - getFakePTRRecords: Get a fake PTR record, see :doc:`DNS64 <../dns64>`
      - udpQueryResponse: Do a UDP query and call a handler, see :ref:`UDP Query Response <udpqueryresponse>`

  .. attribute:: followupName

      see :doc:`DNS64 <../dns64>`

  .. attribute:: followupPrefix

      see :doc:`DNS64 <../dns64>`

  .. attribute:: appliedPolicy

    The decision that was made by the policy engine, see :ref:`modifyingpolicydecisions`.

    .. attribute:: appliedPolicy.policyName

      A string with the name of the policy.
      Set by :ref:`policyName <rpz-policyName>` in the :func:`rpzFile` and :func:`rpzPrimary` configuration items.
      It is advised to overwrite this when modifying the :attr:`DNSQuestion.appliedPolicy.policyKind`

    .. attribute:: appliedPolicy.policyType

      The type of match for the policy.

      -  ``pdns.policytypes.None``  the empty policy type
      -  ``pdns.policytypes.QName`` a match on qname
      -  ``pdns.policytypes.ClientIP`` a match on client IP
      -  ``pdns.policytypes.ResponseIP`` a match on response IP
      -  ``pdns.policytypes.NSDName`` a match on the name of a nameserver
      -  ``pdns.policytypes.NSIP`` a match on the IP of a nameserver

    .. attribute:: appliedPolicy.policyCustom

        The CNAME content for the ``pdns.policyactions.Custom`` response, a string

    .. attribute:: appliedPolicy.policyKind

      The kind of policy response, there are several policy kinds:

      -  ``pdns.policykinds.Custom`` will return a NoError, CNAME answer with the value specified in :attr:`DNSQuestion.appliedPolicy.policyCustom`
      -  ``pdns.policykinds.Drop`` will simply cause the query to be dropped
      -  ``pdns.policykinds.NoAction`` will continue normal processing of the query
      -  ``pdns.policykinds.NODATA`` will return a NoError response with no value in the answer section
      -  ``pdns.policykinds.NXDOMAIN`` will return a response with a NXDomain rcode
      -  ``pdns.policykinds.Truncate`` will return a NoError, no answer, truncated response over UDP. Normal processing will continue over TCP

    .. attribute:: appliedPolicy.policyTTL

        The TTL in seconds for the ``pdns.policyactions.Custom`` response

    .. attribute:: appliedPolicy.policyTrigger

        The trigger (left-hand) part of the RPZ rule that was matched

    .. attribute:: appliedPolicy.policyHit

        The value that was matched. This is a string representing a name or an address.

  .. attribute:: wantsRPZ

      A boolean that indicates the use of the Policy Engine.
      Can be set to ``false`` in ``prerpz`` to disable RPZ for this query.

  .. attribute:: data

      A Lua object reference that is persistent throughout the lifetime of the :class:`DNSQuestion` object for a single query.
      It can be used to store custom data.
      Most scripts initialise this to an empty table early on so they can store multiple items.

  .. attribute:: requestorId

      .. versionadded:: 4.1.0

      A string that will be used to set the ``requestorId`` field in :doc:`protobuf <../lua-config/protobuf>` messages.

  .. attribute:: deviceId

      .. versionadded:: 4.1.0

      A string that will be used to set the ``deviceId`` field in :doc:`protobuf <../lua-config/protobuf>` messages.

  .. attribute:: deviceName

      .. versionadded:: 4.3.0

      A string that will be used to set the ``deviceName`` field in :doc:`protobuf <../lua-config/protobuf>` messages.

  .. attribute:: udpAnswer

      Answer to the :attr:`udpQuery <DNSQuestion.udpQuery>` when using the ``udpQueryResponse`` :attr:`followupFunction <DNSQuestion.followupFunction>`.
      Only filled when the call-back function is invoked.

  .. attribute:: udpQueryDest

      Destination IP address to send the UDP packet to when using the ``udpQueryResponse`` :attr:`followupFunction <DNSQuestion.followupFunction>`

  .. attribute:: udpQuery

      The content of the UDP payload when using the ``udpQueryResponse`` :attr:`followupFunction <DNSQuestion.followupFunction>`

  .. attribute:: udpCallback

      The name of the callback function that is called when using the ``udpQueryResponse`` :attr:`followupFunction <DNSQuestion.followupFunction>` when an answer is received.

  .. attribute:: validationState

      .. versionadded:: 4.1.0

      The result of the DNSSEC validation, accessible from the ``postresolve``, ``nxdomain`` and ``nodata`` hooks.
      Possible states are ``pdns.validationstates.Indeterminate``, ``pdns.validationstates.Bogus``, ``pdns.validationstates.Insecure`` and ``pdns.validationstates.Secure``.
      The result will always be ``pdns.validationstates.Indeterminate`` if validation is disabled or was not requested.

  .. attribute:: detailedValidationState

      .. versionadded:: 4.4.2

      The result of the DNSSEC validation, accessible from the ``postresolve``, ``nxdomain`` and ``nodata`` hooks.
      By contrast with :attr:`validationState <DNSQuestion.validationState>`, there are several Bogus states to be
      able to better understand the reason for a DNSSEC validation failure.
      
      Possible states are:
      
      - ``pdns.validationstates.Indeterminate``
      - ``pdns.validationstates.BogusNoValidDNSKEY``
      - ``pdns.validationstates.BogusInvalidDenial``
      - ``pdns.validationstates.BogusUnableToGetDSs``
      - ``pdns.validationstates.BogusUnableToGetDNSKEYs``
      - ``pdns.validationstates.BogusSelfSignedDS``
      - ``pdns.validationstates.BogusNoRRSIG``
      - ``pdns.validationstates.BogusNoValidRRSIG``
      - ``pdns.validationstates.BogusMissingNegativeIndication``
      - ``pdns.validationstates.BogusSignatureNotYetValid``
      - ``pdns.validationstates.BogusSignatureExpired``
      - ``pdns.validationstates.BogusUnsupportedDNSKEYAlgo``
      - ``pdns.validationstates.BogusUnsupportedDSDigestType``
      - ``pdns.validationstates.BogusNoZoneKeyBitSet``
      - ``pdns.validationstates.BogusRevokedDNSKEY``
      - ``pdns.validationstates.BogusInvalidDNSKEYProtocol``
      - ``pdns.validationstates.Insecure``
      - ``pdns.validationstates.Secure``

      The result will always be ``pdns.validationstates.Indeterminate`` is validation is disabled or was not requested.
      There is a convenience function named ``isValidationStateBogus`` that accepts such a state and return a boolean
      indicating whether this state is a Bogus one.

  .. attribute:: logResponse

      .. versionadded:: 4.2.0

      Whether the response to this query will be exported to a remote protobuf logger, if one has been configured.

  .. attribute:: tag

      The packetcache tag set via :func:`gettag` or :func:`gettag_ffi`.
      Default tag is zero. Internally to the recursor, the tag is interpreted as an unsigned 32-bit integer.

  .. attribute:: queryTime

     .. versionadded:: 4.8.0

     The time the query was received

     .. attribute:: queryTime.tv_sec

        The number of seconds since the Unix epoch.

     .. attribute:: queryTime.tv_usec

        The number of microseconds, to be added to the number of seconds in :attr:`DNSQuestion.queryTime.tv_sec` to get a high accuracy timestamp.

  It also supports the following methods:

  .. method:: addAnswer(type, content, [ttl, name])

     Add an answer to the record of ``type`` with ``content``.

     :param int type: The type of record to add, can be ``pdns.AAAA`` etc.
     :param str content: The content of the record, will be parsed into wireformat based on the ``type``
     :param int ttl: The TTL in seconds for this record, defaults to 3600
     :param DNSName name: The name of this record, defaults to :attr:`DNSQuestion.qname`

  .. method:: addRecord(type, content, place, [ttl, name])

     Add a record of ``type`` with ``content`` in section ``place``.

     :param int type: The type of record to add, can be ``pdns.AAAA`` etc.
     :param str content: The content of the record, will be parsed into wireformat based on the ``type``
     :param int place: The section to place the record, see :attr:`DNSRecord.place`
     :param int ttl: The TTL in seconds for this record, defaults to 3600
     :param DNSName name: The name of this record, defaults to :attr:`DNSQuestion.qname`

  .. method:: addPolicyTag(tag)

     Add policyTag ``tag`` to the list of policyTags.

     :param str tag: The tag to add

  .. method:: getPolicyTags() -> {str}

      Get the current policy tags as a table of strings.

  .. method:: setPolicyTags(tags)

      Set the policy tags to ``tags``, overwriting any existing policy tags.

      :param {str} tags: The policy tags

  .. method:: discardPolicy(policyname)

     Skip the filtering policy (for example RPZ) named ``policyname`` for this query.
     This is mostly useful in the ``prerpz`` hook.

     :param str policyname: The name of the policy to ignore.

  .. method:: getDH() -> DNSHeader

      Returns the :class:`DNSHeader` of the query or nil.

  .. method:: getProxyProtocolValues() -> {ProxyProtocolValue}

    .. versionadded:: 4.4.0

    Get the Proxy Protocol Type-Length Values if any, as a table of :class:`ProxyProtocolValue` objects.

  .. method:: getRecords() -> {DNSRecord}

      Get a table of DNS Records in this DNS Question (or answer by now).

  .. method:: setRecords(records)

      After your edits, update the answers of this question

      :param {DNSRecord} records: The records to put in the packet

  .. method:: getEDNSFlag(name) -> bool

      Returns true if the EDNS flag with ``name`` is set in the query.

      :param string name: Name of the flag.

  .. method:: getEDNSFlags() -> {str}

      Returns a list of strings with all the EDNS flag mnemonics in the query.

  .. method:: getEDNSOption(num) -> str

      Get the EDNS Option with number ``num`` as a bytestring.

  .. method:: getEDNSOptions() -> {str: str}

      Get a map of all EDNS Options

  .. method:: getEDNSSubnet() -> Netmask

      Returns the :class:`Netmask` specified in the EDNSSubnet option, or empty if there was none.

DNSHeader Object
================

The DNS header as returned by :meth:`DNSQuestion:getDH()` represents a header of a DNS message.

.. class:: DNSHeader

    represents a header of a DNS message.

  .. method:: getRD() -> bool

      The value of the Recursion Desired bit.

  .. method:: getAA() -> bool

      The value of the Authoritative Answer bit.

  .. method:: getAD() -> bool

      The value of the Authenticated Data bit.

  .. method:: getCD() -> bool

      The value of the Checking Disabled bit.

  .. method:: getTC() -> bool

      The value of the Truncation bit.

  .. method:: getRCODE() -> int

      The Response Code of the query

  .. method:: getOPCODE() -> int

      The Operation Code of the query

  .. method:: getID() -> int

      The ID of the query

DNSRecord Object
================

See :doc:`DNSRecord <dnsrecord>`.

The EDNSOptionView Class
========================

.. class:: EDNSOptionView

  An object that represents the values of a single EDNS option

  .. method:: count()

    .. versionadded:: 4.2.0

    The number of values for this EDNS option.

  .. method:: getValues()

    .. versionadded:: 4.2.0

    Return a table of NULL-safe strings values for this EDNS option.

  .. attribute:: size

    The size in bytes of the first value of this EDNS option.

  .. method:: getContent()

    Returns a NULL-safe string object of the first value of this EDNS option.

The ProxyProtocolValue Class
============================

.. class:: ProxyProtocolValue

  .. versionadded:: 4.4.0

  An object that represents the value of a Proxy Protocol Type-Length Value

  .. method:: getContent() -> str

    Returns a NULL-safe string object.

  .. method:: getType() -> int

    Returns the type of this value.
