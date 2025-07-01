Intercepting queries with Lua
=============================

To get a quick start, we have supplied a `sample script <https://github.com/PowerDNS/pdns/blob/master/pdns/recursordist/contrib/powerdns-example-script.lua>`__ that showcases all functionality described below.

Queries can be intercepted in many places:

-  before any packet parsing begins (:func:`ipfilter`)
-  before the packet cache has been looked up (:func:`gettag` and its FFI counterpart, :func:`gettag_ffi`)
-  before any filtering policy have been applied (:func:`prerpz`)
-  before the resolving logic starts to work (:func:`preresolve`)
-  after the resolving process failed to find a correct answer for a domain (:func:`nodata`, :func:`nxdomain`)
-  after the whole process is done and an answer is ready for the client (:func:`postresolve` and its FFI counterpart, :func:`postresolve_ffi`).
-  before an outgoing query is made to an authoritative server (:func:`preoutquery`)
-  after a filtering policy hit has occurred (:func:`policyEventFilter`)

Writing Lua PowerDNS Recursor scripts
-------------------------------------
Addresses and DNS Names are not passed as strings but as native objects.
This allows for easy checking against `Netmasks <scripting-netmasks>`_ and `domain sets <scripting-dnsname>`_.
It also means that to print such names, the ``:toString`` method must be used (or even ``:toStringWithPort`` for addresses).

Once a script is loaded, PowerDNS looks for the interception functions in the loaded script.
All of these functions are optional.

If ``ipfilter`` returns ``true``, the query is dropped.
If ``preresolve`` returns ``true``, it will indicate it handled a query, and the recursor will send the result as constructed in the function to the client.
If it returns ``false``, the Recursor will continue processing.
For the other functions, the return value will indicate that an alteration to the result has been made.
In that case the potentially changed rcode, records and policy will be processed and DNSSEC validation will be automatically disabled since the content might not be genuine anymore.
At specific points the Recursor will check if policy handling should take place.
These points are immediately after ``preresolve``, after resolving and after ``nxdomain``, ``nodata`` and ``postresolve``.

Interception Functions
----------------------

.. function:: ipfilter(remoteip, localip, dh) -> bool

    This hook gets queried immediately after consulting the packet cache, but before parsing the DNS packet.
    If this hook returns something else than ``false``, the packet is dropped.
    However, because this check is after the packet cache, the IP address might still receive answers that require no packet parsing.

    With this hook, undesired traffic can be dropped rapidly before using precious CPU cycles for parsing.
    As an example, to filter all queries coming from 1.2.3.0/24, or with the
    AD bit set:

    .. code-block:: Lua

        badips = newNMG()
        badips:addMask("1.2.3.0/24")

        function ipfilter(rem, loc, dh)
            return badips:match(rem) or dh:getAD()
        end

    This hook does not get the full :class:`DNSQuestion` object, since filling out the fields would require packet parsing, which is what we are trying to prevent with this function.

    :param ComboAddress remoteip: The IP(v6) address of the requestor
    :param ComboAddress localip: The address on which the query arrived.
    :param DNSHeader dh: The DNS Header of the query.


.. function:: gettag(remote, ednssubnet, localip, qname, qtype, ednsoptions, tcp, proxyprotocolvalues) -> multiple values
              gettag(remote, ednssubnet, localip, qname, qtype, ednsoptions, tcp) -> int
              gettag(remote, ednssubnet, localip, qname, qtype, ednsoptions) -> int

    .. versionchanged:: 4.1.0

      The ``tcp`` parameter was added.

    .. versionchanged:: 4.4.0

      The ``proxyprotocolvalues`` parameter was added.

    The :func:`gettag` function is invoked when :program:`Recursor` attempts to discover in which packetcache an answer is available.

    This function must return an unsigned 32-bit integer, which is the tag number of the packetcache.
    The tag is used to partition the packet cache. The default tag (when :func:`gettag` is not defined) is zero.
    If :func:`gettag` throws an exception, the zero tag is used.

    In addition to the tag, this function can return a table of policy tags and a few more values to be passed to the resolving process.
    The resulting tag number can be accessed via :attr:`dq.tag <DNSQuestion.tag>` in the :func:`preresolve` hook, and the policy tags via :meth:`dq:getPolicyTags() <DNSQuestion:getPolicyTags>` in every hook.

    .. versionadded:: 4.1.0

        It can also return a table whose keys and values are strings to fill the :attr:`DNSQuestion.data` table, as well as a ``requestorId`` value to fill the :attr:`DNSQuestion.requestorId` field and a ``deviceId`` value to fill the :attr:`DNSQuestion.deviceId` field.

    .. versionadded:: 4.3.0

        Along the ``deviceId`` value that can be returned, it was added a ``deviceName`` field to fill the :attr:`DNSQuestion.deviceName` field.

    .. versionadded:: 4.4.0
       A ``routingTag`` can be returned, which is used as an extra name to identify records in the record cache.
       If a routing tag is set and a record would be stored with an ENDS subnetmask in the record cache, it will be
       stored with the tag instead. New request using the same tag will be served by the record in the records cache,
       avoiding querying authoritative servers.

    The tagged packetcache can e.g. be used to answer queries from cache that have e.g. been filtered for certain IPs (this logic should be implemented in :func:`gettag`).
    This ensure that queries are answered quickly compared to setting :attr:`dq.variable <DNSQuestion.variable>` to true.
    In the latter case, repeated queries will not be found in the packetcache and pass through the entire resolving process, and all relevant Lua hooks will be called.

    :param ComboAddress remote: The sender's IP address
    :param Netmask ednssubnet: The EDNS Client subnet that was extracted from the packet
    :param ComboAddress localip: The IP address the query was received on
    :param DNSName qname: The domain name the query is for
    :param int qtype: The query type of the query
    :param ednsoptions: A table whose keys are EDNS option codes and values are :class:`EDNSOptionView` objects. This table is empty unless the :ref:`setting-yaml-incoming.gettag_needs_edns_options` option is set.
    :param bool tcp: Added in 4.1.0, a boolean indicating whether the query was received over UDP (false) or TCP (true).
    :param proxyprotocolvalues: Added in 4.4.0, a table of :class:`ProxyProtocolValue` objects representing the Type-Length Values received via the Proxy Protocol, if any.

    :return: ``tag`` [``, policyTags`` [``, data`` [``, reqId`` [``, deviceId`` [``, deviceName`` [``, routingTag`` ]]]]]]

.. function:: gettag_ffi(param) -> optional Lua object

   .. versionadded:: 4.1.2

   .. versionchanged:: 4.3.0

      The ability to craft answers was added.

   This function is the FFI counterpart of the :func:`gettag` function, and offers the same functionality.
   It accepts a single parameter which can be accessed and modified using :doc:`FFI accessors <ffi>`.

   Like the non-FFI version, it has the ability to set a tag for the packetcache, policy tags, a routing tag, the :attr:`DNSQuestion.requestorId` and :attr:`DNSQuestion.deviceId` values and to fill the :attr:`DNSQuestion.data` table. It also offers ways to mark the answer as variable so it's not inserted into the packetcache, to set a cap on the TTL of the returned records, and to generate a response by adding records and setting the RCode. It can also instruct the recursor to do a proper resolution in order to follow any `CNAME` records added in this step.

   If this function does not set the tag or an exception is thrown, the zero tag is assumed. 

.. function:: prerpz(dq) -> bool

  This hook is called before any filtering policy have been applied,  making it possible to completely disable filtering by setting  :attr:`dq.wantsRPZ <DNSQuestion.wantsRPZ>` to false.
  Using the :meth:`dq:discardPolicy() <DNSQuestion:discardPolicy>` function, it is also possible to selectively disable one or more filtering policy, for example RPZ zones, based on the content of the ``dq`` object.
  Currently, the return value of this function is ignored.

  As an example, to disable the "malware" policy for example.com queries:

  .. code-block:: Lua

      function prerpz(dq)
        -- disable the RPZ policy named 'malware' for example.com
        if dq.qname:equal('example.com') then
          dq:discardPolicy('malware')
        end
        return false
      end

  :param DNSQuestion dq: The DNS question to handle

.. function:: preresolve(dq) -> bool

  This function is called before any DNS resolution is attempted, and if this function indicates it, it can supply a direct answer to the DNS query, overriding the internet.
  This is useful to combat botnets, or to disable domains unacceptable to an organization for whatever reason.

  :param DNSQuestion dq: The DNS question to handle

.. function:: postresolve(dq) -> bool

  is called right before returning a response to a client (and, unless :attr:`dq.variable <DNSQuestion.variable>` is set, to the packet cache too).
  It allows inspection and modification of almost any detail in the return packet.

  :param DNSQuestion dq: The DNS question to handle

.. function:: postresolve_ffi(handle) -> bool

  .. versionadded:: 4.7.0

  This is the FFI counterpart of :func:`postresolve`.
  It accepts a single parameter which can be passed to the functions listed in :doc:`ffi`.
  The accessor functions retrieve and modify various aspects of the answer returned to the client.

.. function:: nxdomain(dq) -> bool

  is called after the DNS resolution process has run its course, but ended in an 'NXDOMAIN' situation, indicating that the domain does not exist.
  Works entirely like :func:`postresolve`, but saves a trip through Lua for answers which are not NXDOMAIN.

  :param DNSQuestion dq: The DNS question to handle

.. function:: nodata(dq) -> bool

  is just like :func:`nxdomain`, except it gets called when a domain exists, but the requested type does not.
  This is where one would implement :doc:`DNS64 <../dns64>`.

  :param DNSQuestion dq: The DNS question to handle

.. function:: preoutquery(dq) -> bool

  This hook is not called in response to a client packet, but fires when the Recursor wants to talk to an authoritative server.

  When this hook sets the special result code ``-3``, the whole DNS client query causing this outgoing query gets a ``ServFail``.

  However, this function can also return records like :func:`preresolve`.

  :param DNSQuestion dq: The DNS question to handle.

  In the case of :func:`preoutquery`, only a few attributes if the :class:`dq <DNSQuestion>` object are filled in:

  - :attr:`dq.remoteaddr <DNSQuestion.remoteaddr>` containing the target nameserver address
  - :attr:`dq.localaddr <DNSQuestion.localaddr>`
  - :attr:`dq.qname <DNSQuestion.qname>`
  - :attr:`dq.qtype <DNSQuestion.qtype>`
  - :attr:`dq.isTcp <DNSQuestion.isTcp>`

  Do not rely on other attributes having a value and do not call any method of the :class:`dq <DNSQuestion>` object apart from the record set manipulation methods.

.. function:: policyEventFilter(event) -> bool

  .. versionadded:: 4.4.0

  This hook is called when a filtering policy has been hit, before the decision has been applied, making it possible to change a policy decision by altering its content or to skip it entirely.
  Using the :meth:`event:discardPolicy() <PolicyEvent:discardPolicy>` function, it is also possible to selectively disable one or more filtering policy, for example RPZ zones.
  The return value indicates whether the policy hit should be completely ignored (true) or applied (false), possibly after editing the action to take in that latter case (see :ref:`modifyingpolicydecisions` below). when true is returned, the resolution process will resume as if the policy hit never took place.

  :param PolicyEvent event: The event to handle

  As an example, to ignore the result of a policy hit for the example.com domain:

  .. code-block:: Lua

      function policyEventFilter(event)
        if event.qname:equal("example.com") then
          -- ignore that policy hit
          return true
        end
        return false
      end

  To alter the decision of the policy hit instead:

  .. code-block:: Lua

      function policyEventFilter(event)
        if event.qname:equal("example.com") then
          -- replace the decision with a custom CNAME
          event.appliedPolicy.policyKind = pdns.policykinds.Custom
          event.appliedPolicy.policyCustom = "example.net"
          -- returning false so that the hit is not ignored
          return false
        end
        return false
      end

.. _hook-semantics:

Callback Semantics
^^^^^^^^^^^^^^^^^^
The functions which modify or influence the query flow should all return ``true`` when they have performed an action which alters the rcode, result or applied policy. When a function returns ``false``, the nameserver will process the query normally until a new function is called.

:func:`ipfilter` and :func:`preresolve` callbacks must return ``true`` if they have taken over the query and wish that the nameserver should not proceed with processing.

If a function has taken over a request, it can set an rcode (usually 0), and specify a table with records to be put in the answer section of a packet.
An interesting rcode is `NXDOMAIN` (3, or ``pdns.NXDOMAIN``), which specifies the non-existence of a domain.
Instead of setting an rcode and records, it can also set fields in the applied policy to influence further processing.

The :func:`ipfilter` and :func:`preoutquery` hooks are different, in that :func:`ipfilter` can only return a true or false value, and that :func:`preoutquery` can also set rcode -3 to signify that the whole query should be terminated.

The :func:`policyEventFilter` has a different meaning as well, where returning true means that the policy hit should be ignored and normal processing should be resumed.

A minimal sample script:

.. code-block:: Lua

    function nxdomain(dq)
        print("Intercepting NXDOMAIN for: ",dq.qname:toString())
        if dq.qtype == pdns.A
        then
            dq.rcode=0 -- make it a normal answer
            dq:addAnswer(pdns.A, "192.168.1.1")
            return true
        end
        return false
    end

**Warning**: Please do NOT use the above sample script in production!
Responsible NXDomain redirection requires more attention to detail.

Useful ``rcodes`` include 0 or ``pdns.NOERROR`` for no error and ``pdns.NXDOMAIN`` for ``NXDOMAIN``. Before 4.4.0, ``pdns.DROP`` can also be used to drop the question without any further processing.
Such a drop is accounted in the ``policy-drops`` metric.

Starting with recursor 4.4.0, the method to drop a request is to set the ``dq.appliedPolicy.policyKind`` to the value ``pdns.policykinds.Drop``.

.. code-block:: Lua

    function nxdomain(dq)
        print("Intercepting and dropping NXDOMAIN for: ",dq.qname:toString())
        if dq.qtype == pdns.A
        then
            dq.appliedPolicy.policyKind = pdns.policykinds.Drop
        end
        return false
    end

**Note**: to drop a query set ``policyKind`` and return ``false``, to indicate the Recursor should process the ``Drop`` action.

DNS64
-----

The ``getFakeAAAARecords`` and ``getFakePTRRecords`` followupFunctions
can be used to implement DNS64. See :doc:`../dns64` for more information.

To get fake AAAA records for DNS64 usage, set dq.followupFunction to
``getFakeAAAARecords``, dq.followupPrefix to e.g. "64:ff9b::" and
dq.followupName to the name you want to synthesize an IPv6 address for.

For fake reverse (PTR) records, set dq.followupFunction to
``getFakePTRRecords`` and set dq.followupName to the name to look up and
dq.followupPrefix to the same prefix as used with
``getFakeAAAARecords``.

Follow up actions
-----------------
When modifying queries, it might be needed that the Recursor does some extra work after the function returns.
The :attr:`dq.followupFunction <DNSQuestion.followupFunction>` can be set in this case.

.. _cnamechainresolution:

CNAME chain resolution
^^^^^^^^^^^^^^^^^^^^^^
It may be useful to return a CNAME record for Lua, and then have the PowerDNS Recursor continue resolving that CNAME.
This can be achieved by setting dq.followupFunction to ``followCNAMERecords`` and dq.followupDomain to "www.powerdns.com".
PowerDNS will do the rest.

.. _udpqueryresponse:

UDP Query Response
^^^^^^^^^^^^^^^^^^
The ``udpQueryResponse`` :attr:`dq.followupFunction <DNSQuestion.followupFunction>` allows you to query a simple key-value store over UDP asynchronously.

Several dq variables can be set:

-  :attr:`dq.udpQueryDest <DNSQuestion.udpQueryDest>`: destination IP address to send the UDP packet to
-  :attr:`dq.udpQuery <DNSQuestion.udpQuery>`: The content of the UDP payload
-  :attr:`dq.udpCallback <DNSQuestion.udpCallback>`: The name of the callback function that is called when an answer is received

The callback function must accept the ``dq`` object and can find the response to the UDP query in :attr:`dq.udpAnswer <DNSQuestion.udpAnswer>`.

In this callback function, :attr:`dq.followupFunction <DNSQuestion.followupFunction>` can be set again to any of the available functions for further processing.

This example script queries a simple key/value store over UDP to decide on whether or not to filter a query:

.. literalinclude:: ../../contrib/kv-example-script.lua
    :language: Lua

Example Script
--------------

.. literalinclude:: ../../contrib/powerdns-example-script.lua
    :language: Lua

Dropping all traffic from botnet-infected users
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Frequently, DoS attacks are performed where specific IP addresses are attacked, often by queries coming in from open resolvers.
These queries then lead to a lot of queries to 'authoritative servers' which actually often aren't nameservers at all, but just targets of attack.

This specific script is, as of January 2015, useful to prevent traffic to ezdns.it related traffic from creating CPU load.
This script requires PowerDNS Recursor 4.x or later.

.. code-block:: Lua

    lethalgroup=newNMG()
    lethalgroup:addMask("192.121.121.0/24") -- touch these nameservers and original query gets dropped

    function preoutquery(dq)
        print("pdns wants to ask "..dq.remoteaddr:toString().." about "..dq.qname:toString().." "..dq.qtype.." on behalf of requestor "..dq.localaddr:toString())
        if(lethalgroup:match(dq.remoteaddr))
        then
            print("We matched the group "..lethalgroup:tostring().."! killing query dead from requestor "..dq.localaddr:toString())
            dq.rcode = -3 -- "kill"
            return true
        end
        return false
    end

.. _modifyingpolicydecisions:

Modifying Policy Decisions
--------------------------
The PowerDNS Recursor has a :doc:`policy engine based on Response Policy Zones (RPZ) <../lua-config/rpz>`.
Starting with version 4.0.1 of the recursor, it is possible to alter this decision inside the Lua hooks.

If the decision is modified in a Lua hook, ``false`` should be
returned, as the query is not actually handled by Lua so the decision
is picked up by the Recursor.

Before 4.4.0, the result of the policy decision is checked after :func:`preresolve` and :func:`postresolve`. Beginning with version 4.4.0, the policy decision is checked after :func:`preresolve` and any :func:`policyEventFilter` call instead.

For example, if a decision is set to ``pdns.policykinds.NODATA`` by the policy engine and is unchanged in :func:`preresolve`, the query is replied to with a NODATA response immediately after :func:`preresolve`.

Example script
^^^^^^^^^^^^^^

.. code-block:: Lua

    -- This script demonstrates modifying policies for versions before 4.4.0.
    -- Starting with 4.4.0, it is preferred to use a policyEventFilter.
    -- Dont ever block my own domain and IPs
    myDomain = newDN("example.com")

    myNetblock = newNMG()
    myNetblock:addMasks({"192.0.2.0/24"})

    function preresolve(dq)
      if dq.qname:isPartOf(myDomain) and dq.appliedPolicy.policyKind ~= pdns.policykinds.NoAction then
        pdnslog("Not blocking our own domain!")
        dq.appliedPolicy.policyKind = pdns.policykinds.NoAction
      end
      return false
    end

    function postresolve(dq)
      if dq.appliedPolicy.policyKind ~= pdns.policykinds.NoAction then
        local records = dq:getRecords()
        for k,v in pairs(records) do
          if v.type == pdns.A then
            local blockedIP = newCA(v:getContent())
            if myNetblock:match(blockedIP) then
              pdnslog("Not blocking our IP space")
              dq.appliedPolicy.policyKind = pdns.policykinds.NoAction
            end
          end
        end
      end
      return false
    end

.. _snmp:

SNMP Traps
----------

PowerDNS Recursor, when compiled with SNMP support, has the ability to
act as a SNMP agent to provide SNMP statistics and to be able to send
traps from Lua.

For example, to send a custom SNMP trap containing the qname from the
``preresolve`` hook:

.. code-block:: Lua

    function preresolve(dq)
      sendCustomSNMPTrap('Trap from preresolve, qname is '..dq.qname:toString())
      return false
    end

.. _hooks-maintenance-callback:

Maintenance callback
--------------------
Starting with version 4.2.0 of the recursor, it is possible to define a `maintenance()` callback function that will be called periodically.
This function expects no argument and doesn't return any value.

.. code-block:: Lua

    function maintenance()
        -- This would be called every second
        -- Perform here your maintenance
    end

The interval can be configured through the :ref:`setting-yaml-recursor.lua_maintenance_interval` setting.
