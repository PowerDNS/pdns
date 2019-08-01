Intercepting queries with Lua
=============================
To get a quick start, we have supplied a sample script that showcases all functionality described below.
Please find it `here <https://github.com/PowerDNS/pdns/blob/master/pdns/recursordist/contrib/powerdns-example-script.lua>`_.

Queries can be intercepted in many places:

-  before any packet parsing begins (:func:`ipfilter`)
-  before any filtering policy have been applied (:func:`prerpz`)
-  before the resolving logic starts to work (:func:`preresolve`)
-  after the resolving process failed to find a correct answer for a domain (:func:`nodata`, :func:`nxdomain`)
-  after the whole process is done and an answer is ready for the client (:func:`postresolve`)
-  before an outgoing query is made to an authoritative server (:func:`preoutquery`)

Writing Lua PowerDNS Recursor scripts
-------------------------------------
Addresses and DNS Names are not passed as strings but as native objects.
This allows for easy checking against `Netmasks <scripting-netmasks>`_ and `domain sets <scripting-dnsname>`_.
It also means that to print such names, the ``:toString`` method must be used (or even ``:toStringWithPort`` for addresses).

Once a script is loaded, PowerDNS looks for several `functions <scripting-hooks>`_ in the loaded script.
All of these functions are optional.

If a function returns true, it will indicate that it handled a query.
If it returns false, the Recursor will continue processing unchanged (with one minor exception).

Interception Functions
----------------------

.. function:: ipfilter(remoteip, localip, dh) -> bool

    This hook gets queried immediately after consulting the packet cache, but before parsing the DNS packet.
    If this hook returns something else than false, the packet is dropped.
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


.. function:: gettag(remote, ednssubnet, localip, qname, qtype, ednsoptions, tcp) -> int
              gettag(remote, ednssubnet, localip, qname, qtype, ednsoptions) -> int

    .. versionchanged:: 4.1.0

      The ``tcp`` parameter was added.

    The ``gettag`` function is invoked when the Recursor attempts to discover in which packetcache an answer is available.

    This function must return an integer, which is the tag number of the packetcache.
    In addition to this integer, this function can return a table of policy tags.
    The resulting tag number can be accessed via :attr:`dq.tag <DNSQuestion.tag>` in the :func:`preresolve` hook, and the policy tags via :meth:`dq:getPolicyTags() <DNSQuestion:getPolicyTags>` in every hook.

    .. versionadded:: 4.1.0

        It can also return a table whose keys and values are strings to fill the :attr:`DNSQuestion.data` table, as well as a ``requestorId`` value to fill the :attr:`DNSQuestion.requestorId` field and a ``deviceId`` value to fill the :attr:`DNSQuestion.deviceId` field.
    .. versionadded:: 4.3.0

        Along the ``deviceId`` value that can be returned, it was addded a ``deviceName`` field to fill the :attr:`DNSQuestion.deviceName` field.

    The tagged packetcache can e.g. be used to answer queries from cache that have e.g. been filtered for certain IPs (this logic should be implemented in :func:`gettag`).
    This ensure that queries are answered quickly compared to setting :attr:`dq.variable <DNSQuestion.variable>` to true.
    In the latter case, repeated queries will pass through the entire Lua script.

    :param ComboAddress remote: The sender's IP address
    :param Netmask ednssubnet: The EDNS Client subnet that was extracted from the packet
    :param ComboAddress localip: The IP address the query was received on
    :param DNSName qname: The domain name the query is for
    :param int qtype: The query type of the query
    :param ednsoptions: A table whose keys are EDNS option codes and values are :class:`EDNSOptionView` objects. This table is empty unless the :ref:`setting-gettag-needs-edns-options` option is set.
    :param bool tcp: Added in 4.1.0, a boolean indicating whether the query was received over UDP (false) or TCP (true).

.. function:: prerpz(dq)

  This hook is called before any filtering policy have been applied,  making it possible to completely disable filtering by setting  :attr:`dq.wantsRPZ <DNSQuestion.wantsRPZ>` to false.
  Using the :meth:`dq:discardPolicy() <DNSQuestion:discardPolicy>` function, it is also possible to selectively disable one or more filtering policy, for example RPZ zones, based on the content of the ``dq`` object.

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

.. function:: preresolve(dq)

  This function is called before any DNS resolution is attempted, and if this function indicates it, it can supply a direct answer to the DNS query, overriding the internet.
  This is useful to combat botnets, or to disable domains unacceptable to an organization for whatever reason.

  :param DNSQuestion dq: The DNS question to handle

.. function:: postresolve(dq)

  is called right before returning a response to a client (and, unless :attr:`dq.variable <DNSQuestion.variable>` is set, to the packet cache too).
  It allows inspection and modification of almost any detail in the return packet.

  :param DNSQuestion dq: The DNS question to handle

.. function:: nxdomain(dq)

  is called after the DNS resolution process has run its course, but ended in an 'NXDOMAIN' situation, indicating that the domain does not exist.
  Works entirely like :func:`postresolve`, but saves a trip through Lua for answers which are not NXDOMAIN.

  :param DNSQuestion dq: The DNS question to handle

.. function:: nodata(dq)

  is just like :func:`nxdomain`, except it gets called when a domain exists, but the requested type does not.
  This is where one would implement :doc:`DNS64 <../dns64>`.

  :param DNSQuestion dq: The DNS question to handle

.. function:: preoutquery(dq)

  This hook is not called in response to a client packet, but fires when the Recursor wants to talk to an authoritative server.
  When this hook sets the special result code -3, the whole DNS client query causing this outquery gets dropped.

  However, this function can also return records like :func:`preresolve`.

  :param DNSQuestion dq: The DNS question to handle

Semantics
^^^^^^^^^
The functions must return ``true`` if they have taken over the query and wish that the nameserver should not proceed with its regular query-processing.
When a function returns ``false``, the nameserver will process the query normally until a new function is called.

If a function has taken over a request, it should set an rcode (usually 0), and specify a table with records to be put in the answer section of a packet.
An interesting rcode is NXDOMAIN (3, or ``pdns.NXDOMAIN``), which specifies the non-existence of a domain.

The :func:`ipfilter` and :func:`preoutquery` hooks are different, in that :func:`ipfilter` can only return a true of false value, and that :func:`preoutquery` can also set rcode -3 to signify that the whole query should be terminated.

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

Useful 'rcodes' include 0 for "no error", ``pdns.NXDOMAIN`` for "NXDOMAIN", ``pdns.DROP`` to drop the question from further processing.
Such a drop is accounted in the 'policy-drops' metric.

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

The following script will add a requestor's IP address to a blocking set if they've sent a query that caused PowerDNS to attempt to talk to a certain subnet.

This specific script is, as of January 2015, useful to prevent traffic to ezdns.it related traffic from creating CPU load.
This script requires PowerDNS Recursor 4.x or later.

.. code-block:: Lua

    lethalgroup=newNMG()
    lethalgroup:addMask("192.121.121.0/24") -- touch these nameservers and you die

    function preoutquery(dq)
        print("pdns wants to ask "..dq.remoteaddr:toString().." about "..dq.qname:toString().." "..dq.qtype.." on behalf of requestor "..dq.localaddr:toString())
        if(lethalgroup:match(dq.remoteaddr))
        then
            print("We matched the group "..lethalgroup:tostring().."!", "killing query dead & adding requestor "..dq.localaddr:toString().." to block list")
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

If the decision is modified in a Lua hook, ``false`` should be returned, as the query is not actually handled by Lua so the decision is picked up by the Recursor.
The result of the policy decision is checked after :func:`preresolve` and :func:`postresolve`.

For example, if a decision is set to ``pdns.policykinds.NODATA`` by the policy engine and is unchanged in :func:`preresolve`, the query is replied to with a NODATA response immediately after :func:`preresolve`.

Example script
^^^^^^^^^^^^^^

.. code-block:: Lua

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

The interval can be configured through the :ref:`setting-maintenance-interval` setting.
