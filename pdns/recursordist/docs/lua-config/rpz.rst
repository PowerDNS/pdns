.. _rpz:

Response Policy Zones (RPZ)
===========================

Response Policy Zone is an open standard developed by Paul Vixie (ISC and Farsight) and Vernon Schryver (Rhyolite), to modify DNS responses based on a policy loaded via a zonefile.

Frequently, Response Policy Zones get to be very large and change quickly, so it is customary to update them over IXFR.
It allows the use of third-party feeds, and near real-time policy updates.

If multiple RPZs are loaded, they get consulted in the order they were
defined in. It is however possible from Lua to make queries skip specific
Response Policy Zones.

Configuring RPZ
---------------
An RPZ can be loaded from file or slaved from a master. To load from file, use for example:

.. code-block:: Lua

    rpzFile("dblfilename")

To slave from a master and start IXFR to get updates, use for example:

.. code-block:: Lua

    rpzMaster("192.0.2.4", "policy.rpz")

In this example, 'policy.rpz' denotes the name of the zone to query for.

The action to be taken on a match is defined by the zone itself, but in some cases it might be interesting to be able to override it, and always apply the same action
regardless of the one specified in the RPZ zone. To load from file and override the default action with a custom CNAME to badserver.example.com., use for example:

.. code-block:: Lua

    rpzFile("dblfilename", {defpol=Policy.Custom, defcontent="badserver.example.com"})

To instead drop all queries matching a rule, while slaving from a master:

.. code-block:: Lua

    rpzMaster("192.0.2.4", "policy.rpz", {defpol=Policy.Drop})

Note that since 4.2.0, it is possible for the override policy specified via 'defpol' to no longer be applied to local data entries present in the zone by setting the 'defpolOverrideLocalData' parameter to false.

As of version 4.2.0, the first parameter of :func:`rpzMaster` can be a list of addresses for failover:

    rpzMaster({"192.0.2.4","192.0.2.5:5301"}, "policy.rpz", {defpol=Policy.Drop})
  
  In the example above, two addresses are specified and will be tried one after another until a response is obtained. The first address uses the default port (53) while the second one uses port 5301.
  (If no optional port is set, the default port 53 is used)
  
   
.. function:: rpzFile(filename, settings)

  Load an RPZ from disk.

  :param str filename: The filename to load
  :param {} settings: A table to settings, see below

.. function:: rpzMaster(address, name, settings)

  .. versionchanged:: 4.2.0:

    The first parameter can be a list of addresses.

  Load an RPZ from AXFR and keep retrieving with IXFR.

  :param str address: The IP address to transfer the RPZ from. Also accepts a list of addresses since 4.2.0 in which case they will be tried one after another in the submitted order until a response is obtained.
  :param str name: The name of this RPZ
  :param {} settings: A table to settings, see below


RPZ settings
------------

These options can be set in the ``settings`` of both :func:`rpzMaster` and :func:`rpzFile`.

defcontent
^^^^^^^^^^
CNAME field to return in case of defpol=Policy.Custom

defpol
^^^^^^
Default policy: `Policy.Custom`_, `Policy.Drop`_, `Policy.NXDOMAIN`_, `Policy.NODATA`_, `Policy.Truncate`_, `Policy.NoAction`_.

defpolOverrideLocalData
^^^^^^^^^^^^^^^^^^^^^^^
.. versionadded:: 4.2.0
  Before 4.2.0 local data entries are always overridden by the default policy.

Whether local data entries should be overridden by the default policy. Default is true.

defttl
^^^^^^
the TTL of the CNAME field to be synthesized for the default policy.
The default is to use the zone's TTL,

maxTTL
^^^^^^
The maximum TTL value of the synthesized records, overriding a higher value from ``defttl`` or the zone. Default is unlimited.

.. _rpz-policyName:

policyName
^^^^^^^^^^
The name logged as 'appliedPolicy' in :doc:`protobuf <protobuf>` messages when this policy is applied.

zoneSizeHint
^^^^^^^^^^^^
An indication of the number of expected entries in the zone, speeding up the loading of huge zones by reserving space in advance.

Extra settings for rpzMaster
----------------------------
In addition to the settings above the settings for :func:`rpzMaster` may contain:

tsigname
^^^^^^^^
The name of the TSIG key to authenticate to the server.
When this is set, `tsigalgo`_ and `tsigsecret`_ must also be set.

tsigalgo
^^^^^^^^
The name of the TSIG algorithm (like 'hmac-md5') used

tsigsecret
^^^^^^^^^^
Base64 encoded TSIG secret

refresh
^^^^^^^
An integer describing the interval between checks for updates.
By default, the RPZ zone's default is used

maxReceivedMBytes
^^^^^^^^^^^^^^^^^
The maximum size in megabytes of an AXFR/IXFR update, to prevent resource exhaustion.
The default value of 0 means no restriction.

localAddress
^^^^^^^^^^^^
The source IP address to use when transferring the RPZ.
When unset, :ref:`setting-query-local-address` and :ref:`setting-query-local-address6` are used.

axfrTimeout
^^^^^^^^^^^
.. versionadded:: 4.1.2
  Before 4.1.2, the timeout was fixed on 10 seconds.

The timeout in seconds of the total initial AXFR transaction.
20 by default.

dumpFile
^^^^^^^^
.. versionadded:: 4.2.0

A path to a file where the recursor will dump the latest version of the RPZ zone after
each successful update. This can be used to keep track of changes in the RPZ zone, or
to speed up the initial loading of the zone via the `seedFile`_ parameter.
The format of the generated zone file is the same than the one used with :func:`rpzFile`,
and can also be generated via:

  rec_control dump-rpz *zone-name* *output-file*


seedFile
^^^^^^^^
.. versionadded:: 4.2.0

A path to a file containing an existing dump of the RPZ zone. The recursor will try to load
the zone from this file on startup, then immediately do an IXFR to retrieve any updates.
If the file does not exist or is not valid, the normal process of doing a full AXFR will
be used instead.
This option allows a faster startup by loading an existing zone from a file instead
of retrieving it from the network, then retrieving only the needed updates via IXFR.
The format of the zone file is the same than the one used with :func:`rpzFile`, and can
for example be generated via:

  rec_control dump-rpz *zone-name* *output-file*

It is also possible to use the `dumpFile`_ parameter in order to dump the latest version
of the RPZ zone after each update.

Policy Actions
--------------

If no settings are included, the RPZ is taken literally with no overrides applied.
Several Policy Actions exist

Policy.Custom
^^^^^^^^^^^^^
Will return a NoError, CNAME answer with the value specified with ``defcontent``,
when looking up the result of this CNAME, RPZ is not taken into account.

Policy.Drop
^^^^^^^^^^^
Will simply cause the query to be dropped.

Policy.NoAction
^^^^^^^^^^^^^^^
Will continue normal processing of the query.


Policy.NODATA
^^^^^^^^^^^^^
Will return a NoError response with no value in the answer section.

Policy.NXDOMAIN
^^^^^^^^^^^^^^^
Will return a response with a NXDomain rcode.

Policy.Truncate
^^^^^^^^^^^^^^^
will return a NoError, no answer, truncated response over UDP.
Normal processing will continue over TCP
