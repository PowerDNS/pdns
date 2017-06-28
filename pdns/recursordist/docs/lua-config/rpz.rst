.. _rpz:

Response Policy Zones (RPZ)
===========================

Response Policy Zone is an open standard developed by Paul Vixie (ISC and Farsight) and Vernon Schryver (Rhyolite), to modify DNS responses based on a policy loaded via a zonefile.

Frequently, Response Policy Zones get to be very large and change quickly, so it is customary to update them over IXFR.
It allows the use of third-party feeds, and near real-time policy updates.

Configuring RPZ
---------------
An RPZ can be loaded from file or slaved from a master. To load from file, use for example:

.. code-block:: Lua

    rpzFile("dblfilename", {defpol=Policy.Custom, defcontent="badserver.example.com"})

To slave from a master and start IXFR to get updates, use for example:

.. code-block:: Lua

    rpzMaster("192.0.2.4", "policy.rpz", {defpol=Policy.Drop})

In this example, 'policy.rpz' denotes the name of the zone to query for.

.. function:: rpzFile(filename, settings)

  Load an RPZ from disk.

  :param str filename: The filename to load
  :param {} settings: A table to settings, see below

.. function:: rpzMaster(address, name, settings)

  Load an RPZ from AXFR and keep retrieving with IXFR.

  :param str address: The IP address to transfer the RPZ from
  :param str name: The name of this RPZ
  :param {} settings: A table to settings, see below


RPZ settings
------------

These options can be set in the ``settings`` of both :func:`rpzMaster` and :func:`rpzFile`.

defpol
^^^^^^
Default policy: `Policy.Custom`_, `Policy.Drop`_, `Policy.NXDOMAIN`_, `Policy.NODATA`_, `Policy.Truncate`_, `Policy.NoAction`_.

defcontent
^^^^^^^^^^
CNAME field to return in case of defpol=Policy.Custom

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

Extra Settings for rzpMaster
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
