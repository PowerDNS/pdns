SNMP support
============

:program:`dnsdist` supports exporting statistics and sending traps over SNMP when compiled with ``Net SNMP`` support, acting as an ``AgentX`` subagent.
SNMP support is enabled via the :func:`snmpAgent` directive.

By default, the only traps sent when Traps are enabled, are backend status change notifications.
But custom traps can also be sent:

 * from Lua, with :func:`sendCustomTrap` and :meth:`DNSQuestion:sendTrap`
 * For selected queries and responses, using :func:`SNMPTrapAction` and :func:`SNMPTrapResponseAction`

``Net SNMP snmpd`` doesn't accept subagent connections by default, so to use the SNMP features of :program:`dnsdist` the following line should be added to the ``snmpd.conf`` configuration file::

  master agentx

In addition to that, the permissions on the resulting socket might need to be adjusted so that the ``dnsdist`` user can write to it.
This can be done with the following lines in ``snmpd.conf`` (assuming `dnsdist` is running as `dnsdist:dnsdist`)::

  agentxperms 0700 0700 dnsdist dnsdist

In order to allow the retrieval of statistics via SNMP, ``snmpd``'s access control has to configured.
A very simple SNMPv2c setup only needs the configuration of a read-only community in ``snmpd.conf``::

  rocommunity dnsdist42

``snmpd`` also supports more secure SNMPv3 setup, using for example the ``createUser`` and ``rouser`` directives::

  createUser myuser SHA "my auth key" AES "my enc key"
  rouser myuser

``snmpd`` can be instructed to send SNMPv2 traps to a remote SNMP trap receiver by adding the following directive to the ``snmpd.conf`` configuration file::

  trap2sink 192.0.2.1

The description of :program:`dnsdist`'s SNMP MIB is as follows:

.. literalinclude:: ../../DNSDIST-MIB.txt
