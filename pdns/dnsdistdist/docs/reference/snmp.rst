SNMP reporting
==============

.. function:: snmpAgent(enableTraps [, daemonSocket])

  Enable SNMP support.

  :param bool enableTraps: Indicates whether traps should be sent
  :param string daemonSocket: A string specifying how to connect to the daemon agent. This is a file path to a unix socket, but e.g. ``tcp:localhost:705`` can be used as well. By default, SNMP agent's default socket is used.

.. function:: sendCustomTrap(message)

  Send a custom SNMP trap from Lua.

  :param string message: The message to include in the sent trap

