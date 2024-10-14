Logging from the Lua scripts
============================
To log messages with the main PowerDNS :program:`Recursor` process, use :func:`pdnslog`.
optionally specifying a syslog loglevel.

.. versionchanged:: 5.2.0

   Added table as optional argument.

.. function:: pdnslog(message)
              pdnslog(message, level)
              pdnslog(message, level, table)

  Log ``message`` at the ``Warning`` level if ``level`` is not set.

  :param str msg: The message to log.
  :param int level: The log level to log at, see below.
  :param table table: A table of ``key = value`` entries to add to the structured log message.

The available loglevel values are listed in the following table:

  - All - ``pdns.loglevels.All``
  - Alert - ``pdns.loglevels.Alert``
  - Critical - ``pdns.loglevels.Critical``
  - Error - ``pdns.loglevels.Error``
  - Warning - ``pdns.loglevels.Warning``
  - Notice - ``pdns.loglevels.Notice``
  - Info - ``pdns.loglevels.Info``
  - Debug - ``pdns.loglevels.Debug``
  - None - ``pdns.loglevels.None``

An example logging statement:

.. code-block:: Lua

  pdnslog('You have been warned', pdns.loglevels.Warning, { times = 3, origin = 'documentation' })
