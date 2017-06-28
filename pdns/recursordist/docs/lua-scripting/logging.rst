Logging from the Lua scripts
============================
To log messages with the main PowerDNS Recursor process, use :func:`pdnslog`.
:func:`pdnslog` can also write out to a syslog loglevel if specified.
Use ``pdnslog(message, pdns.loglevels.LEVEL)`` with the
correct pdns.loglevels entry. Entries are listed in the following table:

.. function:: pdnslog(message)
              pdnslog(message, level)

  Log ``message` at the Info level if ``level`` is not set.

  :param str msg: The message to log
  :param int level: The log level to log at, see below.

  - All - ``pdns.loglevels.All``
  - Alert - ``pdns.loglevels.Alert``
  - Critical - ``pdns.loglevels.Critical``
  - Error - ``pdns.loglevels.Error``
  - Warning - ``pdns.loglevels.Warning``
  - Notice - ``pdns.loglevels.Notice``
  - Info - ``pdns.loglevels.Info``
  - Debug - ``pdns.loglevels.Debug``
  - None - ``pdns.loglevels.None``
