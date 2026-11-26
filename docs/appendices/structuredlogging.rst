.. _structured-logging-dictionary:

Structured Logging Dictionary
=============================

This page describes the common entries of the Structured Logging component.
Currently :ref:`setting-structured-logging-backend` can have these values:

- The ``default`` text based backend.
- The ``systemd-journal`` backend (added in version 5.2.0).
- The ``json`` backend (added in version 5.2.0).

The ``default`` backend
-----------------------
The default backend uses a text representation of the key-value pairs.
A line is constructed by appending all key-value pairs as ``key="value"``, separated by spaces.
The output is written by passing the resulting text line to the standard error stream and also to ``syslog`` if :ref:`setting-disable-syslog` is false.
A timestamp is always prepended to the log line.

An example line looks like this::

  Oct 18 08:45:21 msg="Backend does not support DNSSEC operation, not adding NSEC records" zone="example.com" level="5" prio="Notice" ts="1697611521.119"

- Key names are not quoted.
- Values are quoted with double quotes.
- If a value contains a double quote, it is escaped with a backslash.
- Backslashes in the value are escaped by prepending a backslash.

The following keys are always present:

+-------------+------------------+--------------------------------------+---------------------------------------+
| **Key**     | **Type**         | **Example**                          | **Remarks**                           |
+-------------+------------------+--------------------------------------+---------------------------------------+
|``msg``      |``string``        | ``"This is a standalone pdns"``      |Value is the same for all instances of |
|             |                  |                                      |this log entry, together with          |
|             |                  |                                      |``subsystem`` it uniquely identifies   |
|             |                  |                                      |the log message.                       |
+-------------+------------------+--------------------------------------+---------------------------------------+
|``subsystem``|``string``        |``"receiver0"``                       |Uniquely identifies the log            |
|             |                  |                                      |entry together with the value of       |
|             |                  |                                      |``msg``.                               |
+-------------+------------------+--------------------------------------+---------------------------------------+
| ``level``   |``number``        |``"0"``                               |The detail level of the log entry, do  |
|             |                  |                                      |not confuse with                       |
|             |                  |                                      |:ref:`setting-loglevel`.               |
|             |                  |                                      |Not actively used currently.           |
+-------------+------------------+--------------------------------------+---------------------------------------+
| ``prio``    |``enum``          |``"Notice"``                          |One of ``Alert`` (1), ``Critical`` (2),|
|             |                  |                                      |``Error`` (3), ``Warning`` (4),        |
|             |                  |                                      |``Notice`` (5), ``Info`` (6),          |
|             |                  |                                      |``Debug`` (7). A log entry will only be|
|             |                  |                                      |produced if its ``prio`` is equal to or|
|             |                  |                                      |lower than                             |
|             |                  |                                      |:ref:`setting-loglevel`.               |
+-------------+------------------+--------------------------------------+---------------------------------------+
| ``ts``      |``number``        |``"1697614303.039"``                  |Number of seconds since the Unix epoch,|
|             |                  |                                      |including fractional part.             |
+-------------+------------------+--------------------------------------+---------------------------------------+

A log entry can also have zero or more additional key-value pairs. Common keys are:

+-------------+---------------------+----------------------------------+---------------------------------------+
| **Key**     | **Type**            |**Example**                       | **Remarks**                           |
+-------------+---------------------+----------------------------------+---------------------------------------+
|``error``    |``string``           |``"No such file or directory"``   |An error cause.                        |
+-------------+---------------------+----------------------------------+---------------------------------------+
|``address``  |``ip address:port``  |``"[::]:5301"``                   |An IP:port combination.                |
+-------------+---------------------+----------------------------------+---------------------------------------+
|``path``     |``filesystem path``  |``"/usr/local/lib/pdns"``         |                                       |
+-------------+---------------------+----------------------------------+---------------------------------------+
|``proto``    |``string``           |``"udp"``                         |                                       |
+-------------+---------------------+----------------------------------+---------------------------------------+
|``qname``    |``DNS name``         |``"example.com"``                 |                                       |
+-------------+---------------------+----------------------------------+---------------------------------------+
|``qtype``    |``DNS Query Type``   |``"AAAA"``                        |Text representation of DNS query type. |
+-------------+---------------------+----------------------------------+---------------------------------------+
| ``rcode``   |``DNS Response Code``|``"3"``                           |Numeric DNS response code              |
+-------------+---------------------+----------------------------------+---------------------------------------+
|``zone``     |``string``           |``"example.com"``                 |The name of the zone concerned.        |
+-------------+---------------------+----------------------------------+---------------------------------------+

The ``systemd-journal`` backend
-------------------------------
The ``systemd-journal`` structured logging backend uses mostly the same keys and values as the default backend, with the exceptions:

- keys are capitalized as required for ``systemd-journal``.
- ``msg`` is translated to ``MESSAGE``.
- ``prio`` is translated to ``PRIORITY``.
- ``ts`` is translated to ``TIMESTAMP``.
- If the original key is in a list of keys special to ``systemd-journal``, it is capitalized and prepended by ``PDNS_``.
  The list of special keys is: message, message_id, priority, code_file, code_line, code_func, errno, invocation_id, user_invocation_id, syslog_facility, syslog_identifier, syslog_pid, syslog_timestamp, syslog_raw, documentation, tid, unit, user_unit, object_pid.

To query the log, use a command similar to::

  # journalctl -r -n 1 -o json-pretty -u pdns.service

The ``json`` backend
--------------------
The ``json`` structured logging backend uses the same keys and values as the default backend.
An example of a log object::

    {"level": "0", "msg": "Backend does not support DNSSEC operation, not adding NSEC records", "zone": "example.com", "priority": "5", "ts": "1709285994.851"}

All values are represented as strings.

The JSON log objects are written to the standard error stream, each object on its own line.
