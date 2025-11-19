Logging
=======

There are some functions to create log output.

.. function:: errlog(line)

  Writes an error line.

  :param str line: The line to write.


.. function:: warnlog(line)

  Writes a warning line.

  :param str line: The line to write.


.. function:: infolog(line)

  Writes an info line.

  :param str line: The line to write.

.. function:: vinfolog(line)

  .. versionadded:: 1.8.0

  Writes an info line if dnsdist is running in verbose (debug) mode.

  :param str line: The line to write.
