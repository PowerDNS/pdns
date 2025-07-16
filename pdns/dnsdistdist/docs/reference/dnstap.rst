dnstap Logging Reference
========================

`dnstap <https://dnstap.info>`__ is a flexible, structured binary log format for DNS software.
Reader implementations in various languages exist.

:program:`dnsdist` supports dnstap since version 1.3.0.

Canonically, dnstap is sent over a FrameStream socket, either a local AF_UNIX (see :func:`newFrameStreamUnixLogger`) or a TCP/IP socket (see :func:`newFrameStreamTcpLogger`).
As an extension, :program:`dnsdist` can send raw dnstap protobuf messages over a :func:`newRemoteLogger`.

To use FrameStream transport, :program:`dnsdist` must have been built with `libfstrm`.

.. function:: newFrameStreamUnixLogger(path [, options])

  .. versionchanged:: 2.0.0
    Added ``connectionCount`` option.

  .. versionchanged:: 1.5.0
    Added the optional parameter ``options``.

  Create a Frame Stream Logger object, to use with :func:`DnstapLogAction` and :func:`DnstapLogResponseAction`.
  This version will log to a local AF_UNIX socket.

  :param string path: A local AF_UNIX socket path. Note that most platforms have a rather short limit on the length.
  :param table options: A table with key: value pairs with options.

  The following options apply to the settings of the `framestream library
  <https://github.com/farsightsec/fstrm>`. Refer to the documentation of that library for the default and
  allowed values for these options, as well as their exact descriptions. For all these options, absence or a
  zero value has the effect of using the library-provided default value. ``connectionCount`` can be used to open
  multiple connections to the socket, for potential throughput boost.

  * ``bufferHint=0``: unsigned
  * ``flushTimeout=0``: unsigned
  * ``inputQueueSize=0``: unsigned
  * ``outputQueueSize=0``: unsigned
  * ``queueNotifyThreshold=0``: unsigned
  * ``reopenInterval=0``: unsigned
  * ``connectionCount=1``: unsigned

.. function:: newFrameStreamTcpLogger(address [, options])

  .. versionchanged:: 2.0.0
    Added ``connectionCount`` option.

  .. versionchanged:: 1.5.0
    Added the optional parameter ``options``.

  Create a Frame Stream Logger object, to use with :func:`DnstapLogAction` and :func:`DnstapLogResponseAction`.
  This version will log to a possibly remote TCP socket.
  Needs tcp_writer support in libfstrm.

  :param string address: An IP:PORT combination where the logger will connect to.
  :param table options: A table with key: value pairs with options.

  The following options apply to the settings of the `framestream library
  <https://github.com/farsightsec/fstrm>`. Refer to the documentation of that library for the default and
  allowed values for these options, as well as their exact descriptions. For all these options, absence or a
  zero value has the effect of using the library-provided default value. ``connectionCount`` can be used to open
  multiple connections to the socket, for potential throughput boost.

  * ``bufferHint=0``: unsigned
  * ``flushTimeout=0``: unsigned
  * ``inputQueueSize=0``: unsigned
  * ``outputQueueSize=0``: unsigned
  * ``queueNotifyThreshold=0``: unsigned
  * ``reopenInterval=0``: unsigned
  * ``connectionCount=1``: unsigned

.. class:: DnstapMessage

  This object represents a single dnstap message as emitted by :program:`dnsdist`.

.. classmethod:: DnstapMessage:setExtra(extraData)

  Sets the dnstap "extra" field.

  :param string extraData: Extra data stuffed into the dnstap "extra" field.

.. classmethod:: DnstapMessage:toDebugString() -> string

  Return a string containing the content of the message
