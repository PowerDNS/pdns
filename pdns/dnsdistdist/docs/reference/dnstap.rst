dnstap Logging Reference
========================

http://dnstap.info is a flexible, structured binary log format for DNS software.
Reader implementations in various languages exist.

Canonically, dnstap is sent over a FrameStream socket, either a local AF_UNIX (see :func:`newFrameStreamUnixLogger`) or a TCP/IP socket (see :func:`newFrameStreamTcpLogger`).
As an extension, :program:`dnsdist` can send raw dnstap protobuf messages over a :func:`newRemoteLogger`.

To use FrameStream transport, :program:`dnsdist` must have been built with `libfstrm`.

.. function:: newFrameStreamUnixLogger(path)

  Create a Frame Stream Logger object, to use with :func:`DnstapLogAction` and :func:`DnstapLogResponseAction`.
  This version will log to a local AF_UNIX socket.

  :param string path: A local AF_UNIX socket path. Note that most platforms have a rather short limit on the length.

.. function:: newFrameStreamTcpLogger(address)

  Create a Frame Stream Logger object, to use with :func:`DnstapLogAction` and :func:`DnstapLogResponseAction`.
  This version will log to a local AF_UNIX socket.

  :param string address: An IP:PORT combination where the logger will connect to. Needs tcp_writer support in libfstrm.

.. class:: DnstapMessage

  This object represents a single dnstap message as emitted by :program:`dnsdist`.

.. classmethod:: DnstapMessage:setExtra(extraData)

  Set the time at which the query or response has been received.

  :param string extraData: Extra data stuffed into the dnstap "extra" field.

.. classmethod:: DnstapMessage:toDebugString() -> string

  Return a string containing the content of the message
