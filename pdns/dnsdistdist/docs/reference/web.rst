.. _WebObjects:

Webserver-related objects
=========================

.. class:: WebRequest

  Represent a HTTP query, whose attributes are read-only.

  .. attribute:: body

    The body of this query, as a string.

  .. attribute:: getvars

    The GET parameters of this query, as a table whose keys and values are strings.

  .. attribute:: headers

    The HTTP headers of this query, as a table whose keys and values are strings.

  .. attribute:: method

    The method of this query, as a string.

  .. attribute:: path

    The path of this query, as a string.

  .. attribute:: postvars

    The POST parameters of this query, as a table whose keys and values are strings.

  .. attribute:: version

    The HTTP version of this query, as an integer.

.. class:: WebResponse

  Represent a HTTP response.

  .. attribute:: body

    The body of this response, as a string.

  .. attribute:: headers

    The HTTP headers of this response, as a table whose keys and values are strings.

  .. attribute:: status

    The HTTP status code of this response, as an integer.
