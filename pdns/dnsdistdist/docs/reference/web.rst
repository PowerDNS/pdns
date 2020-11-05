.. _WebObjects:

Webserver-related objects
=========================

.. class:: WebRequest

  Represent a HTTP query, whose attributes are read-only.

  .. attribute:: WebRequest.body

    The body of this query, as a string.

  .. attribute:: WebRequest.getvars

    The GET parameters of this query, as a table whose keys and values are strings.

  .. attribute:: WebRequest.headers

    The HTTP headers of this query, as a table whose keys and values are strings.

  .. attribute:: WebRequest.method

    The method of this query, as a string.

  .. attribute:: WebRequest.path

    The path of this query, as a string.

  .. attribute:: WebRequest.postvars

    The POST parameters of this query, as a table whose keys and values are strings.

  .. attribute:: WebRequest.version

    The HTTP version of this query, as an integer.

.. class:: WebResponse

  Represent a HTTP response.

  .. attribute:: WebResponse.body

    The body of this response, as a string.

  .. attribute:: WebResponse.headers

    The HTTP headers of this response, as a table whose keys and values are strings.

  .. attribute:: WebResponse.status

    The HTTP status code of this response, as an integer.
