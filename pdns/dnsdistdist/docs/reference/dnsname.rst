.. _DNSName:

DNSName objects
===============

A :class:`DNSName` object represents a name in the DNS. It has serveral functions that can manipulate it without conversions to strings.
Creating a ``DNSName`` is done with the :func:`newDNSName`::

  myname = newDNSName("www.example.com")

dnsdist will complain loudly if the name is invalid (e.g. too long, dot in the wrong place).

The ``myname`` variable has several functions to get information from it

.. code-block:: lua

  print(myname:countLabels()) -- prints "3"
  print(myname:wirelength()) -- prints "17"
  name2 = newDNSName("example.com")
  if myname:isPartOf(name2) then -- prints "it is"
    print('it is')
  end

Functions and methods of a ``DNSName``
--------------------------------------

.. function:: newDNSName(name) -> DNSName

  Returns the :class:`DNSName` object of ``name``.

  :param string name: The name to create a DNSName for

.. class:: DNSName

  A ``DNSName`` object represents a name in the DNS.
  It is returned by several functions and has several functions to programmatically interact with it.

  .. method:: DNSName:chopOff() -> bool

    .. versionadded:: 1.2.0

    Removes the left-most label and returns ``true``.
    ``false`` is returned if no label was removed

  .. method:: DNSName:countLabels() -> int

    Returns the number of DNSLabels in the name

  .. method:: DNSName:isPartOf(name) -> bool

    Returns true if the DNSName is part of the DNS tree of ``name``.

    :param DNSName name: The name to check against

  .. method:: DNSName:toString() -> string
              DNSName:tostring() -> string

    Returns a human-readable form of the DNSName.

  .. method:: DNSName:wirelength() -> int

    Returns the length in bytes of the DNSName as it would be on the wire.
