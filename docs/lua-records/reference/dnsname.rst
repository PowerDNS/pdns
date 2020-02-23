.. _DNSName:

DNSName objects
^^^^^^^^^^^^^^^

A :class:`DNSName` object represents a name in the DNS. It has several functions that can manipulate it without conversions to strings.
Creating a ``DNSName`` is done with the :func:`newDN`::

  myname = newDN("www.example.com")

PowerDNS will complain loudly if the name is invalid (e.g. too long, dot in the wrong place).

The ``myname`` variable has several functions to get information from it

.. code-block:: lua

  print(myname:countLabels()) -- prints "3"
  print(myname:wireLength()) -- prints "17"
  name2 = newDN("example.com")
  if myname:isPartOf(name2) then -- prints "it is"
    print('it is')
  end

Functions and methods of a ``DNSName``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. function:: newDN(name) -> DNSName

  Returns the :class:`DNSName` object of ``name``.

  :param string name: The name to create a DNSName for

.. class:: DNSName

  A ``DNSName`` object represents a name in the DNS.
  It is returned by several functions and has several functions to programmatically interact with it.

  .. method:: DNSName:canonCompare(name) -> bool

    Performs a comparison of DNS names in canonical order.
    Returns true if the DNSName comes before ``name``.
    See https://tools.ietf.org/html/rfc4034#section-6

    :param DNSName name: The name to compare to

  .. method:: DNSName:makeRelative(name) -> DNSName

    Returns a new DNSName that is relative to ``name``

    .. code-block:: lua

      name = newDN("bb.a.example.com.")
      parent = newDN("example.com.")
      rel = name:makeRelative(parent) -- contains DNSName("bb.a.")

    :param DNSName name: The name to compare to

  .. method:: DNSName:isPartOf(name) -> bool

    Returns true if the DNSName is part of the DNS tree of ``name``.

    :param DNSName name: The name to check against

  .. method:: DNSName:toString() -> string

    Returns a human-readable form of the DNSName

  .. method:: DNSName:toStringNoDot() -> string

    Returns a human-readable form of the DNSName without the trailing dot

  .. method:: DNSName:chopOff() -> bool

    Removes the left-most label and returns ``true``.
    ``false`` is returned if no label was removed

  .. method:: DNSName:countLabels() -> int

    Returns the number of DNSLabels in the name

  .. method:: DNSName:wireLength() -> int

    Returns the length in bytes of the DNSName as it would be on the wire.

  .. method:: DNSName::getRawLabels() -> [ string ]

    Returns a table that contains the raw labels of the DNSName

  .. method:: DNSName::countLabels() -> int

    Returns the number of labels of the DNSName

  .. method:: DNSName::equal(name) -> bool

    Perform a comparison of the DNSName to the given ``name``.
    You can also compare directly two DNSName objects using
    the ``==`` operator

    :param string name: The name to compare to
