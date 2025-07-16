DNS names and comparing them
============================

The PowerDNS Recursor uses a native format for the names it handles.
This native format is exposed to Lua as well.

The DNSName object
------------------
The PowerDNS Recursor's Lua engine has the notion of a :class:`DNSName`, an object that represents a name in the DNS.
It is returned by several functions and has several functions to programmatically interact with it.
:class:`DNSNames <DNSName>` can be compared against each other using the :meth:`:equal <DNSName:equal>` function or the ``==`` operator.
As names in the DNS are case-insensitive, ``www.powerdns.com`` is equal to ``Www.PowerDNS.cOM``.

Creating a :class:`DNSName` is done with :func:`newDN()`.
The PowerDNS Recursor will complain loudly if the name is invalid (e.g. too long, dot in the wrong place).

A small example of the functionality of a :class:`DNSName` is shown below:

.. code-block:: lua

  myname = newDN("www.example.com")
  pdnslog(myname:countLabels()) -- prints "3"
  pdnslog(myname:wirelength()) -- prints "17"
  name2 = newDN(myname)
  name2:chopOff() -- returns true, as 'www' was stripped
  pdnslog(name2:countLabels()) -- prints "2"
  if myname:isPartOf(name2) then -- prints "it is"
    pdnslog('it is')
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

.. _dns-suffix-match-group:
   
DNS Suffix Match Group
----------------------

The :func:`newDS` function creates a ``DNS Suffix Match Group`` that allows fast checking if a :class:`DNSName` is part of a group.
This could e.g. be used to answer questions for known malware domains.
To check e.g. the :attr:`dq.qname` against a list:

.. code-block:: lua

  m = newDS()
  m:add({'example.com', 'example.net'})
  m:check(dq.qname) -- Would be true is dq.qname is a name in example.com or example.net

.. function:: newDS() -> DNSSuffixMatchGroup

  Creates a new ``DNS Suffix Match Group``.

.. class:: DNSSuffixMatchGroup

  This class represents a group of DNS names that can be used to quickly compare a single :class:`DNSName` against.

  .. method:: DNSSuffixMatchGroup:add(domain)
              DNSSuffixMatchGroup:add(dnsname)
              DNSSuffixMatchGroup:add(domains)

    Add one or more domains to the ``DNS Suffix Match Group``.

    :param str domain: A domain name to add
    :param DNSName dnsname: A dnsname to add
    :param {str} domains: A list of domain names to add

  .. method:: DNSSuffixMatchGroup:check(dnsname) -> bool

    Check ``dnsname`` against the ``DNS Suffix Match Group``.
    Returns ``true`` if it is matched, ``false`` otherwise.

    :param DNSName dnsname: The dnsname to check

  .. method:: DNSSuffixMatchGroup:toString() -> str

    Returns a string of the set of suffixes matched by the ``DNS Suffix Match Group``.
