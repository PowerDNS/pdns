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
  print(myname:countLabels()) -- prints "3"
  print(myname:wirelength()) -- prints "17"
  name2 = newDN(myname)
  name2:chopoff() -- returns true, as 'www' was stripped
  print(name2:countLabels()) -- prints "2"
  if myname:isPartOf(name2) then -- prints "it is"
    print('it is')
  end

.. function:: newDN(name) -> DNSName

  Returns the :class:`DNSName` object of ``name``.

  :param string name: The name to create a DNSName for

.. class:: DNSName

  A ``DNSName`` object represents a name in the DNS.

  .. method:: DNSName:chopOff() -> bool

    Removes the left-most label and returns ``true``.
    ``false`` is returned if no label was removed

  .. method:: DNSName:countLabels() -> int

    Returns the number of DNSLabels in the name

  .. method:: DNSName:equal(name) -> bool

    Returns true when both names are equal for the DNS, i.e case insensitive.

    :param DNSName name: The name to compare against.

  .. method:: DNSName:isPartOf(name) -> bool

    Returns true if the DNSName is part of the DNS tree of ``name``.

    .. code-block:: Lua

      newDN("www.powerdns.com"):isPartOf(newDN("CoM.")) -- true

    :param DNSName name: The name to check against

  .. method:: DNSName:toString() -> str
              DNSName:toStringNoDot() -> str

    Returns a human-readable form of the DNSName.
    With or without trailing dot.

  .. method:: DNSName:wirelength() -> int

    Returns the length in bytes of the DNSName as it would be on the wire.

DNS Suffix Match Groups
-----------------------

The :func:`newDS` function creates a "Suffix Match group" that allows fast checking if a :class:`DNSName` is part of a group.
This could e.g. be used to answer questions for known malware domains.
To check e.g. the :attr:`dq.qname` against a list:

.. code-block:: lua

  m = newDS()
  m:add({'example.com', 'example.net'})
  m:check(dq.qname) -- Would be true is dq.qname is a name in example.com or example.net

.. function:: newDS() -> DNSSuffixMatchGroup

  Creates a new DNS Suffix Match Group.

.. class:: DNSSuffixMatchGroup

  This class represents a group of DNS names that can be used to quickly compare a single :class:`DNSName` against.

  .. method:: DNSSuffixMatchGroup:add(domain)
              DNSSuffixMatchGroup:add(domains)

    Add one or more domains to the Suffix Match Group.

    :param str domain: A domain name to add
    :param {str} domain: A list of Domains to add

  .. method:: DNSSuffixMatchGroup:check(domain) -> bool

    Check ``domain`` against the Suffix Match Group.
    Returns true if it is matched, false otherwise.

    :param DNSName domain: The domain name to check

  .. method:: DNSSuffixMatchGroup:toString() -> str

    Returns a string of the set of suffixes matched by the Suffix Match Group
