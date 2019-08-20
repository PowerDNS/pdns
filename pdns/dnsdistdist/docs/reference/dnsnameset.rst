.. _DNSNameSet:

DNSNameSet objects
==================

A :class:`DNSNameSet` object is a set of :class:`DNSName` objects. 
Based on std::unordered_set (hash table).
Creating a ``DNSName`` is done with the :func:`newDNSNameSet`::

  myset = newDNSNameSet()

The set can be filled by func:`DNSNameSet:add`::

  myset.add(newDNSName("domain1.tld"))
  myset.add(newDNSName("domain2.tld"))

Functions and methods of a ``DNSNameSet``
-----------------------------------------

.. function:: newDNSNameSet(name) -> DNSNameSet

  Returns the :class:`DNSNameSet`.

.. class:: DNSNameSet

  A ``DNSNameSet`` object is a set of :class:`DNSName` objects.

  .. method:: DNSNameSet:add(name)

    Adds the name to the set.

    :param DNSName name The name to add.

  .. method:: DNSNameSet:empty() -> bool

    Returns true is the DNSNameSet is empty.

  .. method:: DNSNameSet:clear()

    Clean up the set.

  .. method:: DNSNameSet:toString() -> string

    Returns a human-readable form of the DNSName.

  .. method:: DNSNameSet:size() -> int

    Returns the number of names in the set.

  .. method:: DNSNameSet:delete(name) -> int

    Removes the name from the set. Returns the number of deleted elements.

   :param DNSName name The name to remove.

  .. method:: DNSNameSet:check(name) -> bool

    Returns true if the set contains the name.

   :param DNSname name The name.
