Other functions
===============

These are some functions that don't really have a place in one of the other categories.

.. function:: getregisteredname(name) -> str

  Returns the shortest domain name based on Mozilla's Public Suffix List.
  In general it will tell you the 'registered domain' for a given name.

  For example ``getregisteredname('www.powerdns.com')`` returns "powerdns.com"

  :param str name: The name to check for.

.. function:: getRecursorThreadId() -> int

  returns an unsigned integer identifying the thread handling the current request.
