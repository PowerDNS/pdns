Using Sortlist
==============
Sortlist is a complicated feature which allows for the ordering of A and AAAA records in answers to be modified, optionally dependently on who is asking.
Since clients frequently connect to the 'first' IP address they see, this can effectively allow you to make sure that user from, say 10.0.0.0/8 also preferably connect to servers in 10.0.0.0/8.

The syntax consists of a netmask for which this ordering instruction applies, followed by a set of netmask (groups) which describe the desired ordering.
So an ordering instruction of "1.0.0.0/8", "2.0.0.0/8" will put anything within 1/8 first, and anything in 2/8 second.
Other IP addresses would follow behind the addresses sorted earlier.

If netmasks are grouped, this means these get equal ordering.

``addSortList``
^^^^^^^^^^^^^^^

.. versionadded:: 5.1.0 Alternative equivalent YAML setting: :ref:`setting-yaml-recursor.sortlists`.

``addSortList()`` is used in the :ref:`setting-yaml-recursor.lua_config_file` and is intended to exactly mirror the semantics of the BIND sortlist option, but the syntax is slightly different.


As an example, the following BIND sortlist:

.. code-block:: none

    { 17.50.0.0/16; {17.238.240.0/24; 17.138.149.200;
    {17.218.242.254; 17.218.252.254;}; 17.38.42.80;
    17.208.240.100; }; };

Gets transformed into:

.. code-block:: Lua

    addSortList("17.50.0.0/16", {"17.238.240.0/24", "17.138.149.200",
    {"17.218.242.254", "17.218.252.254"}, "17.38.42.80", 
    "17.208.240.100" })

In other words: each IP address is put within quotes, and are separated by commas instead of semicolons.
For the rest everything is identical.

