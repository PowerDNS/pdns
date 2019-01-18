.. _QType:

QType objects
=========================

The QType class lets you deal easily with the different kind
of resource types, like 'A', 'NS', 'CNAME', etc. These types have
both a name and a number. This class helps seamlessly move
between them.

Functions and methods of a ``QType``
----------------------------------------------

.. function:: newQType(name) -> QType

  Returns a new QType object from `name`. Name can either contain the code
  of the type prefixed with a sharp character, or its name directly

  :param string name: The name of the QType

  .. code-block:: lua

    type = newQType("CNAME")
    anothertype = newQType("#5")
    if type == anothertype then -- prints "equal!"
      print('equal!')
    end

.. class:: QType

  It has these methods:

  .. method:: QType:getCode() -> int

  Returns the numeric code corresponding to the type

  .. method:: QType:getName() -> string

  Returns the name of the type
