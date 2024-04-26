NetmaskGroup
============

.. function:: newNMG() -> NetmaskGroup

  Returns a NetmaskGroup

.. class:: NetmaskGroup

   Represents a group of netmasks that can be used to match :class:`ComboAddress`\ es against.

  .. method:: NetmaskGroup:addMask(mask)
              NetmaskGroup:addMasks(masks)

    Add one or more masks to the NMG.

    :param string mask: Add this mask, prefix with `!` to exclude this mask from matching.
    :param table masks: Adds the keys of the table to the :class:`NetmaskGroup`. It should be a table whose keys are :class:`ComboAddress` objects and whose values are integers. The integer values of the table entries are ignored. The table is of the same type as the table returned by the `exceed*` functions.

  .. method:: NetmaskGroup:addNMG(otherNMG)

    .. versionadded:: 1.9.0

    Add all masks from an existing NMG to this NMG.

    :param NetmaskGroup otherNMG: Add the masks from a :class:`NetmaskGroup` to this one.

  .. method:: NetmaskGroup:match(address) -> bool

    Checks if ``address`` is matched by this NetmaskGroup.

    :param ComboAddress address: The address to match.

  .. method:: NetmaskGroup:clear()

    Clears the NetmaskGroup.

  .. method:: NetmaskGroup:size() -> int

    Returns number of netmasks in this NetmaskGroup.
