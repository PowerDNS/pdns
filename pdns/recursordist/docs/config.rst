Configuration
=============

Configuration of PowerDNS Recursor can be done in two ways. The recommended way (since version 5.2) is using :doc:`YAML <yamlsettings>`.
The older method of a :doc:`settings file<settings>`, combined with a :doc:`Lua configuration <lua-config/index>` is supported, but no longer recommended.

.. toctree::
    :maxdepth: 1
    :glob:

    yamlsettings
    settings
    lua-config/index
    ../performance
    ../dns64
    ../dnssec
    ../nod_udr
    ../metrics
