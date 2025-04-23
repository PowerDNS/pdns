Advanced Configuration Using Lua
================================

:program:`PowerDNS Recursor` supports additional configuration options that can be loaded through :ref:`setting-yaml-recursor.lua_config_file`.

.. toctree::

    dnssec
    protobuf
    rpz
    sortlist
    ztc
    additionals
    proxymapping

In addition, :func:`pdnslog` together with ``pdns.loglevels`` is also supported in the Lua configuration file.

.. note::
   Starting with version 5.1.0, the settings originally specified in a Lua config file can also be put in YAML form.
   The conversion printed by ``rec_control show-yaml`` will print these settings if a Lua config file is specified in the config file being converted.
   You have to choose however: either set Lua settings the old way in the Lua config file, or convert all to YAML.
   If you are using YAML settings of items originally specified in the Lua config file, do not set :ref:`setting-yaml-recursor.lua_config_file` anymore. The :program:`Recursor` will check that you do not mix both configuration methods.

