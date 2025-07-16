Configuring Lua scripts
=======================

In order to load scripts, the PowerDNS Recursor must have Lua support built in.
The packages distributed from the PowerDNS website have this language enabled, other distributions may differ.
By default, the Recursor's configure script will attempt to detect if Lua is available.

**note**: Only one script can be loaded at the same time. If you load a different script, the current one will be replaced (safely)!

If Lua support is available, a script can be configured either via the configuration file, or at runtime via the ``rec_control`` tool.
Scripts can be reloaded or unloaded at runtime with no interruption in operations.
If a new script contains syntax errors, the old script remains in force.

On the command line, or in the configuration file, the setting :ref:`setting-yaml-recursor.lua_dns_script` can be used to supply a full path to the Lua script.

At runtime, ``rec_control reload-lua-script`` can be used to either reload the script from its current location, or, when passed a new filename, load one from a new location.
A failure to parse the new script will leave the old script in working order.

**Note**: It is also possible to precompile scripts using ``luac``, and have PowerDNS load the result.
This means that switching scripts is faster, and also that you'll be informed about syntax errors at compile time.

Finally, ``rec_control unload-lua-script`` can be used to remove the currently installed script, and revert to unmodified behaviour.
