Scripting PowerDNS Recursor
===========================
In the PowerDNS Recursor, it is possible to modify resolving behaviour using simple scripts written in the `Lua <https://www.lua.org>`_ programming language.

Lua scripts can be used for load balancing, legal reasons, commercial purposes, to quickly block dangerous domains or override problematic responses.

Because Lua is extremely fast and lightweight, it easily supports hundreds of thousands of queries per second.
The Lua language is explained very well in the excellent book `Programming in Lua <https://www.amazon.com/exec/obidos/ASIN/859037985X/lua-pilindex-20>`_.
If you already have programming experience, `Learn Lua in 15 Minutes <https://tylerneylon.com/a/learn-lua/>`_ is a great primer.

For extra performance, a Just In Time compiled version of Lua called `LuaJIT <https://luajit.org/>`_ is supported.

.. note::
   PowerDNS Recursor is capable of handling many queries simultaneously using cooperative user space multi-threading.
   Blocking functions called from Lua are not cooperative and will monopolize a worker thread while blocked.
   Avoid blocking calls.

.. toctree::
    :maxdepth: 2

    configure
    dq
    dnsname
    dnsrecord
    comboaddress
    netmask
    policyevent
    statistics
    logging
    hooks
    ffi
    functions
    features

