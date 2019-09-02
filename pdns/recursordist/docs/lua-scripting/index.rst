Scripting The Recursor
======================
In the PowerDNS recursor, it is possible to modify resolving behaviour using simple scripts written in the `Lua <http://www.lua.org>`_ programming language.

**Note**: This describes the Lua scripts as supported by 4.x. They are very different than the ones from 3.x, but tend to be faster and more correct.

These scripts can be used to quickly override dangerous domains, fix things that are wrong, for load balancing or for legal or commercial purposes.
The scripts can also protect you or your users from malicious traffic.

Lua is extremely fast and lightweight, easily supporting hundreds of thousands of queries per second.
The Lua language is explained very well in the excellent book `Programming in Lua <http://www.amazon.com/exec/obidos/ASIN/859037985X/lua-pilindex-20>`_.
If you already have programming experience, `Learn Lua in 15 Minutes <http://tylerneylon.com/a/learn-lua/>`_ is a great primer.

For extra performance, a Just In Time compiled version of Lua called `LuaJIT <http://luajit.org/>`_ is supported.

.. toctree::
    :maxdepth: 2

    configure
    dq
    dnsname
    dnsrecord
    comboaddress
    netmask
    statistics
    logging
    hooks
    functions
    features
    
