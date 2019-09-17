Lua Backend
===========

* Native: Yes
* Master: Yes
* Slave: No
* Superslave: No
* Autoserial: No
* DNSSEC: Yes
* Disabled data: Yes
* Comments: Yes
* Module name: lua
* Launch name: ``lua``

The main author for this module is Fredrik Danerklint.

This backend is just a "glue" between PowerDNS and your own Lua
application.

What this means is that you can not have a working setup that can serve
you dns-questions directly from start. What you need to do is to program
your own backend completely in Lua! Which database server to use etc is
now up to you!

What you have here is the possibility to make your own "dns-server"
without the knowledge of programming in c/c++.

There is one thing that needs to be said. Remember that each thread
PowerDNS launches of this backend is completely different so they cannot
share information between each other!

You will need some kind of a database that can be shared for this.

All the functionnames that PowerDNS accept for a backend should be the
same in your Lua script, in lowercase. Also, the parameters should be in
the same order. Where there is a structure in c/c++ there is a table in
the Lua backend. This is also true for return values. A few functions
expect that you return a table in a table.

New functions
-------------

There is a couple of new functions for you to use in Lua:

``logger(log_facility, "your", "messages")``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

All these ``log_facilities`` is available: 

* ``log_all``
* ``log_ntlog``
* ``log_alert``
* ``log_critical``
* ``log_error``
* ``log_warning``
* ``log_notice,``
* ``log_info``
* ``log_debug``
* ``log_none``

``dnspacket()``
~~~~~~~~~~~~~~~

This will give you back three parameters with ``remote_ip``,
``remote_port`` and ``local_ip`` in that order.

Can only be used in the functions ``list()`` and ``getsoa()``.

.. _backends_lua_fun_getarg:

``getarg("PARAMETER")``
~~~~~~~~~~~~~~~~~~~~~~~

This one tries to get the value of the name ``"lua-PARAMETER"`` from the
pdns.conf file.

``mustdo("PARAMETER")``
~~~~~~~~~~~~~~~~~~~~~~~

This is the same as :ref:`getarg() <backends_lua_fun_getarg>`, but returns
a boolean instead of a string.

You also have all the different QTypes in a table called 'QTypes'.

What has been tested
--------------------

The only functionality of the minimal functions except zone-transfer has
been tested.

In the included powerdns-luabackend.lua file there is a example of how
this can be done. Note that this is more or less a static example since
there is no possibility for each thread to know when something has
changed.

However, you can run ``pdns_control reload`` and it should reload the
whole thing from scratch (does not work for the moment, PowerDNS only
calls two thread with the reload command - not all of them).

What you will find under the test directory
-------------------------------------------

The following script can be used to test the server:

This will yield the following result:

.. code-block:: shell

    $ dig any www.test.com @127.0.0.1 -p5300 +multiline
    ; <<>> DiG 9.7.3 <<>> any www.test.com @127.0.0.1 -p5300 +multiline
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1001
    ;; flags: qr aa rd; QUERY: 1, ANSWER: 3, AUTHORITY: 0, ADDITIONAL: 0
    ;; WARNING: recursion requested but not available

    ;; QUESTION SECTION:
    ;www.test.com.          IN ANY

    ;; ANSWER SECTION:
    www.test.com.           120 IN CNAME host.test.com.
    host.test.com.          120 IN A 10.11.12.13
    host.test.com.          120 IN AAAA 1:2:3:4:5:6:7:8

    ;; Query time: 1 msec
    ;; SERVER: 127.0.0.1#5300(127.0.0.1)
    ;; WHEN: Thu Jun  2 22:19:56 2011
    ;; MSG SIZE  rcvd: 93

Parameters
----------

.. _setting-lua-filename:

``lua-filename``
~~~~~~~~~~~~~~~~

Path to your lua script, 'powerdns-luabackend.lua' by default.

.. _setting-lua-query-logging:

``lua-query-logging``
~~~~~~~~~~~~~~~~~~~~~

Log queries. default is 'no'.

.. _setting-lua-f_FUNCTION:

``lua-f_FUNCTION=NEWFUNCTION``
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You can also override all the default functionsnames for the
luafunctions if you want. For example:

.. _setting-lua-f_lookup:

.. code-block:: ini

  lua-f_lookup = mynewfunction

will call the function ``mynewfunction`` for the lookup-routine.

If you want your own configuration parameters you can have that too.
Just call the function ``getarg("PARAMETER")`` and it will return the
value of ``lua-PARAMETER``. For boolean you use the function
``mustdo("PARAMETER")``.

Your own error function in lua
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

You can have an error function in Lua when Lua gives back a error.

First make your error function then you put this in ``pdns.conf``:

.. code-block:: ini

  lua-f_exec_error = YOUR_METHOD

DNSSEC
------

You can have full dnssec support in our Lua application. You should note
the following regarding this:

You don't have to implement the function 'updateDNSSECOrderAndAuth'
since the default code will work correctly for you via the backend
itself.

The functions activateDomainKey and deactivateDomainKey can be
implemented via a new function called updateDomainKey, which has three
parameters (the other two has only two parameters) where the third is a
boolean which is true or false depending on which function that was
called from the beginning.

Information for logging
-----------------------

If you have the parameter ``query-logging`` or ``lua-query-logging`` set
to true/yes/on, then you will see what is happening in each function
when PowerDNS calls them.

This can, hopefully, help you with some debugging if you run into some
kind of trouble with your Lua application.
