Basic setup: configuring database connectivity
==============================================

This shows you how to configure the Generic SQLite3 backend.

Make sure the SQLite3 backend is installed:

.. code-block:: shell

    sudo apt-get install pdns-backend-sqlite3

or

.. code-block:: shell

    sudo yum install pdns-backend-sqlite

This backend is called :doc:`'gsqlite3' <../backends/generic-sqlite3>`, and needs to be configured in ``pdns.conf``.
Add the following lines, adjusted for your local setup:

.. code-block:: ini

    launch=gsqlite3
    gsqlite3-database=/var/lib/powerdns/pdns.sqlite3

Remove any earlier :ref:`setting-launch` statements and other configuration statements for backends.

Now create the database (on RPM systems, the schema path is ``/usr/share/doc/pdns-backend-sqlite/schema.sqlite3.sql``):

.. code-block:: shell

    sudo mkdir /var/lib/powerdns
    sudo sqlite3 /var/lib/powerdns/pdns.sqlite3 < /usr/share/doc/pdns-backend-sqlite3/schema.sqlite3.sql
    sudo chown -R pdns:pdns /var/lib/powerdns

And start PowerDNS

.. code-block:: shell

    sudo systemctl start pdns

or

.. code-block:: shell

    sudo systemctl restart pdns

Make sure no error is reported, and use ``systemctl status pdns`` to make sure PowerDNS was started correctly.

A sample query sent to the server should now return quickly *without* data::

    $ dig a www.example.com @127.0.0.1

    ; <<>> DiG 9.10.3-P4-Debian <<>> a www.example.com @127.0.0.1
    ;; global options: +cmd
    ;; Got answer:
    ;; ->>HEADER<<- opcode: QUERY, status: REFUSED, id: 40870
    ...

.. warning::
  When debugging DNS problems, don't use ``host``. Please use ``dig`` or ``drill``.

Note the ``REFUSED`` status - this is the code most name servers use to indicate they do not know about a domain.

Now, let's add a zone and some records::

    $ sudo -u pdns pdnsutil create-zone example.com ns1.example.com
    Creating empty zone 'example.com'
    Also adding one NS record
    $ sudo -u pdns pdnsutil add-record example.com '' MX '25 mail.example.com'
    New rrset:
    example.com. 3005 IN MX 25 mail.example.com
    $ sudo -u pdns pdnsutil add-record example.com. www A 192.0.2.1
    New rrset:
    www.example.com. 3005 IN A 192.0.2.1

This should be done as the ``pdns`` user (or root), as sqlite3 requires write access to the directory of the database file.

.. note::
  :doc:`pdnsutil <pdnsutil>` is a tool that can manipulate zones, set DNSSEC parameters for zones and does :doc:`many other <../manpages/pdnsutil.1>` things.
  It is *highly* recommended to use :doc:`pdnsutil <pdnsutil>` or the :doc:`HTTP API <../http-api/index>` to modify zones instead of using raw SQL,
  as :doc:`pdnsutil <pdnsutil>` and the API perform checks on the data and post-store changes to prevent issues when serving DNS data.

If we now requery our database, ``www.example.com`` should be present::

    $ dig +short www.example.com @127.0.0.1
    192.0.2.1

    $ dig +short example.com MX @127.0.0.1
    25 mail.example.com

If this is not the output you get, remove ``+short`` to see the full output so you can find out what went wrong.
The first problem could be that PowerDNS has a :ref:`packet-cache` and a :ref:`query-cache` for performance reasons.
If you see old, or no, data right after changing records, wait for :ref:`setting-cache-ttl`, 
:ref:`setting-negquery-cache-ttl`, :ref:`setting-query-cache-ttl`, or :ref:`setting-zone-cache-refresh-interval`
to expire before testing.

Now, run ``pdnsutil edit-zone example.com`` and try to add a few more records, and query them with dig to make sure they work.

You now have a working database driven nameserver!

To convert other zones already present, see the :doc:`migration guide <../migration>`.

Common problems
---------------

Most problems involve PowerDNS not being able to connect to the database.
This section covers more than just SQLite.

Can't connect to local MySQL server through socket '/tmp/mysql.sock' (2)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Your MySQL installation is probably defaulting to another location for
its socket. Can be resolved by figuring out this location (often
``/var/run/mysqld.sock``), and specifying it in the configuration file
with the :ref:`setting-gmysql-socket` parameter.

Another solution is to not connect to the socket, but to 127.0.0.1,
which can be achieved by specifying ``gmysql-host=127.0.0.1``.

Host 'x.y.z.w' is not allowed to connect to this MySQL server
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

These errors are generic MySQL errors. Solve them by trying to connect
to your MySQL database with the MySQL console utility ``mysql`` with the
parameters specified to PowerDNS. Consult the MySQL documentation.

Typical Errors after Installing
-------------------------------

At this point some things may have gone wrong. Typical errors include:

binding to UDP socket: Address already in use
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This means that another nameserver is listening on port 53 already. You
can resolve this problem by determining if it is safe to shutdown the
nameserver already present, and doing so. If uncertain, it is also
possible to run PowerDNS on another port. To do so, add
:ref:`setting-local-port`\ =5300 to ``pdns.conf``, and
try again. This however implies that you can only test your nameserver
as clients expect the nameserver to live on port 53.

binding to UDP socket: Permission denied
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You must be superuser in order to be able to bind to port 53. If this is
not a possibility, it is also possible to run PowerDNS on another port.
To do so, add :ref:`setting-local-port`\ =5300 to
``pdns.conf``, and try again. This however implies that you can only
test your nameserver as clients expect the nameserver to live on port
53.

Unable to launch, no backends configured for querying
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

You currently don't have a backend configured in the configuration file.
Add a :ref:`setting-launch` statement for the backend you want to use.

If you are following this guide and using an sqlite database as a backend,
please add the ``launch=gsqlite3`` instruction to pdns.conf.

Multiple IP addresses on your server, PowerDNS sending out answers on the wrong one, Massive amounts of 'recvfrom gave error, ignoring: Connection refused'
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you have multiple IP addresses on the internet on one machine, UNIX
often sends out answers over another interface than which the packet
came in on. In such cases, use :ref:`setting-local-address` to bind to specific IP
addresses, which can be comma separated. The second error comes from
remotes disregarding answers to questions it didn't ask to that IP
address and sending back ICMP errors.
