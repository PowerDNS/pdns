Basic setup: configuring database connectivity
==============================================

This shows you how to configure the Generic MySQL backend. This backend
is called 'gmysql', and needs to be configured in ``pdns.conf``. Add the
following lines, adjusted for your local setup (specifically, you may
not want to use the 'root' user):

.. code-block:: ini

    launch=gmysql
    gmysql-host=127.0.0.1
    gmysql-user=root
    gmysql-dbname=pdns
    gmysql-password=mysecretpassword

Remove any earlier :ref:`setting-launch` statements and
other configuration statements for backends.

.. warning::
  Make sure that you can actually resolve the hostname of
  your database without accessing the database! It is advised to supply an
  IP address here to prevent chicken/egg problems!

Now start PowerDNS in the foreground:

::

    # /usr/sbin/pdns_server --daemon=no --guardian=no --loglevel=9
    (...)
    Dec 30 13:40:09 About to create 3 backend threads for UDP
    Dec 30 13:40:09 gmysql Connection failed: Unable to connect to database: Access denied for user 'hubert'@'localhost' to database 'pdns-non-existant'
    Dec 30 13:40:09 Caught an exception instantiating a backend: Unable to launch gmysql connection: Unable to connect to database: Access denied for user 'hubert'@'localhost' to database 'pdns-non-existant'
    Dec 30 13:40:09 Cleaning up
    Dec 30 13:40:10 Done launching threads, ready to distribute questions

This is as to be expected - we did not yet add anything to MySQL for
PowerDNS to read from. At this point you may also see other errors which
indicate that PowerDNS either could not find your MySQL server or was
unable to connect to it. Fix these before proceeding.

General MySQL knowledge is assumed in this chapter, please do not
interpret these commands as DBA advice!

Example: configuring MySQL
--------------------------

Connect to MySQL as a user with sufficient privileges and issue the
following commands below if you are running the 4.2 or master version of PowerDNS:

Please find `the 4.1 schema on GitHub <https://github.com/PowerDNS/pdns/blob/rel/auth-4.1.x/modules/gmysqlbackend/schema.mysql.sql>`_.


.. literalinclude:: ../../modules/gmysqlbackend/schema.mysql.sql
   :language: SQL

We recommend you add the following MySQL statements as well. These will add
foreign key constraints to the tables in order to automate deletion of records, key
material, and other information upon deletion of a domain from the
domains table. These will only work on the InnoDB storage engine, but if you
followed our guide so far, that's exactly the engine we are using.

The following SQL does the job:

.. literalinclude:: ../../modules/gmysqlbackend/enable-foreign-keys.mysql.sql


Now we have a database and an empty table. PowerDNS should now be able
to launch in monitor mode and display no errors:

::

    # /usr/sbin/pdns_server --daemon=no --guardian=no --loglevel=9
    (...)
    15:31:30 PowerDNS 1.99.0 (Mar 12 2002, 15:00:28) starting up
    15:31:30 About to create 3 backend threads
    15:39:55 [gMySQLbackend] MySQL connection succeeded
    15:39:55 [gMySQLbackend] MySQL connection succeeded
    15:39:55 [gMySQLbackend] MySQL connection succeeded

In a different shell, a sample query sent to the server should now
return quickly *without* data:

.. code-block:: shell

    $ dig +short www.example.com @127.0.0.1  # should print nothing

.. warning::
  When debugging DNS problems, don't use ``host``. Please use
  ``dig`` or ``drill``.

And indeed, the output in the first terminal now shows:

::

    Mar 01 16:04:42 Remote 127.0.0.1 wants 'www.example.com|A', do = 0, bufsize = 1680: packetcache MISS

Now we need to add some records to our database (in a separate shell):

::

    # mysql pdnstest
    mysql> INSERT INTO domains (name, type) values ('example.com', 'NATIVE');
    INSERT INTO records (domain_id, name, content, type,ttl,prio)
    VALUES (1,'example.com','localhost admin.example.com 1 10380 3600 604800 3600','SOA',86400,NULL);
    INSERT INTO records (domain_id, name, content, type,ttl,prio)
    VALUES (1,'example.com','dns-us1.powerdns.net','NS',86400,NULL);
    INSERT INTO records (domain_id, name, content, type,ttl,prio)
    VALUES (1,'example.com','dns-eu1.powerdns.net','NS',86400,NULL);
    INSERT INTO records (domain_id, name, content, type,ttl,prio)
    VALUES (1,'www.example.com','192.0.2.10','A',120,NULL);
    INSERT INTO records (domain_id, name, content, type,ttl,prio)
    VALUES (1,'mail.example.com','192.0.2.12','A',120,NULL);
    INSERT INTO records (domain_id, name, content, type,ttl,prio)
    VALUES (1,'localhost.example.com','127.0.0.1','A',120,NULL);
    INSERT INTO records (domain_id, name, content, type,ttl,prio)
    VALUES (1,'example.com','mail.example.com','MX',120,25);

.. warning::
  Host names and the MNAME of a :ref:`types-soa`
  records are NEVER terminated with a '.' in PowerDNS storage! If a
  trailing '.' is present it will inevitably cause problems, problems that
  may be hard to debug.

If we now requery our database, ``www.example.com`` should be present:

.. code-block:: shell

    $ dig +short www.example.com @127.0.0.1
    192.0.2.10

    $ dig +short example.com MX @127.0.0.1
    25 mail.example.com

To confirm what happened, check the statistics:

::

    $ /usr/sbin/pdns_control SHOW \*
    corrupt-packets=0,latency=0,packetcache-hit=2,packetcache-miss=5,packetcache-size=0,
    qsize-a=0,qsize-q=0,servfail-packets=0,tcp-answers=0,tcp-queries=0,
    timedout-packets=0,udp-answers=7,udp-queries=7,
    %

The actual numbers will vary somewhat. Now hit CTRL+C in the shell where
PowerDNS runs, start PowerDNS as a regular daemon, and check launch
status:

On SysV systems:

::

    # /etc/init.d/pdns start
    pdns: started
    # /etc/init.d/pdns status
    pdns: 8239: Child running
    # /etc/init.d/pdns dump
    pdns: corrupt-packets=0,latency=0,packetcache-hit=0,packetcache-miss=0,
    packetcache-size=0,qsize-a=0,qsize-q=0,servfail-packets=0,tcp-answers=0,
    tcp-queries=0,timedout-packets=0,udp-answers=0,udp-queries=0,

On systemd systems:

::

    # systemctl start pdns.service
    # systemctl status pdns.service
    * pdns.service - PowerDNS Authoritative Server
       Loaded: loaded (/lib/systemd/system/pdns.service; enabled)
       Active: active (running) since Tue 2017-01-17 15:59:28 UTC; 1 months 12 days ago
         Docs: man:pdns_server(1)
               man:pdns_control(1)
               https://doc.powerdns.com
     Main PID: 24636 (pdns_server)
       CGroup: /system.slice/pdns.service
               `-24636 /usr/sbin/pdns_server --guardian=no --daemon=no --disable-syslog --write-pid=no

    (...)
    # /usr/sbin/pdns_control SHOW \*
    corrupt-packets=0,latency=0,packetcache-hit=2,packetcache-miss=5,packetcache-size=0,
    qsize-a=0,qsize-q=0,servfail-packets=0,tcp-answers=0,tcp-queries=0,
    timedout-packets=0,udp-answers=7,udp-queries=7,

You now have a working database driven nameserver! To convert other
zones already present, see the :doc:`migration guide <../migration>`.

Common problems
---------------

Most problems involve PowerDNS not being able to connect to the
database.

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

If you are following this guide and using a MySQL database as a backend,
please add the ``launch=gmysql`` instruction to pdns.conf.

Multiple IP addresses on your server, PowerDNS sending out answers on the wrong one, Massive amounts of 'recvfrom gave error, ignoring: Connection refused'
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

If you have multiple IP addresses on the internet on one machine, UNIX
often sends out answers over another interface than which the packet
came in on. In such cases, use :ref:`setting-local-address` to bind to specific IP
addresses, which can be comma separated. The second error comes from
remotes disregarding answers to questions it didn't ask to that IP
address and sending back ICMP errors.

