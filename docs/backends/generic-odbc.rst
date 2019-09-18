Generic ODBC Backend
====================

* Native: Yes
* Master: Yes
* Slave: Yes
* Superslave: Yes
* Autoserial: No
* Case: All lower
* DNSSEC: Yes
* Disabled data: Yes
* Comments: Yes
* Module name: godbc
* Launch name: ``godbc``

The Generic ODBC Backend (godbc) is a child of the Generic SQL (gsql)
backend, similar to the gmysql and gpgsql backends. It uses
`UnixODBC <http://www.unixodbc.org/>`__ and installed drivers to connect
to the databases supported by said drivers.

.. warning::
  When there is a more specific generic sql backend (like
  gmysql or gsqlite3), it is highly recommended to use that backend
  instead!

Enabling the backend
--------------------

When building PowerDNS yourself, append ``godbc`` to ``--with-modules``
or ``--with-dynmodules``. It is expected that most pre-built packages
contain this backend or be separately installable.

Configuration Parameters
------------------------

This section only details the configuration of PowerDNS for use with
ODBC. For ODBC related configuration, please see UnixODBC
website/documentation and the documentation for the driver you intend to
use.

.. _setting-godbc-datasource:

``godbc-datasource``
^^^^^^^^^^^^^^^^^^^^

-  String
-  Default: PowerDNS

The datasource (DSN) to use. This must be configured in the ``odbc.ini``
file, usually found in ``/etc/``, but this depends your local setup.

.. _setting-godbc-username:

``godbc-username``
^^^^^^^^^^^^^^^^^^

-  String
-  Default: powerdns

The user to connect to the datasource.

.. _setting-godbc-password:

``godbc-password``
^^^^^^^^^^^^^^^^^^

-  String
-  Default is empty

The password to connect with the datasource.

Connecting to Microsoft SQL Server
----------------------------------

.. note::
  In order to connect to Microsoft SQL Server, you will need at
  least version 3.2.0 of UnixODBC. FreeDTS has been tested with versions
  0.91 and 0.95.

Install the `FreeTDS <http://www.freetds.org/>`__ driver for UnixODBC,
either by compiling or getting it from our distribution's repository and
configure your ``/etc/odbcinst.ini`` with the driver, e.g.:

.. code-block:: ini

    [FreeTDS]
    Description=v0.95.8 with protocol v7.1
    Driver=/usr/local/lib/libtdsodbc.so
    UsageCount=1

And add the datasource to your ``/etc/odbc.ini``, e.g:

.. code-block:: ini

    [pdns1]
    Driver=FreeTDS
    Trace=No
    Server=server.example.net
    Port=1433
    Database=pdns-1
    TDS_Version=7.1

(For our tests, we add ``ClientCharset=UTF-8`` as well. YMMV.)

You can now test the connection with ``isql pdns1 USERNAME PASSWORD``.

Loading the schema into the database
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

For convenience, a schema for MS SQL Server has been created: (Note:
This schema can also be found in the PowerDNS source as
``modules/godbcbackend/schema.mssql.sql``).

This is the schema for 4.2. For 4.1, please find `the 4.1 schema on GitHub <https://github.com/PowerDNS/pdns/blob/rel/auth-4.1.x/modules/godbcbackend/schema.mssql.sql>`_.

.. literalinclude:: ../../modules/godbcbackend/schema.mssql.sql
   :language: SQL

Load this into the database as follows:

.. code-block:: bash

  cat schema.mssql.sql | tr '\n' ' ' | isql pdns1 USERNAME PASSWORD -b.

Loading records into the database
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Loading records is the same as with any SQL backend, just add them using
SQL-queries. Should you want to use :ref:`zone2sql <migration-zone2sql>`,
use the ``--sqlite`` option for correctly formatted SQL.

Configuring PowerDNS
^^^^^^^^^^^^^^^^^^^^

Add the options required to your ``pdns.conf``:

.. code-block:: ini

    launch=godbc
    godbc-datasource=pdns1
    godbc-username=USERNAME
    godbc-password=PASSWORD

Now restart PowerDNS and you're done. Just don't forget to add zones and
records to the database.

Possible issues
^^^^^^^^^^^^^^^

It might be that you need to compile FreeTDS with the
``--tds-version=7.1`` to connect to SQL Server.

When connecting to a database hosted with Microsoft Azure, FreeTDS must
be compiled with OpenSSL, use the ``--with-openssl`` configure flag.
