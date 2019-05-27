OpenDBX Backend
===============

* Native: Yes
* Master: Yes
* Slave: Yes
* Superslave: Yes
* Autoserial: Yes
* DNSSEC: No
* Disabled data: No
* Comments: No
* Module name: opendbx
* Launch name: ``opendbx``

The OpenDBX backend allows the authoritative server to connect to any
backend supported by
`OpenDBX <http://www.linuxnetworks.de/doc/index.php/OpenDBX>`__.

This document contains a subset of the `full
documentation <http://www.linuxnetworks.de/doc/index.php/PowerDNS_OpenDBX_Backend>`__
supplied by the author Norbert Sendetzky . This module is fully
supported (and tested) by PowerDNS.

The OpenDBX backend has a mechanism to connect different database
servers for read and write actions.

The domains table for the opendbx backend has a "status" column, when
set to "A", the domain is considered active and is actually served.

Settings
--------

.. _setting-opendbx-backend:

``opendbx-backend``
^^^^^^^^^^^^^^^^^^^

Name of the backend used to connect to the database server. Currently
mysql, pgsql, sqlite, sqlite3 and sybase are available. Default=mysql.

.. _setting-opendbx-host-read:

``opendbx-host-read``
^^^^^^^^^^^^^^^^^^^^^

One or more host names or IP addresses of the database servers. These
hosts will be used for retrieving the records via SELECT queries.
Default=127.0.0.1

.. _setting-opendbx-host-write:

``opendbx-host-write``
^^^^^^^^^^^^^^^^^^^^^^

One or more host names or IP addresses of the database servers. These
hosts will be used for INSERT/UPDATE statements (mostly used by
zonetransfers). Default=127.0.0.1

.. _setting-opendbx-port:

``opendbx-port``
^^^^^^^^^^^^^^^^

TCP/IP port number where the database server is listening to. Most
databases will use their default port if you leave this empty.

.. _setting-opendbx-database:

``opendbx-database``
^^^^^^^^^^^^^^^^^^^^

The database name where all domain and record entries are stored.
Default=powerdns

.. _setting-opendbx-username:

``opendbx-username``
^^^^^^^^^^^^^^^^^^^^

Name of the user send to the DBMS for authentication. Default=powerdns.

.. _setting-opendbx-password:

``opendbx-password``
^^^^^^^^^^^^^^^^^^^^

Clear text password for authentication in combination with the username.

Queries
-------

As with the :doc:`generic-sql`, queries
are configurable. Note: If you change one of the SELECT statements must
not change the order of the retrieved columns! To get the default
queries, run ``pdns_server --no-config --launch=opendbx --config``. The
following queries are configurable:

-  ``opendbx-sql-list``: Select records which will be returned to
   clients asking for zone transfers (AXFR).
-  ``opendbx-sql-lookup``: Retrieve DNS records by name.
-  ``opendbx-sql-lookupid``: Retrieve DNS records by id and name.
-  ``opendbx-sql-lookuptype``: Retrieve DNS records by name and type.
-  ``opendbx-sql-lookuptypeid``: Retrieve DNS records by id, name and
   type.
-  ``opendbx-sql-lookupsoa``: Retrieve SOA record for domain.
-  ``opendbx-sql-zonedelete``: Delete all records from zone before
   inserting new ones via AXFR.
-  ``opendbx-sql-zoneinfo``: Get stored information about a domain.
-  ``opendbx-sql-transactbegin``: Start transaction before updating a
   zone via AXFR.
-  ``opendbx-sql-transactend``: Commit transaction after updating a zone
   via AXFR.
-  ``opendbx-sql-transactabort``: Undo changes if an error occurred
   while updating a zone via AXFR.
-  ``opendbx-sql-insert-slave``: Adds a new zone from the authoritative
   DNS server which is currently retrieved via AXFR.
-  ``opendbx-sql-insert-record``: Adds new records of a zone form the
   authoritative DNS server which are currently retrieved via AXFR.
-  ``opendbx-sql-update-serial``: Set zone serial to value of last
   update.
-  ``opendbx-sql-update-lastcheck``: Set time of last zone check.
-  ``opendbx-sql-master``: Get master record for zone.
-  ``opendbx-sql-supermaster``: Get supermaster info.
-  ``opendbx-sql-infoslaves``: Get all unfresh slaves.
-  ``opendbx-sql-infomasters``: Get all updates masters.

Database schemas and information
--------------------------------

Mysql
^^^^^

The file below also contains trigger definitions which are necessary for
``autoserial`` support, but they
are only available in MySQL 5 and later. If you are still using MySQL
4.x and don't want to utilize the automatically generated zone serials,
you can safely remove the "CREATE TRIGGER" statements from the file
before creating the database tables.

.. code-block:: SQL

    SET SESSION sql_mode='ANSI';

    CREATE TABLE "domains" (
        "id" INTEGER NOT NULL AUTO_INCREMENT,
        "name" VARCHAR(255) NOT NULL,
        "type" VARCHAR(6) NOT NULL,
        "master" VARCHAR(40) NOT NULL DEFAULT '',
        "account" VARCHAR(40) NOT NULL DEFAULT '',
        "last_check" INTEGER DEFAULT NULL,
        "notified_serial" INTEGER DEFAULT NULL,
        "auto_serial" INTEGER NOT NULL DEFAULT 0,
        "status" CHAR(1) NOT NULL DEFAULT 'A',
    CONSTRAINT "pdns_pk_domains_id"
        PRIMARY KEY ("id"),
    CONSTRAINT "pdns_unq_domains_name"
        UNIQUE ("name")
    ) type=InnoDB;

    CREATE INDEX "pdns_idx_domains_status_type" ON "domains" ("status","type");

    CREATE TABLE "records" (
        "id" INTEGER NOT NULL AUTO_INCREMENT,
        "domain_id" INTEGER NOT NULL,
        "name" VARCHAR(255) NOT NULL,
        "type" VARCHAR(6) NOT NULL,
        "ttl" INTEGER DEFAULT NULL,
        "prio" INTEGER DEFAULT NULL,
        "content" VARCHAR(255) NOT NULL,
    CONSTRAINT "pdns_pk_records_id"
        PRIMARY KEY ("id"),
    CONSTRAINT "pdns_fk_records_domainid"
        FOREIGN KEY ("domain_id")
        REFERENCES "domains" ("id")
        ON UPDATE CASCADE
        ON DELETE CASCADE
    ) type=InnoDB;

    CREATE INDEX "pdns_idx_records_name_type" ON "records" ("name","type");
    CREATE INDEX "pdns_idx_records_type" ON "records" ("type");

    CREATE TABLE "supermasters" (
        "ip" VARCHAR(40) NOT NULL,
        "nameserver" VARCHAR(255) NOT NULL,
        "account" VARCHAR(40) NOT NULL DEFAULT ''
    );

    CREATE INDEX "pdns_idx_smaster_ip_ns" ON "supermasters" ("ip","nameserver");

    GRANT SELECT ON "supermasters" TO "powerdns";
    GRANT ALL ON "domains" TO "powerdns";
    GRANT ALL ON "records" TO "powerdns";

    DELIMITER :

    CREATE TRIGGER "pdns_trig_records_insert"
    AFTER INSERT ON "records"
    FOR EACH ROW BEGIN
        UPDATE "domains" d SET d."auto_serial" = d."auto_serial" + 1
        WHERE d."id" = NEW."domain_id";
    END;:

    CREATE TRIGGER "pdns_trig_records_update"
    AFTER UPDATE ON "records"
    FOR EACH ROW BEGIN
        UPDATE "domains" d SET d."auto_serial" = d."auto_serial" + 1
        WHERE d."id" = NEW."domain_id";
    END;:

    CREATE TRIGGER "pdns_trig_records_delete"
    AFTER DELETE ON "records"
    FOR EACH ROW BEGIN
        UPDATE "domains" d SET d."auto_serial" = d."auto_serial" + 1
        WHERE d."id" = OLD."domain_id";
    END;:

    DELIMITER ;

PostgreSQL
^^^^^^^^^^

.. code-block:: SQL

    CREATE TABLE "domains" (
        "id" SERIAL NOT NULL,
        "name" VARCHAR(255) NOT NULL,
        "type" VARCHAR(6) NOT NULL,
        "master" VARCHAR(40) NOT NULL DEFAULT '',
        "account" VARCHAR(40) NOT NULL DEFAULT '',
        "last_check" INTEGER DEFAULT NULL,
        "notified_serial" INTEGER DEFAULT NULL,
        "auto_serial" INTEGER NOT NULL DEFAULT 0,
        "status" CHAR(1) NOT NULL DEFAULT 'A',
    CONSTRAINT "pdns_pk_domains_id"
        PRIMARY KEY ("id"),
    CONSTRAINT "pdns_unq_domains_name"
        UNIQUE ("name")
    );

    CREATE INDEX "pdns_idx_domains_status_type" ON "domains" ("status","type");

    CREATE TABLE "records" (
        "id" SERIAL NOT NULL,
        "domain_id" INTEGER NOT NULL,
        "name" VARCHAR(255) NOT NULL,
        "type" VARCHAR(6) NOT NULL,
        "ttl" INTEGER DEFAULT NULL,
        "prio" INTEGER DEFAULT NULL,
        "content" VARCHAR(255) NOT NULL,
    CONSTRAINT "pdns_pk_records_id"
        PRIMARY KEY ("id"),
    CONSTRAINT "pdns_fk_records_domainid"
        FOREIGN KEY ("domain_id")
        REFERENCES "domains" ("id")
        ON UPDATE CASCADE
        ON DELETE CASCADE
    );

    CREATE INDEX "pdns_idx_records_name_type" ON "records" ("name","type");
    CREATE INDEX "pdns_idx_records_type" ON "records" ("type");

    CREATE TABLE "supermasters" (
        "ip" VARCHAR(40) NOT NULL,
        "nameserver" VARCHAR(255) NOT NULL,
        "account" VARCHAR(40) NOT NULL DEFAULT ''
    );

    CREATE INDEX "pdns_idx_smaster_ip_ns" ON "supermasters" ("ip","nameserver");

    GRANT SELECT ON "supermasters" TO "powerdns";
    GRANT ALL ON "domains" TO "powerdns";
    GRANT ALL ON "domains_id_seq" TO "powerdns";
    GRANT ALL ON "records" TO "powerdns";
    GRANT ALL ON "records_id_seq" TO "powerdns";

    CREATE RULE "pdns_rule_records_insert"
    AS ON INSERT TO "records" DO
        UPDATE "domains" SET "auto_serial" = "auto_serial" + 1 WHERE "id" = NEW."domain_id";

    CREATE RULE "pdns_rule_records_update"
    AS ON UPDATE TO "records" DO
        UPDATE "domains" SET "auto_serial" = "auto_serial" + 1 WHERE "id" = NEW."domain_id";

    CREATE RULE "pdns_rule_records_delete"
    AS ON DELETE TO "records" DO
        UPDATE "domains" SET "auto_serial" = "auto_serial" + 1 WHERE "id" = OLD."domain_id";

SQLite and SQLite3
^^^^^^^^^^^^^^^^^^

Supported without changes since OpenDBX 1.0.0 but requires to set
:ref:`setting-opendbx-host-read` to the path of the SQLite file
(including the trailing slash or backslash, depending on your operating
system) and opendbx-database to the name of the file.

.. code-block:: ini

    opendbx-host-read = /path/to/file/
    opendbx-host-write = /path/to/file/
    opendbx-database = powerdns.sqlite

SQLite Schema
~~~~~~~~~~~~~

.. code-block:: SQL

    CREATE TABLE "domains" (
        "id" INTEGER NOT NULL PRIMARY KEY,
        "name" VARCHAR(255) NOT NULL,
        "type" VARCHAR(6) NOT NULL,
        "master" VARCHAR(40) NOT NULL DEFAULT '',
        "account" VARCHAR(40) NOT NULL DEFAULT '',
        "last_check" INTEGER DEFAULT NULL,
        "notified_serial" INTEGER DEFAULT NULL,
        "auto_serial" INTEGER NOT NULL DEFAULT 0,
        "status" CHAR(1) NOT NULL DEFAULT 'A',
    CONSTRAINT "pdns_unq_domains_name"
        UNIQUE ("name")
    );

    CREATE INDEX "pdns_idx_domains_status_type" ON "domains" ("status","type");

    CREATE TABLE "records" (
        "id" INTEGER NOT NULL PRIMARY KEY,
        "domain_id" INTEGER NOT NULL,
        "name" VARCHAR(255) NOT NULL,
        "type" VARCHAR(6) NOT NULL,
        "ttl" INTEGER DEFAULT NULL,
        "prio" INTEGER DEFAULT NULL,
        "content" VARCHAR(255) NOT NULL,
    CONSTRAINT "pdns_fk_records_domainid"
        FOREIGN KEY ("domain_id")
        REFERENCES "domains" ("id")
        ON UPDATE CASCADE
        ON DELETE CASCADE
    );

    CREATE INDEX "pdns_idx_records_name_type" ON "records" ("name","type");
    CREATE INDEX "pdns_idx_records_type" ON "records" ("type");

    CREATE TABLE "supermasters" (
        "ip" VARCHAR(40) NOT NULL,
        "nameserver" VARCHAR(255) NOT NULL,
        "account" VARCHAR(40) NOT NULL DEFAULT ''
    );

    CREATE INDEX "pdns_idx_smaster_ip_ns" ON "supermasters" ("ip","nameserver");

    CREATE TRIGGER "pdns_trig_records_insert"
    AFTER INSERT ON "records"
    FOR EACH ROW BEGIN
        UPDATE "domains" SET "auto_serial" = "auto_serial" + 1
        WHERE "id" = NEW."domain_id";
    END;

    CREATE TRIGGER "pdns_trig_records_update"
    AFTER UPDATE ON "records"
    FOR EACH ROW BEGIN
        UPDATE "domains" SET "auto_serial" = "auto_serial" + 1
        WHERE "id" = NEW."domain_id";
    END;

    CREATE TRIGGER "pdns_trig_records_delete"
    AFTER DELETE ON "records"
    FOR EACH ROW BEGIN
        UPDATE "domains" SET "auto_serial" = "auto_serial" + 1
        WHERE "id" = OLD."domain_id";
    END;

SQLite3 Schema
~~~~~~~~~~~~~~

.. code-block:: SQL

    CREATE TABLE "domains" (
        "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
        "name" VARCHAR(255) NOT NULL,
        "type" VARCHAR(6) NOT NULL,
        "master" VARCHAR(40) NOT NULL DEFAULT '',
        "account" VARCHAR(40) NOT NULL DEFAULT '',
        "last_check" INTEGER DEFAULT NULL,
        "notified_serial" INTEGER DEFAULT NULL,
        "auto_serial" INTEGER NOT NULL DEFAULT 0,
        "status" CHAR(1) NOT NULL DEFAULT 'A',
    CONSTRAINT "pdns_unq_domains_name"
        UNIQUE ("name")
    );

    CREATE INDEX "pdns_idx_domains_status_type" ON "domains" ("status","type");

    CREATE TABLE "records" (
        "id" INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
        "domain_id" INTEGER NOT NULL,
        "name" VARCHAR(255) NOT NULL,
        "type" VARCHAR(6) NOT NULL,
        "ttl" INTEGER DEFAULT NULL,
        "prio" INTEGER DEFAULT NULL,
        "content" VARCHAR(255) NOT NULL,
    CONSTRAINT "pdns_fk_records_domainid"
        FOREIGN KEY ("domain_id")
        REFERENCES "domains" ("id")
        ON UPDATE CASCADE
        ON DELETE CASCADE
    );

    CREATE INDEX "pdns_idx_records_name_type" ON "records" ("name","type");
    CREATE INDEX "pdns_idx_records_type" ON "records" ("type");

    CREATE TABLE "supermasters" (
        "ip" VARCHAR(40) NOT NULL,
        "nameserver" VARCHAR(255) NOT NULL,
        "account" VARCHAR(40) NOT NULL DEFAULT ''
    );

    CREATE INDEX "pdns_idx_smaster_ip_ns" ON "supermasters" ("ip","nameserver");

    CREATE TRIGGER "pdns_trig_records_insert"
    AFTER INSERT ON "records"
    FOR EACH ROW BEGIN
        UPDATE "domains" SET "auto_serial" = "auto_serial" + 1
        WHERE "id" = NEW."domain_id";
    END;

    CREATE TRIGGER "pdns_trig_records_update"
    AFTER UPDATE ON "records"
    FOR EACH ROW BEGIN
        UPDATE "domains" SET "auto_serial" = "auto_serial" + 1
        WHERE "id" = NEW."domain_id";
    END;

    CREATE TRIGGER "pdns_trig_records_delete"
    AFTER DELETE ON "records"
    FOR EACH ROW BEGIN
        UPDATE "domains" SET "auto_serial" = "auto_serial" + 1
        WHERE "id" = OLD."domain_id";
    END;

Firebird/Interbase
^^^^^^^^^^^^^^^^^^

Requires :ref:`setting-opendbx-database` set to the path of
the database file and doesn't support the default statement for starting
transactions. Please add the following lines to your pdns.conf:

.. code-block:: ini

    opendbx-database = /var/lib/firebird2/data/powerdns.gdb
    opendbx-sql-transactbegin = SET TRANSACTION

When creating the database please make sure that you call the ``isql``
tool with the parameter ``-page 4096``. Otherwise, you will get an error
(key size exceeds implementation restriction for index
"pdns\_unq\_domains\_name") when creating the tables.

.. code-block:: SQL

    CREATE TABLE "domains" (
        "id" INTEGER NOT NULL,
        "name" VARCHAR(255) NOT NULL,
        "type" VARCHAR(6) NOT NULL,
        "master" VARCHAR(40) DEFAULT '' NOT NULL,
        "account" VARCHAR(40) DEFAULT '' NOT NULL,
        "last_check" INTEGER,
        "notified_serial" INTEGER,
        "auto_serial" INTEGER DEFAULT 0 NOT NULL,
        "status" CHAR(1) DEFAULT 'A' NOT NULL,
    CONSTRAINT "pdns_pk_domains_id"
        PRIMARY KEY ("id"),
    CONSTRAINT "pdns_unq_domains_name"
        UNIQUE ("name")
    );

    CREATE GENERATOR "pdns_gen_domains_id";

    SET TERM !!;
    CREATE TRIGGER "pdns_trig_domains_id" FOR "domains"
    ACTIVE BEFORE INSERT AS
    BEGIN
        IF (NEW."id" IS NULL) THEN
        NEW."id" = GEN_ID("pdns_gen_domains_id",1);
    END !!
    SET TERM ;!!

    CREATE INDEX "pdns_idx_domains_status_type" ON "domains" ("status","type");

    CREATE TABLE "records" (
        "id" INTEGER NOT NULL,
        "domain_id" INTEGER NOT NULL,
        "name" VARCHAR(255) NOT NULL,
        "type" VARCHAR(6) NOT NULL,
        "ttl" INTEGER DEFAULT NULL,
        "prio" INTEGER DEFAULT NULL,
        "content" VARCHAR(255) NOT NULL,
    CONSTRAINT "pdns_pk_records_id"
        PRIMARY KEY ("id"),
    CONSTRAINT "pdns_fk_records_domainid"
        FOREIGN KEY ("domain_id")
        REFERENCES "domains" ("id")
        ON UPDATE CASCADE
        ON DELETE CASCADE
    );

    CREATE GENERATOR "pdns_gen_records_id";

    SET TERM !!;
    CREATE TRIGGER "pdns_trig_records_id" FOR "records"
    ACTIVE BEFORE INSERT AS
    BEGIN
        IF (NEW."id" IS NULL) THEN
        NEW."id" = GEN_ID("pdns_gen_records_id",1);
    END !!
    SET TERM ;!!

    CREATE INDEX "idx_records_name_type" ON "records" ("name","type");
    CREATE INDEX "idx_records_type" ON "records" ("type");

    CREATE TABLE "supermasters" (
        "ip" VARCHAR(40) NOT NULL,
        "nameserver" VARCHAR(255) NOT NULL,
        "account" VARCHAR(40) DEFAULT '' NOT NULL
    );

    CREATE INDEX "pdns_idx_smaster_ip_ns" ON "supermasters" ("ip","nameserver");

    GRANT SELECT ON "supermasters" TO "powerdns";
    GRANT ALL ON "domains" TO "powerdns";
    GRANT ALL ON "records" TO "powerdns";

    SET TERM !!;

    CREATE TRIGGER "pdns_trig_records_insert" FOR "records"
    ACTIVE AFTER INSERT AS
    BEGIN
        UPDATE "domains" d SET d."auto_serial" = d."auto_serial" + 1
        WHERE d."id" = NEW."domain_id";
    END !!

    CREATE TRIGGER "pdns_trig_records_update" FOR "records"
    ACTIVE AFTER UPDATE AS
    BEGIN
        UPDATE "domains" d SET d."auto_serial" = d."auto_serial" + 1
        WHERE d."id" = NEW."domain_id";
    END !!

    CREATE TRIGGER "pdns_trig_records_delete" FOR "records"
    ACTIVE AFTER DELETE AS
    BEGIN
        UPDATE "domains" d SET d."auto_serial" = d."auto_serial" + 1
        WHERE d."id" = OLD."domain_id";
    END !!

    SET TERM ;!!

Microsoft SQL Server
^^^^^^^^^^^^^^^^^^^^

Supported using the FreeTDS library. It uses a different scheme for host
configuration (requires the name of the host section in the
configuration file of the dblib client library) and doesn't support the
default statement for starting transactions. Please add the following
lines to your pdns.conf:

.. code-block:: ini

    opendbx-host-read = MSSQL2k
    opendbx-host-write = MSSQL2k
    opendbx-sql-transactbegin = BEGIN TRANSACTION

.. code-block:: SQL

    SET quoted_identifier ON;


    CREATE TABLE "domains" (
        "id" INTEGER NOT NULL IDENTITY,
        "name" VARCHAR(255) NOT NULL,
        "type" VARCHAR(6) NOT NULL,
        "master" VARCHAR(40) DEFAULT '' NOT NULL,
        "account" VARCHAR(40) DEFAULT '' NOT NULL,
        "last_check" INTEGER NULL,
        "notified_serial" INTEGER NULL,
        "auto_serial" INTEGER NOT NULL DEFAULT 0,
        "status" CHAR(1) DEFAULT 'A' NOT NULL,
    CONSTRAINT "pdns_pk_domains_id"
        PRIMARY KEY ("id"),
    CONSTRAINT "pdns_unq_domains_name"
        UNIQUE ("name")
    );

    CREATE INDEX "pdns_idx_domains_status_type" ON "domains" ("status","type");

    CREATE TABLE "records" (
        "id" INTEGER NOT NULL IDENTITY,
        "domain_id" INTEGER NOT NULL,
        "name" VARCHAR(255) NOT NULL,
        "type" VARCHAR(6) NOT NULL,
        "ttl" INTEGER NULL,
        "prio" INTEGER NULL,
        "content" VARCHAR(255) NOT NULL,
        "change_date" INTEGER NULL,
    CONSTRAINT "pdns_pk_records_id"
        PRIMARY KEY ("id"),
    CONSTRAINT "pdns_fk_records_domainid"
        FOREIGN KEY ("domain_id")
        REFERENCES "domains" ("id")
    );

    CREATE INDEX "pdns_idx_records_name_type" ON "records" ("name","type");
    CREATE INDEX "pdns_idx_records_type" ON "records" ("type");

    CREATE TABLE "supermasters" (
        "ip" VARCHAR(40) NOT NULL,
        "nameserver" VARCHAR(255) NOT NULL,
        "account" VARCHAR(40) DEFAULT '' NOT NULL
    );

    CREATE INDEX "pdns_idx_smip_smns" ON "supermasters" ("ip","nameserver");

    GRANT SELECT ON "supermasters" TO "powerdns";
    GRANT ALL ON "domains" TO "powerdns";
    GRANT ALL ON "records" TO "powerdns";

    CREATE TRIGGER "pdns_trig_records_insert"
    ON "records" FOR INSERT AS
        UPDATE "domains" SET "auto_serial" = "auto_serial" + 1
        WHERE "id" = ANY (
            SELECT i."domain_id" FROM "inserted" i GROUP BY i."domain_id"
        );

    CREATE TRIGGER "pdns_trig_records_update"
    ON "records" FOR UPDATE AS
        UPDATE "domains" SET "auto_serial" = "auto_serial" + 1
        WHERE "id" = ANY (
            SELECT i."domain_id" FROM "inserted" i GROUP BY i."domain_id"
        );

    CREATE TRIGGER "pdns_trig_records_delete"
    ON "records" FOR DELETE AS
        UPDATE "domains" SET "auto_serial" = "auto_serial" + 1
        WHERE "id" = ANY (
            SELECT d."domain_id" FROM "deleted" d GROUP BY d."domain_id"
        );

Sybase ASE
^^^^^^^^^^

Supported using the native Sybase ctlib or the FreeTDS library. It uses
a different scheme for host configuration (requires the name of the host
section in the configuration file of the ctlib client library) and
doesn't support the default statement for starting transactions. Please
add the following lines to your pdns.conf:

.. code-block:: ini

    opendbx-host-read = SYBASE
    opendbx-host-write = SYBASE
    opendbx-sql-transactbegin = BEGIN TRANSACTION

.. code-block:: SQL

    SET quoted_identifier ON;

    CREATE TABLE "domains" (
        "id" INTEGER NOT NULL IDENTITY,
        "name" VARCHAR(255) NOT NULL,
        "type" VARCHAR(6) NOT NULL,
        "master" VARCHAR(40) DEFAULT '' NOT NULL,
        "account" VARCHAR(40) DEFAULT '' NOT NULL,
        "last_check" INTEGER NULL,
        "notified_serial" INTEGER NULL,
        "auto_serial" INTEGER NOT NULL DEFAULT 0,
        "status" CHAR(1) DEFAULT 'A' NOT NULL,
    CONSTRAINT "pdns_pk_domains_id"
        PRIMARY KEY ("id"),
    CONSTRAINT "pdns_unq_domains_name"
        UNIQUE ("name")
    );

    CREATE INDEX "pdns_idx_domains_status_type" ON "domains" ("status","type");

    CREATE TABLE "records" (
        "id" INTEGER NOT NULL IDENTITY,
        "domain_id" INTEGER NOT NULL,
        "name" VARCHAR(255) NOT NULL,
        "type" VARCHAR(6) NOT NULL,
        "ttl" INTEGER NULL,
        "prio" INTEGER NULL,
        "content" VARCHAR(255) NOT NULL,
        "change_date" INTEGER NULL,
    CONSTRAINT "pdns_pk_records_id"
        PRIMARY KEY ("id"),
    CONSTRAINT "pdns_fk_records_domainid"
        FOREIGN KEY ("domain_id")
        REFERENCES "domains" ("id")
    );

    CREATE INDEX "pdns_idx_records_name_type" ON "records" ("name","type");
    CREATE INDEX "pdns_idx_records_type" ON "records" ("type");

    CREATE TABLE "supermasters" (
        "ip" VARCHAR(40) NOT NULL,
        "nameserver" VARCHAR(255) NOT NULL,
        "account" VARCHAR(40) DEFAULT '' NOT NULL
    );

    CREATE INDEX "pdns_idx_smip_smns" ON "supermasters" ("ip","nameserver");

    GRANT SELECT ON "supermasters" TO "powerdns";
    GRANT ALL ON "domains" TO "powerdns";
    GRANT ALL ON "records" TO "powerdns";

    CREATE TRIGGER "pdns_trig_records_insert"
    ON "records" FOR INSERT AS
        UPDATE "domains" SET "auto_serial" = "auto_serial" + 1
        WHERE "id" = ANY (
            SELECT i."domain_id" FROM "inserted" i GROUP BY i."domain_id"
        );

    CREATE TRIGGER "pdns_trig_records_update"
    ON "records" FOR UPDATE AS
        UPDATE "domains" SET "auto_serial" = "auto_serial" + 1
        WHERE "id" = ANY (
            SELECT i."domain_id" FROM "inserted" i GROUP BY i."domain_id"
        );

    CREATE TRIGGER "pdns_trig_records_delete"
    ON "records" FOR DELETE AS
        UPDATE "domains" SET "auto_serial" = "auto_serial" + 1
        WHERE "id" = ANY (
            SELECT d."domain_id" FROM "deleted" d GROUP BY d."domain_id"
        );

Oracle
^^^^^^

Uses a different syntax for transactions and requires the following
additional line in your pdns.conf:

.. code-block:: ini

    opendbx-sql-transactbegin = SET TRANSACTION NAME 'AXFR'

.. code-block:: SQL

    CREATE TABLE "domains" (
        "id" INTEGER NOT NULL,
        "name" VARCHAR(255) NOT NULL,
        "type" VARCHAR(6) NOT NULL,
        "master" VARCHAR(40) DEFAULT '',
        "account" VARCHAR(40) DEFAULT '',
        "last_check" INTEGER,
        "notified_serial" INTEGER,
        "auto_serial" INTEGER DEFAULT 0,
        "status" CHAR(1) DEFAULT 'A',
    CONSTRAINT "pdns_pk_domains_id"
        PRIMARY KEY ("id"),
    CONSTRAINT "pdns_unq_domains_name"
        UNIQUE ("name")
    );

    CREATE SEQUENCE "pdns_seq_domains_id" START WITH 1 INCREMENT BY 1;

    CREATE TRIGGER "pdns_trig_domains_id"
    BEFORE INSERT ON "domains"
    FOR EACH ROW
    BEGIN
        SELECT "pdns_seq_domains_id".nextval INTO :NEW."id" FROM dual;
    END;

    CREATE INDEX "pdns_idx_domains_status_type" ON "domains" ("status","type");

    CREATE TABLE "records" (
        "id" INTEGER NOT NULL,
        "domain_id" INTEGER NOT NULL,
        "name" VARCHAR(255) NOT NULL,
        "type" VARCHAR(6) NOT NULL,
        "ttl" INTEGER NULL,
        "prio" INTEGER NULL,
        "content" VARCHAR(255) NOT NULL,
        "change_date" INTEGER NULL,
    CONSTRAINT "pdns_pk_records_id"
        PRIMARY KEY ("id"),
    CONSTRAINT "pdns_fk_records_domainid"
        FOREIGN KEY ("domain_id")
        REFERENCES "domains" ("id")
        ON DELETE CASCADE
    );

    CREATE SEQUENCE "pdns_seq_records_id" START WITH 1 INCREMENT BY 1;

    CREATE TRIGGER "pdns_trig_records_id"
    BEFORE INSERT ON "records"
    FOR EACH ROW
    BEGIN
        SELECT "pdns_seq_records_id".nextval INTO :NEW."id" FROM dual;
    END;

    CREATE INDEX "pdns_idx_records_name_type" ON "records" ("name","type");
    CREATE INDEX "pdns_idx_records_type" ON "records" ("type");

    CREATE TABLE "supermasters" (
        "ip" VARCHAR(40) NOT NULL,
        "nameserver" VARCHAR(255) NOT NULL,
        "account" VARCHAR(40) NOT NULL
    );

    CREATE INDEX "pdns_idx_smaster_ip_ns" ON "supermasters" ("ip","nameserver");

    GRANT SELECT ON "supermasters" TO "powerdns";
    GRANT ALL ON "domains" TO "powerdns";
    GRANT ALL ON "records" TO "powerdns";

    CREATE TRIGGER "pdns_trig_records_insert"
    AFTER INSERT ON "records"
    FOR EACH ROW BEGIN
        UPDATE "domains" SET "auto_serial" = "auto_serial" + 1
        WHERE "id" = :NEW."domain_id";
    END;

    CREATE TRIGGER "pdns_trig_records_update"
    AFTER UPDATE ON "records"
    FOR EACH ROW BEGIN
        UPDATE "domains" SET "auto_serial" = "auto_serial" + 1
        WHERE "id" = :NEW."domain_id";
    END;

    CREATE TRIGGER "pdns_trig_records_delete"
    AFTER DELETE ON "records"
    FOR EACH ROW BEGIN
        UPDATE "domains" SET "auto_serial" = "auto_serial" + 1
        WHERE "id" = :OLD."domain_id";
    END;
