# Generic MySQL backend
|&nbsp;|&nbsp;|
|:--|:--|
|Native|Yes|
|Master|Yes|
|Slave|Yes|
|Superslave|Yes|
|Autoserial|Yes (v3.1 and up)|
|Case|All lower|
|DNSSEC|Yes (set `gmysql-dnssec`)|
|Disabled data|Yes (v3.4.0 and up)|
|Comments|Yes (v3.4.0 and up)|
|Module name | gmysql|
|Launch name| gmysql|

**warning**: If using MySQL with 'slave' support enabled in PowerDNS you **must**
run MySQL with a table engine that supports transactions.
In practice, great results are achieved with the 'InnoDB' tables. PowerDNS will
silently function with non-transaction aware MySQLs but at one point this is
going to harm your database, for example when an incoming zone transfer fails.

The default schema is included at the bottom of this page. [`zone2sql`](migration.md#zone2sql)
with the `--gmysql` flag also assumes this layout is in place. For full migration
notes, please see [Migration](migration.md). This schema contains all elements
needed for master, slave and superslave operation.

When using the InnoDB storage engine, we suggest adding the following lines to
the 'create table records' command above:

```
CONSTRAINT `records_ibfk_1` FOREIGN KEY (`domain_id`) REFERENCES `domains`
(`id`) ON DELETE CASCADE
```

Or, if you have already created the tables, execute:

```
ALTER TABLE `records` ADD CONSTRAINT `records_ibfk_1` FOREIGN KEY (`domain_id`)
REFERENCES `domains` (`id`) ON DELETE CASCADE;
```

This automates deletion of records on deletion of a domain from the domains table.

# Using MySQL replication
To support `NATIVE` domains, the `binlog_format` for the MySQL replication **must**
be set to `MIXED` or `ROW` to prevent differences in data between replicated
servers. See ["5.2.4.2, Setting The Binary Log Format"](http://dev.mysql.com/doc/refman/5.7/en/binary-log-setting.html)
for more information.

# Settings
## `gmysql-host`
Host (ip address) to connect to. Mutually exclusive with [`gmysql-socket`](#gmysql-socket).

**WARNING:** When specified as a hostname a chicken/egg situation might arise
where the database is needed to resolve the IP address of the database. It is
best to supply an IP address of the database here.

## `gmysql-port`
The port to connect to on [`gmysql-host`](#gmysql-host). Default: 3306

## `gmysql-socket`
Connect to the UNIX socket at this path. Mutually exclusive with [`gmysql-host`](#gmysql-host).

## `gmysql-dbname`
Name of the database to connect to. Default: "pdns".

## `gmysql-user`
User to connect as. Default: "powerdns".

## `gmysql-group`
Group to connect as. Default: "client".

## `gmysql-password`
The password to for [`gmysql-user`](#gmysql-user).

## `gmysql-dnssec`
Enable DNSSEC processing for this backend. Default=no.

## `gmysql-innodb-read-committed`
Use the InnoDB READ-COMMITTED transaction isolation level. Default=yes.

## `gmysql-timeout`
The timeout in seconds for each attempt to read from, or write to the server. A value of 0 will disable the timeout. Default: 10

# Default Schema
```
!!include=../modules/gmysqlbackend/schema.mysql.sql
```
