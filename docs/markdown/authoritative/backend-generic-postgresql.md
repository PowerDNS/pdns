# Generic PostgreSQL backend
|&nbsp;|&nbsp;|
|:--|:--|
|Native|Yes|
|Master|Yes|
|Slave|Yes|
|Superslave|Yes|
|Autoserial|Yes (v3.1 and up)|
|Case|All lower|
|DNSSEC|Yes (set `gpgsql-dnssec`)|
|Disabled data|Yes (v3.4.0 and up)|
|Comments|Yes (v3.4.0 and up)|
|Module name | pgsql|
|Launch name| pgsql|

This PostgreSQL backend is based on the [generic SQL backend](backend-generic-sql.md).
The default setup conforms to the schema at the bottom of this page, note that
[`zone2sql`](migration.md#zone2sql) with the `--gpgsql` flag also assumes this layout is in place.

This schema contains all elements needed for master, slave and superslave operation.
For full migration notes, please see [Migration](migration.md).

With PostgreSQL, you may have to run `createdb pdns` first and then connect
to that database with `psql pdns`, and feed it the schema above.

# Settings
## `gpgsql-host`
Host (ip address) to connect to. If `pgsql-host` begins with a slash, it
specifies Unix-domain communication rather than TCP/IP communication; the value
is the name of the directory in which the socket file is stored.

**WARNING:** When specified as a hostname a chicken/egg situation might arise
where the database is needed to resolve the IP address of the database. It is
best to supply an IP address of the database here.

## `gpgsql-port`
The port to connect to on [`gpgsql-host`](#gpgsql-host). Default: 5432

## `gpgsql-dbname`
Name of the database to connect to. Default: "pdns".

## `gpgsql-user`
User to connect as. Default: "powerdns".

## `gpgsql-password`
The password to for [`gpgsql-user`](#gpgsql-user).

## `gpgsql-dnssec`
Enable DNSSEC processing for this backend. Default=no.

# Default schema
```
!!include=../modules/gpgsqlbackend/schema.pgsql.sql
```

