# Generic SQLite backend (2 and 3)
| | |
|:--|:--|
|Native|Yes|
|Master|Yes|
|Slave|Yes|
|Superslave|Yes|
|DNSSEC|gsqlite3 only (set `gsqlite3-dnssec`)|
|Disabled data|gsqlite3 only|
|Comments|gsqlite3 only|
|Module name|gsqlite and gsqlite3|
Launch name|gsqlite and gsqlite3|

**Warning**: When importing large amounts of data, be sure to run 'analyze;' afterwards as SQLite3 has a tendency to use sub-optimal indexes otherwise.

This backend retrieves all data from a SQLite database, which is an RDBMS that's embedded into the application itself, so you won't need to be running a separate server process. It also reduces overhead, and simplifies installation. At [www.sqlite.org](http://www.sqlite.org) you can find more information about SQLite.

As this is a generic backend, built on top of the gSql framework, you can specify all queries as documented in [Generic MySQL and PgSQL backends](backend-generic-mypgsql.md).

SQLite exists in two incompatible versions, numbered 2 and 3, and from 2.9.21 onwards, PowerDNS supports both. It is recommended to go with version 3 as it is newer, has better performance and is actively maintained. To use version 3, choose `launch=gsqlite3`.

## Compiling the SQLite backend
Before you can begin compiling PowerDNS with the SQLite backend you need to have the SQLite utility and library installed on your system. You can download these from <http://www.sqlite.org/download.html>, or you can use packages (if your distribution provides those).

When you've installed the library you can use: `./configure --with-modules="gsqlite"` or `./configure --with-modules="gsqlite3"` to configure PowerDNS to use the SQLite backend. Compilation can then proceed as usual.

SQLite is included in most PowerDNS binary releases.

## Setting up the database
Before you can use this backend you first have to set it up and fill it with data. The default setup conforms to the following schema:

```
CREATE TABLE domains (
  id                    INTEGER PRIMARY KEY,
  name                  VARCHAR(255) NOT NULL COLLATE NOCASE,
  master                VARCHAR(128) DEFAULT NULL,
  last_check            INTEGER DEFAULT NULL,
  type                  VARCHAR(6) NOT NULL,
  notified_serial       INTEGER DEFAULT NULL,
  account               VARCHAR(40) DEFAULT NULL
);

CREATE UNIQUE INDEX name_index ON domains(name);


CREATE TABLE records (
  id                    INTEGER PRIMARY KEY,
  domain_id             INTEGER DEFAULT NULL,
  name                  VARCHAR(255) DEFAULT NULL,
  type                  VARCHAR(10) DEFAULT NULL,
  content               VARCHAR(65535) DEFAULT NULL,
  ttl                   INTEGER DEFAULT NULL,
  prio                  INTEGER DEFAULT NULL,
  change_date           INTEGER DEFAULT NULL,
  disabled              BOOLEAN DEFAULT 0,
  ordername             VARCHAR(255),
  auth                  BOOL DEFAULT 1
);

CREATE INDEX rec_name_index ON records(name);
CREATE INDEX nametype_index ON records(name,type);
CREATE INDEX domain_id ON records(domain_id);
CREATE INDEX orderindex ON records(ordername);


CREATE TABLE supermasters (
  ip                    VARCHAR(64) NOT NULL,
  nameserver            VARCHAR(255) NOT NULL COLLATE NOCASE,
  account               VARCHAR(40) DEFAULT NULL
);

CREATE UNIQUE INDEX ip_nameserver_pk ON supermasters(ip, nameserver);


CREATE TABLE comments (
  id                    INTEGER PRIMARY KEY,
  domain_id             INTEGER NOT NULL,
  name                  VARCHAR(255) NOT NULL,
  type                  VARCHAR(10) NOT NULL,
  modified_at           INT NOT NULL,
  account               VARCHAR(40) DEFAULT NULL,
  comment               VARCHAR(65535) NOT NULL
);

CREATE INDEX comments_domain_id_index ON comments (domain_id);
CREATE INDEX comments_nametype_index ON comments (name, type);
CREATE INDEX comments_order_idx ON comments (domain_id, modified_at);


CREATE TABLE domainmetadata (
 id                     INTEGER PRIMARY KEY,
 domain_id              INT NOT NULL,
 kind                   VARCHAR(32) COLLATE NOCASE,
 content                TEXT
);

CREATE INDEX domainmetaidindex ON domainmetadata(domain_id);


CREATE TABLE cryptokeys (
 id                     INTEGER PRIMARY KEY,
 domain_id              INT NOT NULL,
 flags                  INT NOT NULL,
 active                 BOOL,
 content                TEXT
);

CREATE INDEX domainidindex ON cryptokeys(domain_id);


CREATE TABLE tsigkeys (
 id                     INTEGER PRIMARY KEY,
 name                   VARCHAR(255) COLLATE NOCASE,
 algorithm              VARCHAR(50) COLLATE NOCASE,
 secret                 VARCHAR(255)
);

CREATE UNIQUE INDEX namealgoindex ON tsigkeys(name, algorithm);
```

This schema contains all elements needed for master, slave and superslave operation.

After you have created the database you probably want to fill it with data. If you have a BIND zone file it's as easy as: `zone2sql --zone=myzonefile --gmysql | sqlite powerdns.sqlite`, but you can also use AXFR (or insert data manually).

To communicate with a SQLite database, use either the 'sqlite' or 'sqlite3' program, and feed it SQL.

## Using the SQLite backend
The last thing you need to do is telling PowerDNS to use the SQLite backend.

```
# in pdns.conf
launch=gsqlite # or gsqlite3
gsqlite-database=<path to your SQLite database>   # or gsqlite3-database
```

Then you can start PowerDNS and it should notify you that a connection to the database was made.
