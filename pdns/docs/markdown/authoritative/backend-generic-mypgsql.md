# Generic MySQL and PgSQL backends
| | |
|:--|:--|
|Native|Yes|
|Master|Yes|
|Slave|Yes|
|Superslave|Yes|
|Autoserial|Yes (v3.1 and up)|
|Case|All lower|
|DNSSEC|Yes (set `gmysql-dnssec` or `gpgsql-dnssec`)|
|Disabled data|Yes (v3.4.0 and up)|
|Comments|Yes (v3.4.0 and up)|
|Module name &lt; 2.9.3|pgmysql|
|Module name &gt; 2.9.2|gmysql and gpgsql|
|Launch name| gmysql and gpgsql2 and gpgsql|

PostgreSQL and MySQL backend with easily configurable SQL statements, allowing you to graft PDNS on any PostgreSQL or MySQL database of your choosing. Because all database schemas will be different, a generic backend is needed to cover all needs.

**Warning**: Host names and the MNAME of a SOA records are NEVER terminated with a '.' in PowerDNS storage! If a trailing '.' is present it will inevitably cause problems, problems that may be hard to debug.

The template queries are expanded using the C function 'snprintf' which implies that substitutions are performed on the basis of %-place holders. To place a % in a query which will not be substituted, use %%. Make sure to fill out the search key, often called 'name' in lower case!

There are in fact two backends, one for PostgreSQL and one for MySQL but they accept the same settings and use almost exactly the same database schema.

# MySQL specifics

**Warning**: If using MySQL with 'slave' support enabled in PowerDNS you **must** run MySQL with a table engine that supports transactions.

In practice, great results are achieved with the 'InnoDB' tables. PowerDNS will silently function with non-transaction aware MySQLs but at one point this is going to harm your database, for example when an incoming zone transfer fails.

The default setup conforms to the following schema:

```
CREATE TABLE domains (
  id                    INT AUTO_INCREMENT,
  name                  VARCHAR(255) NOT NULL,
  master                VARCHAR(128) DEFAULT NULL,
  last_check            INT DEFAULT NULL,
  type                  VARCHAR(6) NOT NULL,
  notified_serial       INT DEFAULT NULL,
  account               VARCHAR(40) DEFAULT NULL,
  PRIMARY KEY (id)
) Engine=InnoDB;

CREATE UNIQUE INDEX name_index ON domains(name);

CREATE TABLE records (
  id                    INT AUTO_INCREMENT,
  domain_id             INT DEFAULT NULL,
  name                  VARCHAR(255) DEFAULT NULL,
  type                  VARCHAR(10) DEFAULT NULL,
  content               VARCHAR(64000) DEFAULT NULL,
  ttl                   INT DEFAULT NULL,
  prio                  INT DEFAULT NULL,
  change_date           INT DEFAULT NULL,
  disabled              TINYINT(1) DEFAULT 0,
  ordername             VARCHAR(255) BINARY DEFAULT NULL,
  auth                  TINYINT(1) DEFAULT 1,
  PRIMARY KEY (id)
) Engine=InnoDB;

CREATE INDEX nametype_index ON records(name,type);
CREATE INDEX domain_id ON records(domain_id);
CREATE INDEX recordorder ON records (domain_id, ordername);


CREATE TABLE supermasters (
  ip                    VARCHAR(64) NOT NULL,
  nameserver            VARCHAR(255) NOT NULL,
  account               VARCHAR(40) DEFAULT NULL,
  PRIMARY KEY (ip, nameserver)
) Engine=InnoDB;


CREATE TABLE comments (
  id                    INT AUTO_INCREMENT,
  domain_id             INT NOT NULL,
  name                  VARCHAR(255) NOT NULL,
  type                  VARCHAR(10) NOT NULL,
  modified_at           INT NOT NULL,
  account               VARCHAR(40) NOT NULL,
  comment               VARCHAR(64000) NOT NULL,
  PRIMARY KEY (id)
) Engine=InnoDB;

CREATE INDEX comments_domain_id_idx ON comments (domain_id);
CREATE INDEX comments_name_type_idx ON comments (name, type);
CREATE INDEX comments_order_idx ON comments (domain_id, modified_at);


CREATE TABLE domainmetadata (
  id                    INT AUTO_INCREMENT,
  domain_id             INT NOT NULL,
  kind                  VARCHAR(32),
  content               TEXT,
  PRIMARY KEY (id)
) Engine=InnoDB;

CREATE INDEX domainmetadata_idx ON domainmetadata (domain_id, kind);


CREATE TABLE cryptokeys (
  id                    INT AUTO_INCREMENT,
  domain_id             INT NOT NULL,
  flags                 INT NOT NULL,
  active                BOOL,
  content               TEXT,
  PRIMARY KEY(id)
) Engine=InnoDB;

CREATE INDEX domainidindex ON cryptokeys(domain_id);


CREATE TABLE tsigkeys (
  id                    INT AUTO_INCREMENT,
  name                  VARCHAR(255),
  algorithm             VARCHAR(50),
  secret                VARCHAR(255),
  PRIMARY KEY (id)
) Engine=InnoDB;

CREATE UNIQUE INDEX namealgoindex ON tsigkeys(name, algorithm);
```

`zone2sql` with the `--gmysql` flag also assumes this layout is in place.

For full migration notes, please see [Migration](migration.md).

This schema contains all elements needed for master, slave and superslave operation.

When using the InnoDB storage engine, we suggest adding the following lines to the 'create table records' command above:

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

# PostgreSQL specifics

The default setup conforms to the following schema, which you should add to a PostgreSQL database.

```
CREATE TABLE domains (
  id                    SERIAL PRIMARY KEY,
  name                  VARCHAR(255) NOT NULL,
  master                VARCHAR(128) DEFAULT NULL,
  last_check            INT DEFAULT NULL,
  type                  VARCHAR(6) NOT NULL,
  notified_serial       INT DEFAULT NULL,
  account               VARCHAR(40) DEFAULT NULL,
  CONSTRAINT c_lowercase_name CHECK (((name)::TEXT = LOWER((name)::TEXT)))
);

CREATE UNIQUE INDEX name_index ON domains(name);


CREATE TABLE records (
  id                    SERIAL PRIMARY KEY,
  domain_id             INT DEFAULT NULL,
  name                  VARCHAR(255) DEFAULT NULL,
  type                  VARCHAR(10) DEFAULT NULL,
  content               VARCHAR(65535) DEFAULT NULL,
  ttl                   INT DEFAULT NULL,
  prio                  INT DEFAULT NULL,
  change_date           INT DEFAULT NULL,
  disabled              BOOL DEFAULT 'f',
  ordername             VARCHAR(255),
  auth                  BOOL DEFAULT 't',
  CONSTRAINT domain_exists
  FOREIGN KEY(domain_id) REFERENCES domains(id)
  ON DELETE CASCADE,
  CONSTRAINT c_lowercase_name CHECK (((name)::TEXT = LOWER((name)::TEXT)))
);

CREATE INDEX rec_name_index ON records(name);
CREATE INDEX nametype_index ON records(name,type);
CREATE INDEX domain_id ON records(domain_id);
CREATE INDEX recordorder ON records (domain_id, ordername text_pattern_ops);


CREATE TABLE supermasters (
  ip                    INET NOT NULL,
  nameserver            VARCHAR(255) NOT NULL,
  account               VARCHAR(40) DEFAULT NULL,
  PRIMARY KEY(ip, nameserver)
);


CREATE TABLE comments (
  id                    SERIAL PRIMARY KEY,
  domain_id             INT NOT NULL,
  name                  VARCHAR(255) NOT NULL,
  type                  VARCHAR(10) NOT NULL,
  modified_at           INT NOT NULL,
  account               VARCHAR(40) DEFAULT NULL,
  comment               VARCHAR(65535) NOT NULL,
  CONSTRAINT domain_exists
  FOREIGN KEY(domain_id) REFERENCES domains(id)
  ON DELETE CASCADE,
  CONSTRAINT c_lowercase_name CHECK (((name)::TEXT = LOWER((name)::TEXT)))
);

CREATE INDEX comments_domain_id_idx ON comments (domain_id);
CREATE INDEX comments_name_type_idx ON comments (name, type);
CREATE INDEX comments_order_idx ON comments (domain_id, modified_at);


CREATE TABLE domainmetadata (
  id                    SERIAL PRIMARY KEY,
  domain_id             INT REFERENCES domains(id) ON DELETE CASCADE,
  kind                  VARCHAR(32),
  content               TEXT
);

CREATE INDEX domainidmetaindex ON domainmetadata(domain_id);


CREATE TABLE cryptokeys (
  id                    SERIAL PRIMARY KEY,
  domain_id             INT REFERENCES domains(id) ON DELETE CASCADE,
  flags                 INT NOT NULL,
  active                BOOL,
  content               TEXT
);

CREATE INDEX domainidindex ON cryptokeys(domain_id);


CREATE TABLE tsigkeys (
  id                    SERIAL PRIMARY KEY,
  name                  VARCHAR(255),
  algorithm             VARCHAR(50),
  secret                VARCHAR(255),
  CONSTRAINT c_lowercase_name CHECK (((name)::TEXT = LOWER((name)::TEXT)))
);

CREATE UNIQUE INDEX namealgoindex ON tsigkeys(name, algorithm);
```

`zone2sql` with the `--gpgsql` flag also assumes this layout is in place.

This schema contains all elements needed for master, slave and superslave operation.

For full migration notes, please see [Migration](migration.md).

With PostgreSQL, you may have to run `createdb powerdns` first and then connect to that database with `psql powerdns`, and feed it the schema above.

# Oracle specifics

Generic Oracle support is only available since version 2.9.18. The default setup conforms to the following schema, which you should add to an Oracle database. You may need or want to add `namespace` statements.

```
CREATE TABLE domains (
  id              INTEGER NOT NULL,
  name            VARCHAR2(255) NOT NULL,
  master          VARCHAR2(128) DEFAULT NULL,
  last_check      INTEGER DEFAULT NULL,
  type            VARCHAR2(6) NOT NULL,
  notified_serial NUMBER(10,0) DEFAULT NULL,
  account         VARCHAR2(40) DEFAULT NULL,
  PRIMARY KEY (id)
);

CREATE SEQUENCE domains_id_sequence;
CREATE INDEX domains$name ON domains (name);


CREATE TABLE records (
  id              INTEGER NOT NULL,
  domain_id       INTEGER DEFAULT NULL REFERENCES domains (id) ON DELETE CASCADE,
  name            VARCHAR2(255) DEFAULT NULL,
  type            VARCHAR2(10) DEFAULT NULL,
  content         VARCHAR2(4000) DEFAULT NULL,
  ttl             INTEGER DEFAULT NULL,
  prio            INTEGER DEFAULT NULL,
  change_date     INTEGER DEFAULT NULL,
  disabled        NUMBER(1,0) DEFAULT 0 NOT NULL,
  ordername       VARCHAR2(255) DEFAULT NULL,
  auth            NUMBER(1,0) DEFAULT 1 NOT NULL,
  PRIMARY KEY (id)
) pctfree 40;

CREATE SEQUENCE records_id_sequence;
CREATE INDEX records$nametype ON records (name, type);
CREATE INDEX records$domain_id ON records (domain_id);
CREATE INDEX records$recordorder ON records (domain_id, ordername);


CREATE TABLE supermasters (
  ip              VARCHAR2(64) NOT NULL,
  nameserver      VARCHAR2(255) NOT NULL,
  account         VARCHAR2(40) DEFAULT NULL,
  PRIMARY KEY (ip, nameserver)
);


CREATE TABLE comments (
  id              INTEGER NOT NULL,
  domain_id       INTEGER NOT NULL REFERENCES domains (id) ON DELETE CASCADE,
  name            VARCHAR2(255) NOT NULL,
  type            VARCHAR2(10) NOT NULL,
  modified_at     INTEGER NOT NULL,
  account         VARCHAR2(40) NOT NULL,
  "comment"       VARCHAR2(4000) NOT NULL
);
CREATE SEQUENCE comments_id_sequence;
CREATE INDEX comments$nametype ON comments (name, type);
CREATE INDEX comments$domain_id ON comments (domain_id);
CREATE INDEX comments$order ON comments (domain_id, modified_at);


CREATE TABLE domainmetadata (
  id              INTEGER NOT NULL,
  domain_id       INTEGER NOT NULL,
  kind            VARCHAR2(32),
  content         VARCHAR2(4000),
  PRIMARY KEY (id)
);

CREATE SEQUENCE domainmetadata_id_sequence;
CREATE INDEX domainmetadata$domain_id ON domainmetadata (domain_id);


CREATE TABLE cryptokeys (
  id              INTEGER NOT NULL,
  domain_id       INTEGER NOT NULL,
  flags           INTEGER NOT NULL,
  active          INTEGER NOT NULL,
  content         VARCHAR2(4000),
  PRIMARY KEY (id)
);

CREATE SEQUENCE cryptokeys_id_sequence;
CREATE INDEX cryptokeys$domain_id ON cryptokeys (domain_id);


CREATE TABLE tsigkeys (
  id              INTEGER NOT NULL,
  name            VARCHAR2(255),
  algorithm       VARCHAR2(50),
  secret          VARCHAR2(255),
  PRIMARY KEY (id)
);

CREATE SEQUENCE tsigkeys_id_sequence;
CREATE UNIQUE INDEX tsigkeys$namealgo ON tsigkeys (name, algorithm);
```

This schema contains all elements needed for master, slave and superslave operation.

Inserting records is a bit different compared to MySQL and PostgreSQL, you should use:

```
insert into domains (id,name,type) values (domains_id_sequence.nextval,'example.net','NATIVE');
```

Furthermore, use the `goracle-tnsname` setting to specify which TNSNAME the Generic Oracle Backend should be connecting to. There are no `goracle-dbname`, `goracle-host` or `goracle-port` settings, their equivalent is in `/etc/tnsnames.ora`.

# Basic functionality
4 queries are needed for regular lookups, 4 for 'fancy records' which are disabled by default and 1 is needed for zone transfers.

The 4+4 regular queries must return the following 6 fields, in this exact order:

* content: This is the 'right hand side' of a DNS record. For an A record, this is the IP address for example.
* ttl: TTL of this record, in seconds. Must be a real value, no checking is performed.
* prio: For MX records, this should be the priority of the mail exchanger specified.
* qtype: The ASCII representation of the qtype of this record. Examples are 'A', 'MX', 'SOA', 'AAAA'. Make sure that this field returns an exact answer - PDNS won't recognise 'A ' as 'A'. This can be achieved by using a VARCHAR instead of a CHAR.
* domain\_id: Each domain must have a unique domain\_id. No two domains may share a domain\_id, all records in a domain should have the same. A number.
* name: Actual name of a record. Must not end in a '.' and be fully qualified - it is not relative to the name of the domain!
* disabled: If set to true, this record is hidden from DNS clients, but can still be modified from the REST API. See [Disabled data](#disabled-data). (Available since version 3.4.0.)

Please note that the names of the fields are not relevant, but the order is!

As said earlier, there are 8 SQL queries for regular lookups. To configure them, set `gmysql-basic-query` or `gpgsql-basic-query`, depending on your choice of backend. If so called 'MBOXFW' fancy records are not used, four queries remain:

# Queries and settings
## Regular Queries
### `basic-query`
Default: `select content,ttl,prio,type,domain_id,name from records where type='%s' and name='%s'` This is the most used query, needed for doing 1:1 lookups of qtype/name values. First %s is replaced by the ASCII representation of the qtype of the question, the second by the name.

### id-query  
Default: `select content,ttl,prio,type,domain_id,name from records where type='%s' and name='%s' and domain_id=%d` Used for doing lookups within a domain. First %s is replaced by the qtype, the %d which should appear after the %s by the numeric domain\_id.

### any-query  
For doing ANY queries. Also used internally. Default: `select content,ttl,prio,type,domain_id,name from records where name='%s'` The %s is replaced by the qname of the question.

### any-id-query  
For doing ANY queries within a domain. Also used internally. Default: `select content,ttl,prio,type,domain_id,name from records where name='%s' and domain_id=%d` The %s is replaced by the name of the domain, the %d by the numerical domain id.

The last query is for listing the entire contents of a zone. This is needed when performing a zone transfer, but sometimes also internally:

### list-query  
To list an entire zone. Default: `select content,ttl,prio,type,domain_id,name from records where domain_id=%d`

## DNSSEC queries
If DNSSEC is enabled (through the `-dnssec` flag on a gsql backend), many queries are replaced by slightly extended variants that also query the auth column. The auth column is always added as the rightmost column. These are the -auth defaults:

### basic-query-auth  
Basic query. Default: `select content,ttl,prio,type,domain_id,name, auth from records where type='%s' and name='%s'`

### id-query-auth  
Basic with ID query. Default: `select content,ttl,prio,type,domain_id,name, auth from records where type='%s' and name='%s' and domain_id=%d`

### wildcard-query-auth  
Wildcard query. Default: `select content,ttl,prio,type,domain_id,name, auth from records where type='%s' and name like '%s'`

### wildcard-id-query-auth  
Wildcard with ID query. Default: `select content,ttl,prio,type,domain_id,name, auth from records where type='%s' and name like '%s' and domain_id='%d'`

### any-query-auth  
Any query. Default: `select content,ttl,prio,type,domain_id,name, auth from records where name='%s'`

### any-id-query-auth  
Any with ID query. Default: `select content,ttl,prio,type,domain_id,name, auth from records where name='%s' and domain_id=%d`

### wildcard-any-query-auth  
Wildcard ANY query. Default: `select content,ttl,prio,type,domain_id,name, auth from records where name like '%s'`

### wildcard-any-id-query-auth  
Wildcard ANY with ID query. Default: `select content,ttl,prio,type,domain_id,name, auth from records where name like '%s' and domain_id='%d'`

### list-query-auth  
AXFR query. Default: `select content,ttl,prio,type,domain_id,name, auth from records where domain_id='%d' order by name, type`

Additionally, there are some new queries to determine NSEC(3) order:

### get-order-first-query  
DNSSEC Ordering Query, first. Default: `select ordername, name from records where domain_id=%d and ordername is not null order by 1 asc limit 1`

### get-order-before-query  
DNSSEC Ordering Query, before. Default: `select ordername, name from records where ordername &lt;= '%s' and domain_id=%d and ordername is not null order by 1 desc limit 1`

### get-order-after-query  
DNSSEC Ordering Query, after. Default: `select min(ordername) from records where ordername &gt; '%s' and domain_id=%d and ordername is not null`

### get-order-last-query  
DNSSEC Ordering Query, last. Default: `select ordername, name from records where ordername != '' and domain_id=%d and ordername is not null order by 1 desc limit 1`

Finally, these two queries are used to set ordername and auth correctly in a database:

### set-order-and-auth-query  
DNSSEC set ordering query. Default: `update records set ordername='%s',auth=%d where name='%s' and domain_id='%d'`

### nullify-ordername-and-auth-query  
DNSSEC nullify ordername query. Default: `update records set ordername=NULL,auth=0 where name='%s' and type='%s' and domain_id='%d'`

Make sure to read [Rules for filling out fields in database backends](dnssec.md#rules-for-filling-out-fields-in-database-backends) if you wish to calculate ordername and auth without using pdns-rectify.

## Master/slave queries
Most installations will have zero need to change the following settings, but should the need arise, here they are:

### master-zone-query  
Called to determine the master of a zone. Default: `select master from domains where name='%s' and type='SLAVE'`

### info-zone-query  
Called to retrieve (nearly) all information for a domain: Default: `select id,name,master,last_check,notified_serial,type from domains where name='%s'`

### info-all-slaves-query  
Called to retrieve all slave domains Default: `select id,name,master,last_check,type from domains where type='SLAVE'`

### supermaster-query  
Called to determine if a certain host is a supermaster for a certain domain name. Default: `select account from supermasters where ip='%s' and nameserver='%s';`

### insert-slave-query  
Called to add a domain as slave after a supermaster notification. Default: `insert into domains (type,name,master,account) values('SLAVE','%s','%s','%s')`

### insert-record-query  
Called during incoming AXFR. Default: `insert into records (content,ttl,prio,type,domain_id,name) values ('%s',%d,%d,'%s',%d,'%s')`

### update-serial-query  
Called to update the last notified serial of a master domain. Default: `update domains set notified_serial=%d where id=%d`

### update-lastcheck-query  
Called to update the last time a slave domain was checked for freshness. Default: `update domains set last_check=%d where id=%d`

### info-all-master-query  
Called to get data on all domains for which the server is master. Default: `select id,name,master,last_check,notified_serial,type from domains where type='MASTER'`

### delete-zone-query  
Called to delete all records of a zone. Used before an incoming AXFR. Default: `delete from records where domain_id=%d`

## Comments queries
For listing/modifying comments. For defaults, please see `pdns_server --load=BACKEND --config`.

### list-comments-query  
Called to get all comments in a zone. Returns fields: domain\_id, name, type, modified\_at, account, comment.

### insert-comment-query  
Called to create a single comment for a specific RRSet. Given fields: domain\_id, name, type, modified\_at, account, comment

### delete-comment-rrset-query  
Called to delete all comments for a specific RRset. Given fields: domain\_id, name, type

### delete-comments-query  
Called to delete all comments for a zone. Usually called before deleting the entire zone. Given fields: domain\_id

## Fancy records
**Warning**: Fancy records are unsupported as of version 3.0

If PDNS is used with so called 'Fancy Records', the 'MBOXFW' record exists which specifies an email address forwarding instruction, wildcard queries are sometimes needed. This is not enabled by default. A wildcard query is an internal concept - it has no relation to \*.domain-type lookups. You can safely leave these queries blank.

### wildcard-query  
Can be left blank. See above for an explanation. Default: `select content,ttl,prio,type,domain_id,name from records where type='%s' and name like '%s'`

### wildcard-id-query  
Can be left blank. See above for an explanation. Default: `select content,ttl,prio,type,domain_id,name from records where type='%s' and name like '%s' and domain_id=%d` Used for doing lookups within a domain.

### wildcard-any-query  
For doing wildcard ANY queries. Default: `select content,ttl,prio,type,domain_id,name from records where name like '%s'`

### wildcard-any-id-query  
For doing wildcard ANY queries within a domain. Default: `select content,ttl,prio,type,domain_id,name from records where name like '%s' and domain_id=%d`

## Settings and specifying queries
The queries above are specified in pdns.conf. For example, the basic-query would appear as:

```
gpgsql-basic-query=select content,ttl,prio,type,domain_id,name from records where type='%s' and name='%s'
```

When using the Generic PostgreSQL backend, they appear as above. When using the generic MySQL backend, change the "gpgsql-" prefix to "gmysql-".

Queries can span multiple lines, like this:

```
gpgsql-basic-query=select content,ttl,prio,type,domain_id,name from records \
where type='%s' and name='%s'
```

Do not wrap statements in quotes as this will not work. Besides the query related settings, the following configuration options are available, where one should substitute 'gmysql', 'gpgsql', or 'goracle' for the prefix 'backend'. So 'backend-dbname' can stand for 'gpgsql-dbname' or 'gmysql-dbname' etc.

### `backend-dbname`
Database name to connect to

### `backend-host`
Database host to connect to. WARNING: When specified as a hostname a chicken/egg situation might arise where the database is needed to resolve the IP address of the database. It is best to supply an IP address of the database here.

**Only for postgres**: If host begins with a slash, it specifies Unix-domain communication rather than TCP/IP communication; the value is the name of the directory in which the socket file is stored.

### backend-port  
Database port to connect to.

### gmysql-socket (only for MySQL!)  
File name where the MySQL connection socket resides. Often `/tmp/mysql.sock` or `/var/run/mysqld/mysqld.sock`.

### backend-password  
Password to connect with

### backend-user  
User to connect as

### backend-group (MySQL only, since 3.2)  
MySQL 'group' to connect as, defaults to 'client'.

## Native operation
To add a domain, issue the following:

```
insert into domains (name,type) values ('powerdns.com','NATIVE');
```

The records table can now be filled by with the domain\_id set to the id of the domains table row just inserted.

## Slave operation
These backends are fully slave capable. To become a slave of the 'powerdns.com' domain, execute this:

```
        insert into domains (name,master,type) values ('powerdns.com','213.244.168.217','SLAVE');
```

And wait a while for PDNS to pick up the addition - which happens within one minute. There is no need to inform PDNS that a new domain was added. Typical output is:

```
        Apr 09 13:34:29 All slave domains are fresh
        Apr 09 13:35:29 1 slave domain needs checking
        Apr 09 13:35:29 Domain powerdns.com is stale, master serial 1, our serial 0
        Apr 09 13:35:30 [gPgSQLBackend] Connected to database
        Apr 09 13:35:30 AXFR started for 'powerdns.com'
        Apr 09 13:35:30 AXFR done for 'powerdns.com'
        Apr 09 13:35:30 [gPgSQLBackend] Closing connection
```

From now on, PDNS is authoritative for the 'powerdns.com' zone and will respond accordingly for queries within that zone.

Periodically, PDNS schedules checks to see if domains are still fresh. The default [`slave-cycle-interval`](settings.md#slave-cycle-interval) is 60 seconds, large installations may need to raise this value. Once a domain has been checked, it will not be checked before its SOA refresh timer has expired. Domains whose status is unknown get checked every 60 seconds by default.

## Superslave operation
To configure a supermaster with IP address 10.0.0.11 which lists this installation as 'autoslave.powerdns.com', issue the following:

```
        insert into supermasters ('10.0.0.11','autoslave.powerdns.com','internal');
```

From now on, valid notifies from 10.0.0.11 that list a NS record containing 'autoslave.powerdns.com' will lead to the provisioning of a slave domain under the account 'internal'. See [Supermaster](modes-of-operation.md#supermaster-automatic-provisioning-of-slaves) for details.

## 3.13. Master operation
The PostgreSQL backend is fully master capable with automatic discovery of serial changes. Raising the serial number of a domain suffices to trigger PDNS to send out notifications. To configure a domain for master operation instead of the default native replication, issue:

```
        insert into domains (name,type) values ('powerdns.com','MASTER');
```

Make sure that the assigned id in the domains table matches the domain\_id field in the records table!

## 3.14. Disabled data
PowerDNS understands the notion of disabled records. They are marked by setting "disabled" to 1 (for PostgreSQL: true). By extension, when the SOA record for a domain is disabled, the entire domain is considered to be disabled.

Effects: the record (or domain, respectively) will not be visible to DNS clients. The REST API will still see the record (or domain). Even if a domain is disabled, slaving still works. Slaving considers a disabled domain to have a serial of 0; this implies that a slaved domain will not stay disabled.
