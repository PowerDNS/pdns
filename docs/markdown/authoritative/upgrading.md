Before proceeding, it is advised to check the release notes for your PDNS version, as specified in the name of the distribution file.

**WARNING**: Version 3.X of the PowerDNS Authoritative Server is a major upgrade if you are coming from 2.9.x. Please follow **all** instructions.

# 3.4.X to HEAD

## API
Incompatible change: `SOA-EDIT-API` now follows `SOA-EDIT-DNSUPDATE` instead of `SOA-EDIT` (incl. the fact that it now has a default value of `DEFAULT`). You must update your existing `SOA-EDIT-API` metadata (set `SOA-EDIT` to your previous `SOA-EDIT-API` value, and `SOA-EDIT-API` to `SOA-EDIT` to keep the old behaviour).

# 3.4.2 to 3.4.3
No breaking changes.

# 3.4.1 to 3.4.2

## API
**Warning**: `priority` is no longer part of `records` in the API. `content` now includes the backend's `priority` field (see [API Spec](../httpapi/api_spec.md#url-serversserver_idzoneszone_id) for details).

# 3.4.0 to 3.4.1

## Configuration option changes

### New options
* [`experimental-api-key`](settings.md#experimental-api-key)
* [`security-poll-suffix`](settings.md#security-poll-suffix)

# 3.3.1 to 3.4.0
If you are coming from any 3.x version (including 3.3.1), there is a mandatory SQL schema upgrade

## Database schema
**Warning**: The default database schema has changed. The database update below is mandatory.

If custom queries are in use, they probably need an update.

### gmysql backend with nodnssec schema

```
!!include=../modules/gmysqlbackend/nodnssec-3.x_to_3.4.0_schema.mysql.sql
```

### gmysql backend with dnssec schema

```
!!include=../modules/gmysqlbackend/dnssec-3.x_to_3.4.0_schema.mysql.sql
```

### gpgsql backend with nodnssec schema

```
!!include=../modules/gpgsqlbackend/nodnssec-3.x_to_3.4.0_schema.pgsql.sql
```

### gpgsql backend with dnssec schema:

```
!!include=../modules/gpgsqlbackend/dnssec-3.x_to_3.4.0_schema.pgsql.sql
```

### gsqlite3 backend with nodnssec schema

```
!!include=../modules/gsqlite3backend/nodnssec-3.x_to_3.4.0_schema.sqlite3.sql
```

### gsqlite3 backend with dnssec schema:

```
!!include=../modules/gsqlite3backend/dnssec-3.x_to_3.4.0_schema.sqlite3.sql
```

### goracle backend:

```
ALTER TABLE records ADD disabled INT DEFAULT 0;
ALTER TABLE records MODIFY auth INT DEFAULT 1;

UPDATE records SET auth=1 WHERE auth IS NULL;

ALTER TABLE domainmetadata MODIFY kind VARCHAR2(32);
```

## Configuration option changes

### New options
#### `allow-dnsupdate-from`
A global setting to allow DNS update from these IP ranges.

#### `also-notify`
When notifying a domain, also notify these nameservers

#### `carbon-interval`
Number of seconds between carbon (graphite) updates

#### `carbon-ourname`
If set, overrides our reported hostname for carbon stats

#### `carbon-server`
If set, send metrics in carbon (graphite) format to this server

#### `disable-axfr-rectify`
Disable the rectify step during an outgoing AXFR. Only required for regression testing.

#### `experimental-api-readonly`
If the JSON API should disallow data modification

#### `experimental-api-key`
Static API authentication key, must be sent in the X-API-Key header. Required for any API usage.

#### `experimental-dname-processing`
If we should support DNAME records

#### `experimental-dnsupdate`
Enable/Disable DNS update (RFC2136) support. Default is no.

#### `forward-dnsupdate`
A global setting to allow DNS update packages that are for a Slave domain, to be forwarded to the master.

#### `max-signature-cache-entries`
Maximum number of signatures cache entries

#### `local-address-nonexist-fail`
Fail to start if one or more of the local-address's do not exist on this server

#### `local-ipv6-nonexist-fail`
Fail to start if one or more of the local-ipv6 addresses do not exist on this server

#### `max-nsec3-iterations`
Limit the number of NSEC3 hash iterations

#### `only-notify`
Only send AXFR NOTIFY to these IP addresses or netmasks

#### `reuseport`
Enable higher performance on compliant kernels by using SO\_REUSEPORT allowing each receiver thread to open its own socket

#### `udp-truncation-threshold`
Maximum UDP response size before we truncate

#### `webserver-allow-from`
Webserver access is only allowed from these subnets

### Removed options
#### `add-superfluous-nsec3-for-old-bind`
Add superfluous NSEC3 record to positive wildcard response

#### `edns-subnet-option-number`
EDNS option number to use

#### `fancy-records`
Process URL and MBOXFW records

#### `log-failed-updates`
If PDNS should log failed update requests

#### `smtpredirector`
Our smtpredir MX host

#### `urlredirector`
Where we send hosts to that need to be url redirected

#### `wildcard-url`
Process URL and MBOXFW records

### Options with changed default values

#### `allow-axfr-ips`
Allow zonetransfers only to these subnets

* old value: 0.0.0.0/0,::/0
* new value: 127.0.0.0/8,::1

#### log-dns-details
If PDNS should log DNS non-erroneous details

* old value:
* new value: no

#### module-dir
The default location has changed from libdir to pkglibdir. pkglibdir is defined as '$(libdir)/pdns'

#### gpgsql-dbname, gpgsql-user
These are now empty instead of "powerdns"

# 3.3 to 3.3.1
Constraints were added to the PostgreSQL schema:

```
        alter table domains add constraint c_lowercase_name CHECK (((name)::text = lower((name)::text)));
        alter table tsigkeys add constraint c_lowercase_name check (((name)::text = lower((name)::text)));
```

The (gmysql-)innodb-read-committed flag was added to the gmysql backend, and enabled by default. This interferes with statement replication. Please set your binlog\_format to MIXED or ROW, or disable binlog. Alternatively, disable (gmysql-)innodb-read-committed but be aware that this may cause deadlocks during AXFRs.

# 3.2 to 3.3
The 'ip' field in the supermasters table (for the various gsql backends) has been stretched to 64 characters to support IPv6. For MySQL:

```
alter table supermasters modify ip VARCHAR(64);
```

For PostgreSQL:
```
alter table supermasters alter column ip type VARCHAR(64);
```

`pdnssec secure-zone` now creates one KSK and one ZSK, instead of two ZSKs.

The 'rec\_name\_index' index was dropped from the gmysql schema, as it was superfluous.

# 3.1 to 3.2
Previously, on Linux, if the PowerDNS Authoritative Server was configured to bind to the IPv6 address `::`, the server would answer questions that came in via IPv6 **and** IPv4.

As of 3.2, binding to :: on Linux now does the same thing as binding to :: on other operating systems: perform IPv6 service. To continue the old behaviour, use [`local-address`](settings.md#local-address)`=0.0.0.0` and [`local-ipv6`](settings.md#local-ipv6)`=::`.

3.2 again involves some SQL schema changes, to make sure 'ordername' is ordered correctly for NSEC generation. For MySQL:

```
alter table records modify ordername    VARCHAR(255) BINARY;
drop index orderindex on records;
create index recordorder on records (domain_id, ordername);
```

You can test the BINARY change with the new and experimental 'pdnssec test-schema' command. For PostgreSQL, there are no real schema changes, but our indexes turned out to be inefficient, especially given the changed ordername queries in 3.2. Changes:

```
drop index orderindex;
create index recordorder on records (domain_id, ordername text_pattern_ops);
```
Additionally, with 3.2 supporting empty non-terminals (see [Rules for filling out fields in Database Backends](dnssec.md#rules-for-filling-out-fields-in-database-backends)), your frontend may need some changes.

Due to a bug, in 3.1 and earlier releases, the pipebackend would default to a 1000 second timeout for responses from scripts, instead of the intended and documented 1000 milliseconds (1 second). In 3.2, pipe-timeout is in fact in milliseconds. To avoid some surprise, the default is now 2000 (2 seconds). If you have slow pipebackend scripts, make sure to increase [`pipe-timeout`](backend-pipe.md#pipe-timeout).

Some configuration settings (that did not do anything, anyway) have been removed. You need to remove them from your configuration to start pdns\_server. They are: lazy-recursion, use-logfile, logfile.

# 3.0 to 3.1
PowerDNS 3.1 introduces native SQLite3 support for storing key material for DNSSEC in the bindbackend. With this change, support for bind+gsql-setups ('hybrid mode') has been dropped. If you were using this mode, you will need to switch to bind-dnssec-db and migrate your keying material.

There have been changes to the SQL schemas for the generic backends.

For MySQL:
```
mysql> ALTER TABLE records MODIFY content VARCHAR(64000);
mysql> ALTER TABLE tsigkeys MODIFY algorithm VARCHAR(50);
```

For PostgreSQL:
```
postgres=# ALTER TABLE records ALTER COLUMN content TYPE VARCHAR(65535);
postgres=# ALTER TABLE tsigkeys alter column algorithm type VARCHAR(50);
```

The definition of 'auth' and 'ordername' in backends has changed slightly, see [Rules for filling out fields in Database Backends](dnssec.md#rules-for-filling-out-fields-in-database-backends).

PowerDNS 3.0 and 3.1 will only fetch DNSSEC metadata and key material from the first DNSSEC-capable backend in the launch line. In 3.1, the bindbackend supports DNSSEC storage. This means that setups using `launch=bind,gsqlite3` or `launch=gsqlite3,bind` may break. Please tread carefully!

# 2.9.X to 3.0
The 3.0 release of the PowerDNS Authoritative Server is significantly different from previous 2.9.x versions. This section lists important things to be aware of.

**Warning**: Version 3.0 of the PowerDNS Authoritative Server is the biggest change in PowerDNS history. In some senses, this means that it behaves somewhat like a '1.0' version. We advise operators to carefully perform the upgrade process from 2.9.x, and if possible test on a copy of the database beforehand.

In addition, it may also be useful to have a support agreement in place during such upgrades. For first class and rapid support, please contact [powerdns-support@netherlabs.nl](mailto:powerdns-support@netherlabs.nl), or see [www.powerdns.com](http://www.powerdns.com). Alternatively, the [PowerDNS Community](http://wiki.powerdns.com) can be very helpful too.

With similar settings, version 3.0 will most likely use a lot more memory than 2.9. This is due to the new DNSSEC key & signature caches, but also because the database query cache will now store multiple row answers, which it did not do previously. Memory use can be brought down again by tuning the cache-ttl settings.

Performance may be up, or it may be down. We appreciate that this is spotty guidance, but depending on your setup, lookups may be a lot faster or a lot slower. The improved database cache may prove to be a big benefit, and improve performance dramatically. This could be offset by a near duplication of database queries needed because of more strict interpretation of DNS standards.

PowerDNS Authoritative Server 3.0 contains a completely renewed implementation of the core DNS 'Algorithm', loosely specified in RFC 1034. As stated above, our new implementation is a lot closer to the original standard. This may mean that version 3.0 may interpret the contents of your database differently from how 2.9.x interpreted them. For fully standards confirming zones, there should not be a problem, but if zones were misconfigured (no SOA record, for example), things will be different.

When compiling version 3.0, there are now more dependencies than there used to be. Whereas previously, only Boost header files were needed, PowerDNS now needs a number of Boost libraries to be installed (like boost-program-options, boost-serialization). In addition, for now Lua 5.1 is a dependency.

PowerDNS Authoritative Server 3.0 comes with DNSSEC support, but this has required big changes to database schemas. Each backend lists the changes required. To facilitate a smooth upgrade, the old, non-DNSSEC schema is used by default. Features like per-domain metadata, TSIG and DNSSEC itself however need the new schema. Consult your backend documentation for the correct 'alter table' statements. Afterwards, set the relevant '-dnssec' setting for your backend (for example: gmysql-dnssec).

In version 3.0, "Fancy Records", like URL, CURL and MBOXFW are no longer supported. In addition, the LDAP Backend has moved to 'unmaintained' status.

## Frequently Asked Questions about 3.0

Q: Can 2.9.x versions read the 3.0 DNSSEC database schema?
A: Yes, every database can be altered to the new schema without impact on 2.9. The new fields and tables are ignored.

Q: Can 3.x versions read the 2.9 pre-DNSSEC database schema?
A: Yes, as long as the relevant '-dnssec' setting is not enabled. These settings are typically called 'gmysql-dnssec', 'gpgsql-dnssec', 'gsqlite3-dnssec'. If this setting IS enabled, 3.x expects the new schema to be in place.

Q: If I run 3.0 with the new schema, and I have set '-dnssec', do I need to rectify my zones?
A: Yes. If the '-dnssec' setting is enabled, PowerDNS expects the 'auth' field to be filled out correctly. When slaving zones this happens automatically. For other zones, run 'pdnssec rectify-zone zonename'. Even if a zone is not DNSSEC secured, as long as the new schema is in place, the zone must be rectified (or at least have the 'auth' field set correctly).

Q: I want to fill out the 'auth' and 'ordername' fields directly, how do I do this?
A: The 'auth' field should be '1' or 'true' for all records that are within your zone. For a zone without delegations, this means 'auth' should always be set. If you have delegations, both the NS records for that delegation and possible glue records for it should not have 'auth' set.

For more details on 'auth' and 'ordername', please see [Rules for filling out fields in Database Backends](dnssec.md#rules-for-filling-out-fields-in-database-backends).

Q: If I don't update to the new DNSSEC schema, will 3.0 give identical answers as 2.9.x?
A: Not always. The core DNS logic of 3.0 was changed, so even if no changes are made to the database, you may get different answers. This might happen for zones without SOA records for example, which used to (more or less) work. An upgrade from 2.9.x to 3.0 should always be monitored carefully.
