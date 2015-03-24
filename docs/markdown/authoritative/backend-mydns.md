# MyDNS Backend
|&nbsp;|&nbsp;|
|:--|:--|
|Native|Yes|
|Master|No|
|Slave|No|
|Superslave|No|
|Autoserial|No|
|Case|Depends|
|DNSSEC|No|
|Disabled data|No|
|Comments|No|
|Module name|`mydns`|
|Launch name|`mydns`|

The MyDNS backend makes PowerDNS a drop-in replacement for the
[MyDNS](http://mydns.bboy.net/) nameserver, as it uses the same database schema.

## Configuration Parameters
### `mydns-host`
Database host to connect to.

### `mydns-port`
Port on the database server to connect to.

### `mydns-dbname`
Name of the database to connect to, "mydns" by default.

### `mydns-user`
User for the database, "powerdns" by default.

### `mydns-password`
The user password.

### `mydns-socket`
Unix socket to connect to the database.

### `mydns-rr-table`
Name of the resource record table in the database, "rr" by default.

### `mydns-soa-table`
Name of the SOA table in the database, "soa" by default.

### `mydns-soa-where`
Additional WHERE clause for SOA, default is "1 = 1".

### `mydns-rr-where`
Additional WHERE clause for resource records, default is "1 = 1".

### `mydns-soa-active`
Use the active column in the SOA table, "yes" by default.

### `mydns-rr-active`
Use the active column in the resource record table, "yes" by default.

### `mydns-use-minimal-ttl`
Setting this to 'yes' will make the backend behave like MyDNS on the TTL values.
Setting it to 'no' will make it ignore the minimal-ttl of the zone. The default
is "yes".

