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

Please note that if you are upgrading from previous version, you need to either
upgrade your schema to the latest version, or alter the queries. Also, there are
several options that are removed.

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

### `mydns-domain-id-query`
Query for looking up domain from SOA table when id is known.

### `mydns-domain-no-id-query`
Query for looking up domain from SOA table using domain name.

### `mydns-soa-query`
Query for looking up SOA record.

### `mydns-basic-query`
Query for performing lookup using name and type.

### `mydns-any-query`
Query for performing lookup using name and any type. Includes SOA record.

### `mydns-list-query`
Query for listing all records for domain.

### `mydns-use-minimal-ttl`
Setting this to 'yes' will make the backend behave like MyDNS on the TTL values.
Setting it to 'no' will make it ignore the minimal-ttl of the zone. The default
is "yes".

