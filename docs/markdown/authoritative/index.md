# PowerDNS Authoritative Nameserver
The PowerDNS Authoritative Server is a versatile nameserver which supports a large number of backends. These backends can either be plain zone files or be more dynamic in nature.

Examples of backends include relational databases, other DNS data formats and coprocesses.

# Backends
PowerDNS has the concepts of 'backends'. A backend is a datastore that the server will consult that contains DNS records (and some meta-data).
The backends range from database backends (Mysql, PostgreSQL, Oracle) and Bind-zonefiles to co-processes and JSON API's.

Multiple backends can be enabled in the configuration by using the [`launch`](settings.md#launch) option. Each backend can be configured separetly.

## Backend Capabilities
The following table describes the capabilities of the backends.

| Name | Status | Native | Master | Slave | Superslave | [Autoserial](backend-generic-sql.md#autoserial) | DNSSEC | [Disabled Data](backend-generic-sql.md#disabled-data) | Comments | Launch Name |
|:---|:---|:---|:---|:---|:---|:---|:---|:---|:---|:---|
| [BIND](backend-bind.md) | Supported | Yes | Yes | Yes | Experimental | No | Yes | No | No\* | `bind` |
| [Generic MySQL](backend-generic-mysql.md) | Supported | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | `gmysql` |
| [Generic ODBC](backend-generic-odbc.md) | Supported | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes| `godbc` |
| [Generic Oracle](backend-generic-oracle.md) | Supported | Yes | Yes | Yes | Yes | Yes | Yes  | Yes | Yes | `goracle` |
| [Generic PostgreSQL](backend-generic-postgresql.md) | Supported | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | `gpgsql` |
| [Generic SQLite 3](backend-generic-sqlite.md) 3 | Supported | Yes | Yes | Yes | Yes | Yes | Yes  | Yes | Yes | `gsqlite3` |
| [GeoIP](backend-geoip.md) | Supported | Yes | No | No | No | No | Yes | No | No | `geoip` |
| [LDAP](backend-ldap.md) | Supported | Yes | No | No | No | No | No | No | No | `ldap` |
| [MyDNS](backend-mydns.md) | Supported | Yes | No | No | No | No | No | No | No | `mydns` |
| [OpenDBX](backend-opendbx.md) | Supported | Yes | Yes | Yes | Yes | No | No | No | No | `opendbx` |
| [Oracle](backend-oracle.md) | Supported | Yes | Yes | Yes | Yes | Yes | Yes | No | No | `oracle` |
| [Pipe](backend-pipe.md) | Supported | Yes | No | No | No | No | Partial (no delegation, no key storage) | No | No | `pipe` |
| [Random](backend-random.md) | Supported | Yes | No | No | No | No | Yes (no key storage) | No | No | `random` |
| [Remote](backend-remote.md) | Supported | Yes | Yes\* | Yes\* | Yes\* | Yes\* | Yes\* | No | No | `remote` |
| [TinyDNS](backend-tinydns.md) | Experimental | Yes | Yes | No | No | No | No | No | No | `tinydns` |

\*: Please read the backend-specific documentation.

### Native, Master, Slave, Superslave
Which [Mode of Operation](modes-of-operation.md) (DNS data replication) is supported.

### Autoserial
Can the backend [automatically](backend-generic-sql.md#autoserial) generate a SOA serial

### DNSSEC
Is serving DNSSEC signed data supported?

### Disabled Data
Can a record be [marked 'disabled'](backend-generic-sql.md#disabled-data) and not be served but still be in the datastore?

### Comments
Are comments on records supported?
