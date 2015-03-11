# PowerDNS Authoritative Nameserver
The PowerDNS Authoritative Server is a versatile nameserver which supports a large number of backends. These backends can either be plain zone files or be more dynamic in nature.

Examples of backends include relational databases, other DNS data formats and coprocesses.

# Backends
PowerDNS has the concepts of 'backends'. A backend is a datastore that the server will consult that contains DNS records (and some meta-data).
The backends range from database backends (Mysql, PostgreSQL, Oracle) and Bind-zonefiles to co-processes and JSON API's.
For more in-depth information, see [Modules & Backends](internals.md#modules-backends) in the documentation on internals.

Multiple backends can be enabled in the configuration by using the [`launch`](settings.md#launch) option. Each backend can be configured separetly.

## Backend Capabilities
The following table describes the capabilities of the backends.

| Name | Status | Native | Master | Slave | Superslave | Autoserial | DNSSEC | Disabled Data | Comments | Launch Name |
|:---|:---|:---|:---|:---|:---|:---|:---|:---|:---|:---|
| [BIND](backend-bind.md) | Supported | Yes | Yes | Yes | Experimental | No | Yes | No | No | `bind` |
| [Geo](backend-geo.md) | Beta | Partial | No | No | No | No | Yes (no key storage) | Unknown (No) | Unknown (No) | Unknown (No) | `geo` |
| [LDAP](backend-ldap.md) | Unmaintained | Yes | No | No | No | No | No | Unknown (No) | Unknown (No) | Unknown |
| [LMDB](backend-lmdb.md) | Supported | Yes | No | No | No | No | No | Unknown (No) | Unknown (No) | `lmdb`|
| [MySQL](backend-generic-mypgsql.md) | Supported | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | `gmysql` |
| [MyDNS](backend-mydns.md) | Supported | Yes | No | No | No | No | No | No | No | `mydns` |
| [OpenDBX](backend-opendbx.md) | Supported | Yes | Yes | Yes | Yes | Unknown (No) | No | Unknown (No) | Unknown (No) | `opendbx` |
| [Oracle](backend-oracle.md) | Supported | Yes | Yes | Yes | Yes | Yes | Yes | Unknown (No) | No | `oracle` |
| [Pipe](backend-pipe.md) | Supported | Yes | No | No | No | No | Partial (no delegation, no key storage) | No | No | `pipe` |
| [PostgreSQL](backend-generic-mypgsql.md) | Supported | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | `gpgsql` |
| [Random](backend-random.md) | Supported | Yes | No | No | No | No | Yes (no key storage) | No | No | `random` |
| [Remote](backend-remote.md) | Supported | Yes | Yes\* | Yes\* | Yes\* | Yes\* | Yes\* | Unknown (No) | Unknown(No) | `remote` |
| [SQLite](backend-gsqlite.md) 2 | Supported (not recommended) | Yes | Yes | Yes | Yes | No | No | No | No | `gsqlite` |
| [SQLite](backend-gsqlite.md) 3 | Supported | Yes | Yes | Yes | Yes | Yes | Yes  | Yes | Yes | `gsqlite3` |
| [TinyDNS](backend-tinydns.md) | Experimental | Yes | Yes | No | No | No | No | Unknown (No) | Unknown (No) | `tinydns` |

\*: Please read the backend-specific documentation.

### Native, Master, Slave, Superslave
Which [Mode of Operation](modes-of-operation.md) (DNS data replication) is supported.

### Autoserial

### DNSSEC
Is serving DNSSEC signed data supported?

### Disabled Data
Can a record be marked 'disabled' and not be served but still be in the datastore?

### Comments
Are comments on records supported?
