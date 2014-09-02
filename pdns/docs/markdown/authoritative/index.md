# PowerDNS Authoritative Nameserver
The PowerDNS Authoritative Server is a versatile nameserver which supports a large number of backends. These backends can either be plain zone files or be more dynamic in nature.

Prime examples of backends include relational databases, but also (geographical) load balancing and failover algorithms.

# Backends
PowerDNS has the concepts of 'backends'. A backend is a datastore that the server will consult that contains DNS records (and some meta-data).
The backends range from database backends (Mysql, PostGreSQL, Oracle) and Bind-zonefiles to co-processes and JSON API's.

Multiple backends can be enabled in the configuration by using the `[launch](settings.md#launch)` option. Each backend can be configured separetly.

## Backend Capabilities
The following table describes the capabilitie of the backends.

| Name | Status | Native | Master | Slave | Superslave | Autoserial | DNSSEC | Disabled Data | Comments | Launch Name |
|:---|:---|:---|:---|:---|:---|:---|:---|:---|:---|:---|
| BIND | Supported | Yes | Yes | Experimental | No | Yes | No | No | No | `bind` |
| DB2 | Unsupported | Yes | No | No | No | Yes | No | No | No | `db2` |
| MySQL | Supported | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | `gmysql` |
| PostGreSQL | Supported | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes | `gpgsql` |
| Geo | Beta | Partial | No | No | No | No | Unknown (No) | Yes (no key storage) | Unknown (No) | Unknown (No) | `geo` |
| SQLite 2 | Supported (not recommended) | Yes | Yes | Yes | Yes | No | No | No | `gsqlite` |
| SQLite 3 | Supported | Yes | Yes | Yes | Yes | Yes | Yes  | Yes | `gsqlite3` |
| LDAP | Unmaintained | Yes | No | No | No | No | No | Unknown (No) | Unknown (No) | Unknown |
| LMDB | Supported | Yes | No | No | No | No | No | Unknown (No) | Unknown (No) | `lmdb`|
| Oracle | Supported | Yes | Yes | Yes | Yes | Yes | Yes | Unknown (No) | No | `oracle` |
| Pipe | Supported | Yes | No | No | No | No | Partial (no delegation, no key storage) | No | No | `pipe` |
| Random | Supported | Yes | No | No | No | No | Yes (no key storage) | No | No | `random` |
| Remote | Supported | Yes | Yes\* | Yes\* | Yes\* | Yes\* | Yes\* | Unknown (No) | Unknown(No) | `remote` |
| TinyDNS | Experimental | Yes | Yes | No | No | No | No | Unknown (No) | Unknown (No) | `tinydns` |

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
