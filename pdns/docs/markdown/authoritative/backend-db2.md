# DB2 Backend
**Note**: This backend is unsupported.

|&nbsp;|&nbsp;|
|:--|:--|
|Native|Yes|
|Master|No|
|Slave|No|
|Superslave|No|
|Autoserial|Yes|
|DNSSEC|No|
|Disabled data|No|
|Comments|No|
|Module name|db2
|Launch name|db2|

PowerDNS is currently ascertaining if this backend can be distributed in binary form without violating IBM DB2 licensing.

## Queries
The DB2 backend executes the following queries:

### Forward Query
select Content, TimeToLive, Priority, Type, ZoneId, 0 as ChangeDate, Name from Records where Name = ? and type = ?

### Forward By Zone Query
select Content, TimeToLive, Priority, Type, ZoneId, 0 as ChangeDate, Name from Records where Name = ? and Type = ? and ZoneId = ?

### Forward Any Query
select Content, TimeToLive, Priority, Type, ZoneId, 0 as ChangeDate, Name from Records where Name = ?

### List Query
select Content, TimeToLive, Priority, Type, ZoneId, 0 as ChangeDate, Name from Records where ZoneId = ?

## Configuration Parameters

### `db2-server`
Server name to connect to. Defaults to 'powerdns'. Make sure that your nameserver is not needed to resolve an IP address needed to connect as this might lead to a chicken/egg situation.

### `db2-user`
Username to connect as. Defaults to 'powerdns'.

### `db2-password`
Password to connect with. Defaults to 'powerdns'.
