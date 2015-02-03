This page contains some information about deprecated backends.

# DB2 Backend
**Note**: This backend was removed in version 3.5.0.

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
Server name to connect to. Defaults to 'powerdns'. Make sure that your nameserver is not needed to resolve an IP address needed to connect as this might lead

### `db2-user`
Username to connect as. Defaults to 'powerdns'.

### `db2-password`
Password to connect with. Defaults to 'powerdns'.

# ODBC backend
**Note**: This backend was removed in version 3.1.

|&nbsp;|&nbsp;|
|:--|:--|
|Native|Yes|
|Master|Yes (experimental)|
|Slave|Yes (experimental)|
|Superslave|No|
|Autoserial|Yes|

The ODBC backend can retrieve zone information from any source that has a ODBC driver available.

**Note** This backend is only available on PowerDNS for Windows.

The ODBC backend needs data in a fixed schema which is the same as the data needed by the MySQL backend. The create statement will resemble this:

```
          CREATE TABLE records (
      id int(11) NOT NULL auto_increment,
      domain_id int(11) default NULL,
      name varchar(255) default NULL,
      type varchar(10) default NULL,
      content varchar(255) default NULL,
      ttl int(11) default NULL,
      prio int(11) default NULL,
      change_date int(11) default NULL,
      PRIMARY KEY (id),
      KEY name_index(name),
      KEY nametype_index(name,type),
      KEY domainid_index(domain_id)
      );
```

To use the ODBC backend an ODBC source has to be created, to do this see the section Installing PowerDNS on Microsoft Windows, not included in the documentation as installation on Windows is not supported.

## Configuration Parameters
### `odbc-datasource`
Specifies the name of the data source to use.

### `odbc-user`
Specifies the username that has to be used to log into the data source.

### `odbc-pass`
Specifies the user's password.

### `odbc-table`
Specifies the name of the table containing the zone information.

The ODBC backend has been tested with Microsoft Access, MySQL (via MyODBC) and Microsoft SQLServer. As the SQL statements used are very basic, it is expected to work with many ODBC drivers.

# XDB Backend
No longer part of PowerDNS.
