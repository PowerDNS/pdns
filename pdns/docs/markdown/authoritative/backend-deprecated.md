This page contains some information about deprecated backends.

# ODBC backend
**Note**: This backend was removed in version 3.1.

| | |
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
