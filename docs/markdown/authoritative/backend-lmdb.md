# LMDB (high performance) backend
|&nbsp;|&nbsp;|
|:--|:--|
|Native|Yes|
|Master|No|
|Slave|No|
|Superslave|No|
|Autoserial|No|
|DNSSEC|No|
|Module name|lmdb|
|Launch|lmdb|

Based on the [LMDB key-value database](http://symas.com/mdb/), the LMDB backend turns powerdns into a very high performance and DDOS-resilient authoritative DNS server. Testing on a 32-core server shows the ability to answer up to 400,000 queries per second with instant startup and real-time updates independent of database size.

## Configuration Parameters
### `lmdb-datapath`
Location of the database to load

## Operation
Unlike other backends, LMDB does not require any special configuration. New or updated zones are available the next query after the update transaction is committed. If the underlying database is removed or recreated then the reload command should be sent through to powerdns to get it to close and reopen the database.

## Database Format
A full example script for generating a database can be found in pdns/modules/lmdbbackend/lmdb-example.pl. Basically the database environment is comprised of three databases to store the data:

### Zone Database
Each key in the zone database is the reversed lower-cased name of the zone without leading or trailing dots (ie for example.com the key would be moc.elpmaxe).

Each value in the database must contain the following data (tab-separated):

* Zone ID: The Zone's unique integer ID in ASCII (32-bit)
* TTL: The TTL for the zone's SOA record
* SOA data: space-separated SOA data eg
```
ns.foo.com. hostmaster.foo.com. <serial> <refresh> <retry> <expire> <minimum>
```

If refresh, retry, expire or minimum are not specified then the powerdns defaults will be used

### Data Database
This database is required to have been created with the MDB\_DUPSORT flag enabled. It stores the records for each domain. Each key must contain the following data (tab-separated):

* Record name: The reversed lower-cased name of the record and zone without leading or trailing dots
* Record type: The type of record A, NS, PTR etc. SOA is not allowed as it is automatically created from the zone database records.

The value for each entry must contain the following data (tab-separated). If the length of this record is greater than the LMDB limit of 510 bytes (for DUPSORT databases) an entry of "REF" followed by the tab character and a unique 32-bit ASCII integer which contains a reference into [the section called “extended\_data database”](#extended-data-database).

* Zone ID: The Zone's unique integer ID in ASCII (32-bit)
* TTL: The TTL for the SOA record
* Record data: The record's data entry. For MX/SRV records the priority is the first field and space-separated from the rest of the data. Care must be taken to escape the data appropriately for PowerDNS. As in the Pipe backend " and \\ characters are not allowed and any it is advised that any characters outside of ASCII 32-126 are escaped using the \\ character.

### extended\_data database
If the length of the value that you wish to insert into [the section called “data database”](#data-database) is longer than 510 bytes you need to create the REF entry as described above linked in to this table. The value is a unique 32-bit integer value formatted in ASCII and the value is the exact same format as it would have been in [the section called “data database”](#data-database) but can be however long you require.

### Example database structure
(as output by the pdns/modules/lmdbbackend/lmdb-example.pl example script and shown by pdns/modules/lmdbbackend/dumpdb.pl)

```
# perl dumpdb.pl /var/tmp/lmdb zone
key: moc.elpmaxe; value: 1      300     ns.example.com. hostmaster.example.com. 2012021101 86400 7200 604800 86400
# perl dumpdb.pl /var/tmp/lmdb data
key: moc.elpmaxe        MX; value: 1    300     10 mail.example.com
key: moc.elpmaxe        NS; value: 1    300     ns.example.com
key: moc.elpmaxe.tset   A; value: 1     300     192.0.2.66
key: moc.elpmaxe.txet   TXT; value: 1   300     test\010123
key: moc.elpmaxe.txetgnol       TXT; value: REF 1
# perl dumpdb.pl /var/tmp/lmdb extended_data
key: 1; value: 1        300     AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```
