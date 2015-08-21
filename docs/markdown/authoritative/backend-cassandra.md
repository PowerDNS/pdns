# Cassandra backend
|&nbsp;|&nbsp;|
|:--|:--|
|Native|Yes|
|Master|No|
|Slave|No|
|Superslave|No|
|DNSSEC|No|
|Module name|cassandra|
|Launch name|cassandra|

This is a backend powered by a columnar NoSql database [Apache Cassandra](http://cassandra.apache.org/), ritten for the 3.4 release & above, with easily configurable cassandra cluster parameters.

Steps of creating a cluster is given [here](http://wiki.apache.org/cassandra/GettingStarted).
For the cassandra's client driver binary packages are [available](http://downloads.datastax.com/cpp-driver/) (CentOS, Ubuntu, and Windows) or the driver can be built from [source](http://datastax.github.io/cpp-driver/topics/building/).

## Configuration Parameters

### `cassandra-seed-nodes`
Cassandra seed nodes of the cluster. If there are more than 1 seeds, use comma separated ip addresses.

### `cassandra-username`, `cassandra-password`
Cassandra credentials. By default cassandra starts with credentials cassandra/cassandra.

### `cassandra-keyspace`
The keyspace/schema to use for store & access contents.

### `cassandra-core-connections`, `cassandra-max-connections`, `cassandra-max-concurrent-creations`
Parameters for the cassandra connection pool with their defaults.
cassandra-core-connections=40
cassandra-max-connections=100
cassandra-max-concurrent-creations=100

### `cassandra-queue-size-io`, `cassandra-queue-size-event`, `cassandra-reconnect-wait-time`, `cassandra-concurrent-requests-threshold`
### `cassandra-connect-timeout`, `cassandra-request-timeout`, `cassandra-num-io-threads`, `cassandra-enable-tcp-nodelay`, `cassandra-enable-tcp-keepalive`
Some more parameters of cassandra client's driver. The below defaults will work in most of the cases.
cassandra-queue-size-io=4096
cassandra-queue-size-event=4096
cassandra-reconnect-wait-time=2000
cassandra-concurrent-requests-threshold=100
cassandra-connect-timeout=5000
cassandra-request-timeout=12000
cassandra-num-io-threads=1
cassandra-enable-tcp-nodelay=0
cassandra-enable-tcp-keepalive=0
Details about the configurations can be found at [here](http://datastax.github.io/cpp-driver/api/CassCluster/).

### `cassandra-protocol-version`
Cassandra have various connection protocols (1,2,3). Best being 'version 3'. Modify only if you have a very good reason for doing it.
cassandra-protocol-version=3

### `cassandra-enable-load-balance-round-robin`,`cassandra-enable-token-aware-routing`,`cassandra-enable-latency-aware-routing`
The load balancing strategy in the cassandra cluster to use. By default, "round-robin" is enabled.
cassandra-enable-load-balance-round-robin=1   (enabled)
cassandra-enable-token-aware-routing=0        (disabled)
cassandra-enable-latency-aware-routing=0      (disabled)

## The Database Schema
The database schema is mentioned in `script.cql` in the PowerDNS source distribution. 

### Keyspace
Keyspace used is pdns.

### Table DOMAIN\_LOOKUP\_RECORDS
This table lists the zones for which PowerDNS is supposed to be an authoritative nameserver.

#### domain
The FQDN of the zone apex, e.g. 'example.com'.

#### recordmap
This is a map of various record types as key and records (UDT i.e. cassandra's user defined datatype) as value.
Various record type keys are
A, NS, CNAME, SOA, MR, WKS, PTR, HINFO, MINFO, MX, TXT, RP, AFSDB, SIG, KEY, AAAA, LOC, SRV, NAPTR, KX,
CERT, A6, DNAME, OPT, DS, SSHFP, IPSECKEY, RRSIG, NSEC, DNSKEY, DHCID, NSEC3, NSEC3PARAM,
TLSA, SPF, EUI48, EUI64, TKEY, TSIG, IXFR, AXFR, MAILB, MAILA, ANY, ADDR, ALIAS, DLV

#### disabled
Whether the domain is disabled (soft deleted).

#### creation\_time
Creation time of the record.

### UDT records

#### record
This contains a map between the "dns record" as key and its "ttl" as the value
##### Note
For SOA record type, the "dns record" key has to have the below format separated by '#' as delimiter
domain_id nameserver	hostname    serial refresh retry expiry default_ttl
E.g.:
10#ns1.dns.com#hm1.dns.com#0#10#10#10#10


### Table DOMAIN\_ID\_DOMAIN\_RELATION
Cassandra doesnot support queries by non primary keys unless and until its indexed. Indexes should be avoided if possible.
Hence this table is used to handle id based AXFR lookups in powerdns.

#### domain_id
Domain's id for which the AXFR lookup is to be made..

#### domain
A set of domains attached to the id.
Any AXFR lookup will make the query to this table, get the list of domains and use it to lookup DOMAIN\_LOOKUP\_RECORDS for the result.

### Sample inserts to the database

insert into pdns.DOMAIN_LOOKUP_RECORDS (domain,recordmap,disabled,creation_time) values ('cassandra.pdns.com',{ 'A': { record:{'127.0.1.255':123,'127.0.0.1':234} } , 'TXT': { record:{'TXT Record1':345,'TXT Record2':456} } , 'SOA': { record:{'10#ns1.dns.com#hm1.dns.com#0#10#10#10#10':3600} }},False,'2015-05-05 15:00:41+0530');
update pdns.DOMAIN_ID_DOMAIN_RELATION set domain = domain+{'cassandra.pdns.com'} where domain_id = 10;

insert into pdns.DOMAIN_LOOKUP_RECORDS (domain,recordmap,disabled,creation_time) values ('nxdomain.test.com',{ 'A': { record:{'127.0.1.255':123} } , 'TXT': { record:{'TXT Record1':345,'TXT Record2':456} } , 'SOA': { record:{'10#ns1.dns.com#hm1.dns.com#0#10#10#10#10':3600} }},False,'2015-05-05 15:00:41+0530');
update pdns.DOMAIN_ID_DOMAIN_RELATION set domain = domain+{'nxdomain.test.com'} where domain_id = 10;

insert into pdns.DOMAIN_LOOKUP_RECORDS (domain,recordmap,disabled,creation_time) values ('cassandra.pdns.org',{ 'A': { record:{'127.0.1.255':123} } , 'TXT': { record:{'TXT Record1':345,'TXT Record2':456} } , 'SOA': { record:{'1#ns1.dns.com#hm1.dns.com#1#10#10#10#10':3600} }},False,'2015-05-05 15:00:41+0530');
update pdns.DOMAIN_ID_DOMAIN_RELATION set domain = domain+{'cassandra.pdns.org'} where domain_id = 1;

select * from domain_lookup_records;
select * from domain_id_domain_relation;

## Examples

```
$ dig ANY cassandra.pdns.org @127.0.0.1

; <<>> DiG 9.8.3-P1 <<>> ANY cassandra.pdns.org @127.0.0.1
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 62399
;; flags: qr aa rd; QUERY: 1, ANSWER: 4, AUTHORITY: 0, ADDITIONAL: 0
;; WARNING: recursion requested but not available

;; QUESTION SECTION:
;cassandra.pdns.org.		IN	ANY

;; ANSWER SECTION:
cassandra.pdns.org.	123	IN	A	127.0.1.255
cassandra.pdns.org.	3600	IN	SOA	ns1.dns.com. hm1.dns.com. 1 10 10 10 10
cassandra.pdns.org.	456	IN	TXT	"TXT Record2"
cassandra.pdns.org.	345	IN	TXT	"TXT Record1"

;; Query time: 9 msec
;; SERVER: 127.0.0.1#53(127.0.0.1)
;; WHEN: Tue Aug 18 15:19:38 2015
;; MSG SIZE  rcvd: 151


$ dig AXFR cassandra.pdns.org @127.0.0.1

; <<>> DiG 9.8.3-P1 <<>> AXFR cassandra.pdns.org @127.0.0.1
;; global options: +cmd
cassandra.pdns.org.	3600	IN	SOA	ns1.dns.com. hm1.dns.com. 1 10 10 10 10
cassandra.pdns.org.	123	IN	A	127.0.1.255
cassandra.pdns.org.	345	IN	TXT	"TXT Record1"
cassandra.pdns.org.	456	IN	TXT	"TXT Record2"
cassandra.pdns.org.	3600	IN	SOA	ns1.dns.com. hm1.dns.com. 1 10 10 10 10
;; Query time: 8 msec
;; SERVER: 127.0.0.1#53(127.0.0.1)
;; WHEN: Tue Aug 18 15:20:17 2015
;; XFR size: 5 records (messages 3, bytes 274)
```