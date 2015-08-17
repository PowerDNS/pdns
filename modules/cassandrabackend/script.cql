CREATE USER pdns WITH PASSWORD 'pdns';

select * from system_auth.users;

CREATE KEYSPACE pdns WITH replication = {'class': 'SimpleStrategy' , 'DC1' : 1};

select * from system.schema_keyspaces;

use pdns;

CREATE TYPE records (
  record map<text,int>,  --Map of record and ttl 
);

create table if not exists pdns.DOMAIN_LOOKUP_RECORDS (
domain varchar, -- domain regex that will be looked up
recordmap map<varchar,frozen<records>>, --Map of Record Type and Value set
--Key is case insensitive and is maintained in QType enum
disabled boolean,  --The field can be used to temporarily disable the record
creation_time timestamp,
PRIMARY KEY(domain));

-- This table will be used for AXFR lookup
create table if not exists pdns.DOMAIN_ID_DOMAIN_RELATION (
domain_id int, -- domain id
domain set<text>, -- domain
PRIMARY KEY(domain_id));

SELECT columnfamily_name FROM system.schema_columnfamilies WHERE keyspace_name='pdns';


--Example
-- insert into pdns.DOMAIN_LOOKUP_RECORDS (domain,recordmap,disabled,creation_time) values ('cassandra.pdns.com',{ 'A': { record:{'127.0.1.255':123,'127.0.0.1':234} } , 'TXT': { record:{'TXT Record1':345,'TXT Record2':456} } , 'SOA': { record:{'10#ns1.dns.com#hm1.dns.com#0#10#10#10#10':3600} }},False,'2015-05-05 15:00:41+0530');
-- update pdns.DOMAIN_ID_DOMAIN_RELATION set domain = domain+{'cassandra.pdns.com'} where domain_id = 10;
-- insert into pdns.DOMAIN_LOOKUP_RECORDS (domain,recordmap,disabled,creation_time) values ('nxdomain.test.com',{ 'A': { record:{'127.0.1.255':123} } , 'TXT': { record:{'TXT Record1':345,'TXT Record2':456} } , 'SOA': { record:{'10#ns1.dns.com#hm1.dns.com#0#10#10#10#10':3600} }},False,'2015-05-05 15:00:41+0530');
-- update pdns.DOMAIN_ID_DOMAIN_RELATION set domain = domain+{'nxdomain.test.com'} where domain_id = 10;
-- select * from domain_lookup_records;
-- select * from domain_id_domain_relation;
-- Format of SOA record "domain_id nameserver	hostname    serial refresh retry expiry default_ttl" delimited by "#"