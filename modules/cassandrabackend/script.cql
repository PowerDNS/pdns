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

SELECT columnfamily_name FROM system.schema_columnfamilies WHERE keyspace_name='pdns';


--Example
-- insert into pdns.DOMAIN_LOOKUP_RECORDS (domain,recordmap,disabled,creation_time) values ('cassandra.pdns.com',{ 'A': { record:{'127.0.1.255':123,'127.0.0.1':234} } , 'TXT': { record:{'TXT Record1':345,'TXT Record2':456} } , 'SOA': { record:{'10#ns1.dns.com#hm1.dns.com#0#10#10#10#10':3600} }},False,'2015-05-05 15:00:41+0530');
-- insert into pdns.DOMAIN_LOOKUP_RECORDS (domain,recordmap,disabled,creation_time) values ('nxdomain.test.com',{ 'A': { record:{'127.0.1.255':123} } , 'TXT': { record:{'TXT Record1':345,'TXT Record2':456} } , 'SOA': { record:{'10#ns1.dns.com#hm1.dns.com#0#10#10#10#10':3600} }},False,'2015-05-05 15:00:41+0530');
-- select * from domain_lookup_records;