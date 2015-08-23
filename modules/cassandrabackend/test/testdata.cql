use pdns;
insert into pdns.DOMAIN_LOOKUP_RECORDS (domain,recordmap,disabled,creation_time) values ('cassandra.pdns.com',{ 'A': { record:{'127.0.1.255':123,'127.0.0.1':234} } , 'TXT': { record:{'TXT Record1':345,'TXT Record2':456} } , 'SOA': { record:{'10#ns1.dns.com#hm1.dns.com#0#10#10#10#10':3600} }},False,'2015-05-05 15:00:41+0530');
update pdns.DOMAIN_ID_DOMAIN_RELATION set domain = domain+{'cassandra.pdns.com'} where domain_id = 10;
insert into pdns.DOMAIN_LOOKUP_RECORDS (domain,recordmap,disabled,creation_time) values ('nxdomain.test.com',{ 'A': { record:{'127.0.1.255':123} } , 'TXT': { record:{'TXT Record1':345,'TXT Record2':456} } , 'SOA': { record:{'10#ns1.dns.com#hm1.dns.com#0#10#10#10#10':3600} }},False,'2015-05-05 15:00:41+0530');
update pdns.DOMAIN_ID_DOMAIN_RELATION set domain = domain+{'nxdomain.test.com'} where domain_id = 10;
insert into pdns.DOMAIN_LOOKUP_RECORDS (domain,recordmap,disabled,creation_time) values ('cassandra.pdns.org',{ 'A': { record:{'127.0.1.255':123} } , 'TXT': { record:{'TXT Record1':345,'TXT Record2':456} } , 'SOA': { record:{'1#ns1.dns.com#hm1.dns.com#1#10#10#10#10':3600} }},False,'2015-05-05 15:00:41+0530');
update pdns.DOMAIN_ID_DOMAIN_RELATION set domain = domain+{'cassandra.pdns.org'} where domain_id = 1;
select * from domain_lookup_records;
select * from domain_id_domain_relation;
