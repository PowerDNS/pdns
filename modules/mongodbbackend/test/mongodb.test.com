{"domain_id" : 11, "name" : "test.com", "type" : "NATIVE", "ttl" : 3600, "SOA" : {"hostmaster" : "ahu.example.com", "nameserver" : "ns1.test.com", "serial" : 2005092501, "refresh" : 28800, "retry" : 7200, "expire" : 604800, "default_ttl" : 86400 } }
{"domain_id" : 11, "name" : "test.com", "type" : "NS", "ttl" : 3600, "content" : [ {"data" : "ns1.test.com"}, {"data" : "ns2.test.com"} ] }
{"domain_id" : 11, "name" : "test.com", "type" : "MX", "ttl" : 3600, "content" : [ {"prio" : 10, "data" : "smtp-servers.example.com"}, {"prio" : 15, "data" : "smtp-servers.test.com"} ] }
{"domain_id" : 11, "name" : "www.test.com", "type" : "CNAME", "ttl" : 3600, "content" : [ {"data" : "server1.test.com"} ] }
{"domain_id" : 11, "name" : "server1.test.com", "type" : "A", "ttl" : 3600, "content" : [ {"data" : "1.2.3.4"} ] }
{"domain_id" : 11, "name" : "server1.test.com", "type" : "RP", "ttl" : 3600, "content" : [ {"data" : "ahu.ds9a.nl. counter.test.com."} ] }
{"domain_id" : 11, "name" : "*.test.com", "type" : "CNAME", "ttl" : 3600, "content" : [ {"data" : "server1.test.com"} ] }
{"domain_id" : 11, "name" : "www.test.test.com", "type" : "A", "ttl" : 3600, "content" : [ {"data" : "4.3.2.1"} ] }
{"domain_id" : 11, "name" : "enum.test.com", "type" : "NAPTR", "ttl" : 3600, "content" : [ {"data" : "100 50 \"u\" \"e2u+sip\" \"\" testuser@domain.com."} ] }
{"domain_id" : 11, "name" : "counter.test.com", "type" : "A", "ttl" : 3600, "content" : [ {"data" : "1.1.1.5"} ] }
{"domain_id" : 11, "name" : "_ldap._tcp.dc.test.com", "type" : "SRV", "ttl" : 3600, "content" : [ {"prio" : 0, "data" : "100 389 server1.test.com"} ] }
{"domain_id" : 11, "name" : "_double._tcp.dc.test.com", "type" : "SRV", "ttl" : 3600, "content" : [ {"prio" : 0, "data" : "100 389 server1.test.com"}, {"prio" : 1, "data" : "100 389 server1.test.com"} ] }
{"domain_id" : 11, "name" : "blah.test.com", "type" : "NS", "ttl" : 3600, "content" : [ {"data" : "blah.test.com"} ] }
{"domain_id" : 11, "name" : "blah.test.com", "type" : "A", "ttl" : 3600, "content" : [ {"data" : "9.9.9.9"} ] }
{"domain_id" : 11, "name" : "images.test.com", "type" : "URL", "ttl" : 3600, "content" : [ {"data" : "http://www.ds9a.nl"} ] }
{"domain_id" : 11, "name" : "bert@auto.test.com", "type" : "MBOXFW", "ttl" : 3600, "content" : [ {"data" : "bert@ds9a.nl"} ] }
{"domain_id" : 11, "name" : "very-long-txt.test.com", "type" : "TXT", "ttl" : 3600, "content" : [ {"data" : "A very long TXT record! boy you won't believe how long. A very long TXT record! boy you won't believe how long. A very long TXT record! boy you won't believe how long. A very long TXT record! boy you won't believe how long. A very long TXT record! boy you won't believe how long!" } ] }
