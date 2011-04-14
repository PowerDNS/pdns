{"domain_id" : 12, "name" : "wtest.com", "type" : "NATIVE", "ttl" : 3600, "SOA" : {"hostmaster" : "ahu.example.com", "nameserver" : "ns1.wtest.com", "serial" : 2005092501, "refresh" : 28800, "retry" : 7200, "expire" : 604800, "default_ttl" : 86400 } }
{"domain_id" : 12, "name" : "wtest.com", "type" : "NS", "ttl" : 3600, "content" : [ {"data" : "ns1.wtest.com"}, {"data" : "ns2.wtest.com"} ] }
{"domain_id" : 12, "name" : "wtest.com", "type" : "A", "ttl" : 3600, "content" : [ {"data" : "9.9.9.9"} ] }
{"domain_id" : 12, "name" : "wtest.com", "type" : "MX", "ttl" : 3600, "content" : [ {"prio" : 10, "data" : "smtp-servers.example.com"}, {"prio" : 15, "data" : "smtp-servers.wtest.com"} ] }
{"domain_id" : 12, "name" : "*.wtest.com", "type" : "CNAME", "ttl" : 3600, "content" : [ {"data" : "server1.wtest.com"} ] }
{"domain_id" : 12, "name" : "secure.wtest.com", "type" : "MX", "ttl" : 3600, "content" : [ {"prio" : 10, "data" : "server1.wtest.com"} ] }
{"domain_id" : 12, "name" : "server1.wtest.com", "type" : "A", "ttl" : 3600, "content" : [ {"data" : "1.2.3.4"} ] }
{"domain_id" : 12, "name" : "*.something.wtest.com", "type" : "A", "ttl" : 3600, "content" : [ {"data" : "4.3.2.1"} ] }
