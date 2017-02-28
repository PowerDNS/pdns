@ IN 7200 SOA ns1 marka.isc.org. (0 0 0 0 1)
www IN A 127.0.0.1
@ NS ns1
ns1 A 127.0.0.1
$TTL 3600
ns2 A 127.0.0.2
ns3 IN 86400 A 127.0.0.3

