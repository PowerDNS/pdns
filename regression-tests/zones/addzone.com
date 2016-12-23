$TTL 3600
$ORIGIN addzone.com.
@		IN	SOA	ns1.addzone.com.	ahu.example.com. (  2005092501
			8H ; refresh
			2H ; retry
			1W ; expire
			1D ; default_ttl
			)

@			IN	NS	ns1
@			IN	NS	ns2
@			IN	MX	10	smtp-servers.example.com.
@			IN	MX	15	smtp-servers
ns1			IN	A	1.1.1.5
ns2			IN	A	2.2.2.2
www			IN	CNAME	server1
server1			IN	A	1.2.3.4
			IN	RP	ahu.ds9a.nl. counter
*.test			IN	CNAME	server1
www.test		IN	A	4.3.2.1
sub.test		IN	NS	ns-test.example.net
enum			IN	NAPTR 100 50 "u" "e2u+sip" "" testuser.domain.com.
counter			IN	A	1.1.1.5
_ldap._tcp.dc		IN	SRV 	0 100 389 server2.example.net.
_double._tcp.dc		IN	SRV 	0 100 389 server1
_double._tcp.dc		IN	SRV 	1 100 389 server1
_root._tcp.dc		IN	SRV	0 0 0 .
blah			IN	NS	blah
blah			IN	A	192.168.6.1
very-long-txt		IN	TXT	"A very long TXT record! boy you won't believe how long. A very long TXT record! boy you won't believe how long. A very long TXT record! boy you won't believe how long. A very long TXT record! boy you won't believe how long. A very long TXT record! boy you won't believe how long!"
within-server		IN	CNAME	outpost.example.com.
_underscore		IN	TXT	"underscores are terrible"
b.c			IN	A	5.6.7.8
*.a.b.c			IN	A	8.7.6.5
aland		IN TXT "\195\133LAND ISLANDS"
hightxt		IN	TXT	"v=spf1 mx ip4:78.46.192.210 –all"
