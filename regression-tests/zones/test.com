$TTL 3600
$ORIGIN test.com.
@		IN	SOA	ns1.test.com.	ahu.example.com. (  2005092501
			8H ; refresh
			2H ; retry
			1W ; expire
			1D ; default_ttl
			)

@			IN	NS	ns1
@			IN	NS	ns2
@			IN	MX	10	.
@			IN	MX	15	smtp-servers
ns1			IN	A	1.1.1.1
ns2			IN	A	2.2.2.2
toroot			IN	CNAME	.
www			IN	CNAME	server1
server1			IN	A	1.2.3.4
			IN	RP	ahu.ds9a.nl. counter
*.test			IN	CNAME	server1
www.test		IN	A	4.3.2.1
sub.test		IN	NS	ns-test.example.net
enum			IN	NAPTR 100 50 "u" "e2u+sip" "" server1.test.com.
ensm			IN	NAPTR 100 50 "s" "e2u+sip" "" _double._tcp.dc.test.com.
enam			IN	NAPTR 100 50 "a" "e2u+sip" "" server1.test.com.
naptr			IN	NAPTR 100 50 "u" "e2u+sip" "" server1.test.com.
naptr			IN	NAPTR 100 50 "s" "e2u+sip" "" _double._tcp.dc.test.com.
naptr			IN	NAPTR 100 50 "a" "e2u+sip" "" server1.test.com.
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
hightxt		IN	SPF	"v=spf1 mx ip4:78.46.192.210 –all"
d		IN	DNAME	d2.test2.com.
urc65226	IN	TYPE65226 \# 3 414243
interrupted-rrset	IN	A	1.1.1.1
interrupted-rrset	IN	TXT	"check AXFR signpipe"
interrupted-rrset	IN	A	2.2.2.2

; ordername sorting
10.order IN A 192.168.0.1
15.order IN A 192.168.0.1
100.order IN A 192.168.0.1
