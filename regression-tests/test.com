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
@			IN	MX	10	smtp-servers.example.com.
@			IN	MX	15	smtp-servers
www			IN	CNAME	server1
server1			IN	A	1.2.3.4
			IN	RP	ahu.ds9a.nl counter.test.com.
*.test			IN	CNAME	server1
www.test		IN	A	4.3.2.1
sub.test		IN	NS	ns-test.example.net
enum			IN	NAPTR 100 50 "u" "e2u+sip" "" testuser@domain.com.
counter			IN	A	1.1.1.5
_ldap._tcp.dc		IN	SRV 	0 100 389 server1
_double._tcp.dc		IN	SRV 	0 100 389 server1
_double._tcp.dc		IN	SRV 	1 100 389 server1
blah			IN	NS	blah
blah			IN	A	192.168.6.1
;images			IN	URL	"http://www.ds9a.nl"
;bert@auto.test.com.			IN	MBOXFW	"bert@ds9a.nl"
very-long-txt		IN	TXT	"A very long TXT record! boy you won't believe how long. A very long TXT record! boy you won't believe how long. A very long TXT record! boy you won't believe how long. A very long TXT record! boy you won't believe how long. A very long TXT record! boy you won't believe how long!"
within-server		IN	CNAME	outpost.example.com.
_underscore		IN	TXT	"underscores are terrible"
