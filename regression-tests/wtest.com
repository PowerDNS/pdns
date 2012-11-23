$TTL 3600
$ORIGIN wtest.com.
@		IN	SOA	ns1.wtest.com.	ahu.example.com. (  2005092501
			8H ; refresh
			2H ; retry
			1W ; expire
			1D ; default_ttl
			)

@			IN	NS	ns1
@			IN	NS	ns2
@			IN	MX	10	smtp-servers.example.com.
@			IN	MX	15	smtp-servers
@			IN	A	9.9.9.9
ns1			IN	A	2.3.4.5
ns2			IN	A	5.6.7.8
*			IN	CNAME	server1
secure			IN	MX	10 server1
server1			IN	A	1.2.3.4
something		IN	TXT	"make the empty non-terminal non-empty"
*.something		IN	A	4.3.2.1
*.a.b.c.d.e		IN	A	6.7.8.9
e			IN	TXT	"non-empty"
d.e			IN	TXT	"non-empty"
c.d.e			IN	TXT	"non-empty"
b.c.d.e			IN	TXT	"non-empty"
a.b.c.d.e			IN	TXT	"non-empty"
a.something		IN	A	10.11.12.13
