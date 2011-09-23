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
*			IN	CNAME	server1
secure			IN	MX	10 server1
server1			IN	A	1.2.3.4
*.something		IN	A	4.3.2.1
