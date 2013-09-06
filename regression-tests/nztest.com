$TTL 3600
$ORIGIN nztest.com.
@		IN	SOA	ns1.nztest.com.	ahu.example.com. (  2005092501
			8H ; refresh
			2H ; retry
			1W ; expire
			1D ; default_ttl
			)

@			IN	NS	ns1
@			IN	NS	ns2
@			IN	A	127.0.0.1
ns1			IN	A	1.1.1.1
ns2			IN	A	2.2.2.2
testnonzone.com.         IN      A       127.100.100.100
NZTEST.COM.NET.         IN      A       127.100.100.100
