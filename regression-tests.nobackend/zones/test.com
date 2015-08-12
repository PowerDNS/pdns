$TTL 3600
$ORIGIN test.com.
@		IN	SOA	ns1.test.com.	ahu.example.com. (  2005092501
			8H ; refresh
			2H ; retry
			1W ; expire
			1D ; default_ttl
			)

@			IN	NS	ns1.example.com.
@			IN	NS	ns2.example.com.
