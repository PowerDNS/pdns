$TTL 120
$ORIGIN example.com.
@	100000	IN	SOA	ns1.example.com.	ahu.example.com. (
			2000081501
			8H ; refresh
			2H ; retry
			1W ; expire
			1D ; default_ttl
			)

@			IN	NS	ns1.example.com.
@			IN	NS	ns2.example.com.
ns1			IN	A	127.0.0.1
ns2			IN	A	127.0.0.2
