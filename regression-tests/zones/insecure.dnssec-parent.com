$TTL 120
$ORIGIN insecure.dnssec-parent.com.
@		IN	SOA	ns1.example.com.	ahu.example.com. (
			2000081501
			8H ; refresh
			2H ; retry
			1W ; expire
			1D ; default_ttl
			)

@			IN	NS	ns1.example.com.
@			IN	NS	ns2.example.com.
www			IN	A	192.0.2.88
