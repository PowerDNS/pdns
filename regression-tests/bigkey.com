$TTL 120
$ORIGIN bigkey.com
@	100000	IN	SOA	ns1.example.com.	ahu.example.com. (
			2000081501
			8H ; refresh
			2H ; retry
			1W ; expire
			1D ; default_ttl
			)
@			IN	NS	ns1.example.com.
@			IN	NS	ns2.example.com.
@			IN	MX	10	smtp-servers.example.com.
@			IN	MX	15	smtp-servers.test.com.
@			IN	TXT	"a txt record thrown in for good measure"
alpha			IN	A	1.2.3.4
www			IN	A	127.0.0.1
www			IN	AAAA	fe80::a00:27ff:fef4:4219
zomega			IN	A	2.3.4.1
