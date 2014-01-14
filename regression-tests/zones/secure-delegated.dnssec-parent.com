$TTL 3600
$ORIGIN secure-delegated.dnssec-parent.com.
@		IN	SOA	ns1.secure-delegated.dnssec-parent.com.	ahu.example.com. (  2005092501
			8H ; refresh
			2H ; retry
			1W ; expire
			1D ; default_ttl
			)

@			IN	NS	ns1
@			IN	NS	ns2
@			IN	A	9.9.9.9
ns1			IN	A	1.2.3.4
ns2			IN	A	5.6.7.8
www			IN	CNAME	@

