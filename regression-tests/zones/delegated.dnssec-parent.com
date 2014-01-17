$TTL 3600
$ORIGIN delegated.dnssec-parent.com.
@		IN	SOA	ns1.delegated.dnssec-parent.com.	ahu.example.com. (  2005092501
			8H ; refresh
			2H ; retry
			1W ; expire
			1D ; default_ttl
			)

@			IN	NS	ns1
@			IN	NS	ns2
@			IN	A	9.9.9.9
@			IN	DS	44030 8 2 D4C3D5552B8679FAEEBC317E5F048B614B2E5F607DC57F1553182D49AB2179F7
ns1			IN	A	4.5.6.7
ns2			IN	A	5.6.7.8
www			IN	CNAME	@
