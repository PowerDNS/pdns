$TTL 3600
$ORIGIN dnssec-parent.com.
@		IN	SOA	ns1.dnssec-parent.com.	ahu.example.com. (  2005092501
			8H ; refresh
			2H ; retry
			1W ; expire
			1D ; default_ttl
			)

@			IN	NS	ns1
@			IN	NS	ns2
@			IN	A	9.9.9.9
ns1			IN	A	1.2.3.4
ns2			IN	A	4.3.2.1
delegated		IN	NS	ns1.delegated.dnssec-parent.com.
delegated		IN	NS	ns2.delegated.dnssec-parent.com.
ns1.delegated		IN	A	4.5.6.7
ns2.delegated		IN	A	5.6.7.8
secure-delegated	IN	DS	54319 8 2 a0b9c38cd324182af0ef66830d0a0e85a1d58979c9834e18c871779e040857b7
secure-delegated	IN	NS	ns1.secure-delegated.dnssec-parent.com.
secure-delegated	IN	NS	ns2.secure-delegated.dnssec-parent.com.
ns1.secure-delegated	IN	A	1.2.3.4
ns2.secure-delegated	IN	A	5.6.7.8
insecure-delegated.ent.ent.auth-ent	IN	NS	ns.example.com.
something1.auth-ent	IN	A	1.1.2.3
insecure		IN	NS	ns.example.com.
www			IN	CNAME	www.insecure
