#!/usr/bin/perl

use strict;
use warnings;

use 5.10.0; # somewhat sane minimum?

# standard perl
use Test::More;

my $sdigpath = '../../../pdns/sdig';
if (defined($ENV{SDIG})) { $sdigpath = $ENV{SDIG} }
my $sdig = "timeout 3 $sdigpath 127.0.0.1 5300";

exit main(@ARGV);

sub main {
	#plan(tests => 2);
	query('A', 'www.example.com.', 0, <<'EOT');
0	host.example.com.	IN	A	120	10.11.12.13
0	www.example.com.	IN	CNAME	120	host.example.com.
Rcode: 0 (No Error), RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
Reply to question for qname='www.example.com.', qtype=A
EOT

	query('A', 'www.example.org.', 1, <<'EOT');
0	host.example.org.	IN	A	123	192.168.150.150
0	host.example.org.	IN	RRSIG	123	A 8 3 123 [expiry] [inception] [keytag] example.org. ...
0	www.example.org.	IN	CNAME	123	host.example.org.
0	www.example.org.	IN	RRSIG	123	CNAME 8 3 123 [expiry] [inception] [keytag] example.org. ...
2	.	IN	OPT	32768	
Rcode: 0 (No Error), RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
Reply to question for qname='www.example.org.', qtype=A
EOT

	query('A', 'foo.example.com.', 0, <<'EOT');
1	example.com.	IN	SOA	3600	ns1.example.com. ahu.example.com. 2005092501 7200 3600 1209600 3600
Rcode: 3 (Non-Existent domain), RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
Reply to question for qname='foo.example.com.', qtype=A
EOT

	query('A', 'foo.example.org.', 1, <<'EOT');
1	3he9ugm1663rsh2i0g48h0c5832av415.example.org.	IN	NSEC3	3600	1 [flags] 100 abba 3HE9UGM1663RSH2I0G48H0C5832AV417
1	3he9ugm1663rsh2i0g48h0c5832av415.example.org.	IN	RRSIG	3600	NSEC3 8 3 3600 [expiry] [inception] [keytag] example.org. ...
1	example.org.	IN	RRSIG	3600	SOA 8 2 36000 [expiry] [inception] [keytag] example.org. ...
1	example.org.	IN	SOA	3600	nsa.example.org. ahu.example.org. 2016020516 7200 3600 1209600 3600
1	ofe1tpras1895e6rdf38dtk4j0cebrli.example.org.	IN	NSEC3	3600	1 [flags] 100 abba OFE1TPRAS1895E6RDF38DTK4J0CEBRLJ NS SOA RRSIG DNSKEY NSEC3PARAM
1	ofe1tpras1895e6rdf38dtk4j0cebrli.example.org.	IN	RRSIG	3600	NSEC3 8 3 3600 [expiry] [inception] [keytag] example.org. ...
1	qlrm0joffkmpbcml75n92m51nod6n1o5.example.org.	IN	NSEC3	3600	1 [flags] 100 abba QLRM0JOFFKMPBCML75N92M51NOD6N1O7
1	qlrm0joffkmpbcml75n92m51nod6n1o5.example.org.	IN	RRSIG	3600	NSEC3 8 3 3600 [expiry] [inception] [keytag] example.org. ...
2	.	IN	OPT	32768	
Rcode: 3 (Non-Existent domain), RD: 0, QR: 1, TC: 0, AA: 1, opcode: 0
Reply to question for qname='foo.example.org.', qtype=A
EOT
	done_testing();
	return 0;
}

sub query {
	my ($qtype, $qname, $sec, $should) = @_;
	my $req = "$sdig $qname $qtype " . (($sec) ? ' dnssec' : '') . ' | LC_ALL=C sort';
	my $res = `$req`;
	#print "req: '$req' $?\nres: $res\n";
	is($res, $should, "result for $qname $qtype");
}

