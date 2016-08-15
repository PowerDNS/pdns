#!/usr/bin/perl -w
# sample PowerDNS Coprocess backend with edns-client-subnet support
#

use strict;


$|=1;					# no buffering

my $line=<>;
chomp($line);

unless($line eq "HELO\t5" ) {
	print "FAIL\n";
	print STDERR "Received unexpected '$line', wrong ABI version?\n";
	<>;
	exit;
}
print "OK	Sample backend firing up\n";	# print our banner

while(<>)
{
	print STDERR "$$ Received: $_";
        sleep(1);
	chomp();
	my @arr=split(/\t/);

        if ($arr[0] eq "CMD") {
          print $arr[1],"\n";
          print "END\n";
          next;
        }

	if(@arr < 8) {
		print "LOG	PowerDNS sent unparseable line\n";
		print "FAIL\n";
		next;
	}

	my ($type,$qname,$qclass,$qtype,$id,$ip,$localip,$ednsip)=split(/\t/);
	my $bits=21;
	my $auth = 1;

	if(($qtype eq "SOA" || $qtype eq "ANY") && $qname eq "example.com") {
		print STDERR "$$ Sent SOA records\n";
		print "DATA	$bits	$auth	$qname	$qclass	SOA	3600	-1	ahu.example.com ns1.example.com 2008080300 1800 3600 604800 3600\n";
	}
	if(($qtype eq "NS" || $qtype eq "ANY") && $qname eq "example.com") {
		print STDERR "$$ Sent NS records\n";
		print "DATA	$bits	$auth	$qname	$qclass	NS	3600	-1	ns1.example.com\n";
		print "DATA	$bits	$auth	$qname	$qclass	NS	3600	-1	ns2.example.com\n";
	}
	if(($qtype eq "TXT" || $qtype eq "ANY") && $qname eq "example.com") {
		print STDERR "$$ Sent TXT records\n";
		print "DATA	$bits	$auth	$qname	$qclass	TXT	3600	-1	\"hallo allemaal!\"\n";
	}
	if(($qtype eq "A" || $qtype eq "ANY") && $qname eq "webserver.example.com") {
		print STDERR "$$ Sent A records\n";
		print "DATA	$bits	$auth	$qname	$qclass	A	3600	-1	1.2.3.4\n";
		print "DATA	$bits	$auth	$qname	$qclass	A	3600	-1	1.2.3.5\n";
		print "DATA	$bits	$auth	$qname	$qclass	A	3600	-1	1.2.3.6\n";
	}
	if(($qtype eq "CNAME" || $qtype eq "ANY") && $qname eq "www.example.com") {
		print STDERR "$$ Sent CNAME records\n";
		print "DATA	$bits	$auth	$qname	$qclass	CNAME	3600	-1	webserver.example.com\n";
	}
	if(($qtype eq "MX" || $qtype eq "ANY") && $qname eq "example.com") {
		print STDERR "$$ Sent MX records\n";
		print "DATA	$bits	$auth	$qname	$qclass	MX	3600	-1	25	smtp.powerdns.com\n";
	}

	print STDERR "$$ End of data\n";
	print "END\n";
}

