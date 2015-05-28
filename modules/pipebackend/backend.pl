#!/usr/bin/perl -w
# sample PowerDNS Coprocess backend
#

use strict;


$|=1;					# no buffering

my $line=<>;
chomp($line);

unless($line eq "HELO\t1") {
	print "FAIL\n";
	print STDERR "Received '$line'\n";
	<>;
	exit;
}
print "OK	Sample backend firing up\n";	# print our banner

while(<>)
{
	print STDERR "$$ Received: $_";
	chomp();
	my @arr=split(/\t/);
	if(@arr<6) {
		print "LOG	PowerDNS sent unparseable line\n";
		print "FAIL\n";
		next;
	}

	# note! the qname is what PowerDNS asks the backend. It need not be what the internet asked PowerDNS!
	my ($type,$qname,$qclass,$qtype,$id,$ip)=split(/\t/);

	if(($qtype eq "SOA" || $qtype eq "ANY") && $qname eq "example.com") {
		print STDERR "$$ Sent SOA records\n";
		print "DATA	$qname	$qclass	SOA	3600	-1	ns1.example.com ahu.example.com 2008080300 1800 3600 604800 3600\n";
	}
	if(($qtype eq "NS" || $qtype eq "ANY") && $qname eq "example.com") {
		print STDERR "$$ Sent NS records\n";
		print "DATA	$qname	$qclass	NS	3600	-1	ns1.example.com\n";
		print "DATA	$qname	$qclass	NS	3600	-1	ns2.example.com\n";
	}
	if(($qtype eq "TXT" || $qtype eq "ANY") && $qname eq "example.com") {
		print STDERR "$$ Sent NS records\n";
		print "DATA	$qname	$qclass	TXT	3600	-1	\"hallo allemaal!\"\n";
	}
	if(($qtype eq "A" || $qtype eq "ANY") && $qname eq "webserver.example.com") {
		print STDERR "$$ Sent A records\n";
		print "DATA	$qname	$qclass	A	3600	-1	1.2.3.4\n";
		print "DATA	$qname	$qclass	A	3600	-1	1.2.3.5\n";
		print "DATA	$qname	$qclass	A	3600	-1	1.2.3.6\n";
	}
	elsif(($qtype eq "CNAME" || $qtype eq "ANY") && $qname eq "www.example.com") {
		print STDERR "$$ Sent CNAME records\n";
		print "DATA	$qname	$qclass	CNAME	3600	-1	webserver.example.com\n";
	}


	print STDERR "$$ End of data\n";
	print "END\n";
}

