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

	my ($type,$qname,$qclass,$qtype,$id,$ip)=split(/\t/);

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
	elsif($qtype eq "MBOXFW") {
		print STDERR "$$ Sent MBOXFW records\n";
		print "DATA	$qname	$qclass	MBOXFW	3600	-1	powerdns\@example.com\n";
	}


	print STDERR "$$ End of data\n";
	print "END\n";
}

