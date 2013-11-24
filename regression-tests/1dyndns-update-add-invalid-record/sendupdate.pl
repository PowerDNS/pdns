#!/usr/bin/perl

use strict;
use Net::DNS;
use Net::DNS::Update;

my $update = Net::DNS::Update->new('test.dyndns');
$update->push(update => rr_add('host-invalid.test.dyndns. ANY'));

my $res = Net::DNS::Resolver->new;
$res->nameservers($ARGV[0]);
$res->port($ARGV[1]);

my $reply = $res->send($update);

if ($reply) {
	print "RCODE: ", $reply->header->rcode, "\n";
} else {
	print "ERROR: ", $res->errorstring, "\n";
}
