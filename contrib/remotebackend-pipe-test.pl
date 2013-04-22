#!/usr/bin/perl
### This script is intended for testing/developing remotebackend scripts
### To use, please install libjson-any-perl (JSON::Any) and libjson-xs-perl (JSON::XS)
### (c) Aki Tuomi 2013 - Distributed under same license as PowerDNS Authoritative Server
use strict;
use warnings;
use 5.005;
use IPC::Open2;
use JSON::Any;

### CONFIGURATION SECTION

## Full path to your remotebackend script
my $script = "/home/cmouse/projects/pdns-v6-autorev/rev.pl";

## These are used to send initialize method before your actual code
my $initparams = { value => "foo", value2 => "bar" }; 

## END CONFIGURATION

$|=1;
my $in;
my $out;
my $pid = open2($in,$out,$script);

my $j = JSON::Any->new;

sub rpc {
  my $meth = shift;
  my %p = @_;

  print $j->encode({method => $meth, parameters => \%p}),"\r\n";
  print $out $j->encode({method => $meth, parameters => \%p}),"\r\n";
  my $res = <$in>;
  if ($res) {
    chomp $res;
    print $res,"\n";
  }
}

rpc 'initialize', %$initparams;

if (@ARGV>1) {

## this lets you call whatever method with simple parameters
## like this:

# perl remotebackend-pipe-test.pl lookup qtype SOA qname powerdns.com 

## this will execute 
## {"parameters":{"qname":"powerdns.com","qtype":"SOA"},"method":"lookup"}
## on your remotebackend

my $meth = shift;
rpc $meth, @ARGV;


} else {

## Put whatever you want to run here. Or leave it empty if you
## only want to use the command line

#rpc 'lookup', qname => 'powerdns.com', qtype => 'SOA';

}
