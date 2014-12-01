#!/usr/bin/perl
# An example script to generate files for the PowerDNS LMDB high performance
# backend

use LMDB_File 0.04 qw( :dbflags :envflags :cursor_op :writeflags );

use strict;
use warnings;

my $HOME = "/var/tmp/lmdb";

mkdir $HOME unless -d $HOME;
my $env = LMDB::Env->new( $HOME, {
    mapsize => 100*1024*1024*1024,
    maxdbs => 3,
});
my $txn = LMDB::Txn->new( $env, 0 );
my $dns_zone = $txn->OpenDB( 'zone', MDB_CREATE );

my $zone = 'example.com';
my $zone_id = 1;
my $zone_ttl = 300;
my $soa_entry = "ns.$zone. hostmaster.$zone. 2012021101 86400 7200 604800 86400";
# XXX $zone length MUST be less than 500 bytes
$dns_zone->put( scalar reverse(lc $zone), join("\t", $zone_id, $zone_ttl, $soa_entry) );

my $dns_data = $txn->OpenDB( 'data', MDB_CREATE | MDB_DUPSORT );
my $dns_extended_data = $txn->OpenDB( 'extended_data', MDB_CREATE );
my @entries = (
    # host type data
    [ $zone, 'NS', "ns.$zone" ],
    # MX/SRV put priority <space> data
    [ $zone, 'MX', "10 mail.example.com" ],
    # No SOA records
    [ "test.$zone", 'A', '192.0.2.66' ],
    [ "text.$zone", 'TXT', "test\n123" ],
    [ "longtext.$zone", 'TXT', "A" x 550 ],

);

my $extended_ref = 0;
for my $row (@entries) {
    my ($host, $type, $data) = @$row;

    # Don't ever allow these characters as they break powerdns
    $data =~ tr/"\\//d;

    if( $type eq 'TXT' ) {
        $data =~ s/([^ -~])/sprintf '\\%03d', ord $1/eg;
    }

    my $key = join( "\t", scalar reverse(lc $host), $type );  # XXX must be less than 500 bytes
    my $val = join( "\t", $zone_id, $zone_ttl, $data);
    if( length $val > 500 ) {
        $dns_data->put( $key, "REF\t" . ++$extended_ref );
        $dns_extended_data->put( $extended_ref, $val );
        # Extended data record storage as DUPSORT can only store up to 500 bytes of data unfortunately
    } else {
        $dns_data->put( $key, $val );
    }
}

$txn->commit;
