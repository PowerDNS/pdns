#!/usr/bin/perl
use strict;
use warnings;

use LMDB_File qw( :dbflags :envflags :cursor_op :writeflags );

my ($path, $dbname, $searchkey) = @ARGV;
die unless -d $path;

my $env = LMDB::Env->new( $path, {
    mapsize => 1024*1024*1024,
    maxdbs => 3,
    flags => MDB_RDONLY,
});
my $txn = LMDB::Txn->new( $env, MDB_RDONLY );
my $db = $txn->OpenDB( $dbname, MDB_DUPSORT );
my $c = $db->Cursor;
my ($k, $v);
if( $searchkey ) {
    $c->get( $k = $searchkey, $v, MDB_SET_RANGE );
} else {
    $c->get( $k, $v, MDB_FIRST );
}

print "key: $k; value: $v\n";

while(1) {
    eval {
        $c->get( $k, $v, MDB_NEXT );
    };
    if( $@ =~ /MDB_NOTFOUND/ ) {
        exit;
    }
    die $@ if $@;
    print "key: $k; value: $v\n";
}
