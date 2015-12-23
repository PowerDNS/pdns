#!/usr/bin/env perl

use strict;
use warnings;
use 5.005;

# usage: feed_ds.pl domain parent pdnsutil sqlcmd

my $domain = shift;
my $parent = shift;
my $pdnsutil = shift;
my $sqlcmd = shift;

die "Usage: $0 domain parent pdnsutil sqlcmd" unless($domain and $parent and $pdnsutil and $sqlcmd);

open IN, "-|", "$pdnsutil show-zone -v $domain 2>&1";

my $recs = [];

while(<IN>) {
  chomp;
  if (/DS = (.*) IN DS (.*) ;/) {
     # we have data
     
     push @$recs, [ $1, $2 ]
  }
}

for my $rec (@$recs) {
  my ($name,$value) = @$rec;
  # fix name
  $name=~s/[.]$//;
  my $sql = qq(INSERT INTO records (domain_id, name, type, content, ttl, auth) SELECT id, '$name', 'DS', '$value', 120, 1 FROM domains WHERE name = '$parent');
  # then feed data
  qx($sqlcmd "$sql")
}
