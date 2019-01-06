#!/usr/bin/perl
# This script takes null delimited files as input
# it drops paths that match the listed exclusions
# output is null delimited to match input
$/="\0";
my @excludes=qw(
  spellchecker
);
my $exclude = join "|", @excludes;
while (<>) {
  chomp;
  next if m{$exclude};
  print "$_$/";
}
