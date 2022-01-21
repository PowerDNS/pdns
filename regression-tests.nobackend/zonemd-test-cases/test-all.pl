#!/usr/bin/perl

# Copyright 2021 Verisign, Inc.

use strict;
use warnings;
use POSIX;
use File::Path;
use File::Copy;
use File::Basename;
use Getopt::Long;

my $RED="\033[0;31m";
my $GRN="\033[0;32m";
my $YEL="\033[1;33m";
my $NC="\033[0m"; # No Color

my $do_html = 0;
my $do_markdown = 0;
GetOptions('html' => \$do_html, 'markdown' => \$do_markdown) or die "usage: $0 [--html] [--markdown] [verifiers...]\n";

my @VERIFIERS = @ARGV ? @ARGV : glob('verifiers/*.sh');
my @ZONES = glob('zones/*');
$ENV{'TZ'} = '';

my $YMD = POSIX::strftime('%Y-%m-%d', gmtime(time));
my $rundir = "results/$YMD";
File::Path::make_path($rundir);

sub read_cfg {
	my $file = shift;
	my $cfg;
	open(F, $file) or die "$file: $!";
	while (<F>) {
		next unless /(\w+)\s*=\s*([-\w\.]+)/;
		die "'fail' should be 'failure' in $file\n" if $1 eq 'expected_result' and $2 eq 'fail';
		$cfg->{$1} = $2;
	}
	close(F);
	$cfg;
}

sub rundir_zonefile {
	my $Z = basename(shift);
	"$rundir/zone-$Z.txt";
}

sub rundir_logfile {
	my $V = basename(shift, '.sh');
	my $Z = basename(shift);
	"$rundir/log-$V-$Z.txt";
}

sub output_html {
	my $results = shift;
	open (HTML, ">$rundir/index.html") or die "$rundir/index.html: $!";
	print HTML <<'EOF';
<style type="text/css">
table, th, td {
  padding: 10px;
  border: 1px solid black;
  border-collapse: collapse;
}
td.pass { text-align:center }
td.pass a { color:green; }
td.fail { text-align:center }
td.fail a { color:red; }
td.zone { text-align:left }
</style>
EOF

	print HTML "<table>\n";
	print HTML "<tr>\n";
	print HTML "  <th>$YMD</th>\n";
	foreach my $V (@VERIFIERS) {
		my $VN = basename($V, '.sh');
		print HTML "  <th>$VN</th>\n";
	}
	foreach my $Z (@ZONES) {
		my $ZN = basename($Z);
		my $ZF = basename(rundir_zonefile($Z));
		print HTML "<tr>\n";
		print HTML "  <td class='zone'><a href='$ZF'>$ZN</a></td>\n";
		foreach my $V (@VERIFIERS) {
			my $VN = basename($V, '.sh');
			my $LF = basename(rundir_logfile($V, $Z));
			my $pf = $results->{$Z}->{$V};
			print HTML "  <td class='$pf'><a href='$LF'>$pf</a></td>\n";
		}
		print HTML "</tr>\n";
	}
	print HTML "</table>\n";
	close(HTML);
}

sub output_markdown {
	my $results = shift;
	open (MD, ">$rundir/README.md") or die "$rundir/README.md: $!";
	print MD join(' | ', $YMD, map {basename($_, '.sh')} @VERIFIERS) . "\n";
	print MD join(' | ', '----', map {'----'} @VERIFIERS) . "\n";
	foreach my $Z (@ZONES) {
		my $ZN = basename($Z);
		my $ZF = basename(rundir_zonefile($Z));
		print MD "[$ZN]($ZF)";
		foreach my $V (@VERIFIERS) {
			my $VN = basename($V, '.sh');
			my $LF = basename(rundir_logfile($V, $Z));
			my $pf = $results->{$Z}->{$V};
			print MD " | [$pf]($LF)";
		}
		print MD "\n";
	}
	close(MD);
}

my $results;
foreach my $vsh (@VERIFIERS) {
	my $vname = basename($vsh, '.sh');
	my $npass = 0;
	my $nfail = 0;

	foreach my $Z (@ZONES) {
		my $cfg = read_cfg("$Z/config");
		if ($cfg->{'validation_time'}) {
			$ENV{'DNSSEC_VALIDATION_TIME'} = $cfg->{'validation_time'};
		}
		my $log = rundir_logfile($vsh, $Z);
		my $zfile = join('/', $Z, $cfg->{'zonefile'});
		if ($do_html || $do_markdown) {
			my $zcopy = rundir_zonefile($Z);
			File::Copy::copy($zfile, $zcopy) or die "$zfile -> $zcopy: $!";
		}
		printf "%s verifying %s: ", $vname, $Z;
		my $cmd = join(' ', 'sh', $vsh, $cfg->{'origin'}, $zfile, ">$log", '2>&1');
		system $cmd;
		die if $? & 127;  # exited due to signal
		my $result = $? >> 8;
		open(LOG, ">>$log") or die "$log: $!";
		printf LOG "\n%s exited with status %d\n", basename($vsh), $result;
		close(LOG);
		my $passfail = '';
		if ($result == 0 && $cfg->{'expected_result'} eq 'success') {
			print "${GRN}Success as expected${NC}\n";
			$passfail='pass';
			$npass++;
		} elsif ($result != 0 && $cfg->{'expected_result'} eq 'failure') {
			print "${GRN}Failed as expected${NC}\n";
			$passfail='pass';
			$npass++;
		} else {
			print "${RED}Expected ". $cfg->{'expected_result'}. " but return code was $result${NC}\n";
			$passfail='fail';
			$nfail++;
		}
		$results->{$Z}->{$vsh} = $passfail;
		delete $ENV{'DNSSEC_VALIDATION_TIME'};
	}
	print "Tests Passed: $npass\n";
	print "Tests Failed: $nfail\n\n";
}
output_html($results) if $do_html;
output_markdown($results) if $do_markdown;
exit(0);
