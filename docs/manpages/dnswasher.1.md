% DNSWASHER(8)
% Joerg Jungermann (jj+debian At borkum.net)
% September 2012

# NAME
**dnswasher** - A PowerDNS nameserver debugging tool

# SYNOPSIS
**dnswasher** *INFILE* *OUTFILE*

# DESCRIPTION
dnswasher takes an *INFILE* in PCAP format and writes out *OUTFILE* also in
PCAP format. It copies all network traffic found in *INFILE* to *OUTFILE*
except for non DNS traffic. This might be handy when creating bug reports or
test cases for DNS software e.g. PowerDNS.

# OPTIONS
None

# SEE ALSO
pcap(3PCAP), tcpdump(8)
