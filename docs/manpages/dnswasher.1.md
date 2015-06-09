% DNSWASHER(1)
% Joerg Jungermann (jj+debian At borkum.net)
% September 2012

# NAME
**dnswasher** - A PowerDNS nameserver debugging tool

# SYNOPSIS
**dnswasher** *INFILE* *OUTFILE*

# DESCRIPTION
dnswasher takes an *INFILE* in PCAP format and writes out *OUTFILE* also in
PCAP format, while obfuscating end-user IP addresses.

This is useful to share data with third parties while attempting to protect
the privacy of your users.

Please check the output of **dnswasher** to make sure no customer IP
addresses remain.

# OPTIONS
None

# SEE ALSO
pcap(3PCAP), tcpdump(8)
