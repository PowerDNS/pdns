% DNSWASHER(1)
% Joerg Jungermann (jj+debian At borkum.net)
% September 2012

# NAME
**dnswasher** - A PowerDNS nameserver debugging tool

# SYNOPSIS
**dnswasher** *INFILE* [*INFILE*] *OUTFILE*

# DESCRIPTION
dnswasher takes one or more *INFILE*s in PCAP format and writes out
*OUTFILE* also in PCAP format, while obfuscating end-user IP addresses.

This is useful to share data with third parties while attempting to protect
the privacy of your users.

The INFILEs must be of identical PCAP type.

Please check the output of **dnswasher** to make sure no customer IP
addresses remain.  Also realize that sufficient data could allow
individuals to be re-identified based on the domain names they care about.

# OPTIONS
None

# SEE ALSO
pcap(3PCAP), tcpdump(8)
