dnswasher
=========

Synopsis
--------

:program:`dnswasher` *INFILE* [*INFILE*] *OUTFILE*

Description
-----------

dnswasher takes one or more *INFILE*\ s in PCAP format and writes out
*OUTFILE* also in PCAP format, while obfuscating end-user IP addresses.

This is useful to share data with third parties while attempting to
protect the privacy of your users.

The INFILEs must be of identical PCAP type.

Please check the output of :program:`dnswasher` to make sure no customer IP
addresses remain. Also realize that sufficient data could allow
individuals to be re-identified based on the domain names they care
about.

Options
-------

None

See also
--------

pcap(3PCAP), tcpdump(8)
