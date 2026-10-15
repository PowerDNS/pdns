dnswasher
=========

Synopsis
--------

:program:`dnswasher` [OPTION]... <INFILE> [INFILE] <OUTFILE>

Description
-----------

:program:`dnswasher` takes one or more *INFILE*\ s in PCAP format and writes out
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

.. option:: --decrypt, -d

   Undo IPCipher encryption of IP addresses.

.. option:: --help, -h

   Show summary of options.

.. option:: --key, -k

   Base64 encoded 128-bit key for IPCipher.

.. option:: --passphrase, -p

   Passphrase that will be used to derive an IPCipher key.

.. option:: --version, -v

   Output version.

See also
--------

pcap(3PCAP), tcpdump(8)
