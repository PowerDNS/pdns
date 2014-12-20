# Cryptographic software and export control
In certain legal climates, PowerDNS might potentially require an export control status, particularly since PowerDNS software contains cryptographic primitives.

PowerDNS does not itself implement any cryptographic algorithms but relies on third party implementations of AES, RSA, ECDSA, GOST, MD5 and various SHA-based hashing algorithms.

Furthermore, RSA, MD5 and the SHA-based algorithms are supplied as a copy of [PolarSSL](http://www.polarssl.org/).

Optionally, PowerDNS can link in a copy of the open source [Botan](http://botan.randombits.org/) cryptographic library.

Optionally, PowerDNS can link in a copy of the open source [Crypto++](http://www.cryptopp.com/) library.

## Specific United States Export Control Notes

PowerDNS is not "US Origin" software. For re-export, like most open source,
publicly available "mass market" projects, PowerDNS is considered to be
governed by section 740.13(e) of the US EAR, "Unrestricted encryption source
code", under which PowerDNS source code would be considered re-exportable
from the US without an export license under License Exception TSU
(Technology and Software - Unrestricted).

Like most open source projects containing some encryption, the ECCN that
best fits PowerDNS software is 5D002.

The official link to the publicly available source code is
<http://downloads.powerdns.com/releases>.

If absolute certainty is required, we recommend consulting an expert in US
Export Control, or asking the BIS for confirmation.
