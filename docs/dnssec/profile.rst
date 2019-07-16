DNSSEC Profile and Support
==========================

PowerDNS aims to serve unexciting, standards compliant, DNSSEC
information. One goal is to have relevant parts of our output be
identical or equivalent to important fellow-traveller software like
NLNetLabs' NSD.

Particularly, if a PowerDNS secured zone is transferred via AXFR, it
should be able to contain the same records as when that zone was signed
using ``ldns-signzone`` using the same keys and settings.

PowerDNS supports serving pre-signed zones, as well as online ('live')
signed operations. In the last case, Signature Rollover and Key
Maintenance are fully managed by PowerDNS.

.. _dnssec-supported-algos:

Supported Algorithms
--------------------

Supported Algorithms (See the `IANA
website <http://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml#dns-sec-alg-numbers-1>`__
for more information):

-  RSASHA1 (algorithm 5, algorithm 7)
-  RSASHA256 (algorithm 8)
-  RSASHA512 (algorithm 10)
-  ECDSA (algorithm 13 and 14)
-  ed25519 (algorithm 15)
-  ed448 (algorithm 16)

For the DS records, these `digest
types <http://www.iana.org/assignments/ds-rr-types/ds-rr-types.xhtml#ds-rr-types-1>`__
are supported:

-  SHA-1 (algorithm 1)
-  SHA-256 (algorithm 2)
-  SHA-384 (algorithm 4)

This corresponds to:

- :rfc:`4033`: DNS Security Introduction and Requirements
- :rfc:`4034`: Resource Records for the DNS Security Extensions, Protocol Modifications for the DNS Security Extensions
- :rfc:`4035`: Protocol Modifications for the DNS Security Extensions
- :rfc:`4509`: Use of SHA-256 in DNSSEC Delegation Signer (DS) Resource Records (RRs)
- :rfc:`5155`: DNS Security (DNSSEC) Hashed Authenticated Denial of Existence
- :rfc:`5702`: Use of SHA-2 Algorithms with RSA in DNSKEY and RRSIG Resource Records for DNSSEC
- :rfc:`6605`: Elliptic Curve Digital Signature Algorithm (DSA) for DNSSEC
- :rfc:`8080`: Edwards-Curve Digital Security Algorithm (EdDSA) for DNSSEC

In order to facilitate interoperability with existing technologies,
PowerDNS keys can be imported and exported in industry standard formats.

When using OpenSSL for ECDSA signatures (this is default), starting from
OpenSSL 1.1.0, the algorithm used is resilient against PRNG failure,
while not strictly conforming to :rfc:`6979`.

.. note::
  Actual supported algorithms depend on the crypto-libraries
  PowerDNS was compiled against. To check the supported DNSSEC algoritms
  in your build of PowerDNS, run ``pdnsutil list-algorithms``.
