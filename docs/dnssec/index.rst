DNSSEC
======

PowerDNS contains support for DNSSEC, enabling the easy serving of
DNSSEC secured data, with minimal administrative overhead.

In PowerDNS, DNS and signatures and keys are (usually) treated as
separate entities. The domain & record storage is thus almost completely
devoid of DNSSEC record types.

Instead, keying material is stored separately, allowing operators to
focus on the already complicated task of keeping DNS data correct. In
practice, DNSSEC related material is often stored within the same
database, but within separate tables.

If a DNSSEC configuration is found for a domain, the PowerDNS daemon
will provide key records, signatures and (hashed) denials of existence
automatically.

As an example, securing an existing zone can be as simple as:

.. code-block:: shell

    $ pdnsutil secure-zone powerdnssec.org

Alternatively, PowerDNS can serve pre-signed zones, without knowledge of
private keys.

.. toctree::
  :maxdepth: 2

  intro
  profile
  modes-of-operation
  pdnsutil
  migration
  operational
  advice
  pkcs11

Thanks to, acknowledgements
---------------------------

PowerDNS DNSSEC has been made possible by the help & contributions of
many people. We would like to thank:

-  Peter Koch (DENIC)
-  Olaf Kolkman (NLNetLabs)
-  Wouter Wijngaards (NLNetLabs)
-  Marco Davids (SIDN)
-  Markus Travaille (SIDN)
-  Antoin Verschuren (SIDN)
-  Olafur Guðmundsson (IETF)
-  Dan Kaminsky (Recursion Ventures)
-  Roy Arends (Nominet)
-  Miek Gieben
-  Stephane Bortzmeyer (AFNIC)
-  Michael Braunoeder (nic.at)
-  Peter van Dijk
-  Maik Zumstrull
-  Jose Arthur Benetasso Villanova
-  Stefan Schmidt (CCC ;-))
-  Roland van Rijswijk (Surfnet)
-  Paul Bakker (Brainspark/Fox-IT)
-  Mathew Hennessy
-  Johannes Kuehrer (Austrian World4You GmbH)
-  Marc van de Geijn (bHosted.nl)
-  Stefan Arentz
-  Martin van Hensbergen (Fox-IT)
-  Christoph Meerwald
-  Leen Besselink
-  Detlef Peeters
-  Christof Meerwald
-  Jack Lloyd
-  Frank Altpeter
-  Fredrik Danerklint
-  Vasiliy G Tolstov
-  Brielle Bruns
-  Evan Hunt (ISC)
-  Ralf van der Enden
-  Jan-Piet Mens
-  Justin Clift
-  Kees Monshouwer
-  Aki Tuomi
-  Ruben Kerkhof
-  Christian Hofstaedtler
-  Ruben d'Arco
-  Morten Stevens
-  Pieter Lexis

This list is far from complete yet ..
