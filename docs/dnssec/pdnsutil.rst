``pdnsutil`` and DNSSEC
=======================

``pdnsutil`` (previously called ``pdnssec``) is a powerful command that
is the operator-friendly gateway into PowerDNS configuration. Behind the
scenes, ``pdnsutil`` manipulates a PowerDNS backend database, which also
means that for many databases, ``pdnsutil`` can be run remotely, and can
configure key material on different servers.

For a list of available commands, see the :doc:`manpage <../manpages/pdnsutil.1>`.

.. _dnssec-pdnsutil-dnssec-defaults:

DNSSEC Defaults
---------------

Since version 4.0, when securing a zone using ``pdnsutil secure-zone``,
a single ECDSA (algorithm 13, ECDSAP256SHA256) key is generated that is
used as CSK. Before 4.0, 3 RSA (algorithm 8) keys were generated, one as
the KSK and two ZSKs. As all keys are online in the database, it made no
sense to have this split-key setup.

The default negative answer strategy is NSEC.

.. note::
  Not all registrars support algorithm 13.
