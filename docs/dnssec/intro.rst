A brief introduction to DNSSEC
==============================

DNSSEC is a complicated subject, but it is not required to know all the
ins and outs of this protocol to be able to use PowerDNS. In this
section, we explain the core concepts that are needed to operate a
PowerDNSSEC installation.

Zone material is enhanced with signatures using 'keys'. Such a signature
(called an RRSIG) is a cryptographic guarantee that the data served is
the original data. DNSSEC keys are asymmetric (RSA, DSA, ECSDA or GOST),
the public part is published in DNS and is called a DNSKEY record, and
is used for verification. The private part is used for signing and is
never published.

To make sure that the internet knows that the key that is used for
signing is the authentic key, confirmation can be obtained from the parent
zone. This means that to become operational, a zone operator will have
to publish a representation of the signing key to the parent zone, often
a ccTLD or a gTLD. This representation is called a DS record, and is a
shorter (hashed) version of the DNSKEY.

Once the parent zone has the DS, and the zone is signed with the DNSSEC
key, we are done in theory.

However, for a variety of reasons, most DNSSEC operations run with
another layer of keys. The so called 'Key Signing Key' is sent to the
parent zone, and this Key Signing Key is used to sign a new set of keys
called the Zone Signing Keys.

This setup allows us to change our keys without having to tell the zone
operator about it.

A final challenge is how to DNSSEC sign the answer 'no such domain'. In
the language of DNS, the way to say 'there is no such domain' (NXDOMAIN)
or there is no such record type is to send an empty answer. Such empty
answers are universal, and can't be signed.

In DNSSEC parlance we therefore sign a record that says 'there are no
domains between A.powerdnssec.org and C.powerdnssec.org'. This securely
tells the world that B.powerdnssec.org does not exist. This solution is
called NSEC, and is simple but has downsides - it also tells the world
exactly which records DO exist.

So alternatively, we can say that if a certain mathematical operation
(an 'iterated salted hash') is performed on a question, that no valid
answers exist that have as outcome of this operation an answer between
two very large numbers. This leads to the same 'proof of non-existence'.
This solution is called NSEC3.

A PowerDNS zone can either be operated in NSEC or in one of two NSEC3
modes ('inclusive' and 'narrow').
