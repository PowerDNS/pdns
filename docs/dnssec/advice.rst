DNSSEC advice & precautions
===========================

DNSSEC is a major change in the way DNS works. Furthermore, there is a
bewildering array of settings that can be configured.

It is easy to (mis)configure DNSSEC in such a way that your domain
will not operate reliably, or even, at all. We advise operators to stick
to the keying defaults of ``pdnsutil zone secure`` (``pdnsutil secure-zone``
prior to version 5.0).

.. note::
  GOST may be more widely available in Russia, because it might
  be mandatory to implement this regional standard there.

It is possible to operate a zone with different keying algorithms
simultaneously, but it has also been observed that this is not reliable.

Depending on your primary/secondary setup, you may need to tinker with the
:ref:`SOA-EDIT <metadata-soa-edit>` metadata on your primary.
This is described in the :ref:`soa-edit-ensure-signature-freshness-on-secondaries` section.

Packet sizes, fragments, TCP/IP service
---------------------------------------

DNSSEC answers contain (bulky) keying material and signatures, and are
therefore a lot larger than regular DNS answers. Normal DNS responses
almost always fit in the 'magical' 512 byte limit previously imposed on
DNS.

In order to support DNSSEC, operators must make sure that their network
allows for:

-  Larger than 512 byte UDP packets on port 53
-  Fragmented UDP packets
-  ICMP packets related to fragmentation
-  TCP queries on port 53
-  EDNS0 queries/responses (filtered by some firewalls)

If any of the conditions outlined above is not met, DNSSEC service will
suffer or be completely unavailable.

In addition, the larger your DNS answers, the more critical the above
becomes. It is therefore advised not to provision too many keys, or keys
that are unnecessarily large.
