Adding new DNS record types
===========================

Here are the full descriptions on how we added the TLSA record type to
all PowerDNS products, with links to the actual source code.

First, define the TLSARecordContent class in
`dnsrecords.hh <https://github.com/PowerDNS/pdns/blob/5a3409cbb4314b84f1171a69c7337386568fa886/pdns/dnsrecords.hh#L396>`__:

.. code-block:: cpp

    class TLSARecordContent : public DNSRecordContent
    {
    public:
      includeboilerplate(TLSA)

    private:
      uint8_t d_certusage, d_selector, d_matchtype;
      string d_cert;
    };

The ``includeboilerplate(TLSA)`` macro generates the four methods that
do everything PowerDNS would ever want to do with a record:

-  read TLSA records from zonefile format
-  write out a TLSA record in zonefile format
-  read a TLSA record from a packet
-  write a TLSA record to a packet

The `actual parsing
code <https://github.com/PowerDNS/pdns/blob/5a3409cbb4314b84f1171a69c7337386568fa886/pdns/dnsrecords.cc#L304>`__:

.. code-block:: cpp

    boilerplate_conv(TLSA, 52,
                     conv.xfr8BitInt(d_certusage);
                     conv.xfr8BitInt(d_selector);
                     conv.xfr8BitInt(d_matchtype);
                     conv.xfrHexBlob(d_cert, true);
                     )

This code defines the TLSA rrtype number as 52. Secondly, it says there
are 3 eight bit fields for Certificate Usage, Selector and Match type.
Next, it defines that the rest of the record is the actual certificate
(hash).
`'conv' <https://github.com/PowerDNS/pdns/blob/5a3409cbb4314b84f1171a69c7337386568fa886/pdns/dnsparser.hh#L68>`__
methods are supplied for all DNS data types in use.

Now add ``TLSARecordContent::report()`` to
`reportOtherTypes() <https://github.com/PowerDNS/pdns/blob/5a3409cbb4314b84f1171a69c7337386568fa886/pdns/dnsrecords.cc#L594>`__.

And that's it. For completeness, add TLSA and 52 to the QType enum in
`qtype.hh <https://github.com/PowerDNS/pdns/blob/5a3409cbb4314b84f1171a69c7337386568fa886/pdns/qtype.hh#L116>`__,
which makes it easier to refer to the TLSA record in code if so
required.

