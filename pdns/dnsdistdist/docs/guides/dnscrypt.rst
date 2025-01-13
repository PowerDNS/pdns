DNSCrypt
========

:program:`dnsdist`, when compiled with ``--enable-dnscrypt``, can be used as a DNSCrypt server, uncurving queries before forwarding them to downstream servers and curving responses back.
To make :program:`dnsdist` listen to incoming DNSCrypt queries on 127.0.0.1 port 8443, with a provider name of "2.providername", using a resolver certificate and associated key stored respectively in the resolver.cert and resolver.key files, the :func:`addDNSCryptBind` directive can be used::

  addDNSCryptBind("127.0.0.1:8443", "2.providername", "/path/to/resolver.cert", "/path/to/resolver.key")


And in ``yaml``:

.. code-block:: yaml

  binds:
    - listen_address: "127.0.0.1:8443"
      protocol: "DNSCrypt"
      dnscrypt:
        provider_name: "2.providername"
        certificates:
          - certificate: "/path/to/resolver.cert"
            key: "/path/to/resolver.key"


To generate the provider and resolver certificates and keys, you can simply do::

  > generateDNSCryptProviderKeys("/path/to/providerPublic.key", "/path/to/providerPrivate.key")
  Provider fingerprint is: E1D7:2108:9A59:BF8D:F101:16FA:ED5E:EA6A:9F6C:C78F:7F91:AF6B:027E:62F4:69C3:B1AA
  > generateDNSCryptCertificate("/path/to/providerPrivate.key", "/path/to/resolver.cert", "/path/to/resolver.key", serial, validFrom, validUntil)

Ideally, the certificates and keys should be generated on an offline dedicated hardware and not on the resolver.
The resolver key should be regularly rotated and should never touch persistent storage, being stored in a tmpfs with no swap configured.

You can display the currently configured DNSCrypt binds with::

  > showDNSCryptBinds()
  #   Address              Provider Name        Serial   Validity              P. Serial P. Validity
  0   127.0.0.1:8443       2.name               14       2016-04-10 08:14:15   0         -

If you forgot to write down the provider fingerprint value after generating the provider keys, you can use :func:`printDNSCryptProviderFingerprint` to retrieve it later::

  > printDNSCryptProviderFingerprint("/path/to/providerPublic.key")
  Provider fingerprint is: E1D7:2108:9A59:BF8D:F101:16FA:ED5E:EA6A:9F6C:C78F:7F91:AF6B:027E:62F4:69C3:B1A
