DNS-over-TLS
============

Incoming
--------

Since version 1.3.0, :program:`dnsdist` supports DNS-over-TLS for incoming queries.
To see if the installation supports this, run ``dnsdist --version``.
If the output shows ``dns-over-tls`` with one or more SSL libraries in brackets, DNS-over-TLS is supported.

Adding a listen port for DNS-over-TLS can be done with the :func:`addTLSLocal` function, e.g.::

  addTLSLocal('192.0.2.55', '/etc/ssl/certs/example.com.pem', '/etc/ssl/private/example.com.key')

Or in ``yaml``:

.. code-block:: yaml

  binds:
    - listen_address: "192.0.2.55"
      protocol: "DoT"
      tls:
        certificates:
          - certificate: "/etc/ssl/certs/example.com.pem"
            key: "/etc/ssl/certs/example.com.key"

This will make :program:`dnsdist` listen on 192.0.2.55:853 on TCP, and will use the provided certificate and key to serve incoming TLS connections.

In order to support multiple certificates and keys, for example an ECDSA and an RSA one, the following syntax may be used instead::

  addTLSLocal('192.0.2.55', {'/etc/ssl/certs/example.com.rsa.pem', '/etc/ssl/certs/example.com.ecdsa.pem'}, {'/etc/ssl/private/example.com.rsa.key', '/etc/ssl/private/example.com.ecdsa.key'})

.. code-block:: yaml

  binds:
    - listen_address: "192.0.2.55"
      protocol: "DoT"
      tls:
        certificates:
          - certificate: "/etc/ssl/certs/example.com.rsa.pem"
            key: "/etc/ssl/private/example.com.rsa.key"
          - certificate: "/etc/ssl/certs/example.com.ecdsa.pem"
            key: "/etc/ssl/private/example.com.ecdsa.key"

The certificate chain presented by the server to an incoming client will then be selected based on the algorithms this client advertised support for.

A particular attention should be taken to the permissions of the certificate and key files. Many ACME clients used to get and renew certificates, like CertBot, set permissions assuming that services are started as root, which is no longer true for dnsdist as of 1.5.0. For that particular case, making a copy of the necessary files in the /etc/dnsdist directory is advised, using for example CertBot's ``--deploy-hook`` feature to copy the files with the right permissions after a renewal.

More information about sessions management can also be found in :doc:`../advanced/tls-sessions-management`.

Outgoing
--------

Since version 1.7.0, :program:`dnsdist` also supports outgoing DNS-over-TLS. This way, all queries, regardless of whether they were initially received by dnsdist over UDP, TCP, DoT or DoH, are forwarded to the backend over a secure DNS-over-TLS channel.
Such that support can be enabled via the ``tls`` parameter of the :func:`newServer` command. Additional parameters control the validation of the certificate presented by the backend (``caStore``, ``validateCertificates``), the actual TLS ciphers used (``ciphers``, ``ciphersTLS13``) and the SNI value sent (``subjectName``).

.. code-block:: lua

  newServer({address="[2001:DB8::1]:853", tls="openssl", subjectName="dot.powerdns.com", validateCertificates=true})

The same backend configuration in ``yaml``:

.. code-block:: yaml

   backends:
     - address: "[2001:DB8::1]:853"
       protocol: "DoT"
       tls:
         - provider: "OpenSSL"
           subject_name: "dot.powerdns.com"
           validate_certificate: true

Investigating issues
--------------------

dnsdist provides a lot of counters to investigate issues:

 * :func:`showTCPStats` will display a lot of information about current and passed connections
 * :func:`showTLSErrorCounters` some metrics about why TLS sessions failed to establish
