DNS-over-TLS
============

Since version 1.3.0, :program:`dnsdist` supports experimental DNS-over-TLS support.
To see if the installation supports this, run ``dnsdist --version``.
If the output shows ``dns-over-tls`` with one or more SSL libraries in brackets, DNS-over-TLS is supported.

Adding a listen port for DNS-over-TLS can be done with the :func:`addTLSLocal` function, e.g.::

  addTLSLocal('192.0.2.55', '/etc/ssl/certs/example.com.pem', '/etc/ssl/private/example.com.key')

This will make :program:`dnsdist` listen on 192.0.2.55:853 on TCP and UDP and will use the provided certificate and key to provide the TLS connection.
