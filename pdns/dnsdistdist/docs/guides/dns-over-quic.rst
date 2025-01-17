DNS-over-QUIC (DoQ)
====================

:program:`dnsdist` supports DNS-over-QUIC (DoQ, standardized in RFC 9250) for incoming queries since 1.9.0.
To see if the installation supports this, run ``dnsdist --version``.
If the output shows ``dns-over-quic`` incoming DNS-over-QUIC is supported.

Incoming
--------

Adding a listen port for DNS-over-QUIC can be done with the :func:`addDOQLocal` function, e.g.::

  addDOQLocal('2001:db8:1:f00::1', '/etc/ssl/certs/example.com.pem', '/etc/ssl/private/example.com.key')

This will make :program:`dnsdist` listen on [2001:db8:1:f00::1]:853 on UDP, and will use the provided certificate and key to serve incoming DoQ connections.

The fourth parameter, if present, indicates various options. For instance, you can change the congestion control algorithm used. An example is::

  addDOQLocal('2001:db8:1:f00::1', '/etc/ssl/certs/example.com.pem', '/etc/ssl/private/example.com.key', {congestionControlAlgo="bbr"})

.. code-block:: yaml

  binds:
    - listen_address: "2001:db8:1:f00::1"
      protocol: "DoQ"
      tls:
        certificates:
          - certificate: "/etc/ssl/certs/example.com.pem"
            key: "/etc/ssl/private/example.com.key"
      quic:
        congestion_control_algorithm: "bbr"


A particular attention should be taken to the permissions of the certificate and key files. Many ACME clients used to get and renew certificates, like CertBot, set permissions assuming that services are started as root, which is no longer true for dnsdist as of 1.5.0. For that particular case, making a copy of the necessary files in the /etc/dnsdist directory is advised, using for example CertBot's ``--deploy-hook`` feature to copy the files with the right permissions after a renewal.

More information about sessions management can also be found in :doc:`../advanced/tls-sessions-management`.
