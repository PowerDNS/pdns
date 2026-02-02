DNS-over-HTTP/3 (DoH3)
======================

.. note::
  This guide is about DNS over HTTP/3. For DNS over HTTP/1 and DNS over HTTP/2, please see :doc:`dns-over-https`

:program:`dnsdist` supports DNS-over-HTTP/3 (DoH3) for incoming queries since 1.9.0.
To see if the installation supports this, run ``dnsdist --version``.
If the output shows ``dns-over-http3`` incoming DNS-over-HTTP/3 is supported.

Incoming
--------

Adding a listen port for DNS-over-HTTP/3 can be done with the :func:`addDOH3Local` function, e.g.::

  addDOH3Local('2001:db8:1:f00::1', '/etc/ssl/certs/example.com.pem', '/etc/ssl/private/example.com.key')

This will make :program:`dnsdist` listen on [2001:db8:1:f00::1]:443 on UDP, and will use the provided certificate and key to serve incoming DoH3 connections.

The fourth parameter, if present, indicates various options. For instance, you can change the congestion control algorithm used. An example is::

  addDOH3Local('2001:db8:1:f00::1', '/etc/ssl/certs/example.com.pem', '/etc/ssl/private/example.com.key', {congestionControlAlgo="cubic"})

.. code-block:: yaml

  binds:
    - listen_address: "2001:db8:1:f00::1"
      protocol: "DoH3"
      tls:
        certificates:
          - certificate: "/etc/ssl/certs/example.com.pem"
            key: "/etc/ssl/private/example.com.key"
      quic:
        congestion_control_algorithm: "cubic"


A particular attention should be taken to the permissions of the certificate and key files. Many ACME clients used to get and renew certificates, like CertBot, set permissions assuming that services are started as root, which is no longer true for dnsdist as of 1.5.0. For that particular case, making a copy of the necessary files in the /etc/dnsdist directory is advised, using for example CertBot's ``--deploy-hook`` feature to copy the files with the right permissions after a renewal.

More information about sessions management can also be found in :doc:`../advanced/tls-sessions-management`.

Advertising DNS over HTTP/3 support
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If DNS over HTTP/2 is also enabled in the configuration via :func:`addDOHLocal` (see :doc:`dns-over-https` for more information), it might be useful to advertise DNS over HTTP/3 support via the ``Alt-Svc`` header::

  addDOHLocal('2001:db8:1:f00::1', '/etc/ssl/certs/example.com.pem', '/etc/ssl/private/example.com.key', "/dns", {customResponseHeaders={["alt-svc"]="h3=\":443\""}})

This will advertise that HTTP/3 is available on the same IP, port UDP/443.
