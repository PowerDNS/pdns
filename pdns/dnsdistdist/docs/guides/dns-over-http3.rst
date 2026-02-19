DNS-over-HTTP/3 (DoH3)
======================

.. note::
  This guide is about DNS over HTTP/3. For DNS over HTTP/1 and DNS over HTTP/2, please see :doc:`dns-over-https`

:program:`dnsdist` supports DNS-over-HTTP/3 (DoH3) for incoming queries since 1.9.0.
To see if the installation supports this, run ``dnsdist --version``.
If the output shows ``dns-over-http3`` incoming DNS-over-HTTP/3 is supported.

Incoming
--------

To make :program:`dnsdist` listen for on [2001:db8:1:f00::1]:443 on UDP, using provided certificate and key to serve incoming DoH3 connections, use the following configuration:

.. md-tab-set::

   .. md-tab-item:: YAML

      The :ref:`binds <yaml-settings-BindConfiguration>` key is used to create an HTTP/3 bind.

      .. code-block:: yaml

        binds:
          - listen_address: "2001:db8:1:f00::1"
            protocol: "DoH3"
            tls:
              certificates:
                - certificate: "/etc/ssl/certs/example.com.pem"
                  key: "/etc/ssl/private/example.com.key"

   .. md-tab-item:: Lua

      Use the :func:`addDOH3Local` function.

      .. code-block:: lua

        addDOH3Local('2001:db8:1:f00::1', '/etc/ssl/certs/example.com.pem', '/etc/ssl/private/example.com.key')

Optionally, specific options can be set on the listen socket. For instance, you can change the congestion control algorithm used:

.. md-tab-set::

   .. md-tab-item:: YAML

      The :ref:`quic <yaml-settings-IncomingQuicConfiguration>` subkey can be used.

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

   .. md-tab-item:: Lua

      The fourth parameter to :func:`addDOH3Local` indicates various options.

      .. code-block:: lua

        addDOH3Local('2001:db8:1:f00::1', '/etc/ssl/certs/example.com.pem', '/etc/ssl/private/example.com.key', {congestionControlAlgo="cubic"})

A particular attention should be taken to the permissions of the certificate and key files. Many ACME clients used to get and renew certificates, like CertBot, set permissions assuming that services are started as root, which is no longer true for dnsdist as of 1.5.0. For that particular case, making a copy of the necessary files in the /etc/dnsdist directory is advised, using for example CertBot's ``--deploy-hook`` feature to copy the files with the right permissions after a renewal.

More information about sessions management can also be found in :doc:`../advanced/tls-sessions-management`.

Advertising DNS over HTTP/3 support
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

If DNS over HTTP/2 is also enabled in the configuration (see :doc:`dns-over-https` for more information), it might be useful to advertise DNS over HTTP/3 support via the ``Alt-Svc`` header.
An example is available in the :ref:`DoH documentation <DOH-altsvc>`.
