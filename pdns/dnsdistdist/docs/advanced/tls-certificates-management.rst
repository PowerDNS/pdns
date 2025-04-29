TLS Certificates Management
===========================

TLS certificates and keys are used in several places of :program:`dnsdist`, dealing with incoming connections over :doc:`../guides/dns-over-tls`, :doc:`../guides/dns-over-https`, :doc:`../guides/dns-over-http3` and :doc:`../guides/dns-over-quic`.

The related functions (:func:`addTLSLocal`, :func:`addDOHLocal`, :func:`addDOH3Local` and :func:`addDOQLocal`) accept:

- a path to a X.509 certificate file in ``PEM`` format, or a list of paths to such files, or a :class:`TLSCertificate` object
- a path to the private key file corresponding to the certificate, or a list of paths to such files whose order should match the certificate files ones. This parameter is ignored if the first one contains :class:`TLSCertificate` objects, as keys are then retrieved from the objects.

For example, to load two certificates, one ``RSA`` and one ``ECDSA`` one:

.. code-block:: lua

  addTLSLocal("192.0.2.1:853", { "/path/to/rsa/pem", "/path/to/ecdsa/pem" }, { "/path/to/rsa/key", "/path/to/ecdsa/key" })

Before 2.0.0 the ``OpenSSL`` provider did not support selecting the certificate to provide to the client based on the value sent in ``Server Name Indication`` extension of the ``Client Hello`` message, so providing more than one certificate only made sense to support different algorithms, like ``RSA`` and ``ECDSA``. The ``GnuTLS`` provider had no such limitation.
Since 2.0.0, the ``OpenSSL`` provider is capable of selecting the certificate based on the ``SNI`` value, so loading several certificates for different hostnames is now possible.

.. code-block:: lua

  addTLSLocal("192.0.2.1:853", { "/path/to/cert-hostname1", "/path/to/cert-hostname2" }, { "/path/to/key-hostname1", "/path/to/key-hostname2" })


Password-protected PKCS12 files
-------------------------------

.. note::

  ``PKCS12`` support requires the use of the ``openssl`` TLS provider.

:program:`dnsdist` can use password-protected ``PKCS12`` certificates and keys. The certificate and key are loaded from a password-protected file using :func:`newTLSCertificate`
which returns a :class:`TLSCertificate` object, which can then be passed to :func:`addTLSLocal`, :func:`addDOHLocal`, :func:`addDOH3Local` and :func:`addDOQLocal`.

.. code-block:: lua

  myCertObject = newTLSCertificate("path/to/domain.p12", {password="passphrase"}) -- use a password protected PKCS12 file

Reloading certificates
----------------------

There are two ways to instruct :program:`dnsdist` to reload the certificate and key files from disk. The easiest one is to use :func:`reloadAllCertificates` which reload all :doc:`../guides/dnscrypt` and TLS certificates, along with their associated keys.
The second allows a finer-grained, per-bind, approach:

.. code-block:: lua

  -- reload certificates and keys for DoT binds:
  for idx = 0, getTLSFrontendCount() - 1 do
    frontend = getTLSFrontend(idx)
    frontend:reloadCertificates()
  end

  -- reload certificates and keys for DoH binds:
  for idx = 0, getDOHFrontendCount() - 1 do
    frontend = getDOHFrontend(idx)
    frontend:reloadCertificates()
  end

  -- reload certificates and keys for DoQ binds:
  for idx = 0, getDOQFrontendCount() - 1 do
    frontend = getDOQFrontend(idx)
    frontend:reloadCertificates()
  end

  -- reload certificates and keys for DoH3 binds:
  for idx = 0, getDOH3FrontendCount() - 1 do
    frontend = getDOH3Frontend(idx)
    frontend:reloadCertificates()
  end

TLS sessions
------------

See :doc:`tls-sessions-management`.

OCSP stapling
-------------

See :doc:`ocsp-stapling`.
