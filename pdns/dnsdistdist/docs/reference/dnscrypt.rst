DNSCrypt objects and functions
==============================

.. function:: addDNSCryptBind(address, provider, certificate, keyfile[, options])

  Adds a DNSCrypt listen socket on ``address``.

  :param string address: The address and port to listen on
  :param string provider: The provider name for this bind
  :param string certificate: Path to the certificate file
  :param string keyfile: Path to the key file of the certificate
  :param table options: A table with key: value pairs with options (see below)

  Options:

  * ``doTCP=true``: bool - Also bind on TCP on ``address``.
  * ``reusePort=false``: bool - Set the ``SO_REUSEPORT`` socket option.
  * ``tcpFastOpenSize=0``: int - Set the TCP Fast Open queue size, enabling TCP Fast Open when available and the value is larger than 0
  * ``interface=""``: str - Sets the network interface to use
  * ``cpus={}``: table - Set the CPU affinity for this listener thread, asking the scheduler to run it on a single CPU id, or a set of CPU ids. This parameter is only available if the OS provides the pthread_setaffinity_np() function.

.. function:: generateDNSCryptProviderKeys(publicKey, privateKey)

  Generate a new provider keypair and write them to ``publicKey`` and ``privateKey``.

  :param string publicKey: path to write the public key to
  :param string privateKey: path to write the private key to

.. function:: generateDNSCryptCertificate(privatekey, certificate, keyfile, serial, validFrom, validUntil)

  generate a new resolver private key and related certificate, valid from the ``validFrom`` UNIX timestamp until the ``validUntil`` one, signed with the provider private key.

  :param string privatekey: Path to the private key of the provider.
  :param string certificate: Path where to write the certificate file.
  :param string keyfile: Path where to write the private key for the certificate.
  :param int serial: The certificate's serial number.
  :param int validFrom: Unix timestamp from when the certificate will be valid.
  :param int validUntil: Unix timestamp until when the certificate will be valid.

.. function:: printDNSCryptProviderFingerprint(keyfile)

  Display the fingerprint of the provided resolver public key

  :param string keyfile: Path to the key file

.. function:: showDNSCryptBinds()

  Display the currently configured DNSCrypt binds

.. function:: getDNSCryptBind(n) -> DNSCryptContext

  Return the :class:`DNSCryptContext` object corresponding to the bind ``n``.

Certificates
------------

.. class:: DNSCryptCert

  Represents a DNSCrypt certificate.

.. classmethod:: DNSCryptCert:getClientMagic() -> string

  Return this certificate's client magic value.

.. classmethod:: DNSCryptCert:getEsVersion() -> string

  Return the cryptographic construction to use with this certificate,.

.. classmethod:: DNSCryptCert:getMagic() -> string

  Return the certificate magic number.

.. classmethod:: DNSCryptCert:getProtocolMinorVersion() -> string

  Return this certificate's minor version.

.. classmethod:: DNSCryptCert:getResolverPublicKey() -> string

  Return the public key corresponding to this certificate.

.. classmethod:: DNSCryptCert:getSerial() -> int

  Return the certificate serial number.

.. classmethod:: DNSCryptCert:getSignature() -> string

  Return this certificate's signature.

.. classmethod:: DNSCryptCert:getTSEnd() -> int

  Return the date the certificate is valid from, as a Unix timestamp.

.. classmethod:: DNSCryptCert:getTSStart() -> int

  Return the date the certificate is valid until (inclusive), as a Unix timestamp

Context
-------

.. class:: DNSCryptContext

  Represents a DNSCrypt content. Can be used to rotate certs.

.. classmethod:: DNSCryptContext:generateAndLoadInMemoryCertificate(keyfile, serial, begin, end)

  Generate a new resolver key and the associated certificate in-memory, sign it with the provided provider key, and use the new certificate

  :param string keyfile: Path to the key file to use
  :param int serial: The serial number of the certificate
  :param int begin: Unix timestamp from when the certificate is valid
  :param int end: Unix timestamp from until the certificate is valid

.. classmethod:: DNSCryptContext:getCurrentCertificate() -> DNSCryptCert

  Return the current certificate.

.. classmethod:: DNSCryptContext:getOldCertificate() -> DNSCryptCert

  Return the previous certificate.

.. classmethod:: DNSCryptContext:getProviderName() -> string

  Return the provider name

.. classmethod:: DNSCryptContext:hasOldCertificate() -> bool

  Whether or not the context has a previous certificate, from a certificate rotation.

.. classmethod:: DNSCryptContext:loadNewCertificate(certificate, keyfile)

  Load a new certificate and the corresponding private key, and use it

  :param string certificate: Path to a certificate file
  :param string keyfile: Path to a the corresponding key file
