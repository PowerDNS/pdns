DNSCrypt objects and functions
==============================

.. function:: addDNSCryptBind(address, provider, certFile(s), keyFile(s) [, options])

  .. versionchanged:: 1.4.0
    Removed ``doTCP`` from the options. A listen socket on TCP is always created.
    ``certFile(s)`` and ``keyFile(s)`` now accept a list of files.

  .. versionchanged:: 1.5.0
    Added ``tcpListenQueueSize`` parameter.

  .. versionchanged:: 1.6.0
    Added ``maxInFlight`` and ``maxConcurrentTCPConnections`` parameters.

  Adds a DNSCrypt listen socket on ``address``.

  :param string address: The address and port to listen on
  :param string provider: The provider name for this bind
  :param str certFile(s): The path to a X.509 certificate file in PEM format, or a list of paths to such files.
  :param str keyFile(s): The path to the private key file corresponding to the certificate, or a list of paths to such files, whose order should match the certFile(s) ones.
  :param table options: A table with key: value pairs with options (see below)

  Options:

  * ``doTCP=true``: bool - Also bind on TCP on ``address``, removed in 1.4.0.
  * ``reusePort=false``: bool - Set the ``SO_REUSEPORT`` socket option.
  * ``tcpFastOpenQueueSize=0``: int - Set the TCP Fast Open queue size, enabling TCP Fast Open when available and the value is larger than 0
  * ``interface=""``: str - Sets the network interface to use
  * ``cpus={}``: table - Set the CPU affinity for this listener thread, asking the scheduler to run it on a single CPU id, or a set of CPU ids. This parameter is only available if the OS provides the pthread_setaffinity_np() function.
  * ``tcpListenQueueSize=SOMAXCONN``: int - Set the size of the listen queue. Default is ``SOMAXCONN``.
  * ``maxInFlight=0``: int - Maximum number of in-flight queries. The default is 0, which disables out-of-order processing.
  * ``maxConcurrentTCPConnections=0``: int - Maximum number of concurrent incoming TCP connections. The default is 0 which means unlimited.

.. function:: generateDNSCryptProviderKeys(publicKey, privateKey)

  Generate a new provider keypair and write them to ``publicKey`` and ``privateKey``.

  :param string publicKey: path to write the public key to
  :param string privateKey: path to write the private key to

.. function:: generateDNSCryptCertificate(privatekey, certificate, keyfile, serial, validFrom, validUntil[, version])

  generate a new resolver private key and related certificate, valid from the ``validFrom`` UNIX timestamp until the ``validUntil`` one, signed with the provider private key.

  :param string privatekey: Path to the private key of the provider
  :param string certificate: Path where to write the certificate file
  :param string keyfile: Path where to write the private key for the certificate
  :param int serial: The certificate's serial number
  :param int validFrom: Unix timestamp from when the certificate will be valid
  :param int validUntil: Unix timestamp until when the certificate will be valid
  :param DNSCryptExchangeVersion version: The exchange version to use. Possible values are ``DNSCryptExchangeVersion::VERSION1`` (default, X25519-XSalsa20Poly1305) and ``DNSCryptExchangeVersion::VERSION2`` (X25519-XChacha20Poly1305)

.. function:: printDNSCryptProviderFingerprint(keyfile)

  Display the fingerprint of the provided resolver public key

  :param string keyfile: Path to the key file

.. function:: showDNSCryptBinds()

  Display the currently configured DNSCrypt binds

.. function:: getDNSCryptBind(n) -> DNSCryptContext

  Return the :class:`DNSCryptContext` object corresponding to the bind ``n``.

.. function:: getDNSCryptBindCount()

  .. versionadded:: 1.5.0

  Return the number of DNSCrypt binds.

Certificates
------------

.. class:: DNSCryptCert

  Represents a DNSCrypt certificate.

  .. method:: DNSCryptCert:getClientMagic() -> string

    Return this certificate's client magic value.

  .. method:: DNSCryptCert:getEsVersion() -> string

    Return the cryptographic construction to use with this certificate,.

  .. method:: DNSCryptCert:getMagic() -> string

    Return the certificate magic number.

  .. method:: DNSCryptCert:getProtocolMinorVersion() -> string

    Return this certificate's minor version.

  .. method:: DNSCryptCert:getResolverPublicKey() -> string

    Return the public key corresponding to this certificate.

  .. method:: DNSCryptCert:getSerial() -> int

    Return the certificate serial number.

  .. method:: DNSCryptCert:getSignature() -> string

    Return this certificate's signature.

  .. method:: DNSCryptCert:getTSEnd() -> int

    Return the date the certificate is valid from, as a Unix timestamp.

  .. method:: DNSCryptCert:getTSStart() -> int

    Return the date the certificate is valid until (inclusive), as a Unix timestamp

Certificate Pairs
-----------------

.. class:: DNSCryptCertificatePair

  Represents a pair of DNSCrypt certificate and associated key

  .. method:: DNSCryptCertificatePair:getCertificate() -> DNSCryptCert

    Return the certificate.

  .. method:: DNSCryptCertificatePair:isActive() -> bool

    Return whether this pair is active and will be advertised to clients.


Context
-------

.. class:: DNSCryptContext

  Represents a DNSCrypt content. Can be used to rotate certs.

  .. method:: DNSCryptContext:addNewCertificate(cert, key[, active])

    Add a new certificate to the given context. Active certificates are advertised to
    clients, inactive ones are not.

    :param DNSCryptCert cert: The certificate to add to the context
    :param DNSCryptPrivateKey key: The private key corresponding to the certificate
    :param bool active: Whether the certificate should be advertised to clients. Default is true

  .. method:: DNSCryptContext:generateAndLoadInMemoryCertificate(keyfile, serial, begin, end [, version])

    Generate a new resolver key and the associated certificate in-memory, sign it with the provided provider key, and add it to the context

    :param string keyfile: Path to the provider key file to use
    :param int serial: The serial number of the certificate
    :param int begin: Unix timestamp from when the certificate is valid
    :param int end: Unix timestamp from until the certificate is valid
    :param DNSCryptExchangeVersion version: The exchange version to use. Possible values are ``DNSCryptExchangeVersion::VERSION1`` (default, X25519-XSalsa20Poly1305) and ``DNSCryptExchangeVersion::VERSION2`` (X25519-XChacha20Poly1305)

  .. method:: DNSCryptContext:getCertificate(index) -> DNSCryptCert

    Return the certificate with index `index`.

    :param int index: The index of the certificate, starting at 0

  .. method:: DNSCryptContext:getCertificatePair(index) -> DNSCryptCertificatePair

    Return the certificate pair with index `index`.

    :param int index: The index of the certificate, starting at 0

  .. method:: DNSCryptContext:getCertificatePair(index) -> table of DNSCryptCertificatePair

    Return a table of certificate pairs.

  .. method:: DNSCryptContext:getProviderName() -> string

    Return the provider name

  .. method:: DNSCryptContext:loadNewCertificate(certificate, keyfile[, active])

    Load a new certificate and the corresponding private key. If `active` is false, the
    certificate will not be advertised to clients but can still be used to answer queries
    tied to it.

    :param string certificate: Path to a certificate file
    :param string keyfile: Path to a the corresponding key file
    :param bool active: Whether the certificate should be marked as active. Default is true

  .. method:: DNSCryptContext:markActive(serial)

    Mark the certificate with serial `serial` as active, meaning it will be advertised to clients.

    :param int serial: The serial of the number to mark as active

  .. method:: DNSCryptContext:markInactive(serial)

    Mark the certificate with serial `serial` as inactive, meaning it will not be advertised
    to clients but can still be used to answer queries tied to this certificate.

    :param int serial: The serial of the number to mark as inactive

  .. method:: DNSCryptContext:printCertificates()

    Print all the certificates.

  .. method:: DNSCryptContext:reloadCertificates()

    .. versionadded:: 1.6.0

    Reload the current TLS certificate and key pairs.

  .. method:: DNSCryptContext:removeInactiveCertificate(serial)

    Remove the certificate with serial `serial`. It will not be possible to answer queries tied
    to this certificate, so it should have been marked as inactive for a certain time before that.
    Active certificates should be marked as inactive before they can be removed.

    :param int serial: The serial of the number to remove
