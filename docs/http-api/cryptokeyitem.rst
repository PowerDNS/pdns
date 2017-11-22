Cryptokeys
==========

CryptoKey
---------

.. json:object:: CryptoKey

  Represents a DNSSEC crypto key

  :param string type: "Cryptokey"
  :param int id: The internal identifier, read only
  :param string keytype: One of the following: ``ksk``, ``zsk``, ``csk``
  :param bool active: Whether or not the key is in active use
  :param string dnskey: The DNSKEY record for this key
  :param [string] ds: An array of DS records for this key
  :param string privatekey: The private key in ISC format
  :param string algorithm: The key's algorithm
  :param int bit: The bitsize of this key
