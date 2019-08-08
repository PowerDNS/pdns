PKCS#11 support
===============

.. note::
  This feature is experimental, use at your own risk!

.. deprecated:: 4.0.0
  slot IDs are deprecated, and you are expected to use slot label instead

To enable it, compile PowerDNS Authoritative Server using
``--enable-experimental-pkcs11`` flag on configure. This requires you to
have p11-kit libraries and headers.

You can also log on to the tokens after starting server, in this case
you need to edit your PKCS#11 cryptokey record and remove PIN or set it
empty. PIN is required for assigning keys to zone.

Using with SoftHSM
------------------

.. warning::
  Due to an interaction between `SoftHSM and Botan <https://github.com/PowerDNS/pdns/issues/2496>`__,
  the PowerDNS Authoritative Server **will most likely** crash on exit when built with ``--enable-botan1.10 --enable-experimental-pkcs11``.
  In 4.2.0, Botan support has been removed and this is no longer an issue.

To test this feature, a software HSM can be used. It is **not
recommended** to use this in production.

Instructions on how to setup SoftHSM to work with the feature after
compilation on Ubuntu/Debian (tested with Ubuntu 12.04 and 14.04).

- ``apt-get install softhsm p11-kit opensc``
- create directory ``/etc/pkcs11/modules``
- create a file ``softhsm`` (``softhsm.module`` on newer versions),
  with contents:::

    module: /home/cmouse/softhsm/lib/softhsm/libsofthsm.so     managed: yes

- Verify that it works: ``p11-kit -l``
- Create at least two tokens (ksk and zsk) with (slot-number starts from 0)::

    sudo softhsm --init-token --slot slot-number --label zone-ksk|zone-zsk --pin some-pin --so-pin another-pin

-  Using pkcs11-tool, initialize your new keys.::

    sudo pkcs11-tool --module=/home/cmouse/softhsm/lib/softhsm/libsofthsm.so -l -p some-pin -k --key-type RSA:2048 -a zone-ksk|zone-zsk --slot-index slot-number

-  Assign the keys using (note that token label is not necessarily same
   as object label, see p11-kit -l)::

    pdnsutil hsm assign zone rsasha256 ksk|zsk softhsm token-label pin zone-ksk|zsk

-  Verify that everything worked, you should see valid data there::

    pdnsutil show-zone zone

-  SoftHSM signatures are fast enough to be used in live environment.

Using CryptAS
-------------

Instructions on how to use CryptAS
`Athena IDProtect Key USB Token V2J <http://www.cryptoshop.com/products/smartcards/idprotect-key-j-laser.html>`_
Smart Card token on Ubuntu 14.04.

- Install the manufacturer's support software on your system and initialize
  the Smart Card token as per instructions (do not use PIV).
- ``apt-get install p11-kit opensc``
- Create directory ``/etc/pkcs11/modules``.
- Create file named ``athena.module`` with contents::

    module: /lib64/libASEP11.so
    managed: yes

- Verify it worked, it should resemble output below. Do not continue if
  this does not show up. ::

    $ p11-kit -l
    athena: /lib64/libASEP11.so
        library-description: ASE Cryptoki
        library-manufacturer: Athena Smartcard Solutions
        library-version: 3.1
        token: IDProtect#0A50123456789
            manufacturer: Athena Smartcard Solutions
            model: IDProtect
            serial-number: 0A50123456789
            hardware-version: 1.0
            firmware-version: 1.0
            flags:
                  rng
                  login-required
                  user-pin-initialized
                  token-initialized

- Using pkcs11-tool, initialize your new keys. After this IDProtect
  Manager no longer can show your token certificates and keys, at least
  on version v6.23.04. ::

    pkcs11-tool --module=/home/cmouse/softhsm/lib/softhsm/libsofthsm.so -l -p some-pin -k --key-type RSA:2048 -a zone-ksk
    pkcs11-tool --module=/home/cmouse/softhsm/lib/softhsm/libsofthsm.so -l -p some-pin -k --key-type RSA:2048 -a zone-zsk

- Verify that keys are there::

    $ pkcs11-tool --module=/lib64/libASEP11.so -l -p some-pin -O
    Using slot 0 with a present token (0x0)
    Public Key Object; RSA 2048 bits
      label:      zone-ksk
      Usage:      encrypt, verify, wrap
    Public Key Object; RSA 2048 bits
      label:      zone-zsk
      Usage:      encrypt, verify, wrap
    Private Key Object; RSA
      label:      zone-ksk
      Usage:      decrypt, sign, unwrap
    Private Key Object; RSA
      label:      zone-zsk
      Usage:      decrypt, sign, unwrap

- Assign the keys using::

    pdnsutil hsm assign zone rsasha256 ksk|zsk athena IDProtect#0A50123456789 pin zone-ksk|zsk

- Verify that everything worked, you should see valid data there. ::

    pdnsutil show-zone zone

- Note that the physical token is pretty slow, so you have to use it as
  hidden master. It has been observed to produce about 1.5 signatures/second.
