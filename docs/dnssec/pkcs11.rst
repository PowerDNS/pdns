PKCS#11 support
===============

.. note::
  This is an experimental feature, use at your own risk!

To enable it, compile PowerDNS Authoritative Server using ``--enable-experimental-pkcs11`` flag on configure.
This requires you to have the p11-kit libraries and headers.

You can also log on to the tokens after starting the server, in this case you need to edit your PKCS#11 cryptokey record and remove PIN or set it empty.
Do this after assigning/creating a key, as the PIN is required for assigning keys to zone.

Using PKCS#11 with SoftHSM
--------------------------

.. warning::
  Due to an interaction between `SoftHSM and Botan <https://github.com/PowerDNS/pdns/issues/2496>`__, the PowerDNS Authoritative Server **will most likely** crash on exit when built with ``--enable-botan1.10 --enable-experimental-pkcs11``.
  In 4.2.0, Botan support has been removed and this is no longer an issue.

To test this feature, a software HSM can be used.
It is **not recommended** to do this in production.

These instructions have been tested on Debian 10 (Buster).

- ``apt-get install softhsm p11-kit``
- Verify that it works: ``p11-kit -l``, you should see ``softhsm2: .....``
- Create a token::

    softhsm2-util --init-token --label my-pkcs11-dnskey --free --pin 1234 --so-pin 1234

- Assign the token to a zone (it says KSK, but because there is no ZSK, this will become a CSK)::

    pdnsutil hsm assign example.com ecdsa256 ksk softhsm2 my-pkcs11-dnskey 1234 'my key' 'my pub key'

- Create the key (for 25, use the ID shown by the previous command)::

    pdnsutil hsm create-key example.com 25

-  Verify that everything worked, you should see valid data there::

    pdnsutil zone show example.com

  or, prior to version 5.0::

    pdnsutil show-zone example.com

SoftHSM2 with forwarding
------------------------

Based on https://p11-glue.github.io/p11-glue/p11-kit/manual/remoting.html.

You need to install ``gnutls-bin`` to get token URLs.

You cannot run ``p11-kit server`` as root, so you will need some user for running it. This user must be in the ``softhsm`` group.

These commands need to be run as the non-root user (we shall call it ``tokenuser``).

First, set up your token::

   softhsm2-util --init-token --label "ecdsa#1" --pin 1234 --so-pin 1234 --free
   pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so --keypairgen --key-type EC:prime256v1 --pin 1234 -a 'my key' --token-label "ecdsa#1"

Ensure it's there::

   pkcs11-tool --module /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so -l -O -p 1234

Get the URL for ``p11-kit server``, which is needed for the server::

   p11tool --provider /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so --list-tokens

Set up forwarding::

  cat <<EOF > /etc/pkcs11/modules/p11-kit-client.module
  module: /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so
  EOF

  p11-kit server -u pdns --provider /usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so "pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=29fdc44dc0d61539;token=ecdsa%231"
  P11_KIT_SERVER_ADDRESS=unix:path=/run/user/1000/p11-kit/pkcs11-5198; export P11_KIT_SERVER_ADDRESS;
  P11_KIT_SERVER_PID=5199; export P11_KIT_SERVER_PID;

You will need those values in PowerDNS running environment. Now you can verify that the token is reachable as ``pdns`` user with::

  pkcs11-tool --module /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so -T
  Available slots:
  Slot 0 (0x10): SoftHSM slot ID 0x40d61539
    token label        : ecdsa#1
    token manufacturer : SoftHSM project
    token model        : SoftHSM v2
    token flags        : login required, rng, token initialized, PIN initialized, other flags=0x20
    hardware version   : 2.5
    firmware version   : 2.5
    serial num         : 29fdc44dc0d61539
    pin min/max        : 4/255

Then assign the HSM token to your zone with::

  pdnsutil hsm assign example.com ecdsa256 ksk p11-kit-client 'ecdsa#1' 1234 'my key'

And then verify with ``zone show`` that the zone now has a valid key.

You can do this over SSH as well (note that the example connects from token server to DNS server)::

    ssh -R /var/run/pdns/pkcs11:${P11_KIT_SERVER_ADDRESS#*=} pdns@server
    export P11_KIT_SERVER_ADDRESS=/var/run/pdns/pkcs11

Verify that the token is visible::

   pkcs11-tool --module /usr/lib/x86_64-linux-gnu/pkcs11/p11-kit-client.so -T

Then use the ``pdnsutil hsm assign`` command like before to assign the key to your zone; now you have DNSSEC over SSH.

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

    pkcs11-tool --module=/lib64/libASEP11.so -l -p some-pin -k --key-type RSA:2048 -a zone-ksk
    pkcs11-tool --module=/lib64/libASEP11.so -l -p some-pin -k --key-type RSA:2048 -a zone-zsk

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

    pdnsutil zone show zone

  or, prior to version 5.0::

    pdnsutil show-zone zone

- Note that the physical token is pretty slow, so you have to use it as
  hidden primary. It has been observed to produce about 1.5 signatures/second.
