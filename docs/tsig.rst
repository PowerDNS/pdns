TSIG
====

TSIG, as defined in :rfc:`2845`,
is a method for signing DNS messages using shared secrets. Each TSIG
shared secret has a name, and PowerDNS can be told to allow zone
transfer of a domain if the request is signed with an authorized name.

In PowerDNS, TSIG shared secrets are stored by the various backends. In
case of the :doc:`backends/generic-sql`, they
can be found in the 'tsigkeys' table. The name can be chosen freely, but
the algorithm name will typically be 'hmac-md5'. Other supported
algorithms are 'hmac-sha1', 'hmac-shaX' where X is 224, 256, 384 or 512.
The content is a Base64-encoded secret.

.. note::
  Most backends require DNSSEC support enabled to support TSIG.
  For the Generic SQL Backend make sure to use the DNSSEC enabled schema
  and to turn on the relevant '-dnssec' flag (for example,
  ``gmysql-dnssec``)!

Provisioning outbound AXFR access
---------------------------------

To actually provision a named secret permission to AXFR a zone, set a
metadata item in the 'domainmetadata' table called ``TSIG-ALLOW-AXFR``
with the key name in the content field. For example::

    insert into tsigkeys (name, algorithm, secret) values ('test', 'hmac-md5', 'kp4/24gyYsEzbuTVJRUMoqGFmN3LYgVDzJ/3oRSP7ys=');
    select id from domains where name='powerdnssec.org';
    5
    insert into domainmetadata (domain_id, kind, content) values (5, 'TSIG-ALLOW-AXFR', 'test');

    $ dig -t axfr powerdnssec.org @127.0.0.1 -y 'test:kp4/24gyYsEzbuTVJRUMoqGFmN3LYgVDzJ/3oRSP7ys='

Another of importing and activating TSIG keys into the database is using
:doc:`pdnsutil <manpages/pdnsutil.1>`:

.. code-block:: shell

    pdnsutil import-tsig-key test hmac-md5 'kp4/24gyYsEzbuTVJRUMoqGFmN3LYgVDzJ/3oRSP7ys='
    pdnsutil activate-tsig-key powerdnssec.org test master

To ease interoperability, the equivalent configuration above in BIND
would look like this::

    key test. {
            algorithm hmac-md5;
            secret "kp4/24gyYsEzbuTVJRUMoqGFmN3LYgVDzJ/3oRSP7ys=";
    };

    zone "powerdnssec.org" {
        type master;
        file "powerdnssec.org";
        allow-transfer {  key test.; };
    };

A packet authorized and authenticated by a TSIG signature will gain
access to a zone even if the remote IP address is not otherwise allowed
to AXFR a zone.

.. _tsig-provision-signed-notify-axfr:

Provisioning signed notification and AXFR requests
--------------------------------------------------

To configure PowerDNS to send out TSIG signed AXFR requests for a zone
to its master(s), set the ``AXFR-MASTER-TSIG`` metadata item for the
relevant domain to the key that must be used.

The actual TSIG key must also be provisioned, as outlined in the
previous section.

For the Generic SQL backends, configuring the use of TSIG for AXFR
requests could be achieved as follows::

    insert into tsigkeys (name, algorithm, secret) values ('test', 'hmac-md5', 'kp4/24gyYsEzbuTVJRUMoqGFmN3LYgVDzJ/3oRSP7ys=');
    select id from domains where name='powerdnssec.org';
    5
    insert into domainmetadata (domain_id, kind, content) values (5, 'AXFR-MASTER-TSIG', 'test');

This can also be done using
:doc:`/manpages/pdnsutil.1`:

.. code-block:: shell

    pdnsutil import-tsig-key test hmac-md5 'kp4/24gyYsEzbuTVJRUMoqGFmN3LYgVDzJ/3oRSP7ys='
    pdnsutil activate-tsig-key powerdnssec.org test slave

This setup corresponds to the ``TSIG-ALLOW-AXFR`` access rule defined in
the previous section.

In the interest of interoperability, the configuration above is (not
quite) similar to the following BIND statements::

    key test. {
            algorithm hmac-md5;
            secret "kp4/24gyYsEzbuTVJRUMoqGFmN3LYgVDzJ/3oRSP7ys=";
    };

    server 127.0.0.1 {
            keys { test.; };
    };

    zone "powerdnssec.org" {
     type slave;
     masters { 127.0.0.1; };
     file "powerdnssec.org";
    };

Except that in this case, TSIG will be used for all communications with
the master, not just those about AXFR requests.

.. _tsig-gss-tsig:

GSS-TSIG support
----------------

GSS-TSIG allows authentication and authorization of DNS updates or AXFR
using Kerberos with TSIG signatures.

.. note::
  This feature is experimental and subject to change in future releases.

Prerequisites
~~~~~~~~~~~~~

-  Working Kerberos environment. Please refer to your Kerberos vendor
   documentation on how to setup it.
-  Principal (such as ``DNS/<your.dns.server.name>@REALM``) in either
   per-user keytab or system keytab.

In particular, if something does not work, read logs and ensure that
your kerberos environment is ok before filing an issue. Most common
problems are time synchronization or changes done to the principal.

Setting up
~~~~~~~~~~

To allow AXFR / DNS update to work, you need to configure
``GSS-ACCEPTOR-PRINCIPAL`` in
:doc:`domainmetadata`. This will define the
principal that is used to accept any GSS context requests. This *must*
match to your keytab. Next you need to define one or more
``GSS-ALLOW-AXFR-PRINCIPAL`` entries for AXFR, or
``TSIG-ALLOW-DNSUPDATE`` entries for DNS update. These must be set to
the exact initiator principal names you intend to use. No wildcards
accepted.
