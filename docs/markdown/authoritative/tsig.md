# TSIG: shared secret authorization and authentication
TSIG, as defined in [RFC 2845](http://tools.ietf.org/html/rfc2845), is a method
for signing DNS messages using shared secrets. Each TSIG shared secret has a name,
and PowerDNS can be told to allow zone transfer of a domain if the request is
signed with an authorized name.

In PowerDNS, TSIG shared secrets are stored by the various backends. In case of
the [`Generic SQL backends`](backend-generic-sql.md), they can be found in the
'tsigkeys' table. The name can be chosen freely, but the algorithm name will
typically be 'hmac-md5'. Other supported algorithms are 'hmac-sha1', 'hmac-shaX'
where X is 224, 256, 384 or 512. The content is a Base64-encoded secret.

**Note**: Most backends require DNSSEC support enabled to support TSIG. For the
Generic SQL Backend make sure to use the DNSSEC enabled schema and to turn on
the relevant '-dnssec' flag (for example, gmysql-dnssec)!

## Provisioning TSIG secrets

TSIG secrets can be generated or imported. Both operations are done with 
`pdnsutil`. To generate a new TSIG secret, use:

```
pdnsutil generate-tsig-key test hmac-md5
```

To import an existing TSIG secret:

```
pdnsutil import-tsig-key test hmac-md5 'kp4/24gyYsEzbuTVJRUMoqGFmN3LYgVDzJ/3oRSP7ys='
```

Listing all TSIG secrets known by powerdns is done with 
`pdnsutil list-tsig-keys` Before a TSIG secret is used, it must be assigned to 
a zone for either master or slave purpose. 

## Provisioning outbound AXFR access
To actually provision a named secret permission to AXFR a zone, either 
generate, or import a TSIG secret with `pdnsutil` and activate it for the 
required zones. For example, to allow AXFR with the above generated TSIG 
secret:

```
pdnsutil activate-tsig-key powerdns.org test master
```

To ease interoperability, the equivalent configuration above in BIND would look like this:

```
key test. {
        algorithm hmac-md5;
        secret "kp4/24gyYsEzbuTVJRUMoqGFmN3LYgVDzJ/3oRSP7ys=";
};

zone "powerdnssec.org" {
    type master;
    file "powerdnssec.org";
    allow-transfer {  key test.; };
};
```

A packet authorized and authenticated by a TSIG signature will gain access to a
zone even if the remote IP address is not otherwise allowed to AXFR a zone.

## Provisioning signed notification and AXFR requests
To configure PowerDNS to send out TSIG signed AXFR requests for a zone to its
master(s), activate a TSIG key as slave with `pdnsutil` for the required zone.

Configuring the use of TSIG for AXFR requests could be achieved as follows:

```
pdnsutil activate-tsig-key powerdns.org test slave
```

In the interest of interoperability, the configuration above is (not quite)
similar to the following BIND statements:

```
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
```

Except that in this case, TSIG will be used for all communications with the master,
not just those about AXFR requests.

# GSS-TSIG support
GSS-TSIG allows authentication and authorization of DNS updates or AXFR using
Kerberos with TSIG signatures.

**Note**: this feature is experimental and subject to change on future releases.

## Prerequisites

- Working Kerberos environment. Please refer to your Kerberos vendor documentation on how to setup it.
- Principal (such as `DNS/<your.dns.server.name>@REALM`) in either per-user keytab or system keytab.

In particular, if something does not work, read logs and ensure that your kerberos
environment is ok before filing an issue. Most common problems are time
synchronization or changes done to the principal.

## Setting up
To allow AXFR / DNS update to work, you need to configure `GSS-ACCEPTOR-PRINCIPAL`
in [`domain metadata`](domainmetadata.md). This will define the principal that is
used to accept any GSS context requests. This *must* match to your keytab. Next
you need to define one or more `GSS-ALLOW-AXFR-PRINCIPAL` entries for AXFR, or
`TSIG-ALLOW-DNSUPDATE` entries for DNS update. These must be set to the exact
initiator principal names you intend to use. No wildcards accepted.
