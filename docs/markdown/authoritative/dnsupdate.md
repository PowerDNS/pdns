# Dynamic DNS Update (RFC2136)
Starting with the PowerDNS Authoritative Server 3.4.0, DNS update support is available. There are a number of items NOT supported:

* There is no support for GSS*TSIG and SIG (TSIG is supported);
* WKS records are specifically mentioned in the RFC, we don't specifically care about WKS records;
* Anything we forgot....

The implementation requires the backend to support a number of new oparations. Currently, the following backends have been modified to support DNS update:

* [gmysql](backend-generic-mysql.md)
* [gpgsql](backend-generic-postgresql.md)
* [gsqlite3](backend-generic-sqlite.md)
* [goracle](backend-generic-oracle.md)
* [godbc](backend-generic-odbc.md)

# Configuration options
There are two configuration parameters that can be used within the powerdns configuration file.

## `dnsupdate`
A setting to enable/disable DNS update support completely. The default is no, which means that DNS updates are ignored by PowerDNS (no message is logged about this!). Change the setting to **dnsupdate=yes** to enable DNS update support. Default is **no**.

## `allow-dnsupdate-from`
A list of IP ranges that are allowed to perform updates on any domain. The default is 0.0.0.0/0, which means that all ranges are accepted. Multiple entries can be used on this line (**allow-dnsupdate-from=198.51.100.0/8 203.0.113.2/32**). The option can be left empty to disallow everything, this then should be used in combination with the **allow-dnsupdate-from** domainmetadata setting per zone.

## `forward-dnsupdate`
Tell PowerDNS to forward to the master server if the zone is configured as slave. Masters are determined by the masters field in the domains table. The default behaviour is enabled (yes), which means that it will try to forward. In the processing of the update packet, the **allow-dnsupdate-from** and **TSIG-ALLOW-DNSUPDATE** are processed first, so those permissions apply before the **forward-dnsupdate** is used. It will try all masters that you have configured until one is successful.

The semantics are that first a dynamic update has to be allowed either by the global allow-dnsupdate-from setting, or by a per-zone ALLOW-DNSUPDATE-FROM metadata setting.

Secondly, if a zone has a TSIG-ALLOW-DNSUPDATE metadata setting, that must match too.

So to only allow dynamic DNS updates to a zone based on TSIG key, and regardless of IP address, set allow-dnsupdate-from to empty, set ALLOW-DNSUPDATE-FROM to "0.0.0.0/0" and "::/0" and set the TSIG-ALLOW-DNSUPDATE to the proper key name.

Further information can be found [below](#how-it-works).

# Per zone settings
For permissions, a number of per zone settings are available via the domain metadata (See [Per zone settings aka Domain Metadata](domainmetadata.md)).

## ALLOW-DNSUPDATE-FROM
This setting has the same function as described in the configuration options (See [above](#configuration-options)). Only one item is allowed per row, but multiple rows can be added. An example:

```
sql> select id from domains where name='example.org';
5
sql> insert into domainmetadata(domain_id, kind, content) values(5, ‘ALLOW-DNSUPDATE-FROM’,’198.51.100.0/8’);
sql> insert into domainmetadata(domain_id, kind, content) values(5, ‘ALLOW-DNSUPDATE-FROM’,’203.0.113.2/32’);
```

This will allow 198.51.100.0/8 and 203.0.113.2/32 to send DNS update messages for the example.org domain.

## TSIG-ALLOW-DNSUPDATE
This setting allows you to set the TSIG key required to do an DNS update. If you have GSS-TSIG enabled, you can use Kerberos principals here. An example:

```
sql> insert into tsigkeys (name, algorithm, secret) values ('test', 'hmac-md5', 'kp4/24gyYsEzbuTVJRUMoqGFmN3LYgVDzJ/3oRSP7ys=');
sql> select id from domains where name='example.org';
5
sql> insert into domainmetadata (domain_id, kind, content) values (5, 'TSIG-ALLOW-DNSUPDATE', 'test');
```

An example of how to use a TSIG key with the **nsupdate** command:

```
nsupdate <<!
server <ip> <port>
zone example.org
update add test1.example.org 3600 A 203.0.113.1
key test kp4/24gyYsEzbuTVJRUMoqGFmN3LYgVDzJ/3oRSP7ys=
send
!
```

If a TSIG key is set for the domain, it is required to be used for the update. The TSIG is extra security on top of the **ALLOW-DNSUPDATE-FROM** setting. If a TSIG key is set, the IP(-range) still needs to be allowed via **ALLOW-DNSUPDATE-FROM**.

## FORWARD-DNSUPDATE
See [Configuration options](#configuration-options) for what it does, but per domain.

```
sql> select id from domains where name='example.org';
5
sql> insert into domainmetadata(domain_id, kind, content) values(5, ‘FORWARD-DNSUPDATE’,’’);
```

There is no content, the existence of the entry enables the forwarding. This domain-specific setting is only useful when the configuration option **forward-dnsupdate** is set to 'no', as that will disable it globally. Using the domainmetadata setting than allows you to enable it per domain.

## SOA-EDIT-DNSUPDATE
This configures how the soa serial should be updated. See [below](#soa-serial-updates).

# SOA Serial Updates
After every update, the soa serial is updated as this is required by section 3.7 of RFC2136. The behaviour is configurable via domainmetadata with the SOA-EDIT-DNSUPDATE option. It has a number of options listed below. If no behaviour is specified, DEFAULT is used.

RFC2136 (Section 3.6) defines some specific behaviour for updates of SOA records. Whenever the SOA record is updated via the update message, the logic to change the SOA is not executed.

**Note**: Powerdns will always use **SOA-EDIT** when serving SOA records, thus a query for the SOA record of the recently update domain, might have an unexpected result due to a SOA-EDIT setting.

An example:

```
sql> select id from domains where name='example.org';
5
sql> insert into domainmetadata(domain_id, kind, content) values(5, ‘SOA-EDIT-DNSUPDATE’,’INCREASE’);
```

This will make the SOA Serial increase by one, for every successful update.

## SOA-EDIT-DNSUPDATE settings
These are the settings available for **SOA-EDIT-DNSUPDATE**.

* DEFAULT: Generate a soa serial of YYYYMMDD01. If the current serial is lower than the generated serial, use the generated serial. If the current serial is higher or equal to the generated serial, increase the current serial by 1.
* INCREASE: Increase the current serial by 1.
* EPOCH: Change the serial to the number of seconds since the EPOCH, aka unixtime.
* SOA-EDIT: Change the serial to whatever SOA-EDIT would provide. See [Domain metadata](domainmetadata.md)
* SOA-EDIT-INCREASE: Change the serial to whatever SOA-EDIT would provide. If what SOA-EDIT provides is lower than the current serial, increase the current serial by 1.

# DNS update How-to: Setup dyndns/rfc2136 with dhcpd
DNS update is often used with DHCP to automatically provide a hostname whenever a new IP-address is assigned by the DHCP server. This section describes how you can setup PowerDNS to receive DNS updates from ISC's dhcpd (version 4.1.1-P1).

## Setting up dhcpd
We're going to use a TSIG key for security. We're going to generate a key using the following command:

```
dnssec-keygen -a hmac-md5 -b 128 -n USER dhcpdupdate
```

This generates two files (Kdhcpdupdate.*.key and Kdhcpdupdate.*.private). You're interested in the .key file:

```
# ls -l Kdhcp*
-rw------- 1 root root  53 Aug 26 19:29 Kdhcpdupdate.+157+20493.key
-rw------- 1 root root 165 Aug 26 19:29 Kdhcpdupdate.+157+20493.private

# cat Kdhcpdupdate.+157+20493.key
dhcpdupdate. IN KEY 0 3 157 FYhvwsW1ZtFZqWzsMpqhbg==
```

The important bits are the name of the key (**dhcpdupdate**) and the hash of the key (**FYhvwsW1ZtFZqWzsMpqhbg==**

Using the details from the key you've just generated. Add the following to your dhcpd.conf:

```
key "dhcpdupdate" {
        algorithm hmac-md5;
        secret "FYhvwsW1ZtFZqWzsMpqhbg==";
};
```

You must also tell dhcpd that you want dynamic dns to work, add the following section:

```
ddns-updates on;
ddns-update-style interim;
update-static-leases on;
```

This tells dhcpd to:

1.  Enable Dynamic DNS
2.  Which style it must use (interim)
3.  Update static leases as well

For more information on this, consult the dhcpd.conf manual.

Per subnet, you also have to tell **dhcpd** which (reverse-)domain it should update and on which master domain server it is running.

```
ddns-domainname "example.org";
ddns-rev-domainname "in-addr.arpa.";

zone example.org {
    primary 127.0.0.1;
    key dhcpdupdate;
}

zone 1.168.192.in-addr.arpa. {
    primary 127.0.0.1;
    key dhcpdupdate;
}
```

This tells **dhcpd** a number of things:

1.  Which domain to use (**ddns-domainname "example.org";**)
2.  Which reverse-domain to use (**dnssec-rev-domainname "in-addr.arpa.";**)
3.  For the zones, where the primary master is located (**primary 127.0.0.1;**)
4.  Which TSIG key to use (**key dhcpdupdate;**). We defined the key earlier.

This concludes the changes that are needed to the **dhcpd** configuration file.

## Setting up PowerDNS
A number of small changes are needed to powerdns to make it accept dynamic updates from **dhcpd**.

Enabled DNS update (RFC2136) support functionality in PowerDNS by adding the following to the PowerDNS configuration file (pdns.conf).

```
dnsupdate=yes
allow-dnsupdate-from=
```

This tells PowerDNS to:

1.  Enable DNS update support([`dnsupdate`](settings.md#dnsupdate))
2.  Allow updates from NO ip-address ([`allow-dnsupdate-from=`](settings.md#allow-dnsupdate-from))

We just told powerdns (via the configuration file) that we accept updates from nobody via the [`allow-dnsupdate-from`](settings.md#allow-dnsupdate-from) parameter. That's not very useful, so we're going to give permissions per zone, via the domainmetadata table.

```
sql> select id from domains where name='example.org';
5
sql> insert into domainmetadata(domain_id, kind, content) values(5, ‘ALLOW-DNSUPDATE-FROM’,’127.0.0.1’);
```

This gives the ip '127.0.0.1' access to send update messages. Make sure you use the ip address of the machine that runs **dhcpd**.

Another thing we want to do, is add TSIG security. This can only be done via the domainmetadata table:

```
sql> insert into tsigkeys (name, algorithm, secret) values ('dhcpdupdate', 'hmac-md5', 'FYhvwsW1ZtFZqWzsMpqhbg==');
sql> select id from domains where name='example.org';
5
sql> insert into domainmetadata (domain_id, kind, content) values (5, 'TSIG-ALLOW-DNSUPDATE', 'dhcpdupdate');
sql> select id from domains where name='1.168.192.in-addr.arpa';
6
sql> insert into domainmetadata (domain_id, kind, content) values (6, 'TSIG-ALLOW-DNSUPDATE', 'dhcpdupdate');
```

This will:

1.  Add the 'dhcpdupdate' key to our PowerDNSinstallation
2.  Associate the domains with the given TSIG key

Restart PowerDNS and you should be ready to go!

# How it works
This is a short description of how DNS update messages are processed by PowerDNS.

1.  The DNS update message is received. If it is TSIG signed, the TSIG is validated against the tsigkeys table. If it is not valid, Refused is returned to the requestor.
2.  A check is performed on the zone to see if it is a valid zone. ServFail is returned when not valid.
3.  The **dnsupdate** setting is checked. Refused is returned when the setting is 'no'.
4.  If the **ALLOW-DNSUPDATE-FROM** has a value (from both domainmetadata and the configuration file), a check on the value is performed. If the requestor (sender of the update message) does not match the values in **ALLOW-DNSUPDATE-FROM**, Refused is returned.
5.  If the message is TSIG signed, the TSIG keyname is compared with the TSIG keyname in domainmetadata. If they do not match, a Refused is send. The TSIG-ALLOW-DNSUPDATE domainmetadata setting is used to find which key belongs to the domain.
6.  The backends are queried to find the backend for the given domain.
7.  If the domain is a slave domain, the **forward-dnsupdate** option and domainmetadata settings are checked. If forwarding to a master is enabled, the message is forward to the master. If that fails, the next master is tried until all masters are tried. If all masters fail, ServFail is returned. If a master succeeds, the result from that master is returned.
8.  A check is performed to make sure all updates/prerequisites are for the given zone. NotZone is returned if this is not the case.
9.  The transaction with the backend is started.
10. The prerequisite checks are performed (section 3.2 of RFC2136). If a check fails, the corresponding RCode is returned. No further processing will happen.
11. Per record in the update message, a the prescan checks are performed. If the prescan fails, the corresponding RCode is returned. If the prescan for the record is correct, the actual update/delete/modify of the record is performed. If the update fails (for whatever reason), ServFail is returned. After changes to the records have been applied, the ordername and auth flag are set to make sure DNSSEC remains working. The cache for that record is purged.
12. If there are records updated and the SOA record was not modified, the SOA serial is updated. See [SOA Serial Updates](#soa-serial-updates). The cache for this record is purged.
13. The transaction with the backend is committed. If this fails, ServFail is returned.
14. NoError is returned.
