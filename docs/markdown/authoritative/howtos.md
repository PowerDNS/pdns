# Basic setup: configuring database connectivity
This shows you how to configure the Generic MySQL backend. This backend
is called 'gmysql', and needs to be configured in `pdns.conf`.  Add the
following lines, adjusted for your local setup (specifically, you may not
want to use the 'root' user):

```
launch=gmysql
gmysql-host=127.0.0.1
gmysql-user=root
gmysql-dbname=pdns
gmysql-password=mysecretpassword
```

Remove any earlier [`launch`](settings.md#launch) statements and other configuration
statements for backends.

**Warning**: Make sure that you can actually resolve the hostname of your database without accessing the database! It is advised to supply an IP address here to prevent chicken/egg problems!

Now start PowerDNS using the monitor command:

```
# service pdns monitor
(...)
Dec 30 13:40:09 About to create 3 backend threads for UDP
Dec 30 13:40:09 gmysql Connection failed: Unable to connect to database: Access denied for user 'hubert'@'localhost' to database 'pdns-non-existant'
Dec 30 13:40:09 Caught an exception instantiating a backend: Unable to launch gmysql connection: Unable to connect to database: Access denied for user 'hubert'@'localhost' to database 'pdns-non-existant'
Dec 30 13:40:09 Cleaning up
Dec 30 13:40:10 Done launching threads, ready to distribute questions
```

This is as to be expected - we did not yet add anything to MySQL for PowerDNS to read from. At this point you may also see other errors which indicate that PowerDNS either could not find your MySQL server or was unable to connect to it. Fix these before proceeding.

General MySQL knowledge is assumed in this chapter, please do not interpret these commands as DBA advice!

## Example: configuring MySQL
Connect to MySQL as a user with sufficient privileges and issue the following commands:

``` 
!!include=../modules/gmysqlbackend/schema.mysql.sql
```

Now we have a database and an empty table. PowerDNS should now be able to launch in monitor mode and display no errors:

```
# /etc/init.d/pdns monitor
(...)
15:31:30 PowerDNS 1.99.0 (Mar 12 2002, 15:00:28) starting up
15:31:30 About to create 3 backend threads
15:39:55 [gMySQLbackend] MySQL connection succeeded
15:39:55 [gMySQLbackend] MySQL connection succeeded
15:39:55 [gMySQLbackend] MySQL connection succeeded
```

In a different shell, a sample query sent to the server should now return quickly without data:

```
$ dig +short www.example.com @127.0.0.1
$
```

**Warning**: When debugging DNS problems, don't use `host`. Please use `dig`  or `drill`.

And indeed, the control console now shows:

```
Mar 12 15:41:12 We're not authoritative for 'www.example.com', sending unauth normal response
```

Now we need to add some records to our database (in a separate shell):

```
# mysql pdnstest
mysql> INSERT INTO domains (name, type) values ('example.com', 'NATIVE');
INSERT INTO records (domain_id, name, content, type,ttl,prio)
VALUES (1,'example.com','localhost ahu@ds9a.nl 1','SOA',86400,NULL);
INSERT INTO records (domain_id, name, content, type,ttl,prio)
VALUES (1,'example.com','dns-us1.powerdns.net','NS',86400,NULL);
INSERT INTO records (domain_id, name, content, type,ttl,prio)
VALUES (1,'example.com','dns-eu1.powerdns.net','NS',86400,NULL);
INSERT INTO records (domain_id, name, content, type,ttl,prio)
VALUES (1,'www.example.com','192.0.2.10','A',120,NULL);
INSERT INTO records (domain_id, name, content, type,ttl,prio)
VALUES (1,'mail.example.com','192.0.2.12','A',120,NULL);
INSERT INTO records (domain_id, name, content, type,ttl,prio)
VALUES (1,'localhost.example.com','127.0.0.1','A',120,NULL);
INSERT INTO records (domain_id, name, content, type,ttl,prio)
VALUES (1,'example.com','mail.example.com','MX',120,25);
```

**Warning**: Host names and the MNAME of a [SOA](../types.md#soa) records are NEVER terminated with a '.' in PowerDNS storage! If a trailing '.' is present it will inevitably cause problems, problems that may be hard to debug.

If we now requery our database, `www.example.com` should be present:

```
$ dig +short www.example.com @127.0.0.1
192.0.2.10

$ dig +short example.com MX @127.0.0.1
25 mail.example.com
```

To confirm what happened, issue the command `SHOW *` to the control console:

```
% show *
corrupt-packets=0,latency=0,packetcache-hit=2,packetcache-miss=5,packetcache-size=0,
qsize-a=0,qsize-q=0,servfail-packets=0,tcp-answers=0,tcp-queries=0,
timedout-packets=0,udp-answers=7,udp-queries=7,
%
```

The actual numbers will vary somewhat. Now enter `QUIT` and start PowerDNS as a regular daemon, and check launch status:

```
# /etc/init.d/pdns start
pdns: started
# /etc/init.d/pdns status
pdns: 8239: Child running
# /etc/init.d/pdns dump
pdns: corrupt-packets=0,latency=0,packetcache-hit=0,packetcache-miss=0,
packetcache-size=0,qsize-a=0,qsize-q=0,servfail-packets=0,tcp-answers=0,
tcp-queries=0,timedout-packets=0,udp-answers=0,udp-queries=0,
```

You now have a working database driven nameserver! To convert other zones already present, use the [`zone2sql`](migration.md#zone2sql) tool.

## Common problems
Most problems involve PowerDNS not being able to connect to the database.

### Can't connect to local MySQL server through socket '/tmp/mysql.sock' (2)
Your MySQL installation is probably defaulting to another location for its socket. Can be resolved by figuring out this location (often `/var/run/mysqld.sock`), and specifying it in the configuration file with the [`gmysql-socket`](backend-generic-mysql.md#gmysql-socket) parameter.

Another solution is to not connect to the socket, but to 127.0.0.1, which can be achieved by specifying [`gmysql-host=127.0.0.1`](backend-generic-mysql.md#gmysql-host).

### Host 'x.y.z.w' is not allowed to connect to this MySQL server
These errors are generic MySQL errors. Solve them by trying to connect to your MySQL database with the MySQL console utility `mysql` with the parameters specified to PowerDNS. Consult the MySQL documentation.

## Typical Errors after Installing
At this point some things may have gone wrong. Typical errors include:

### binding to UDP socket: Address already in use
This means that another nameserver is listening on port 53 already. You can resolve this problem by determining if it is safe to shutdown the nameserver already present, and doing so. If uncertain, it is also possible to run PowerDNS on another port. To do so, add [`local-port=5300`](settings.md#local-port) to `pdns.conf`, and try again. This however implies that you can only test your nameserver as clients expect the nameserver to live on port 53.

### binding to UDP socket: Permission denied
You must be superuser in order to be able to bind to port 53. If this is not a possibility, it is also possible to run PowerDNS on another port. To do so, add [`local-port=5300`](settings.md#local-port) to `pdns.conf`, and try again. This however implies that you can only test your nameserver as clients expect the nameserver to live on port 53.

### Unable to launch, no backends configured for querying
PowerDNS did not find the `launch=bind` instruction in pdns.conf.

### Multiple IP addresses on your server, PowerDNS sending out answers on the wrong one, Massive amounts of 'recvfrom gave error, ignoring: Connection refused'
If you have multiple IP addresses on the internet on one machine, UNIX often sends out answers over another interface than which the packet came in on. In such cases, use [`local-address`](settings.md#local-address) to bind to specific IP addresses, which can be comma separated. The second error comes from remotes disregarding answers to questions it didn't ask to that IP address and sending back ICMP errors.

# Using ALIAS records
The ALIAS record provides a way to have CNAME-like behaviour on the zone apex.

In order to correctly serve ALIAS records, set the [`recursor`](settings.md#recursor)
setting to an existing resolver: 

```
recursor=[::1]:5300
```

and add the ALIAS record to your zone apex. e.g.:

```
$ORIGIN example.net
$TTL 1800

@ IN SOA ns1.example.net. hostmaster.example.net. 2015121101 1H 15 1W 2H

@ IN NS ns1.example.net.

@ IN ALIAS mywebapp.paas-provider.net.
```

When the authoritative server receives a query for the A-record for `example.net`,
it will resolve the A record for `mywebapp.paas-provider.net` and serve an answer
for `example.net` with that A record.

When a zone containing ALIAS records is transferred over AXFR, the
[`outgoing-axfr-expand-alias`](settings.md#outgoing-axfr-expand-alias) setting
controls the behaviour of ALIAS records. When set to 'no' (the default), ALIAS
records are sent as-is (RRType 65401 and a DNSName in the RDATA) in the AXFR.
When set to 'yes', PowerDNS will lookup the A and AAAA records of the name in the
ALIAS-record and send the results in the AXFR.

Set `outgoing-axfr-expand-alias` to 'yes' if your slaves don't understand ALIAS
or should not look up the addresses themselves. Note that slaves will not
automatically follow changes in those A/AAAA records unless you AXFR regularly.

## ALIAS and DNSSEC
Starting with the PowerDNS Authoritative Server 4.0.0, DNSSEC 'washing' of ALIAS
records is supported on AXFR (**not** on live-siging). Set `outgoing-axfr-expand-alias`
to 'yes' and enable DNSSEC for the zone on the master. PowerDNS will sign the
A/AAAA records during the AXFR.

# KSK Rollover
Before attempting a KSK rollover, please read [RFC 6581 "DNSSEC Operational
Practices, Version 2", section 4](https://tools.ietf.org/html/rfc6781#section-4)
carefully to understand the terminology, actions and timelines (TTL and RRSIG
expiry) involved in rolling a KSK.

This How To describes the "Double-Signature Key Signing Key Rollover" from the
above mentioned RFC.

To start the rollover, add an **active** new KSK to the zone (example.net in this
case):

```
pdnsutil add-zone-key example.net ksk active
```

Note that a key with same algorith as the KSK to be replaced should be created,
as this is not an algorithm roll over.

If this zone is of the type 'MASTER', increase the SOA serial. The rollover is
now in the "New KSK" stage. Retrieve the DS record(s) for the new KSK:

```
pdnsutil show-zone example.net
```

And communicate this securely to your registrar/parent zone. Now wait until the
new DS is published in the parent zone and at least the TTL for the DS records
has passed. The rollover is now in the "DS Change" state and can continue to the
"DNSKEY Removal" stage by actually deleting the old KSK.

**Note**: The key-id for the old KSK is shown in the output of `pdnsutil show-zone
example.net`.

```
pdnsutil remove-zone-key example.net KEY-ID
```

The rollover is now complete.

# ZSK Rollover
This how to describes the way to roll a ZSK that is not a secure entrypoint (a
ZSK that is not tied to a DS record in the parent zone) using the ["RFC 6781
Pre-Publish Zone Signing Key Rollover"](https://tools.ietf.org/html/rfc6781#section-4.1.1.1)
method. The documentation linked above also lists the minimum time between
stages. **PLEASE READ THAT DOCUMENT CAREFULLY**

First, create a new inactive ZSK for the zone (if one already exists, you can
skip this step), we add an ECDSA 256 bit key (algorithm 13) here:

```
pdnsutil add-zone-key example.net zsk inactive ecdsa256

```

You are now almost at the "new DNSKEY"-stage of the rollover, if the zone is of
type 'MASTER' you'll need to update the SOA serial in the database and wait for
the slaves to pickup the zone change.

To change the RRSIGs on your records, the new key must be made active. Note: you
can get the key-ids with `pdnsutil show-zone example.net`:

```
pdnsutil activate-zone-key example.net new-key-id
pdnsutil deactivate-zone-key example.net previous-key-id
```

Again, if this is a 'MASTER'-zone, update the SOA serial. You are now at the "new
RRSIGs" stage of the roll over.

The last step is to remove the old key from the completely:

```
pdnsutil remove-zone-key example.net previous-key-id
```

Don't forget to update the SOA serial for 'MASTER' zones. The rollover is now at
the "DNSKEY removal" stage and complete.

# CDS & CDNSKEY Key Rollover
If the upstream registry supports [RFC 7344](https://tools.ietf.org/html/rfc7344)
key rollovers you can use several [`pdnsutil`](dnssec.md#pdnsutil) commands to do
this rollover. This HowTo follows the rollover example from the RFCs [Appendix B](https://tools.ietf.org/html/rfc7344#appendix-B).

We assume the zone name is example.com and is already DNSSEC signed.

Start by adding a new KSK to the zone: `pdnsutil add-zone-key example.com ksk 2048 inactive`.
The "inactive" means that the key is not used to sign any ZSK records. This limits
the size of `ANY` and DNSKEY responses.

Publish the CDS records: `pdnsutil set-publish-cds example.com`, these records
will tell the parent zone to update its DS records. Now wait for the DS records
to be updated in the parent zone.

Once the DS records are updated, do the actual key-rollover: `pdnsutil activate-zone-key example.com new-key-id`
and `pdnsutil deactivate-zone-key example.com old-key-id`. You can get the `new-key-id`
and `old-key-id` by listing them through `pdnsutil show-zone example.com`.

After the rollover, wait *at least* until the TTL on the DNSKEY records have
expired so validating resolvers won't mark the zone as BOGUS. When the wait is
over, delete the old key from the zone: `pdnsutil remove-zone-key example.com old-key-id`.
This updates the CDS records to reflect only the new key.

Wait for the parent to pick up on the CDS change. Once the upstream DS records
show only the DS records for the new KSK, you may disable sending out the CDS
responses: `pdnsutil unset-publish-cds example.com`.

Done!

# Adding new DNS record types
Here are the full descriptions on how we added the TLSA record type to all
PowerDNS products, with links to the actual source code.

First, define the TLSARecordContent class in [dnsrecords.hh](https://github.com/PowerDNS/pdns/blob/5a3409cbb4314b84f1171a69c7337386568fa886/pdns/dnsrecords.hh#L396):

```
class TLSARecordContent : public DNSRecordContent
{
public:
  includeboilerplate(TLSA)

private:
  uint8_t d_certusage, d_selector, d_matchtype;
  string d_cert;
};
```

The `includeboilerplate(TLSA)` macro generates the four methods that do everything
PowerDNS would ever want to do with a record:

- read TLSA records from zonefile format
- write out a TLSA record in zonefile format
- read a TLSA record from a packet
- write a TLSA record to a packet

The [actual parsing code](https://github.com/PowerDNS/pdns/blob/5a3409cbb4314b84f1171a69c7337386568fa886/pdns/dnsrecords.cc#L304):

```
boilerplate_conv(TLSA, 52,
                 conv.xfr8BitInt(d_certusage);
                 conv.xfr8BitInt(d_selector);
                 conv.xfr8BitInt(d_matchtype);
                 conv.xfrHexBlob(d_cert, true);
                 )
```

This code defines the TLSA rrtype number as 52. Secondly, it says there are 3
eight bit fields for Certificate Usage, Selector and Match type. Next, it defines
that the rest of the record is the actual certificate (hash).
['conv'](https://github.com/PowerDNS/pdns/blob/5a3409cbb4314b84f1171a69c7337386568fa886/pdns/dnsparser.hh#L68)
methods are supplied for all DNS data types in use.

Now add `TLSARecordContent::report()` to [`reportOtherTypes()`](https://github.com/PowerDNS/pdns/blob/5a3409cbb4314b84f1171a69c7337386568fa886/pdns/dnsrecords.cc#L594).

And that's it. For completeness, add TLSA and 52 to the QType enum in [`qtype.hh`](https://github.com/PowerDNS/pdns/blob/5a3409cbb4314b84f1171a69c7337386568fa886/pdns/qtype.hh#L116),
which makes it easier to refer to the TLSA record in code if so required.
