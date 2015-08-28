PDNS offers full master and slave semantics for replicating domain information. Furthermore, PDNS can benefit from native database replication.

# Native replication
Native replication is the default, unless other operation is specifically configured. Native replication basically means that PDNS will not send out DNS update notifications, nor will react to them. PDNS assumes that the backend is taking care of replication unaided.

MySQL replication has proven to be very robust and well suited, even over transatlantic connections between badly peering ISPs. Other PDNS users employ Oracle replication which also works very well.

To use native replication, configure your backend storage to do the replication and do not configure PDNS to do so.

# Master operation
When operating as a master, PDNS sends out notifications of changes to slaves, which react to these notifications by querying PDNS to see if the zone changed, and transferring its contents if it has. Notifications are a way to promptly propagate zone changes to slaves, as described in [RFC 1996](http://tools.ietf.org/html/rfc1996).

**Warning**: Master support is OFF by default, turn it on by adding [`master`](settings.md#master) to the configuration.

**Warning**: If you have DNSSEC-signed zones and non-PowerDNS slaves, please check your SOA-EDIT settings.

**Warning**: Notifications are only sent for domains with type MASTER in your backend.

Left open by RFC 1996 is who is to be notified - which is harder to figure out than it sounds. All slaves for this domain must receive a notification but the nameserver only knows the names of the slaves - not the IP addresses, which is where the problem lies. The nameserver itself might be authoritative for the name of its secondary, but not have the data available.

To resolve this issue, PDNS tries multiple tactics to figure out the IP addresses of the slaves, and notifies everybody. In contrived configurations this may lead to duplicate notifications being sent out, which shouldn't hurt.

Some backends may be able to detect zone changes, others may chose to let the operator indicate which zones have changed and which haven't. Consult the documentation for your backend to see how it processes changes in zones.

To help deal with slaves that may have missed notifications, or have failed to respond to them, several override commands are available via the [`pdns_control`](../authoritative/internals.md#pdnscontrol) tool:

* `pdns_control notify <domain>`
This instructs PDNS to notify all IP addresses it considers to be slaves of this domain.

* `pdns_control notify-host <domain> <ip-address>`
This is truly an override and sends a notification to an arbitrary IP address. Can be used in [`also-notify`](settings.md#also-notify) situations or when PDNS has trouble figuring out who to notify - which may happen in contrived configurations.

# Slave operation
On launch, PDNS requests from all backends a list of domains which have not been checked recently for changes. This should happen every '**refresh**' seconds, as specified in the SOA record. All domains that are unfresh are then checked for changes over at their master. If the [SOA](../types.md#soa) serial number there is higher, the domain is retrieved and inserted into the database. In any case, after the check the domain is declared 'fresh', and will only be checked again after '**refresh**' seconds have passed.

**Warning**: Slave support is OFF by default, turn it on by adding [`slave`](settings.md#slave) to the configuration.

PDNS also reacts to notifies by immediately checking if the zone has updated and if so, retransfering it.

All backends which implement this feature must make sure that they can handle transactions so as to not leave the zone in a half updated state. MySQL configured with either BerkeleyDB or InnoDB meets this requirement, as do PostgreSQL and Oracle. The Bindbackend implements transaction semantics by renaming files if and only if they have been retrieved completely and parsed correctly.

Slave operation can also be programmed using several [`pdns_control`](internals.md#pdnscontrol) commands. The `retrieve` command is especially useful as it triggers an immediate retrieval of the zone from the configured master.

Since version 2.9.21, PowerDNS supports multiple masters. For the BIND backend, the native BIND configuration language suffices to specify multiple masters, for SQL based backends, list all master servers separated by commas in the 'master' field of the domains table.

## Supermaster: automatic provisioning of slaves
PDNS can recognize so called 'supermasters'. A supermaster is a host which is master for domains and for which we are to be a slave. When a master (re)loads a domain, it sends out a notification to its slaves. Normally, such a notification is only accepted if PDNS already knows that it is a slave for a domain.

However, a notification from a supermaster carries more persuasion. When PDNS determines that a notification comes from a supermaster and it is bonafide, PDNS can provision the domain automatically, and configure itself as a slave for that zone.

Before a supermaster notification succeeds, the following conditions must be met:
-   The supermaster must carry a SOA record for the notified domain
-   The supermaster IP must be present in the 'supermaster' table
-   The set of NS records for the domain, as retrieved by the slave from the supermaster, must include the name that goes with the IP address in the supermaster table

**Warning**: If you use another PowerDNS server as master and have DNSSEC enabled on that server please don't forget to rectify the domains after every change. If you don't do this there is no SOA record available and one requirement will fail.

So, to benefit from this feature, a backend needs to know about the IP address of the supermaster, and how PDNS will be listed in the set of NS records remotely, and the 'account' name of your supermaster. There is no need to fill the account name out but it does help keep track of where a domain comes from.

## Modifying a slave zone using a script
As of version 3.0, the PowerDNS Authoritative Server can invoke a Lua script on an incoming AXFR zone transfer. The user-defined function `axfrfilter` within your script is invoked for each resource record read during the transfer, and the outcome of the function defines what PowerDNS does with the records.

What you can accomplish using a Lua script:
-   Ensure consistent values on SOA
-   Change incoming SOA serial number to a YYYYMMDDnn format
-   Ensure consistent NS RRset
-   Timestamp the zone transfer with a TXT record

To enable a Lua script for a particular slave zone, determine the `domain_id` for the zone from the `domains` table, and add a row to the `domainmetadata` table for the domain. Supposing the domain we want has an `id` of 3, the following SQL statement will enable the Lua script `my.lua` for that domain:

```
    INSERT INTO domainmetadata (domain_id, kind, content) VALUES (3, "LUA-AXFR-SCRIPT", "/lua/my.lua");
```

The Lua script must both exist and be syntactically correct; if not, the zone transfer is not performed.

Your Lua functions have access to the query codes through a pre-defined Lua table called `pdns`. For example if you want to check for a CNAME record you can either compare `qtype` to the numeric constant 5 or the value `pdns.CNAME` -- they are equivalent.

If your function decides to handle a resource record it must return a result code of 0 together with a Lua table containing one or more replacement records to be stored in the back-end database. If, on the other hand, your function decides not to modify a record, it must return pdns.PASS and an empty table indicating that PowerDNS should handle the incoming record as normal. If your function decides to drop a query and not respond whatsoever, it must return pdns.DROP and an empty table indicating that the recursor does not want to process the packet in Lua nor in the core recursor logic.

Consider the following simple example:

```
    function axfrfilter(remoteip, zone, qname, qtype, ttl, prio, content)

       -- Replace each HINFO records with this TXT
       if qtype == pdns.HINFO then
          resp = {}
          resp[1] = {    qname   = qname,
            qtype   = pdns.TXT,
            ttl   = 99,
            content   = "Hello Ahu!"
         }
          return 0, resp
       end

       -- Grab each _tstamp TXT record and add a time stamp
       if qtype == pdns.TXT and string.starts(qname, "_tstamp.") then
          resp = {}
          resp[1] = {
            qname   = qname,
            qtype   = qtype,
            ttl   = ttl,
            content   = os.date("Ver %Y%m%d-%H:%M")
         }
          return 0, resp
       end

       resp = {}
       return pdns.PASS, resp
    end

    function string.starts(s, start)
       return s.sub(s, 1, s.len(start)) == start
    end
```

Upon an incoming AXFR, PowerDNS calls our `axfrfilter` function for each record. All HINFO records are replaced by a TXT record with a TTL of 99 seconds and the specified string. TXT Records with names starting with `_tstamp.` get their value (rdata) set to the current time stamp. All other records are unhandled.

# TSIG: shared secret authorization and authentication
**Note**: Available since PowerDNS Authoritative Server 3.0!

TSIG, as defined in [RFC 2845](http://tools.ietf.org/html/rfc2845), is a method for signing DNS messages using shared secrets. Each TSIG shared secret has a name, and PowerDNS can be told to allow zone transfer of a domain if the request is signed with an authorized name.

In PowerDNS, TSIG shared secrets are stored by the various backends. In case of the popular Generic backends, they can be found in the 'tsigkeys' table. The name can be chosen freely, but the algorithm name will typically be 'hmac-md5'. Other supported algorithms are 'hmac-sha1', 'hmac-shaX' where X is 224, 256, 384 or 512. The content is a Base64-encoded secret.

**Note**: Most backends require DNSSEC support enabled to support TSIG. For the Generic SQL Backend make sure to use the DNSSEC enabled schema and to turn on the relevant '-dnssec' flag (for example, gmysql-dnssec)!

## Provisioning outbound AXFR access
To actually provision a named secret permission to AXFR a zone, set a metadata item in the 'domainmetadata' table called 'TSIG-ALLOW-AXFR' with the key name in the content field.

As an example:

```
sql> insert into tsigkeys (name, algorithm, secret) values ('test', 'hmac-md5', 'kp4/24gyYsEzbuTVJRUMoqGFmN3LYgVDzJ/3oRSP7ys=');
sql> select id from domains where name='powerdnssec.org';
5
sql> insert into domainmetadata (domain_id, kind, content) values (5, 'TSIG-ALLOW-AXFR', 'test');

$ dig -t axfr powerdnssec.org @127.0.0.1 -y 'test:kp4/24gyYsEzbuTVJRUMoqGFmN3LYgVDzJ/3oRSP7ys='
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

A packet authorized and authenticated by a TSIG signature will gain access to a zone even if the remote IP address is not otherwise allowed to AXFR a zone.

## Provisioning signed notification and AXFR requests
To configure PowerDNS to send out TSIG signed AXFR requests for a zone to its master(s), set the AXFR-MASTER-TSIG metadata item for the relevant domain to the key that must be used.

The actual TSIG key must also be provisioned, as outlined in the previous section.

For the popular Generic SQL backends, configuring the use of TSIG for AXFR requests could be achieved as follows:

```
sql> insert into tsigkeys (name, algorithm, secret) values ('test', 'hmac-md5', 'kp4/24gyYsEzbuTVJRUMoqGFmN3LYgVDzJ/3oRSP7ys=');
sql> select id from domains where name='powerdnssec.org';
5
sql> insert into domainmetadata (domain_id, kind, content) values (5, 'AXFR-MASTER-TSIG', 'test');
```

This setup corresponds to the TSIG-ALLOW-AXFR access rule defined in the previous section.

In the interest of interoperability, the configuration above is (not quite) similar to the following BIND statements:

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

Except that in this case, TSIG will be used for all communications with the master, not just those about AXFR requests.
