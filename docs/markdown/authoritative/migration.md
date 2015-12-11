# Migrating to PowerDNS
Before migrating to PowerDNS a few things should be considered.

PowerDNS does not operate as a 'slave' or 'master' server with all backends.
Only the [Generic SQL](backend-generic-sql.md), [BIND](backend-bind.md) backends have the ability to act as master or slave.

To migrate, the `zone2sql` tool is provided. There are also scripts from external contributors for migrating from `MyDNS` server. See https://github.com/PowerDNS/pdns/wiki/Migrating-DBs-FROM-MyDNS for details. There is also tool in pdnsutil to migrate using various backends, most notably bind and mydns. See below for more information.

Additionally, the PowerDNS source comes with a number of diagnostic tools, which can be helpful in verifying proper PowerDNS operation, versus incumbent nameservers. See [Tools to analyse DNS traffic](../tools/analysis.md) for more details.

# Zone2sql
`zone2sql` parses BIND `named.conf` files and zone files and outputs SQL on standard out, which can then be fed to your database.
It understands the Bind master file extension `$GENERATE` and will also honour `$ORIGIN` and `$TTL`.

For backends supporting slave operation (currently only the Generic PostgreSQL, Generic MySQL and BIND backend), there is also an option to keep slave zones as slaves, and not convert them to native operation.

`zone2sql` can generate SQL for the Generic PostgreSQL, Generic MySQL and Oracle backends. The following commands are available:

## `--bare`
Output in a bare format, suitable for further parsing. The output is formatted as follows:

```
          domain_id<TAB>'qname'<TAB>'qtype'<TAB>'content'<TAB>prio<TAB>ttl
```

## `--gmysql`
Output in format suitable for the default configuration of the Generic MySQL backend.

## `--gpgsql`
Output in format suitable for the default configuration of the Generic PostgreSQL backend.

## `--help`
List options.

## `--named-conf`
Parse this named.conf to find locations of zones.

## `--on-error-resume-next`
Ignore missing files during parsing. Dangerous.

## `--oracle`
Output in format suitable for the default configuration of the Generic Oracle backend.

## `--slave`
Maintain slave status of zones listed in named.conf as being slaves. The default behaviour is to convert all zones to native operation.

## `--transactions`
For Oracle and PostgreSQL output, wrap each domain in a transaction for higher speed and integrity.

## `--verbose`
Be verbose during conversion.

## `--zone`
Parse only this zone file. Conflicts with `--named-conf` parameter.

## `--zone-name`
When parsing a single zone without $ORIGIN statement, set this as the zone name.

# Migrating from backend to another

NB! This is experimental feature.

Syntax: `pdnsutil b2b-migrate old new`

This tool lets you migrate data from one backend to another, it moves all data, including zones, metadata and crypto keys (if present). Some example use cases are moving from Bind style zonefiles to SQL based, or other way around, or moving from MyDNS to gMySQL.

## Prerequisites

 - Target backend must support same features as source from set of domains, zones, metadata, DNSSEC and TSIG. See [Backend Capabilities](index.md)
 - There must be no data in the target backend, otherwise the migration will fail. This is checked in the code for domains.

You can perform live upgrade with this tool, provided you follow the procedure.

## Moving from source to target.

Take backups of everything.

Configure both backends to pdns.conf, if you have source configured, you can just add target backend. **DO NOT RESTART AUTH SERVER BEFORE YOU HAVE FINISHED**

Then run `pdnsutil b2b-migrate old new`, the old and new being configuration prefixes in pdns.conf. If something goes wrong, make sure you properly clear **ALL** data from target backend before retrying.

Remove (or comment out) old backend from pdns.conf, and run `pdnsutil rectify-all-zones` and `pdnsutil check-all-zones` to make sure everything is OK.

If everything is OK, then go ahead to restart your pdns auth process. Check logs to make sure everything went ok.
