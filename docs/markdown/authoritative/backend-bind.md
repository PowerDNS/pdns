# Bind zone file backend

|&nbsp;|&nbsp;|
|:--|:--|
|Native|Yes|
|Master|Yes|
|Slave|Yes|
|Superslave|Experimental|
|Autoserial|No|
|DNSSEC|Yes|
|Disabled data|No|
|Comments|No|
|Module name|bind|
|Launch|bind|

The BindBackend started life as a demonstration of the versatility of PDNS but quickly gained in importance when there appeared to be demand for a Bind 'work-alike'.

The BindBackend parses a Bind-style `named.conf` and extracts information about zones from it. It makes no attempt to honour other configuration flags, which you should configure (when available) using the PDNS native configuration.

## Configuration Parameters
### `--help=bind`
Outputs all known parameters related to the bindbackend

### `bind-example-zones`
Loads the 'example.com' zone which can be queried to determine if PowerDNS is functioning without configuring database backends. This feature is no longer supported from 2.9.21 onwards.

### `bind-config`
Location of the Bind configuration file to parse.

### `bind-check-interval`
How often to check for zone changes. See 'Operation' section.

### `bind-dnssec-db`
Filename to store and access our DNSSEC metadatabase, empty for none.

### `bind-hybrid`
Store DNSSEC keys and metadata storage in an other backend. See the
[hybrid BIND-mode operation](dnssec.md#powerdnssec-hybrid-bind-mode-operation)

### `bind-ignore-broken-records`
Setting this option to `yes` makes PowerDNS ignore out of zone records when
loading zone files.

## Operation
On launch, the BindBackend first parses the `named.conf` to determine which zones need to be loaded. These will then be parsed and made available for serving, as they are parsed. So a `named.conf` with 100.000 zones may take 20 seconds to load, but after 10 seconds, 50.000 zones will already be available. While a domain is being loaded, it is not yet available, to prevent incomplete answers.

Reloading is currently done only when a request for a zone comes in, and then only after [`bind-check-interval`](#bind-check-interval) seconds have passed after the last check. If a change occurred, access to the zone is disabled, the file is reloaded, access is restored, and the question is answered. For regular zones, reloading is fast enough to answer the question which lead to the reload within the DNS timeout.

If [`bind-check-interval`](#bind-check-interval) is specified as zero, no checks will be performed until the `pdns_control reload` is given.

## pdns\_control commands
### `bind-add-zone <domain> <filename>`
Add zone `domain` from `filename` to PDNS's bind backend. Zone will be loaded at first request.

### `bind-domain-status <domain> [domain]`
Output status of domain or domains. Can be one of `seen in named.conf, not parsed`, `parsed successfully at <time>` or `error parsing at line ... at <time>`.

### `bind-list-rejects`
Lists all zones that have problems, and what those problems are.

### `bind-reload-now <domain>`
Reloads a zone from disk NOW, reporting back results.

### `rediscover`
Reread the bind configuration file (`named.conf`). If parsing fails, the old configuration remains in force and `pdns_control` reports the error. Any newly discovered domains are read, discarded domains are removed from memory.

**Note**: Except that with 2.9.3, they are not removed from memory.

### `reload`
All zones with a changed timestamp are reloaded at the next incoming query for them.

## Performance
The BindBackend does not benefit from the packet cache as it is fast enough on its own. Furthermore, on most systems, there will be no benefit in using multiple CPUs for the packetcache, so a noticeable speedup can be attained by specifying [`distributor-threads`](settings.md#distributor-threads)`=1` in `pdns.conf`.

## Master/slave configuration

### Master
Works as expected. At startup, no notification storm is performed as this is generally not useful. Perhaps in the future the Bind Backend will attempt to store zone metadata in the zone, allowing it to determine if a zone has changed its serial since the last time notifications were sent out.

Changes which are discovered when reloading zones do lead to notifications however.

### Slave
Also works as expected. The Bind backend expects to be able to write to a directory where a slave domain lives. The incoming zone is stored as 'zonename.RANDOM' and atomically renamed if it is retrieved successfully, and parsed only then.

In the future, this may be improved so the old zone remains available should parsing fail.
