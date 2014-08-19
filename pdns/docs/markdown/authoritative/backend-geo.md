# Geo backend
**Warning**: This section is a subset of the full documentation which can be found in `modules/geobackend/README` of the PowerDNS distribution.

The main author for this module is Mark Bergsma.

| | |
|:--|:--|
|Native|Partial|
|Master|No|
|Slave|No|
|Superslave|No|
|Autoserial|No|
|DNSSEC|Yes (no key storage)|

The Geo Backend can be used to distribute queries globally using an IP-address/country mapping table, several of which are freely available online or can be acquired for a small fee.

This allows visitors to be sent to a server close to them, with no appreciable delay, as would otherwise be incurred with a protocol level redirect. Additionally, the Geo Backend can be used to provide service over several clusters, any of which can be taken out of use easily, for example for maintenance purposes.

The Geo Backend is in wide use, for example by the Wikimedia foundation, which uses it to power the Wikipedia global load balancing.

More details can be found [here](http://wiki.powerdns.com/cgi-bin/trac.fcgi/browser/trunk/pdns/modules/geobackend/README), or in `modules/geobackend/README`, part of the PowerDNS Authoritative Server distribution.
