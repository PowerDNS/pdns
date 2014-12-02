# GeoIP backend

|&nbsp;|&nbsp;|
|:--|:--|
|Native|Yes|
|Master|No|
|Slave|No|
|Superslave|No|
|Autoserial|No|
|DNSSEC|Yes|

The GeoIP backend can be used to distribute queries globally using an MaxMind IP-address/country mapping table, currently avaible for debian and ubuntu for free. Other formats are not yet supported but will be in the future. The only format supported at the moment is country listing.

This allows visitors to be sent to a server close to them, with no appreciable delay, as would otherwise be incurred with a protocol level redirect. Additionally, the Geo Backend can be used to provide service over several clusters, any of which can be taken out of use easily, for example for maintenance purposes.

## Prerequisites
To compile the backend, you need libyaml-cpp 0.5 or later and libgeoip.

You must have geoip database available. As of writing, on debian/ubuntu systems, you can use apt-get install geoip-database to get one, and the backend is configured to use the location where these files are installed as source. On other systems you might need to alter the database-file and database-file6 attribute. If you don't need ipv4 or ipv6 support, set the respective setting to "". Leaving it unset leaves it pointing to default location, preventing the software from starting up.

## Configuration Parameters
These are the configuration file parameters that are available for the GeoIP backend. geoip-zones-files is the only thing you must set, if the defaults suite you.

### `geoip-database-file`
Specifies the full path of the data file for IPv4 to use.

### `geoip-database-file6`
Specifies the full path of the data file for IPv6 to use.

### `geoip-zones-file`
Specifies the full path of the zone configuration file to use.

### `geoip-dnssec-keydir`
Specifies the full path of a directory that will contain DNSSEC keys.

## Zonefile format
Zone configuration file uses YAML syntax. Here is simple example. Note that the ‐ before certain keys is part of the syntax.

```
domains:
- domain: geo.example.com
  ttl: 30
  records:
    geo.example.com:
      - soa: ns1.example.com hostmaster.example.com 2014090125 7200 3600 1209600 3600
      - ns: ns1.example.com
      - ns: ns2.example.com
      - mx: 10 mx.example.com
    fin.eu.service.geo.example.com:
      - a: 198.51.100.221
      - txt: hello world
      - aaaa: 2001:DB8::12:34DE:3
  services:
    service.geo.example.com: '%co.%cn.service.geo.example.com'
```

### Keys explained
* **domains**: Mandatory root key. All configuration is below this
* **domain**: Defines a domain. You need ttl, records, services under this.
* **ttl**: TTL value for all records
* **records**: Put fully qualified name as subkey, under which you must define at least soa: key. Note that this is an array of records, so ‐ is needed for the values.
* **services**: Defines one or more services for querying. The format supports following placeholders, %% = %, %co = 3-letter country, %cn = continent, %af = v4 or v6. There are also other specifiers that will only work with suitable database and currently are untested. These are %re = region, %na = Name (such as, organisation), %ci = City.
