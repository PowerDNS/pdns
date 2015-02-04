GeoSQL Backend for PowerDNS is copyright Ⓒ 2013-2018 Shin Sterneck

Last Update: Jan. 2018

Table of Contents
=================

1. `Introduction <#introduction%5D>`__

   -  `How does it work <#how-does-it-work>`__
   -  `Overlay Concept <#overlay-concept>`__
   -  `Special RR Records <#special-rr-records>`__

2. `Setup <#setup>`__

   -  `Requirements <#requirements>`__
   -  `Preparing the GeoIP Database <#preparing-the-geoip-database>`__
   -  `Creating regions to group countries
      together <#creating-regions-to-group-countries-together>`__
   -  `Testing the Country IP
      Database <#testing-the-country-ip-database>`__
   -  `Updating the Country IP
      Database <#updating-the-country-ip-database>`__
   -  `PowerDNS Configuration
      Requirements <#powerdns-configuration-requirements>`__
   -  `Backend Configuration Options <#backend-configuration-options>`__

3. `License <#license>`__
4. `Future Plans <#future-plans>`__

Introduction
============

The GeoSQL backend for PowerDNS enables you to distribute your services
globally and direct your users the nearest server or simple maintain
different zones depending on the country or region. This is achieved by
adding location awareness to PowerDNS and maintaining regional DNS
'views'.

One goal for the GeoSQL backend module is to keep the administration and
maintenance as simple as possible by centralizing the data into an SQL
database and thus allowing the domain/zone maintainers to use existing
powerdns administration tools, such as
`PowerAdmin <http://www.poweradmin.org>`__ to manage GeoSQL enabled
domains without the need to maintain local mapping files on the powerdns
server. The GeoSQL module uses "IP Address to Location" mapping data
stored inside an SQL Database.

GeoIP enabled DNS records are stored in the same database table and
format as PowerDNS's gmysql backend, and basically appear exactly like
any other domain except that they have a custom TLD identifier. If
required, they can of course be also stored in a different database
using the same gmysql schema structure, but this will require further
configuration.

Support for "EDNS0 Client-Subnet" extension (ECS) helps to best identify
the client region even when behind a CDN or other recursive DNS servers
(if supported by the provider), such as Google's Public DNS service.

Here a summary of the main features:

1. Create and maintain different DNS records depending country/region or
   create DNS records visible in only selected countries.
2. IP address to country mapping data is completely housed inside an SQL
   database (allows replication, central administration, and
   customization of the GeoIP Data)
3. Use existing admin tools to manage geoip enabled domains/zones
   (allows for admin delegation)
4. Support for edns0-client-subnet extension to best identify client
   region

How does it work?
-----------------

1. **The administrator, has the option of grouping countries together
   into "regions" or to use the "country ID" directly**

   **a)** For example, if you want to create a zone specific for asian
   countries you could group all asian countries together and assign
   them to the region "asia".

   **b)** Alternatively the country code itself can be used directly
   without adding it to groups E.g: HK for Hong Kong or US for the
   United States of America.

2. **All GeoIP enabled zones have a suffix, which is by default
   "geosql"**

   By default all records/zones/domains that end with the custom TLD
   "geosql" are handled by the GeoSQL backend module. This effectively
   creates "views" for each region. Instead of "geosql" you can also use
   your own real subdomain as SUFFIX (e.g: geo.example.com).

As such, GeoIP enabled domains or views have the following format:

+-----------------------------------+------+---------------------------------------+
| Format                            | OR   | Format                                |
+===================================+======+=======================================+
| [domain-name].[REGION].[SUFFIX]   |      | [domain-name].[COUNTRY-ID].[SUFFIX]   |
+-----------------------------------+------+---------------------------------------+

**When PowerDNS receives a query from a client:**

**1.** It forwards the request to the GeoSQL backend.

**2.** The GeoSQL backend tries to identify the visitors geographic
location and appends the identified REGION and SUFFIX text to the
request. This results in a new "temporary" backend-internal request:
[requested-domain-name].[REGION].[SUFFIX]

**3.** The GeoSQL backend queries the database, retrieves results and
stripps away the [REGION] and [SUFFIX] text.

**4.** Finally it returns the "stripped" (without the [REGION].[SUFFIX]
text) DNS response back to PowerDNS for further processing.

All you need in the PowerDNS database is a domain entry for each REGION
or COUNTRY-ID, with its own records just like with any other domain.

--------------

As an example, lets say your domain name is called 'example.com' and you
want to create views for the countries 'us' (U.S.A) and 'it' (Italy).
The quickest way would be to create the zones like this:

+----------------------+----------------+------------+
| Actual Domain Name   | [COUNTRY-ID]   | [SUFFIX]   |
+======================+================+============+
| example.com          | us             | geosql     |
+----------------------+----------------+------------+
| example.com          | it             | geosql     |
+----------------------+----------------+------------+

Your domain within PowerDNS would then look like this:

+----------------------------------+--------------------------+
| Zone Name in PowerDNS's SQL DB   | Description              |
+==================================+==========================+
| example.com                      | main or default domain   |
+----------------------------------+--------------------------+
| example.com.us.geosql            | view for the U.S.A       |
+----------------------------------+--------------------------+
| example.com.it.geosql            | view for Italy           |
+----------------------------------+--------------------------+

As another example, you can create so called "regions". Regions group
countries together. Such as 'europe' containing the individual countries
in Europe. **For this to work, you need to associate the countries to a
region inside the SQL database first, see below optional setup step on
how to accomplish this**

Following would be a 'regional' example:

+------------------------+----------------+------------+
| [Actual Domain Name]   | [REGION]       | [SUFFIX]   |
+========================+================+============+
| example.com            | europe         | geosql     |
+------------------------+----------------+------------+
| example.com            | asia           | geosql     |
+------------------------+----------------+------------+
| example.com            | northamerica   | geosql     |
+------------------------+----------------+------------+

Your domain within PowerDNS would then look like this:

+-----------------------------------+--------------------------------------------------+
| Zone Name in PowerDNS's SQL DB    | Description                                      |
+===================================+==================================================+
| example.com                       | main or default domain, part of gmysql backend   |
+-----------------------------------+--------------------------------------------------+
| example.com.europe.geosql         | view for european region                         |
+-----------------------------------+--------------------------------------------------+
| example.com.asia.geosql           | view for asian region                            |
+-----------------------------------+--------------------------------------------------+
| example.com.northamerica.geosql   | view for north american region                   |
+-----------------------------------+--------------------------------------------------+

The first 'example.com' domain would act as the default domain and is
actually not part of the GeoSQL backend. The remaining domains,
containing the REGION's text, are geographic specific views, containing
DNS records specific to the geographic location such as A, CNAME, TXT,
MX records or even NS records.

--------------

Once you have these views, you can simply maintain DNS records within
them, just like with any other domains within PowerDNS. The only
important issue to take care of is that you don't use a real world TLD
(Top Level Domain) as the SUFFIX such as 'com', 'org' or 'net' to
prevent conflicts with real domains. The default SUFFIX is 'geosql';

Some administration tools, such as PowerAdmin, require you to enable
non-standard TLDs, otherwise they won't allow you to create them in the
first place. See the individual admin tools' documentation.
Alternatively use a subdomain of a real domain you own as SUFFIX (e.g:
geosql.example.com).

Overlay Concept
---------------

GeoSQL is designed to be used as an overlay module, this means that
GeoSQL needs to be used together with the gmysql backend at this moment.

This also means that you only need to create DNS records, which need to
be different in each geographic location. All other records are handled
by other PowerDNS backends, such as the gmysql backend.

If you have DNS records that are different in each geographic location
and other records that are same across all geographic regions, there is
no need to create the common ones again in all GeoSQL views. Simple
create them once in the main domain (the real domain) and the differing
entries in the .geosql suffixed view. This makes maintenance extremely
easy and allows for any DNS resource record to be used with GeoSQL. It
also eliminates the use of CNAME redirects or other types of tricks. You
can for example have different MX priorities depending the region or
have some records only visible in one region while not having them
available in other regions.

--------------

**Example:**

Lets say you have the following A records in the 'example.com'
zone/domain:

Domain **"example.com"** for **all** visitors worldwide

+--------------------+-----------------+
| Host Entry         | A record        |
+====================+=================+
| www.example.com    | 203.0.113.100   |
+--------------------+-----------------+
| test.example.com   | 203.0.113.200   |
+--------------------+-----------------+

Domain **"example.com.asia.geosql"** specific for **asian** visitors
(asian view):

+-------------------+---------------+
| Host Entry        | A record      |
+===================+===============+
| www.example.com   | 192.0.2.100   |
+-------------------+---------------+

Domain **"example.com.europe.geosql"** specific for **european**
visitors (european view):

+-------------------+------------------+
| Host Entry        | A record         |
+===================+==================+
| www.example.com   | 198.51.100.100   |
+-------------------+------------------+

**The final combined result would look as follows:**

**Asian** visitors would see the following records:

+--------------------+-----------------+------------------+
| Host Entry         | Response        | Handled by       |
+====================+=================+==================+
| www.example.com    | 192.0.2.100     | GeoSQL backend   |
+--------------------+-----------------+------------------+
| test.example.com   | 203.0.113.200   | Other backend    |
+--------------------+-----------------+------------------+

**European** visitors would see the following records:

+--------------------+------------------+------------------+
| Request            | Response         | Handled by       |
+====================+==================+==================+
| www.example.com    | 198.51.100.100   | GeoSQL backend   |
+--------------------+------------------+------------------+
| test.example.com   | 203.0.113.200    | Other backend    |
+--------------------+------------------+------------------+

In the above example you can see that the 'test.example.com' entry is
shown even though the asian or european views do not include this entry.
What actually happens is that after PowerDNS has processed the GeoSQL
response, it continues on with the next backend, until all relevant
backends have been queried (this logic is handled by PowerDNS) and the
"test.example.com" comes from one of the other "Other" backends. Once
all data is available, PowerDNS responds to the client with the combined
results of all backends.

--------------

    1. Note that in the event the visitor can't be mapped to a REGION,
       such as in the case when no region has been configured, the
       GeoSQL backend will assign the actual country code and try to
       retrieve any country-code specific DNS records from the database.

    2. If you have country-code specific records for the domain in the
       records database, it will always use those regardless of whether
       the country-code is part of a region or if region specific
       records exist in the database. Country-Code is more specific and
       therefore set as a higher priority than any configured region
       records.

    3. If GeoSQL can not find a region nor a country code, it will
       simply report that it could not find any records, back to
       PowerDNS, which in turn may process the request with other
       backends.

Note that GeoSQL does not directly support slave or zone-transfer
operations but you can get the geosql zones via the gmysql backend by
using the the full domain name like in the database
"example.com.us.geosql".

Special RR records
------------------

The main DNS domain will be used for SOA record queries! The GeoSQL
module will ignore the SOA record inside a .geosql domain and instead
use the 'real' SOA record.

Setup
-----

The following instructions can be used as a basic setup to get GeoSQL
running:

GeoSQL depends on two data sources:

1. The GeoIP Database containing IP Address Ranges and their assigned
   Location
2. The PowerDNS DNS Records Database, containing your DNS records.

Requirements
~~~~~~~~~~~~

GeoSQL currently requires the following libraries:

-  MySQL and database with PowerDNS gmysql schema

Preparing the GeoIP Database
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

1. To prepare the database, we will first need to download the GeoIP
   Data. There are several free and commercial ready to download
   collections available, however for this tutorial we will be using the
   MaxMind GeoLite Legacy Database in CSV format, which is freely
   available on their
   `homepage <http://dev.maxmind.com/geoip/legacy/geolite>`__ and is
   regularly updated. > It's also possible to use the new GeoLite2
   database but for the sake of simplicity > we will use the legacy
   database as the import method can also be applied to other database >
   sources such as ip2location's lite database.

2. Once you have downloaded the GeoIP data, we'll have to import it into
   our MySQL server.

The below sql statements will take care of this procedure, it presumes
that the MaxMind CSV file "GeoIPCountryWhois.csv" is located at
'/tmp/GeoIPCountryWhois.csv'. Change it to wherever you have downloaded
the file to. It also assumes that you have created and selected a
database for the geoip data.

::

    /* Table to hold the IP Address - Geo Mapping Information */
    CREATE TABLE ip (
        ip_poly POLYGON NOT NULL,
        cc CHAR(2) NOT NULL,
        SPATIAL INDEX (ip_poly)
    ) ENGINE=MYISAM;

    /* Table to hold the custom region details */
    CREATE TABLE regions (
        regionid INT UNSIGNED NOT NULL PRIMARY KEY AUTO_INCREMENT,
        regionname VARCHAR(20) NOT NULL UNIQUE,
        comment VARCHAR(50)
    );

    /* Table to connect country code with custom regions */
    CREATE TABLE connect_regions (
        id INT UNSIGNED NOT NULL PRIMARY KEY auto_increment,
        cc CHAR(2) NOT NULL UNIQUE,
        regionid INT UNSIGNED,
        FOREIGN KEY (regionid) REFERENCES regions(regionid)
    );

    /* Create a view linking ip, country code and region together for geosql's lookup function */
    CREATE VIEW lookup AS
        SELECT ip_poly, ip.cc, regions.regionname FROM ip
        LEFT JOIN connect_regions on ip.cc=connect_regions.cc
        LEFT JOIN regions on connect_regions.regionid=regions.regionid;

    /* Importing of CSV file and converting IP Address into a GeoSpacial format for a more efficient search */
    LOAD DATA LOCAL INFILE "/tmp/GeoIPCountryWhois.csv"
        INTO TABLE ip FIELDS TERMINATED BY "," ENCLOSED BY "\"" LINES TERMINATED BY "\n"
         (@ip_start_string, @ip_end_string, @ip_start, @ip_end, @cc)
        SET
         ip_poly := GEOMFROMWKB(POLYGON(LINESTRING(
          POINT(@ip_start, -1), POINT(@ip_end, -1), POINT(@ip_end, 1), POINT(@ip_start, 1), POINT(@ip_start, -1)))),
         cc := @cc;

Create an index on the gmysql backend database (the main powerdns
records table)

::

    CREATE INDEX records_name ON records (name);

Creating regions to group countries together
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This step is optional and allows you to group multiple countries into
regions. You can then create zones/views for the entire region instead
of for each individual country. Keep in mind that country specific zones
are handled with higher priority and used instead if found, which means
that if for example you have a region "europe", which countains "de"
(Germany) and records for "*.europe.geosql" and "*.de.geosql"
configured, the latter will be used and the former disregarded.

Example on how to create regions:

::

    /* create 'europe' example region */
     insert into regions values (null, 'europe','test region for europe');

    /* create 'asia' example region */
     insert into regions values (null, 'asia','test region for asia');

Example: Assigning countries to the region:

::

    /* Assigning Germany (de) to the 'europe' example region */
     insert ignore into connect_regions select null, 'DE' , regionid from regions where regionname='europe';

    /* Another example assigning Asia Pacific countries to the 'asia' example region */
     select regionid from regions where regionname='asia' into @regionid;
     insert ignore into connect_regions values
      (null,'AP',@regionid),
      (null,'AU',@regionid),
      (null,'CN',@regionid),
      (null,'HK',@regionid),
      (null,'ID',@regionid),
      (null,'IN',@regionid),
      (null,'JP',@regionid),
      (null,'KH',@regionid),
      (null,'KP',@regionid),
      (null,'KR',@regionid),
      (null,'MY',@regionid),
      (null,'NZ',@regionid),
      (null,'PH',@regionid),
      (null,'SG',@regionid),
      (null,'TH',@regionid),
      (null,'TW',@regionid),
      (null,'VN',@regionid);

Testing the Country IP Database
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Sometimes it's neccessary to check whether the IP's are properly
associated and return the desired region or country. This can be easily
done using a long sql command, but this can be combersome to remember,
so to make this simple we can create a stored procedure:

::

    DELIMITER //
    CREATE PROCEDURE getcountry
    (IN arg_ip CHAR(39))
    BEGIN
      SELECT cc,regionname from lookup
      WHERE MBRCONTAINS(ip_poly, POINTFROMWKB(POINT(INET_ATON(arg_ip), 0)));
    END //
    DELIMITER ;

This creates a stored procedure called 'getcountry' that accepts an IP
address as argument. You can then test an IP address using the following
command:

::

    call getcountry('8.8.8.8');

Updating the Country IP Database
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Updating the GeoIP Database is as simple as reimporting the database.
Simply empty the 'ip' table and import the new GeoIP Database.

::

    /* update geoip database */
    DELETE FROM ip;

    /* Importing of CSV file and converting IP Address into a GeoSpacial format for a more efficient search */
    LOAD DATA LOCAL INFILE "/tmp/GeoIPCountryWhois.csv"
        INTO TABLE ip FIELDS TERMINATED BY "," ENCLOSED BY "\"" LINES TERMINATED BY "\n"
         (@ip_start_string, @ip_end_string, @ip_start, @ip_end, @cc)
        SET
         ip_poly := GEOMFROMWKB(POLYGON(LINESTRING(
          POINT(@ip_start, -1), POINT(@ip_end, -1), POINT(@ip_end, 1), POINT(@ip_start, 1), POINT(@ip_start, -1)))),
         cc := @cc;

PowerDNS Configuration Requirements
-----------------------------------

Following is an example /etc/pdns.conf configuration

::

    # disable caching because responses will be different depending on the source ip
    query-cache-ttl=0
    cache-ttl=0

    # load geosql before gmysql
    launch=geosql,gmysql

    ## Configure gmysql backend ##
    gmysql-host=127.0.0.1
    gmysql-dbname=powerdns
    gmysql-user=powerdns
    gmysql-password=password

    ## configure geosql backend ##

    # specify GeoIP database details to retrieve country and region information
    geosql-geo-backend=mysql
    geosql-geo-host=127.0.0.1
    geosql-geo-database=geoip
    geosql-geo-username=root
    geosql-geo-password=password

    # specify powerdns database details for geosql to retrieve geosql suffixed records
    geosql-pdns-backend=mysql
    geosql-pdns-host=127.0.0.1
    geosql-pdns-database=powerdns
    geosql-pdns-username=powerdns
    geosql-pdns-password=password

Backend Configuration Options
-----------------------------

following is a description of the available configuration options and
their default values.

Option: domain-suffix
~~~~~~~~~~~~~~~~~~~~~

    **Description** : Set the domain suffix for GeoSQL zones without
    prefixed 'dot' character

    **Default** : geosql

Option: geo-host
~~~~~~~~~~~~~~~~

    **Description** : The GeoIP Database server IP/FQDN

    **Default** : localhost

Option: geo-database
~~~~~~~~~~~~~~~~~~~~

    **Description**: The GeoIP Database name

    **Default** : geoip

Option: geo-username
~~~~~~~~~~~~~~~~~~~~

    **Description** : The GeoIP Database username

    **Default** : geoip

Option: geo-password
~~~~~~~~~~~~~~~~~~~~

    **Description** : The GeoIP Database password

    **Default** : geoip

Option: pdns-host
~~~~~~~~~~~~~~~~~

    **Description** : The PowerDNS Database server IP/FQDN

    **Default** : localhost

Option: pdns-database
~~~~~~~~~~~~~~~~~~~~~

    **Description** : The PowerDNS Database name

    **Default** : pdns

Option: pdns-username
~~~~~~~~~~~~~~~~~~~~~

    **Description** : The PowerDNS Database username

    **Default** : pdns

Option: pdns-password
~~~~~~~~~~~~~~~~~~~~~

    **Description** : The PowerDNS Database password

    **Default** : pdns

--------------

**The following options support variable substitution of the following
strings:**

+---------------+------------------------------------------------------------+
| Variable      | Replaced by                                                |
+===============+============================================================+
| {{REGION}}    | Replaced by the detected region or country code            |
+---------------+------------------------------------------------------------+
| {{DOMAIN-SUFF | Replaced by domain suffix configured with the              |
| IX}}          | "domain-suffix" configuration option                       |
+---------------+------------------------------------------------------------+
| {{QDOMAIN}}   | Replaced by the requested domainname (e.g: example.com)    |
+---------------+------------------------------------------------------------+
| {{QTYPE}}     | Replaced by the requested query type (e.g: MX,A, CNAME,    |
|               | TXT, etc...)                                               |
+---------------+------------------------------------------------------------+
| {{S-IP}}      | Replaced by the IP Address of the original requestor or    |
|               | the ECS Information                                        |
+---------------+------------------------------------------------------------+

Option: sql-pdns-lookuptype
~~~~~~~~~~~~~~~~~~~~~~~~~~~

    **Description** : SQL Statement to retrieve RR types such as
    A,CNAME,TXT or MX records.

    **Expected Columns** : name, type, content, ttl, prio (order is not
    important)

    **Default** : select replace(name,
    '.{{REGION}}.{{DOMAIN-SUFFIX}}','') as name, type ,
    replace(content,'.{{REGION}}.{{DOMAIN-SUFFIX}}','') as content, ttl,
    prio from records where
    name='{{QDOMAIN}}.{{REGION}}.{{DOMAIN-SUFFIX}}' and type='{{QTYPE}}'
    and disabled=0;

Option: sql-pdns-lookuptype-any
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    **Description** : SQL Statement to retrieve the ANY RR type requests

    **Expected Columns** : name, type, content, ttl, prio (order is not
    important)

    **Default** : select replace(name,
    '.{{REGION}}.{{DOMAIN-SUFFIX}}','') as name, type,
    replace(content,'.{{REGION}}.{{DOMAIN-SUFFIX}}','') as content, ttl,
    prio from records where
    name='{{QDOMAIN}}.{{REGION}}.{{DOMAIN-SUFFIX}}' and type != 'SOA'
    and disabled=0;

Option: sql-geo-lookup-region
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

    **Description** : SQL Statement to lookup the REGION and Country
    Code by source IP address

    **Expected Columns** : cc, regionname (order is not important)

    **Default** : select cc,regionname from lookup where
    MBRCONTAINS(ip\_poly, POINTFROMWKB(POINT(INET\_ATON('{{S-IP}}'),
    0)));

License
-------

GeoSQL backend for PowerDNS to support geo-location based DNS responses
with configuration data stored in an SQL database.

Copyright (C) Shin Sterneck 2013-2018 (email: shin at sterneck dot asia)

This program is free software; you can redistribute it and/or modify it
under the terms of version 2 of the GNU General Public License as
published by the Free Software Foundation.

In addition, for the avoidance of any doubt, permission is granted to
link this program with OpenSSL and to (re)distribute the binaries
produced as the result of such linking.

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

Future Plans
------------

1. Additional backend database support (e.g: PostgreSQL)
2. Performance improvements
3. If possible, better integration with the gmysql backend

Please drop me an email or leave some feedback if this backend is useful
to you or you have improvement suggestions.

Have fun!

Shin Sterneck (shin at sterneck dot asia)
