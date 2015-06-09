# LDAP backend
**Warning**: As of PowerDNS Authoritative Server 3.0, the LDAP backend is unmaintained. While care will be taken that this backend still compiles, this backend is known to have problems in version 3.0 and beyond! Please contact <a href="mailto:powerdns.support@powerdns.com">powerdns.support@powerdns.com</a> or visit [www.powerdns.com](http://www.powerdns.com) to rectify this situation.

**Warning**: Grégory Oestreicher has forked the LDAP backend shortly before our 3.2 release. Please visit his [repository](http://repo.or.cz/w/pdns-ldap-backend.git) for the latest code.

**Warning**: This documentation has moved to [its own page](http://wiki.linuxnetworks.de/index.php/PowerDNS_ldapbackend). The information in this chapter may be outdated!

The main author for this module is Norbert Sendetzky.

He also maintains the [LDAP backends documentation](http://wiki.linuxnetworks.de/index.php/PowerDNS_ldapbackend) there. The information below may be outdated!

**Warning**: Host names and the MNAME of a SOA records are NEVER terminated with a '.' in PowerDNS storage! If a trailing '.' is present it will inevitably cause problems, problems that may be hard to debug.

|&nbsp;|&nbsp;|
|:--|:--|
|Native|Yes|
|Master|No|
|Slave|No|
|Superslave|No|
|Autoserial|No|
|DNSSEC|No|
