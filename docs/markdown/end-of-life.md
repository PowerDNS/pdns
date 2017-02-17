# End of life statements
The currently supported release train of PowerDNS, for both the Authoritative Server and the Recursor is 4.x.

PowerDNS Authoritative Server 3.4 is considered legacy and will only receive critical bug fixes and security fixes.

PowerDNS Authoritative Server 3.3 will only receive security fixes.

PowerDNS Recursor 3.7 is considered legacy and will only receive critical bug fixes and security fixes.

PowerDNS Recursor 3.6 will only receive security fixes.

PowerDNS Authoritative Server and Recursor 2.x are end of life.

## PowerDNS Authoritative Server 2.x
21st of May 2015 (updated January 2017)

PowerDNS Authoritative Server 2.9.22 was released in January 2009.
Because of its immense and durable popularity, some patch releases have been provided, the last one of which (2.9.22.6) was made available in January 2012.

The 2.9.22.x series contains a number of probable and actual violations of the DNS standards.
In addition, some behaviours of 2.9.22.x are standards conforming but cause interoperability problems today.
Finally, 2.9.22.4 and earlier are impacted by [PowerDNS Security Advisory 2012-01](https://doc.powerdns.com/md/security/powerdns-advisory-2012-01/), which means PowerDNS can be used in a Denial of Service attack.

Although we have long been telling users that we can no longer support the use of 2.x, and urging upgrading, with this statement we formally declare 2.x end of life.

This means that any 2.x issues will not be addressed.
This has been the case for a long time, but with this statement we make it formal.

To upgrade to 3.x, please consult the [instructions on how to upgrade the database](https://doc.powerdns.com/3/authoritative/upgrading/#29x-to-30).
To upgrade from 3.x to 4.x, [follow these instructions](authoritative/upgrading.md).
If you need help with upgrading, we provide [migration services](https://www.powerdns.com/support-services-consulting.html) to our supported users.
If you are currently running 2.9.22 and need help to tide you over, we can also provide that as part of a [support agreement](https://www.powerdns.com/support-services-consulting.html).

But we urge everyone to move on to PowerDNS Authoritative Server 4.0 or later - it is a faster, more standards conforming and more powerful nameserver!
