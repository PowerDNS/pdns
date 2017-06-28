Older security advisories
^^^^^^^^^^^^^^^^^^^^^^^^^
Version 3.0 of the PowerDNS recursor contains a denial of service bug which can be exploited remotely.
This bug, which we believe to only lead to a crash, has been fixed in 3.0.1.
There are no guarantees however, so an upgrade from 3.0 is highly recommended.

All versions of PowerDNS before 2.9.21.1 do not respond to certain queries.
This in itself is not a problem, but since the discovery by Dan Kaminsky of a new spoofing technique, this silence for queries PowerDNS considers invalid, within a valid domain, allows attackers more chances to feed *other* resolvers bad data.

All versions of PowerDNS before 2.9.18 contain the following two bugs, which only apply to installations running with the LDAP backend, or installations providing recursion to a limited range of IP addresses.
If any of these apply to you, an upgrade is highly advised:

-  The LDAP backend did not properly escape all queries, allowing it to
   fail and not answer questions. We have not investigated further risks
   involved, but we advise LDAP users to update as quickly as possible
   (Norbert Sendetzky, Jan de Groot)

-  Questions from clients denied recursion could blank out answers to
   clients who are allowed recursion services, temporarily. Reported by
   Wilco Baan. This would've made it possible for outsiders to blank out
   a domain temporarily to your users. Luckily PowerDNS would send out
   SERVFAIL or Refused, and not a denial of a domain's existence.

All versions of PowerDNS before 2.9.17 are known to suffer from remote denial of service problems which can disrupt operation.
Please upgrade to 2.9.17 as this page will only contain detailed security information from 2.9.17 onwards.
