# Security Policy

If you have a security problem to report, please email us at both <a href="mailto:security@netherlabs.nl">security@netherlabs.nl</a> and <a href="mailto:ahu@ds9a.nl">ahu@ds9a.nl</a>. Please do not mail security issues to public lists, nor file a ticket, unless we do not get back to you in a timely manner. We fully credit reporters of security issues, and respond quickly, but please allow us a reasonable timeframe to coordinate a response.

We remind PowerDNS users that under the terms of the GNU General Public License, PowerDNS comes with ABSOLUTELY NO WARRANTY. This license is included in this documentation.

As of the 2nd of September 2015, no actual security problems with PowerDNS Authoritative Server 3.4.6, Recursor 3.6.3, Recursor 3.7.2, or later are known about. This page will be updated with all bugs which are deemed to be security problems, or could conceivably lead to those. Any such notifications will also be sent to all PowerDNS mailing lists.

PowerDNS Authoritative Server 3.4.0 through 3.4.5 can have their threads crashed with a malformed packet, see [PowerDNS Security Advisory 2015-02](powerdns-advisory-2015-02.md) for more information.

All recent Recursor versions up to and including 3.6.2 and 3.7.1, and all recent Authoritative servers up to and including version 3.4.3, can in specific situations be crashed with a malformed packet. For more detail, see [PowerDNS Security Advisory 2015-01](powerdns-advisory-2015-01.md)

All Recursor versions up to and including 3.6.1 can be made to provide degraded service. For more detail, see [PowerDNS Security Advisory 2014-02](powerdns-advisory-2014-02.md)

Version 3.6.0 of the Recursor (but not 3.5.x) can be crashed remotely with a specific packet sequence. For more detail, see [PowerDNS Security Advisory 2014-01](powerdns-advisory-2014-01.md)

Versions 2.9.22 and lower and 3.0 of the PowerDNS Authoritative Server were vulnerable to a temporary denial of service attack. For more detail, see [PowerDNS Security Advisory 2012-01](powerdns-advisory-2012-01.md).

Version 3.1.7.1 and earlier of the PowerDNS Recursor were vulnerable to a probably exploitable buffer overflow and a spoofing attack. For more detail, see [PowerDNS Security Advisory 2010-01](powerdns-advisory-2010-01.md "PowerDNS Security Advisory 2010-01: PowerDNS Recursor up to and including 3.1.7.1 can be brought down and probably exploited") and [PowerDNS Security Advisory 2010-02](powerdns-advisory-2010-02.md "PowerDNS Recursor up to and including 3.1.7.1 can be spoofed into accepting bogus data").

Version 3.1.4 and earlier of the PowerDNS recursor were vulnerable to a spoofing attack. For more detail, see [PowerDNS Security Advisory 2008-01](powerdns-advisory-2008-01.md "System random generator can be predicted, leading to the potential to 'spoof' PowerDNS Recursor").

Version 3.1.3 and earlier of the PowerDNS recursor contain two security issues, both of which can lead to a denial of service, both of which can be triggered by remote users. One of the issues might be exploited and ead to a system compromise. For more detail, see [PowerDNS Security Advisory 2006-01](powerdns-advisory-2006-01.md "Malformed TCP queries can lead to a buffer overflow which might be exploitable") and [PowerDNS Security Advisory 2006-02](powerdns-advisory-2006-02.md "Zero second CNAME TTLs can make PowerDNS exhaust allocated stack space, and crash").

Version 3.0 of the PowerDNS recursor contains a denial of service bug which can be exploited remotely. This bug, which we believe to only lead to a crash, has been fixed in 3.0.1. There are no guarantees however, so an upgrade from 3.0 is highly recommended.

All versions of PowerDNS before 2.9.21.1 do not respond to certain queries. This in itself is not a problem, but since the discovery by Dan Kaminsky of a new spoofing technique, this silence for queries PowerDNS considers invalid, within a valid domain, allows attackers more chances to feed *other* resolvers bad data.

All versions of PowerDNS before 2.9.18 contain the following two bugs, which only apply to installations running with the LDAP backend, or installations providing recursion to a limited range of IP addresses. If any of these apply to you, an upgrade is highly advised:

 * The LDAP backend did not properly escape all queries, allowing it to fail and not answer questions. We have not investigated further risks involved, but we advise LDAP users to update as quickly as possible (Norbert Sendetzky, Jan de Groot)

 * Questions from clients denied recursion could blank out answers to clients who are allowed recursion services, temporarily. Reported by Wilco Baan. This would've made it possible for outsiders to blank out a domain temporarily to your users. Luckily PowerDNS would send out SERVFAIL or Refused, and not a denial of a domain's existence.

All versions of PowerDNS before 2.9.17 are known to suffer from remote denial of service problems which can disrupt operation. Please upgrade to 2.9.17 as this page will only contain detailed security information from 2.9.17 onwards.
