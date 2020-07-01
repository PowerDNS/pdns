PowerDNS Security Advisory 2020-04: Access restriction bypass
=============================================================

-  CVE: CVE-2020-14196
-  Date: July 1st 2020
-  Affects: PowerDNS Recursor up to and including 4.3.1, 4.2.2 and 4.1.16
-  Not affected: 4.3.2, 4.2.3, 4.1.17
-  Severity: Low
-  Impact: Access restriction bypass
-  Exploit: This problem can be triggered by sending HTTP queries
-  Risk of system compromise: No
-  Solution: Upgrade to a non-affected version 
-  Workaround: Disable the webserver, set a password or an API key.
   Additionally, restrict the binding address using the
   `webserver-address` setting to local addresses only and/or use a
   firewall to disallow web requests from untrusted sources reaching the
   webserver listening address.

An issue has been found in PowerDNS Recursor where the ACL applied to
the internal web server via `webserver-allow-from` is not properly
enforced, allowing a remote attacker to send HTTP queries to the
internal web server, bypassing the restriction.
 
In the default configuration the API webserver is not enabled. Only
installations using a non-default value for `webserver` and
`webserver-address` are affected.

