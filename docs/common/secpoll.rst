Security Polling
----------------
PowerDNS products can poll the security status of their respective versions.
This polling, naturally, happens over DNS.
If the result is that a given version has a security problem, the software will report this at level 'Error' during startup, and repeatedly during operations.

By default, security polling happens on the domain 'secpoll.powerdns.com', but this can be changed with the :ref:`setting-security-poll-suffix`.
If this setting is made empty, no polling will take place.
Organizations wanting to host their own security zones can do so by changing this setting to a domain name under their control.

To make this easier, the zone used to host secpoll.powerdns.com is `available <https://github.com/PowerDNS/pdns/blob/master/docs/secpoll.zone>`_.

To enable distributors of PowerDNS to signal that they have backported versions, the PACKAGEVERSION compilation-time macro can be used to set a distributor suffix.

Details
^^^^^^^
PowerDNS software sadly sometimes has critical security bugs.
Even though we send out notifications of these via all channels available, we find that not everybody actually finds out about our security releases.

To solve this, PowerDNS software will start polling for security notifications, and log these periodically.
Secondly, the security status of the software will be reported using the built-in metrics.
This allows operators to poll for the PowerDNS security status and alert on it.

In the implementation of this idea, we have taken the unique role of operating system distributors into account.
Specifically, we can deal with backported security fixes.

Finally, this feature can be disabled, or operators can have the automated queries point at their own status service.

Implementation
~~~~~~~~~~~~~~
PowerDNS software periodically tries to resolve 'auth-x.y.z.security-status.secpoll.powerdns.com|TXT' or 'recursor-x.y.z.security-status.secpoll.powerdns.com'.

The data returned is in one of the following forms:

-  NXDOMAIN or resolution failure -> 0
-  "1 Ok" -> 1
-  "2 Upgrade recommended for security reasons, see ..." -> 2
-  "3 Upgrade mandatory for security reasons, see ..." -> 3

In cases 2 or 3, periodic logging commences.
Case 2 can also be issued for non-security related upgrade recommendations for pre-releases.
The metric security-status is set to 2 or 3 respectively.
If at a later date, resolution fails, the security-status is not reset to 1.
It could be lowered however if we discover the security status is less urgent than we thought.

If resolution fails, and the previous security-status was 1, the new security-status becomes 0 ('no data').
If the security-status was greater than 1, it will remain that way, and not get set to 0.

In this way, security-status of 0 really means 'no data', and cannot mask a known problem.

Distributions
~~~~~~~~~~~~~
Distributions frequently backport security fixes to the PowerDNS versions they ship.
This might lead to a version number that is known to us to be insecure to be secure in reality.

To solve this issue, PowerDNS can be compiled with a distribution setting which will move the security polls from: 'auth-x.y.z.security-status.secpoll.powerdns.com' to 'auth-x.y.z-n.debian.security-status.secpoll.powerdns.com.

Note two things, one, there is a separate namespace for debian, and secondly, we use the package version of this release.
This allows us to know that 4.0.1-1 (say) is insecure, but that 4.0.1-2 is not.

Configuration Details
~~~~~~~~~~~~~~~~~~~~~
The configuration setting :ref:`setting-security-poll-suffix` is by default set to 'secpoll.powerdns.com'.
If empty, nothing is polled. This can be moved to 'secpoll.yourorganization.com'.

If compiled with PACKAGEVERSION=3.1.6-abcde.debian, queries will be sent to "auth-3.1.6-abcde.debian.security-status.security-poll-suffix".

Delegation
~~~~~~~~~~
If a distribution wants to host its own file with version information, we can delegate dist.security-status.secpoll.powerdns.com to their nameservers directly.
