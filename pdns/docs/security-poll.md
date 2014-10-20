# PowerDNS Security Polling
PowerDNS software sadly sometimes has critical security bugs. Even though we
send out notifications of these via all channels available, we find that not
everybody actually find out about our security releases.

To solve this, PowerDNS software will start polling for security
notifications, and log these periodically. Secondly, the security status
of the software will be reported using the built-in metrics. This allows
operators to poll for the PowerDNS security status and alert on it.

In the implementation of this idea, we have taken the unique role of
operating system distributors into account. Specifically, we can deal with
backported security fixes.

Finally, this feature can be disabled, or operators can have the automated
queries point at their own status service.

## Implementation
PowerDNS software periodically tries to resolve
'auth-x.y.z.security-status.secpoll.powerdns.com|TXT' or
'recursor-x.y.z.security-status.secpoll.powerdns.com'. 

The data returned is in one of the following forms:

 * NXDOMAIN or resolution failure
 * "0 Ok"
 * "1 Upgrade recommended for security reasons, see http://powerdns.com/..."
 * "2 Upgrade mandatory for security reasons, see http://powerdns.com/..."

In cases 1 or 2, periodic logging commences. The metric security-status is
set to 1 or 2 respectively. If at a later date, resolution fails, the
security-status is not reset to 0. It could be lowered however if we
discover the security status is less urgent than we thought.

## Distributions
Distributions frequently backport security fixes to the PowerDNS versions
they ship. This might lead to a version number that is known to us to be
insecure to be secure in reality.

To solve this issue, PowerDNS can be compiled with a distribution setting
which will move the security polls from:
'auth-x.y.z.security-status.secpoll.powerdns.com' to
'auth-x.y.z-n.security-status.debian.secpoll.powerdns.com

Note two things, one, there is a separate namespace for debian, and
secondly, we include the sub-version of this release. This allows us to know
that 3.6.0-1 (say) is insecure, but that 3.6.0-2 is not.

## Details
The configuration setting 'security-poll-suffix' is by default set to
'secpoll.powerdns.com'. If empty, nothing is polled. This can be moved to
'secpoll.yourorganization.com'.

If compiled with DISTRIBUTION=dist SUBVERSION=abcde, queries will be sent to
"auth-x.y.z-abcde.dist.security-poll-suffix".


