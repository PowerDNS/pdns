# Security Settings
PowerDNS has several options to easily allow it to run more securely. Most notable are the [`chroot`](../authoritative/settings.md#chroot), [`setuid`](../authoritative/settings.md#setuid) and [`setgid`](../authoritative/settings.md#setgid) options which can be specified.

For additional information on PowerDNS security, PowerDNS security incidents and PowerDNS security policy, see [our security policy](../security/index.md).

## Running as a less privileged identity

By specifying [`setuid`](../authoritative/settings.md#setuid) and [`setgid`](../authoritative/settings.md#setgid), PowerDNS changes to this identity shortly after binding to the privileged DNS ports. These options are highly recommended. It is suggested that a separate identity is created for PowerDNS as the user 'nobody' is in fact quite powerful on most systems.

Both these parameters can be specified either numerically or as real names. You should set these parameters immediately if they are not set!

## Jailing the process in a chroot

The [`chroot`](../authoritative/settings.md#chroot) option secures PowerDNS to its own directory so that even if it should become compromised and under control of external influences, it will have a hard time affecting the rest of the system.

Even though this will hamper hackers a lot, chroot jails have been known to be broken.

**Warning**: When chrooting PowerDNS, take care that backends will be able to get to their files. Many databases need access to a UNIX domain socket which should live within the chroot. It is often possible to hardlink such a socket into the chroot dir.

When running with master or slave support, be aware that many operating systems need access to specific libraries (often `/lib/libnss*`) in order to support resolution of domain names! You can also hardlink these.

In addition, make sure that `/dev/log` is available from within the chroot. Logging will silently fail over time otherwise (on logrotate).

The default PowerDNS configuration is best chrooted to `./`, which boils down to the configured location of the controlsocket.

This is achieved by adding the following to pdns.conf: `chroot=./`, and restarting PowerDNS.

# Security Considerations
In general, make sure that the PowerDNS process is unable to execute commands on your backend database. Most database backends will only need SELECT privilege. Take care to not connect to your database as the 'root' or 'sa' user, and configure the chosen user to have very slight privileges.

Databases empathically do not need to run on the same machine that runs PowerDNS! In fact, in benchmarks it has been discovered that having a separate database machine actually improves performance.

Separation will enhance your database security highly. Recommended.

# Security Polling
As of Authoritative Server 3.4.1 and Recursor 3.6.2, PowerDNS products can poll the security status of their respective versions. This polling, naturally, happens over DNS. If the result is that a given version has a security problem, the software will report this at level 'Error' during startup, and repeatedly during operations.

By default, security polling happens on the domain 'secpoll.powerdns.com', but this can be changed with the security-poll-suffix. If this setting is made empty, no polling will take place. Organizations wanting to host their own security zones can do so by changing this setting to a domain name under their control.

To make this easier, the zone used to host secpoll.powerdns.com is available [here](https://github.com/PowerDNS/pdns/blob/master/docs/secpoll.zone).

To enable distributors of PowerDNS to signal that they have backported versions, the PACKAGEVERSION compilation-time macro can be used to set a distributor suffix.

## Details
PowerDNS software sadly sometimes has critical security bugs. Even though we send out notifications of these via all channels available, we find that not everybody actually find out about our security releases.

To solve this, PowerDNS software will start polling for security notifications, and log these periodically. Secondly, the security status of the software will be reported using the built-in metrics. This allows operators to poll for the PowerDNS security status and alert on it.

In the implementation of this idea, we have taken the unique role of operating system distributors into account. Specifically, we can deal with backported security fixes.

Finally, this feature can be disabled, or operators can have the automated queries point at their own status service.

### Implementation
PowerDNS software periodically tries to resolve 'auth-x.y.z.security-status.secpoll.powerdns.com|TXT' or 'recursor-x.y.z.security-status.secpoll.powerdns.com'.

The data returned is in one of the following forms:

* NXDOMAIN or resolution failure -> 0
* "1 Ok" -> 1
* "2 Upgrade recommended for security reasons, see http://powerdns.com/..." -> 2
* "3 Upgrade mandatory for security reasons, see http://powerdns.com/..." -> 3

In cases 2 or 3, periodic logging commences. The metric security-status is set to 2 or 3 respectively. If at a later date, resolution fails, the security-status is not reset to 1. It could be lowered however if we discover the security status is less urgent than we thought.

If resolution fails, and the previous security-status was 1, the new security-status becomes 0 ('no data'). If the security-status was higher than 1, it will remain that way, and not get set to 0.

In this way, security-status of 0 really means 'no data', and can not mask a known problem.

### Distributions
Distributions frequently backport security fixes to the PowerDNS versions they ship. This might lead to a version number that is known to us to be insecure to be secure in reality.

To solve this issue, PowerDNS can be compiled with a distribution setting which will move the security polls from: 'auth-x.y.z.security-status.secpoll.powerdns.com' to 'auth-x.y.z-n.debian.security-status.secpoll.powerdns.com

Note two things, one, there is a separate namespace for debian, and secondly, we use the package version of this release. This allows us to know that 3.6.0-1 (say) is insecure, but that 3.6.0-2 is not.

### Configuration Details
The configuration setting 'security-poll-suffix' is by default set to 'secpoll.powerdns.com'. If empty, nothing is polled. This can be moved to 'secpoll.yourorganization.com'.

If compiled with PACKAGEVERSION=3.1.6-abcde.debian, queries will be sent to "auth-3.1.6-abcde.debian.security-status.security-poll-suffix".

### Delegation
If a distribution wants to host its own file with version information, we can delegate dist.security-status.secpoll.powerdns.com to their nameservers directly.
