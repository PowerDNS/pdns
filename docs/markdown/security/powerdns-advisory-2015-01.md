## PowerDNS Security Advisory 2015-01: Label decompression bug can cause crashes on specific platforms

* CVE: CVE-2015-1868
* Date: 23rd of April 2015
* Credit: Aki Tuomi
* Affects: PowerDNS Recursor versions 3.5 and up; Authoritative Server 3.2 and up
* Not affected: Recursor 3.6.3; Recursor 3.7.2; Auth 3.4.4
* Severity: High
* Impact: Degraded service
* Exploit: This problem can be triggered by sending queries for specifically configured domains
* Risk of system compromise: No
* Solution: Upgrade to any of the non-affected versions
* Workaround: Run your Recursor under a supervisor. Exposure can be limited by
  configuring the [`allow-from`](../recursor/settings.md#allow-from) setting so
  only trusted users can query your nameserver.

A bug was discovered in our label decompression code, making it possible for
names to refer to themselves, thus causing a loop during decompression. This
loop is capped at a 1000 iterations by a failsafe, making the issue harmless
on most platforms.

However, on specific platforms (so far, we are only aware of this happening on
RHEL5/CentOS5), the recursion involved in these 1000 steps causes memory
corruption leading to a quick crash, presumably because the default stack is
too small.

We recommend that all users upgrade to a corrected version if at all possible.
Alternatively, if you want to apply a minimal fix to your own tree, please
[find patches here](https://downloads.powerdns.com/patches/2015-01/).

These should be trivial to backport to older versions by hand.

As for workarounds, only clients in allow-from are able to trigger the
degraded service, so this should be limited to your userbase; further,  we
recommend running your critical services under supervision such as systemd,
supervisord, daemontools, etc.

We want to thank Aki Tuomi for noticing this in production, and then digging
until he got to the absolute bottom of what at the time appeared to be a
random and spurious failure.