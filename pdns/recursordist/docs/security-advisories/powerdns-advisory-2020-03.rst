PowerDNS Security Advisory 2020-03: Information disclosure
==========================================================

-  CVE: CVE-2020-10030
-  Date: May 19th 2020
-  Affects: PowerDNS Recursor from 4.1.0 up to and including 4.3.0
-  Not affected: 4.3.1, 4.2.2, 4.1.16
-  Severity: Low
-  Impact: Information Disclosure, Denial of Service
-  Exploit: This problem can be triggered via a crafted hostname
-  Risk of system compromise: No
-  Solution: Upgrade to a non-affected version
-  Workaround: None

An issue has been found in PowerDNS Authoritative Server allowing an
attacker with enough privileges to change the system's hostname to
cause disclosure of uninitialized memory content via a stack-based
out-of-bounds read.
It only occurs on systems where gethostname() does not null-terminate
the returned string if the hostname is larger than the supplied buffer.
Linux systems are not affected because the buffer is always large enough.
OpenBSD systems are not affected because the returned hostname is always
null-terminated.
Under some conditions this issue can lead to the writing of one null-byte
out-of-bounds on the stack, causing a denial of service or possibly
arbitrary code execution.

This issue has been assigned CVE-2020-10030.

PowPowerDNS Recursor from 4.1.0 up to and including 4.3.0 is affected.

Please note that at the time of writing, PowerDNS Authoritative 4.0 and
below are no longer supported, as described in
https://doc.powerdns.com/authoritative/appendices/EOL.html.

We would like to thank Valеntei Sergey for finding and subsequently
reporting this issue!

