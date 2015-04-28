# Tools to analyse DNS traffic
DNS is highly mission critical, it is therefore necessary to be able to
study and compare DNS traffic.  Since version 2.9.18, PowerDNS comes with
various tools to aid in analysis.

The following tools are available:

 * [dnsbulktest](../manpages/dnsbulktest.1.md) - A resolver stress-tester
 * [dnsgram](../manpages/dnsgram.1.md) - Show per 5-second statistics to study intermittent resolver issues
 * [dnsreplay](../manpages/dnsreplay.1.md) - Replay a pcap with DNS queries
 * [dnsscan](../manpages/dnsscan.1.md) - Prints the query-type amounts in a pcap
 * [dnsscope](../manpages/dnsscope.1.md) - Calculates statistics without replaying traffic
 * [dnstcpbench](../manpages/dnstcpbench.1.md) - Perform TCP benchmarking of DNS servers
 * [dnswasher](../manpages/dnswasher.1.md) - Clean a pcap of identifying IP information
 * [nsec3dig](../manpages/nsec3dig.1.md) - Calculate the correctness of NSEC3 proofs
 * [saxfr](../manpages/saxfr.1.md) - AXFR zones and show extra information

# Downloading the tools
The PowerDNS tools do not (yet) follow an independent release process.
However, we keep them working, and they are shipped with PowerDNS
Authoritative Server tarballs.

In addition, our build infrastructure creates fresh Linux packages for every
commit, and these can be found on:

 * <https://autotest.powerdns.com/job/auth-git-semistatic-deb-amd64/>
 * <https://autotest.powerdns.com/job/auth-git-semistatic-deb-i386/>
 * <https://autotest.powerdns.com/job/auth-git-semistatic-rpm-amd64/>
 * <https://autotest.powerdns.com/job/auth-git-semistatic-rpm-i386/>
