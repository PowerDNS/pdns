# Tools to analyse DNS traffic
DNS is highly mission critical, it is therefore necessary to be able to
study and compare DNS traffic.  Since version 2.9.18, PowerDNS comes with
various tools to aid in analysis.  These tools are best documented by their
manpages, and their `--help` output.

The PowerDNS tools do not (yet) follow an independent release process. 
However, we keep them working, and they are shipped with PowerDNS
Authoritative Server tarballs.

In addition, our build infrastructure creates fresh Linux packages for every
commit, and these can be found on:

 * <https://autotest.powerdns.com/job/auth-git-semistatic-deb-amd64/>
 * <https://autotest.powerdns.com/job/auth-git-semistatic-deb-i386/>
 * <https://autotest.powerdns.com/job/auth-git-semistatic-rpm-amd64/>
 * <https://autotest.powerdns.com/job/auth-git-semistatic-rpm-i386/>

## `dnsreplay pcapfile [ipaddress] [port number]`
This program takes recorded questions and answers and replays them to a specified nameserver and reporting afterwards which percentage of answers matched, were worse or better.

## `dnswasher pcapfile output`
Anonymises recorded traffic, making sure it only contains DNS, and that the originating IP addresses of queries are stripped, which may allow you to send traces to our company or mailing list without violating obligations towards your customers or privacy laws.

## `dnsscope pcapfile`
Calculates statistics without replaying traffic.

## `dnsgram`
Creates statistics on 5-second segments of a pcap, allowing you to study intermittent 
performance problems. 

## `dnsbulktest`
Send out thousands of queries in parallel from Alexa top list to stress out resolvers.

## `dnsdist`
Simple but high performance UDP and TCP DNS load balancer/distributor.

## `dnstcpbench`
Stress out DNS servers with TCP based queries, as read from a file.

