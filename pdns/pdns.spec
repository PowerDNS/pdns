Buildroot: /tmp/pdns
Name: pdns
Version: 2.8
Release: 1
Summary: extremely powerful and versatile nameserver
Copyright: see /usr/doc/pdns/copyright
Distribution: Neutral
Vendor: PowerDNS.COM BV
Group: System/DNS
AutoReqProv: no

%define _rpmdir ../
%define _rpmfilename %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm

%description
PowerDNS is a versatile nameserver which supports a large number
of different backends ranging from simple zonefiles to relational
databases and load balancing/failover algorithms.

This RPM is statically compiled and should work on all Linux distributions.
It comes with support for MySQL, PostgreSQL, Bind zonefiles and the 'pipe
backend'.

%files
%defattr(-,root,root)
"/usr/sbin/pdns_server"
"/usr/sbin/pdns_control"
"/usr/sbin/zone2sql"
"/usr/doc/pdns/LICENSE"
"/usr/doc/pdns/README"
"/usr/doc/pdns/html/"
"/usr/doc/pdns/pdns.txt"
"/usr/doc/pdns/pdns.pdf"
%dir "/etc/powerdns/"
%config(noreplace) "/etc/powerdns/pdns.conf"
%config "/etc/init.d/pdns"

%post
echo Remember to create a 'pdns' user before starting pdns
