Buildroot: /tmp/pdns
Name: pdns-static
Version: 2.9.8
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
"/usr/bin/pdns_control"
"/usr/bin/zone2sql"
"/usr/bin/xdb-fill"
%dir "/etc/powerdns/"
%config(noreplace) "/etc/powerdns/pdns.conf"
%config "/etc/init.d/pdns"

%post
echo Remember to create a 'pdns' user before starting pdns
