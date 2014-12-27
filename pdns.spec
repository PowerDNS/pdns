BuildRoot: /tmp/pdns
Name: pdns-static
Version: 3.3
Release: 1
Summary: extremely powerful and versatile nameserver
License: GPL
Distribution: Neutral
Vendor: PowerDNS.COM BV
Group: System/DNS
AutoReqProv: no
Requires: glibc >= 2.4

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
%{_sbindir}/pdns_server
%{_bindir}/pdns_control
%{_bindir}/zone2sql
%{_bindir}/zone2json
%{_bindir}/pdnssec
#%{_bindir}/zone2ldap
%{_mandir}/man8/pdns_control.8
%{_mandir}/man8/pdns_server.8
%{_mandir}/man8/zone2sql.8
%{_mandir}/man8/pdnssec.8
%{_datadir}/doc/pdns/*.sql

%dir %{_sysconfdir}/powerdns/
%config(noreplace) %{_sysconfdir}/powerdns/pdns.conf
%config %{_sysconfdir}/init.d/pdns

%post
echo Remember to create a 'pdns' user before starting pdns

%package -n pdns-tools
Summary: extremely powerful and versatile nameserver
License: GPL
Distribution: Neutral
Vendor: PowerDNS.COM BV
Group: System/DNS
AutoReqProv: no

%description -n pdns-tools
These are the tools

%files -n pdns-tools
%defattr(-,root,root)
%{_bindir}/dnsbulktest
%{_bindir}/dnsgram
%{_bindir}/dnsreplay
%{_bindir}/dnsscan
%{_bindir}/dnsscope
%{_bindir}/dnsdist
%{_bindir}/dnstcpbench
%{_bindir}/dnswasher
%{_bindir}/notify
%{_bindir}/nproxy
%{_bindir}/nsec3dig
%{_bindir}/saxfr
%{_mandir}/man8/dnsreplay.1
%{_mandir}/man8/dnsscope.1
%{_mandir}/man8/dnswasher.1
%{_mandir}/man1/dnstcpbench.1
%{_mandir}/man1/dnsdist.1
