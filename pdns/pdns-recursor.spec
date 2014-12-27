%define _builddir .

Buildroot: /tmp/pdns/
Name: pdns-recursor
Version: 3.5.1
Release: 1
Summary: extremely powerful and versatile recursing nameserver
License: GPLv2
Distribution: Neutral
Vendor: PowerDNS.COM BV
Group: System/DNS

%define _rpmdir ../
%define _rpmfilename %%{name}-%%{version}-%%{release}.%%{arch}.rpm

%build
rm -rf %{buildroot}
export PATH=/opt/gcc-4.1.1/bin:${PATH}
export LD_LIBRARY_PATH=/opt/gcc-4.1.1/lib
CC=gcc make STATIC=semi

%install
make install DESTDIR=%{buildroot}

%description
PowerDNS is a versatile nameserver which supports a large number
of different backends ranging from simple zonefiles to relational
databases and load balancing/failover algorithms.

This RPM is semi-statically compiled and should work on all Linux distributions.

%files
%defattr(-,root,root)
%{_sbindir}/pdns_recursor
%{_bindir}/rec_control
%{_sysconfdir}/init.d/pdns-recursor
%{_mandir}/man1/pdns_recursor.1.gz
%{_mandir}/man1/rec_control.1.gz
%dir %{_sysconfdir}/powerdns/
%config %{_sysconfdir}/powerdns/recursor.conf-dist

%post
echo Remember to create a 'pdns' user before starting pdns
