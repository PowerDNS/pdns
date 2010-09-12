%define _builddir .

Buildroot: /tmp/pdns/
Name: pdns-recursor
Version: 3.3rc2
Release: 1
Summary: extremely powerful and versatile recursing nameserver
License: GPL
Distribution: Neutral
Vendor: PowerDNS.COM BV
Group: System/DNS
AutoReqProv: no

%define _rpmdir ../
%define _rpmfilename %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm

%build
rm -rf $RPM_BUILD_ROOT
export PATH=/opt/gcc-4.1.1/bin:${PATH}
export LD_LIBRARY_PATH=/opt/gcc-4.1.1/lib
CC=gcc make STATIC=semi

%install
DESTDIR=$RPM_BUILD_ROOT make install

%description
PowerDNS is a versatile nameserver which supports a large number
of different backends ranging from simple zonefiles to relational
databases and load balancing/failover algorithms.

This RPM is semi-statically compiled and should work on all Linux distributions.

%files
%defattr(-,root,root)
"/usr/sbin/pdns_recursor"
"/usr/bin/rec_control"
"/etc/init.d/pdns-recursor"
"/usr/share/man/man1/pdns_recursor.1.gz"
"/usr/share/man/man1/rec_control.1.gz"
%dir "/etc/powerdns/"
%config "/etc/powerdns/recursor.conf-dist"

%post
echo Remember to create a 'pdns' user before starting pdns
