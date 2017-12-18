Name: dnsdist
Version: %{getenv:BUILDER_VERSION}
Release: %{getenv:BUILDER_RELEASE}
Summary: Powerful and scriptable DNS loadbalancer
License: GPLv2
Vendor: PowerDNS.COM BV
Group: System/DNS
Source: dnsdist-%{version}.tar.bz2
BuildRequires: readline-devel
BuildRequires: libedit-devel

%if 0%{?el6}
BuildRequires: boost148-devel
BuildRequires: lua-devel
BuildRequires: protobuf-compiler
BuildRequires: protobuf-devel
BuildRequires: re2-devel
%elif 0%{?suse_version}
BuildRequires: boost-devel
BuildRequires: lua-devel
BuildRequires: systemd-units
BuildRequires: systemd-devel
%else
BuildRequires: boost-devel
BuildRequires: libsodium-devel
BuildRequires: luajit-devel
BuildRequires: net-snmp-devel
BuildRequires: protobuf-compiler
BuildRequires: protobuf-devel
BuildRequires: re2-devel
BuildRequires: systemd-units
BuildRequires: systemd-devel
%endif

%if 0%{?el6}
Requires(pre): shadow-utils
%elif 0%{suse_version}
Requires(pre): shadow
%systemd_requires
%else
Requires(pre): shadow-utils
%systemd_requires
%endif

%description
dnsdist is a high-performance DNS loadbalancer that is scriptable in Lua.

%prep
%setup

# run as dnsdist user
sed -i '/^ExecStart/ s/dnsdist/dnsdist -u dnsdist -g dnsdist/' dnsdist.service.in

%build
%configure \
  --sysconfdir=/etc/dnsdist \
%if 0%{?el6}
  --disable-dnscrypt \
  --disable-libsodium \
  --enable-re2 \
  --with-net-snmp \
  --with-protobuf \
  --with-boost=/usr/include/boost148 LIBRARY_PATH=/usr/lib64/boost148
%elif 0%{suse_version}
  --disable-dnscrypt \
  --disable-libsodium \
  --disable-re2 \
  --enable-systemd --with-systemd=/lib/systemd/system \
  --without-protobuf \
  --without-net-snmp
%else
  --with-protobuf \
  --with-luajit \
  --enable-libsodium \
  --enable-dnscrypt \
  --enable-systemd --with-systemd=/lib/systemd/system \
  --enable-re2 \
  --with-net-snmp
%endif

%if 0%{?el6}
make %{?_smp_mflags} LIBRARY_PATH=/usr/lib64/boost148
%else
make %{?_smp_mflags}
%endif
mv dnsdistconf.lua dnsdist.conf.sample

%check
make %{?_smp_mflags} check || (cat test-suite.log && false)

%install
%make_install
install -d %{buildroot}/%{_sysconfdir}/dnsdist
%if 0%{?el6}
install -d -m 755 %{buildroot}/%{_initrddir} && install -m 755 contrib/dnsdist.init.centos6 %{buildroot}/%{_initrddir}/dnsdist
%else
# EL7 and SUSE
sed -i "s,/^\(ExecStart.*\)dnsdist\(.*\)\$,\1dnsdist -u dnsdist -g dnsdist\2," %{buildroot}/lib/systemd/system/dnsdist.service
sed -i "s,/^\(ExecStart.*\)dnsdist\(.*\)\$,\1dnsdist -u dnsdist -g dnsdist\2," %{buildroot}/lib/systemd/system/dnsdist@.service
%endif

%pre
getent group dnsdist >/dev/null || groupadd -r dnsdist
getent passwd dnsdist >/dev/null || \
	useradd -r -g dnsdist -d / -s /sbin/nologin \
	-c "dnsdist user" dnsdist
exit 0

%post
%if 0%{?el6}
/sbin/chkconfig --add %{name}
%elif 0%{?suse_version}
%service_add_post %{name}.service
%else
%systemd_post %{name}.service
%endif

%preun
%if 0%{?el6}
if [ "\$1" -eq "0" ]; then
  # Package removal, not upgrade
  /sbin/service %{name} stop > /dev/null 2>&1 || :
  /sbin/chkconfig --del %{name}
fi
%elif 0%{?suse_version}
%service_del_preun %{name}.service
%else
%systemd_preun %{name}.service
%endif

%postun
%if 0%{?el6}
if [ "\$1" -ge "1" ] ; then
  /sbin/service %{name} condrestart >/dev/null 2>&1 || :
fi
%elif 0%{?suse_version}
%service_del_postun %{name}.service
%else
%systemd_postun_with_restart %{name}.service
%endif

%files
%{!?_licensedir:%global license %%doc}
%doc dnsdist.conf.sample
%doc README.md
%{_bindir}/*
%{_mandir}/man1/*
%dir %{_sysconfdir}/dnsdist
%if 0%{?el6}
%{_initrddir}/dnsdist
%else
/lib/systemd/system/dnsdist*
%endif
