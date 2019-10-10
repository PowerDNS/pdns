Name: dnsdist
Version: %{getenv:BUILDER_RPM_VERSION}
Release: %{getenv:BUILDER_RPM_RELEASE}%{dist}
Summary: Powerful and scriptable DNS loadbalancer
License: GPLv2
Vendor: PowerDNS.COM BV
Group: System/DNS
Source: %{name}-%{getenv:BUILDER_VERSION}.tar.bz2
BuildRequires: readline-devel
BuildRequires: libedit-devel
BuildRequires: openssl-devel

%if 0%{?el6}
BuildRequires: boost148-devel
BuildRequires: lua-devel
BuildRequires: protobuf-compiler
BuildRequires: protobuf-devel
BuildRequires: re2-devel
%endif
%if 0%{?suse_version}
BuildRequires: boost-devel
BuildRequires: lua-devel
BuildRequires: systemd
BuildRequires: systemd-units
BuildRequires: systemd-devel
%endif
%if 0%{?rhel} >= 7
BuildRequires: boost-devel
BuildRequires: gnutls-devel
BuildRequires: libcap-devel
BuildRequires: lmdb-devel
BuildRequires: libsodium-devel
%ifarch aarch64
BuildRequires: lua-devel
%define lua_implementation lua
%else
BuildRequires: luajit-devel
%define lua_implementation luajit
%endif
BuildRequires: net-snmp-devel
BuildRequires: protobuf-compiler
BuildRequires: protobuf-devel
BuildRequires: re2-devel
BuildRequires: systemd
BuildRequires: systemd-devel
BuildRequires: systemd-units
BuildRequires: tinycdb-devel
%endif

%if 0%{?el6}
Requires(pre): shadow-utils
%endif
%if 0%{?suse_version}
Requires(pre): shadow
%systemd_requires
%endif
%if 0%{?rhel} >= 7
Requires(pre): shadow-utils
%if 0%{?rhel} == 7
# No fstrm in EPEL 8 (yet) https://bugzilla.redhat.com/show_bug.cgi?id=1760298
BuildRequires: fstrm-devel
%endif
%systemd_requires
%endif

%description
dnsdist is a high-performance DNS loadbalancer that is scriptable in Lua.

%prep
%if 0%{?rhel} == 6
%setup -n %{name}-%{getenv:BUILDER_VERSION}
%else
%autosetup -p1 -n %{name}-%{getenv:BUILDER_VERSION}
%endif

# run as dnsdist user
sed -i '/^ExecStart/ s/dnsdist/dnsdist -u dnsdist -g dnsdist/' dnsdist.service.in

%build
%configure \
  --enable-option-checking=fatal \
  --sysconfdir=/etc/dnsdist \
  --disable-static \
  --disable-dependency-tracking \
  --disable-silent-rules \
  --enable-unit-tests \
  --enable-dns-over-tls \
%if 0%{?el6}
  --disable-dnscrypt \
  --without-libsodium \
  --with-re2 \
  --with-net-snmp \
  --with-protobuf \
  --with-boost=/usr/include/boost148 LIBRARY_PATH=/usr/lib64/boost148
%endif
%if 0%{?suse_version}
  --disable-dnscrypt \
  --without-libsodium \
  --without-re2 \
  --enable-systemd --with-systemd=/lib/systemd/system \
  --without-protobuf \
  --without-net-snmp
%endif
%if 0%{?rhel} == 7
  --enable-dnstap \
%endif
%if 0%{?rhel} >= 7
  --with-gnutls \
  --with-protobuf \
  --with-lua=%{lua_implementation} \
  --with-libcap \
  --with-libsodium \
  --enable-dnscrypt \
  --enable-dns-over-https \
  --enable-systemd --with-systemd=/lib/systemd/system \
  --with-re2 \
  --with-net-snmp \
  PKG_CONFIG_PATH=/opt/lib64/pkgconfig
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
install -d -m 755 %{buildroot}/%{_sysconfdir}/init && install -m 644 contrib/dnsdist.upstart.conf %{buildroot}/%{_sysconfdir}/init/%{name}.conf
install -d -m 755 %{buildroot}/%{_sysconfdir}/default && install -m 644 contrib/dnsdist.default %{buildroot}/%{_sysconfdir}/default/%{name}
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
if [ -x /sbin/initctl ]; then
  /sbin/initctl reload-configuration
fi
%endif
%if 0%{?suse_version}
%service_add_post %{name}.service
%endif
%if 0%{?rhel} >= 7
%systemd_post %{name}.service
%endif

%preun
%if 0%{?el6}
if [ $1 -eq 0 ] ; then
    # This is package removal, not upgrade
    /sbin/stop %{name} >/dev/null 2>&1 || :
fi
%endif
%if 0%{?suse_version}
%service_del_preun %{name}.service
%endif
%if 0%{?rhel} >= 7
%systemd_preun %{name}.service
%endif

%postun
%if 0%{?el6}
if [ $1 -ge 1 ] ; then
    # Package upgrade, not uninstall
    if [ -x /sbin/initctl ] && /sbin/initctl status %{name} 2>/dev/null | grep -q 'running' ; then
      /sbin/initctl restart %{name} > /dev/null 2>&1 || :
    fi
fi
%endif
%if 0%{?suse_version}
%service_del_postun %{name}.service
%endif
%if 0%{?rhel} >= 7
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
%{_sysconfdir}/init/%{name}.conf
%{_sysconfdir}/default/%{name}
%else
/lib/systemd/system/dnsdist*
%endif
