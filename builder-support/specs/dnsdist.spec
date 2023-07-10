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

%if 0%{?suse_version}
BuildRequires: lua-devel
BuildRequires: systemd
BuildRequires: systemd-units
BuildRequires: systemd-devel
%endif

%if 0%{?rhel} < 8 && 0%{?amzn} != 2023
BuildRequires: boost169-devel
%else
BuildRequires: boost-devel
%endif

%if 0%{?rhel} >= 7 || 0%{?amzn} == 2023
BuildRequires: gnutls-devel
BuildRequires: libcap-devel
BuildRequires: libnghttp2-devel
BuildRequires: lmdb-devel
%ifarch aarch64
BuildRequires: lua-devel
%define lua_implementation lua
%else
BuildRequires: luajit-devel
%define lua_implementation luajit
%endif
BuildRequires: re2-devel
BuildRequires: systemd
BuildRequires: systemd-devel
BuildRequires: systemd-units
BuildRequires: tinycdb-devel
%if 0%{?amzn} != 2023
BuildRequires: libsodium-devel
BuildRequires: net-snmp-devel
%endif
%endif

%if 0%{?suse_version}
Requires(pre): shadow
%systemd_requires
%endif
%if 0%{?rhel} >= 7 || 0%{?amzn} == 2023
Requires(pre): shadow-utils
BuildRequires: fstrm-devel
%systemd_requires
%endif

%description
dnsdist is a high-performance DNS loadbalancer that is scriptable in Lua.

%prep
%autosetup -p1 -n %{name}-%{getenv:BUILDER_VERSION}

# run as dnsdist user
sed -i '/^ExecStart/ s/dnsdist/dnsdist -u dnsdist -g dnsdist/' dnsdist.service.in

%build
%if 0%{?rhel} < 8
export CPPFLAGS=-I/usr/include/boost169
export LDFLAGS=-L/usr/lib64/boost169
%endif

export AR=gcc-ar
export RANLIB=gcc-ranlib

%configure \
  --enable-option-checking=fatal \
  --sysconfdir=/etc/dnsdist \
  --disable-static \
  --disable-dependency-tracking \
  --disable-silent-rules \
  --enable-unit-tests \
  --enable-lto=thin \
  --enable-dns-over-tls \
%if 0%{?suse_version}
  --disable-dnscrypt \
  --without-libsodium \
  --without-re2 \
  --enable-systemd --with-systemd=%{_unitdir} \
  --without-net-snmp
%endif
%if 0%{?rhel} >= 7
  --with-gnutls \
  --enable-dnstap \
  --with-lua=%{lua_implementation} \
  --with-libcap \
  --with-libsodium \
  --enable-dnscrypt \
  --enable-dns-over-https \
  --enable-systemd --with-systemd=%{_unitdir} \
  --with-re2 \
  --with-net-snmp \
  PKG_CONFIG_PATH=/opt/lib64/pkgconfig
%endif

make %{?_smp_mflags}

%check
make %{?_smp_mflags} check || (cat test-suite.log && false)

%install
%make_install
install -d %{buildroot}/%{_sysconfdir}/dnsdist
%{__mv} %{buildroot}%{_sysconfdir}/dnsdist/dnsdist.conf-dist %{buildroot}%{_sysconfdir}/dnsdist/dnsdist.conf
chmod 0640 %{buildroot}/%{_sysconfdir}/dnsdist/dnsdist.conf
sed -i "s,/^\(ExecStart.*\)dnsdist\(.*\)\$,\1dnsdist -u dnsdist -g dnsdist\2," %{buildroot}/%{_unitdir}/dnsdist.service
sed -i "s,/^\(ExecStart.*\)dnsdist\(.*\)\$,\1dnsdist -u dnsdist -g dnsdist\2," %{buildroot}/%{_unitdir}/dnsdist@.service

%pre
getent group dnsdist >/dev/null || groupadd -r dnsdist
getent passwd dnsdist >/dev/null || \
	useradd -r -g dnsdist -d / -s /sbin/nologin \
	-c "dnsdist user" dnsdist
exit 0

%post
%if 0%{?suse_version}
%service_add_post %{name}.service
%endif
%if 0%{?rhel} >= 7
systemctl daemon-reload ||:
%systemd_post %{name}.service
%endif

%preun
%if 0%{?suse_version}
%service_del_preun %{name}.service
%endif
%if 0%{?rhel} >= 7
%systemd_preun %{name}.service
%endif

%postun
%if 0%{?suse_version}
%service_del_postun %{name}.service
%endif
%if 0%{?rhel} >= 7
%systemd_postun_with_restart %{name}.service
%endif

%files
%{!?_licensedir:%global license %%doc}
%doc README.md
%{_bindir}/*
%{_mandir}/man1/*
%dir %{_sysconfdir}/dnsdist
%config(noreplace) %{_sysconfdir}/%{name}/dnsdist.conf
%{_unitdir}/dnsdist*
