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

BuildRequires: boost-devel
BuildRequires: python3-pyyaml
BuildRequires: clang
BuildRequires: lld

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
BuildRequires: libsodium-devel
BuildRequires: net-snmp-devel

%if 0%{?suse_version}
Requires(pre): shadow
%systemd_requires
%endif
Requires(pre): shadow-utils
BuildRequires: fstrm-devel
%systemd_requires
%if ( "%{_arch}" != "aarch64" && 0%{?rhel} >= 8 ) || ( "%{_arch}" == "aarch64" && 0%{?rhel} >= 9 )
BuildRequires: libbpf-devel
BuildRequires: libxdp-devel
%endif

%description
dnsdist is a high-performance DNS loadbalancer that is scriptable in Lua.

%prep
%autosetup -p1 -n %{name}-%{getenv:BUILDER_VERSION}

%build
# We need to build with LLVM/clang to be able to use LTO, since we are linking against a static Rust library built with LLVM
export CC=clang
export CXX=clang++
# build-id SHA1 prevents an issue with the debug symbols ("export: `-Wl,--build-id=sha1': not a valid identifier")
# and the --no-as-needed -ldl an issue with the dlsym not being found ("ld.lld: error: undefined symbol: dlsym eferenced by weak.rs:142 (library/std/src/sys/pal/unix/weak.rs:142) [...] in archive ./dnsdist-rust-lib/rust/libdnsdist_rust.a)
export LDFLAGS="-fuse-ld=lld -Wl,--build-id=sha1 -Wl,--no-as-needed -ldl"

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
  --with-h2o \
%if 0%{?suse_version}
  --disable-dnscrypt \
  --without-libsodium \
  --without-re2 \
  --enable-systemd --with-systemd=%{_unitdir} \
  --without-net-snmp
%endif
  --enable-dnstap \
  --enable-dns-over-https \
  --enable-systemd --with-systemd=%{_unitdir} \
  --with-gnutls \
  --with-libcap \
  --with-lua=%{lua_implementation} \
  --with-re2 \
  --enable-dnscrypt \
  --with-libsodium \
  --with-net-snmp \
  --enable-dns-over-quic \
  --enable-dns-over-http3 \
  --with-quiche \
  --enable-yaml \
  PKG_CONFIG_PATH=/usr/lib/pkgconfig:/opt/lib64/pkgconfig

make %{?_smp_mflags}

%check
make %{?_smp_mflags} check || (cat test-suite.log && false)

%install
%make_install
install -d %{buildroot}/%{_sysconfdir}/dnsdist
install -Dm644 /usr/lib/libdnsdist-quiche.so %{buildroot}/%{_libdir}/libdnsdist-quiche.so
%{__mv} %{buildroot}%{_sysconfdir}/dnsdist/dnsdist.conf-dist %{buildroot}%{_sysconfdir}/dnsdist/dnsdist.conf
chmod 0640 %{buildroot}/%{_sysconfdir}/dnsdist/dnsdist.conf

%{__install } -d %{buildroot}/%{_sharedstatedir}/%{name}

%pre
getent group dnsdist >/dev/null || groupadd -r dnsdist
getent passwd dnsdist >/dev/null || \
	useradd -r -g dnsdist -d /var/lib/dnsdist -s /sbin/nologin \
	-c "dnsdist user" dnsdist
# Change home directory to /var/lib/dnsdist if needed
if [[ $(getent passwd dnsdist | cut -d: -f6) == "/" ]]; then
    usermod -d /var/lib/dnsdist dnsdist
fi
exit 0

%post
%if 0%{?suse_version}
%service_add_post %{name}.service
%endif
systemctl daemon-reload ||:
%systemd_post %{name}.service

%preun
%if 0%{?suse_version}
%service_del_preun %{name}.service
%endif
%systemd_preun %{name}.service

%postun
%if 0%{?suse_version}
%service_del_postun %{name}.service
%endif
%systemd_postun_with_restart %{name}.service

%files
%{!?_licensedir:%global license %%doc}
%doc README.md
%{_bindir}/*
%define __requires_exclude libdnsdist-quiche\\.so
%{_libdir}/libdnsdist-quiche.so
%{_mandir}/man1/*
%dir %{_sysconfdir}/dnsdist
%attr(-, root, dnsdist) %config(noreplace) %{_sysconfdir}/%{name}/dnsdist.conf
%dir %attr(-,dnsdist,dnsdist) %{_sharedstatedir}/%{name}
%{_unitdir}/dnsdist*
