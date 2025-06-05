Name: pdns-recursor
Version: %{getenv:BUILDER_RPM_VERSION}
Release: %{getenv:BUILDER_RPM_RELEASE}%{?dist}
Summary: Modern, advanced and high performance recursing/non authoritative name server
Group: System Environment/Daemons
License: GPLv2
Vendor: PowerDNS.COM BV
URL: https://powerdns.com
Source0: %{name}-%{getenv:BUILDER_VERSION}.tar.xz

Provides: powerdns-recursor = %{version}-%{release}

BuildRequires: clang
BuildRequires: lld
BuildRequires: ninja-build

%if 0%{?rhel} < 9
BuildRequires: boost1.78-devel
%else
BuildRequires: boost-devel
%endif
BuildRequires: fstrm-devel
BuildRequires: hostname
BuildRequires: libcap-devel
BuildRequires: libcurl-devel
BuildRequires: libsodium-devel
BuildRequires: net-snmp-devel
BuildRequires: openssl-devel
BuildRequires: systemd
BuildRequires: systemd-devel

%ifarch aarch64
BuildRequires: lua-devel
%define lua_implementation lua
%else
BuildRequires: luajit-devel
%define lua_implementation luajit
%endif

%ifarch ppc64 ppc64le
BuildRequires: libatomic
%endif

Requires(pre): shadow-utils
%systemd_requires

%description
PowerDNS Recursor is a non authoritative/recursing DNS server. Use this
package if you need a dns cache for your network.

%prep
%autosetup -p1 -n %{name}-%{getenv:BUILDER_VERSION}

%if 0%{?rhel} >= 9
%global toolchain clang
%else
# we need to disable the hardened flags because they are GCC-only
%undefine _hardened_build
%endif

%build
%if 0%{?rhel} < 9
export BOOST_INCLUDEDIR=/usr/include/boost1.78
export BOOST_LIBRARYDIR=/usr/lib64/boost1.78
%endif
# We need to build with LLVM/clang to be able to use LTO, since we are linking against a static Rust library built with LLVM
export CC=clang
export CXX=clang++
# build-id SHA1 prevents an issue with the debug symbols ("export: `-Wl,--build-id=sha1': not a valid identifier")
export LDFLAGS="-fuse-ld=lld -Wl,--build-id=sha1"

%if 0%{?rhel} < 9
# starting with EL-9 we get these hardening settings for free by just setting the right toolchain (see above)
%ifarch aarch64
%define cf_protection %{nil}
%else
%define cf_protection -fcf-protection
%endif
%if "%{_arch}" == "aarch64" && 0%{?amzn2023}
%define stack_clash_protection %{nil}
%else
%define stack_clash_protection -fstack-clash-protection
%endif
export CFLAGS="-O2 -g -pipe -Wall -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -Wp,-D_GLIBCXX_ASSERTIONS -fexceptions -fstack-protector-strong -m64 -mtune=generic -fasynchronous-unwind-tables %{stack_clash_protection} %{cf_protection} -gdwarf-4"
# Adding -Wno-deprecated-declarations -Wno-deprecated-builtins as boost generates tonnes of warnings
export CXXFLAGS="-O2 -g -pipe -Wall -Wno-deprecated-declarations -Wno-deprecated-builtins -Werror=format-security -Wp,-D_FORTIFY_SOURCE=2 -Wp,-D_GLIBCXX_ASSERTIONS -fexceptions -fstack-protector-strong -m64 -mtune=generic -fasynchronous-unwind-tables %{stack_clash_protection} %{cf_protection} -gdwarf-4"
%endif

# Note that the RPM meson macro "helpfully" sets
# --auto-features=enabled so our auto-detection is broken
%meson \
    --sysconfdir=%{_sysconfdir}/%{name} \
    -Dunit-tests=true \
    -Db_lto=true \
    -Db_lto_mode=thin \
    -Db_pie=true \
    -Ddns-over-tls=enabled \
    -Ddnstap=enabled \
    -Dlibcap=enabled \
    -Dlua=%{lua_implementation} \
    -Dsigners-libsodium=enabled \
    -Dsnmp=enabled \
    -Dnod=enabled
%meson_build

%check
%meson_test

%install
%meson_install

%{__mkdir} %{buildroot}%{_sysconfdir}/%{name}/recursor.d

# change user and group to pdns-recursor and add default include-dir
cat << EOF > %{buildroot}%{_sysconfdir}/%{name}/recursor.conf
dnssec:
  # validation: process
recursor:
  include_dir: %{_sysconfdir}/%{name}/recursor.d
  setuid: pdns-recursor
  setgid: pdns-recursor
incoming:
  # listen:
  # - 127.0.0.1
outgoing:
  # source_address:
  # - 0.0.0.0
EOF

%{__install } -d %{buildroot}/%{_sharedstatedir}/%{name}

%pre
getent group pdns-recursor > /dev/null || groupadd -r pdns-recursor
getent passwd pdns-recursor > /dev/null || \
    useradd -r -g pdns-recursor -d /var/lib/pdns-recursor -s /sbin/nologin \
    -c "PowerDNS Recursor user" pdns-recursor
# Change home directory to /var/lib/pdns-recursor if needed
if [[ $(getent passwd pdns-recursor | cut -d: -f6) == "/" ]]; then
    usermod -d /var/lib/pdns-recursor pdns-recursor
fi
exit 0

%post
systemctl daemon-reload ||:
%systemd_post %{name}.service

%preun
%systemd_preun %{name}.service

%postun
%systemd_postun_with_restart pdns-recursor.service

%files
%{_bindir}/rec_control
%{_sbindir}/pdns_recursor
%{_mandir}/man1/pdns_recursor.1.gz
%{_mandir}/man1/rec_control.1.gz
%{_unitdir}/pdns-recursor.service
%{_unitdir}/pdns-recursor@.service
%dir %{_sysconfdir}/%{name}
%dir %{_sysconfdir}/%{name}/recursor.d
%config(noreplace) %{_sysconfdir}/%{name}/recursor.conf
%config %{_sysconfdir}/%{name}/recursor.yml-dist
%dir %attr(-,pdns-recursor,pdns-recursor) %{_sharedstatedir}/%{name}
%doc README
