Name: pdns-recursor
Version: %{getenv:BUILDER_RPM_VERSION}
Release: %{getenv:BUILDER_RPM_RELEASE}%{?dist}
Summary: Modern, advanced and high performance recursing/non authoritative name server
Group: System Environment/Daemons
License: GPLv2
Vendor: PowerDNS.COM BV
URL: https://powerdns.com
Source0: %{name}-%{getenv:BUILDER_VERSION}.tar.bz2

Provides: powerdns-recursor = %{version}-%{release}

BuildRequires: boost-devel
BuildRequires: libcap-devel
BuildRequires: systemd
BuildRequires: systemd-devel
BuildRequires: openssl-devel
BuildRequires: fstrm-devel
BuildRequires: libcurl-devel
BuildRequires: net-snmp-devel
BuildRequires: libsodium-devel

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

%build

%configure \
    --enable-option-checking=fatal \
    --sysconfdir=%{_sysconfdir}/%{name} \
    --disable-silent-rules \
    --disable-static \
    --enable-unit-tests \
    --enable-dns-over-tls \
    --enable-dnstap \
    --with-libcap \
    --with-lua=%{lua_implementation} \
    --with-libsodium \
    --with-net-snmp \
    --enable-systemd --with-systemd=%{_unitdir} \
    --enable-nod

make %{?_smp_mflags}

%check
make %{?_smp_mflags} check || (cat test-suite.log && false)

%install
make install DESTDIR=%{buildroot}

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

# The EL7 and 8 systemd actually supports %t, but its version number is older than that, so we do use seperate runtime dirs, but don't rely on RUNTIME_DIRECTORY
%if 0%{?rhel} < 9
sed -e 's!/pdns_recursor!& --socket-dir=%t/pdns-recursor!' -i %{buildroot}/%{_unitdir}/pdns-recursor.service
%endif

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
