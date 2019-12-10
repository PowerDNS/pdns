Name: pdns-recursor
Version: %{getenv:BUILDER_RPM_VERSION}
Release: %{getenv:BUILDER_RPM_RELEASE}%{?dist}
Summary: Modern, advanced and high performance recursing/non authoritative name server
Group: System Environment/Daemons
License: GPLv2
URL: https://powerdns.com
Source0: %{name}-%{getenv:BUILDER_VERSION}.tar.bz2

Provides: powerdns-recursor = %{version}-%{release}

BuildRequires: boost-devel
BuildRequires: libcap-devel
BuildRequires: systemd
BuildRequires: systemd-devel
BuildRequires: protobuf-compiler
BuildRequires: protobuf-devel
BuildRequires: openssl-devel
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

%if 0%{?rhel} >= 7
BuildRequires: fstrm-devel
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
    --with-libsodium \
    --with-net-snmp \
    --disable-silent-rules \
    --disable-static \
    --enable-unit-tests \
    --enable-dnstap \
    --with-libcap \
    --with-lua=%{lua_implementation} \
    --enable-systemd --with-systemd=%{_unitdir}

make %{?_smp_mflags}

%check
make %{?_smp_mflags} check || (cat test-suite.log && false)

%install
make install DESTDIR=%{buildroot}

%{__mv} %{buildroot}%{_sysconfdir}/%{name}/recursor.conf{-dist,}

# change user and group to pdns-recursor
sed -i \
    -e 's/# setuid=/setuid=pdns-recursor/' \
    -e 's/# setgid=/setgid=pdns-recursor/' \
    %{buildroot}%{_sysconfdir}/%{name}/recursor.conf

%pre
getent group pdns-recursor > /dev/null || groupadd -r pdns-recursor
getent passwd pdns-recursor > /dev/null || \
    useradd -r -g pdns-recursor -d / -s /sbin/nologin \
    -c "PowerDNS Recursor user" pdns-recursor
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
%config(noreplace) %{_sysconfdir}/%{name}/recursor.conf
%doc README
