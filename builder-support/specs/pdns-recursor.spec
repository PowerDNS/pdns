Name: pdns-recursor
Version: %{getenv:BUILDER_RPM_VERSION}
Release: %{getenv:BUILDER_RPM_RELEASE}%{?dist}
Summary: Modern, advanced and high performance recursing/non authoritative name server
Group: System Environment/Daemons
License: GPLv2
URL: https://powerdns.com
Source0: %{name}-%{getenv:BUILDER_VERSION}.tar.bz2

Provides: powerdns-recursor = %{version}-%{release}

%if 0%{?rhel} < 8 && 0%{?amzn} != 2023
BuildRequires: boost169-devel
%else
BuildRequires: boost-devel
%endif
BuildRequires: libcap-devel
BuildRequires: systemd
BuildRequires: systemd-devel
BuildRequires: openssl-devel
BuildRequires: fstrm-devel
BuildRequires: libcurl-devel

%if 0%{?amzn} != 2023
BuildRequires: net-snmp-devel
BuildRequires: libsodium-devel
%endif

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
%if 0%{?rhel} < 8
export CPPFLAGS=-I/usr/include/boost169
export LDFLAGS=-L/usr/lib64/boost169
%endif

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
%if 0%{?amzn} != 2023
    --with-libsodium \
    --with-net-snmp \
%endif
    --enable-systemd --with-systemd=%{_unitdir} \
    --enable-nod

make %{?_smp_mflags}

%check
make %{?_smp_mflags} check || (cat test-suite.log && false)

%install
make install DESTDIR=%{buildroot}

%{__mv} %{buildroot}%{_sysconfdir}/%{name}/recursor.conf{-dist,}
%{__mkdir} %{buildroot}%{_sysconfdir}/%{name}/recursor.d

# change user and group to pdns-recursor and add default include-dir
sed -i \
    -e 's/# setuid=/setuid=pdns-recursor/' \
    -e 's/# setgid=/setgid=pdns-recursor/' \
    -e 's!# include-dir=.*!&\ninclude-dir=%{_sysconfdir}/%{name}/recursor.d!' \
    %{buildroot}%{_sysconfdir}/%{name}/recursor.conf

# The EL7 and 8 systemd actually supports %t, but its version number is older than that, so we do use seperate runtime dirs, but don't rely on RUNTIME_DIRECTORY
%if 0%{?rhel} < 9
sed -e 's!/pdns_recursor!& --socket-dir=%t/pdns-recursor!' -i %{buildroot}/%{_unitdir}/pdns-recursor.service
%if 0%{?rhel} < 8
sed -e 's!/pdns_recursor!& --socket-dir=%t/pdns-recursor-%i!' -e 's!RuntimeDirectory=pdns-recursor!&-%i!' -i %{buildroot}/%{_unitdir}/pdns-recursor@.service
%endif
%endif

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
%dir %{_sysconfdir}/%{name}/recursor.d
%config(noreplace) %{_sysconfdir}/%{name}/recursor.conf
%doc README
