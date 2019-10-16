Name: pdns-recursor
Version: %{getenv:BUILDER_RPM_VERSION}
Release: %{getenv:BUILDER_RPM_RELEASE}%{?dist}
Summary: Modern, advanced and high performance recursing/non authoritative name server
Group: System Environment/Daemons
License: GPLv2
URL: https://powerdns.com
Source0: %{name}-%{getenv:BUILDER_VERSION}.tar.bz2
%if 0%{?rhel} == 6
Source1: pdns-recursor.init
%endif

Provides: powerdns-recursor = %{version}-%{release}
%if 0%{?rhel} == 6
BuildRequires: boost148-devel
BuildRequires: lua-devel
%else
BuildRequires: boost-devel
BuildRequires: libcap-devel
%ifarch aarch64
BuildRequires: lua-devel
%define lua_implementation lua
%else
BuildRequires: luajit-devel
%define lua_implementation luajit
%endif
BuildRequires: systemd
BuildRequires: systemd-devel
%endif

%ifarch ppc64 ppc64le
BuildRequires: libatomic
%endif

%if 0%{?rhel} >= 7
BuildRequires: protobuf-compiler
BuildRequires: protobuf-devel

%if 0%{?rhel} == 7
# No fstrm in EPEL 8 yet
BuildRequires: fstrm-devel
%endif
%endif

BuildRequires: openssl-devel
BuildRequires: net-snmp-devel
BuildRequires: libsodium-devel

Requires(pre): shadow-utils
%if 0%{?rhel} == 6
Requires(post): /sbin/chkconfig
Requires(preun): /sbin/service, /sbin/chkconfig
Requires(postun): /sbin/service
%else
%systemd_requires
%endif

%description
PowerDNS Recursor is a non authoritative/recursing DNS server. Use this
package if you need a dns cache for your network.


%prep
%if 0%{?rhel} == 6
%setup -n %{name}-%{getenv:BUILDER_VERSION}
%else
%autosetup -p1 -n %{name}-%{getenv:BUILDER_VERSION} 
%endif

%build
%configure \
    --enable-option-checking=fatal \
    --sysconfdir=%{_sysconfdir}/%{name} \
    --with-libsodium \
    --with-net-snmp \
    --disable-silent-rules \
    --disable-static \
    --enable-unit-tests \
%if 0%{?rhel} == 6
    --without-protobuf \
    --with-boost=/usr/include/boost148 LIBRARY_PATH=/usr/lib64/boost148

make %{?_smp_mflags} LIBRARY_PATH=/usr/lib64/boost148
%else
    --with-protobuf \
    --with-libcap \
    --with-lua=%{lua_implementation} \
    --enable-systemd --with-systemd=%{_unitdir}

make %{?_smp_mflags}
%endif

%check
make %{?_smp_mflags} check || (cat test-suite.log && false)

%install
make install DESTDIR=%{buildroot}

%{__mv} %{buildroot}%{_sysconfdir}/%{name}/recursor.conf{-dist,}

%if 0%{?rhel} == 6
%{__install} -D -p %{SOURCE1} %{buildroot}%{_initrddir}/pdns-recursor
%endif

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
%if 0%{?rhel} == 6
chkconfig --add %{name}
%else
%systemd_post %{name}.service
%endif

%preun
%if 0%{?rhel} == 6
if [ $1 -eq 0 ]; then
    service %{name} stop >/dev/null 2>&1 || :
    chkconfig --del %{name}
fi
%else
%systemd_preun %{name}.service
%endif

%if 0%{?rhel} == 6
%postun
if [ $1 -ge 1 ]; then
    service %{name} condrestart >/dev/null 2>&1 || :
fi
%else
%postun
%systemd_postun_with_restart pdns-recursor.service
%endif

%files
%{_bindir}/rec_control
%{_sbindir}/pdns_recursor
%{_mandir}/man1/pdns_recursor.1.gz
%{_mandir}/man1/rec_control.1.gz
%if 0%{?rhel} == 6
%{_initrddir}/pdns-recursor
%else
%{_unitdir}/pdns-recursor.service
%{_unitdir}/pdns-recursor@.service
%endif
%dir %{_sysconfdir}/%{name}
%config(noreplace) %{_sysconfdir}/%{name}/recursor.conf
%doc README
