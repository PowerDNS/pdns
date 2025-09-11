%global _hardened_build 1
%global backends %{nil}

Name: pdns
Version: %{getenv:BUILDER_RPM_VERSION}
Release: %{getenv:BUILDER_RPM_RELEASE}%{dist}
Summary: A modern, advanced and high performance authoritative-only nameserver
Group: System Environment/Daemons
License: GPLv2
Vendor: PowerDNS.COM BV
URL: https://powerdns.com
Source0: %{name}-%{getenv:BUILDER_VERSION}.tar.bz2

Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd
BuildRequires: systemd
BuildRequires: systemd-units
BuildRequires: systemd-devel
BuildRequires: krb5-devel
BuildRequires: p11-kit-devel
BuildRequires: libcurl-devel
%if 0%{?rhel} == 8
BuildRequires: boost1.78-devel
%else
BuildRequires: boost-devel
%endif
BuildRequires: bison
BuildRequires: openssl-devel
BuildRequires: libsodium-devel
Requires(pre): shadow-utils

%ifarch aarch64
BuildRequires: lua-devel
%define lua_implementation lua
%else
BuildRequires: luajit-devel
%define lua_implementation luajit
%endif

Provides: powerdns = %{version}-%{release}
%global backends %{backends} bind

%description
The PowerDNS Nameserver is a modern, advanced and high performance
authoritative-only nameserver. It is written from scratch and conforms
to all relevant DNS standards documents.
Furthermore, PowerDNS interfaces with almost any database.

%package tools
Summary: Extra tools for %{name}
Group: System Environment/Daemons

%description tools
This package contains the extra tools for %{name}

%package backend-mysql
Summary: MySQL backend for %{name}
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
BuildRequires: mariadb-connector-c-devel
%global backends %{backends} gmysql

%description backend-mysql
This package contains the gmysql backend for %{name}

%package backend-postgresql
Summary: PostgreSQL backend for %{name}
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
BuildRequires: postgresql-devel
%global backends %{backends} gpgsql

%description backend-postgresql
This package contains the gpgsql backend for %{name}

%package backend-pipe
Summary: Pipe backend for %{name}
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
%global backends %{backends} pipe

%description backend-pipe
This package contains the pipe backend for %{name}

%package backend-remote
Summary: Remote backend for %{name}
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
%global backends %{backends} remote

%description backend-remote
This package contains the remote backend for %{name}

%package backend-ldap
Summary: LDAP backend for %{name}
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
BuildRequires: openldap-devel
%global backends %{backends} ldap

%description backend-ldap
This package contains the LDAP backend for %{name}

%package backend-lua2
Summary: Lua backend for %{name}
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
%global backends %{backends} lua2

%description backend-lua2
This package contains the lua2 backend for %{name}

%package backend-sqlite
Summary: SQLite backend for %{name}
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
BuildRequires: sqlite-devel
%global backends %{backends} gsqlite3

%description backend-sqlite
This package contains the SQLite backend for %{name}

%package backend-odbc
Summary: UnixODBC backend for %{name}
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
BuildRequires: unixODBC-devel
%global backends %{backends} godbc

%description backend-odbc
This package contains the godbc backend for %{name}

%package backend-geoip
Summary: Geo backend for %{name}
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
BuildRequires: yaml-cpp-devel
BuildRequires: libmaxminddb-devel
%global backends %{backends} geoip

%description backend-geoip
This package contains the geoip backend for %{name}
It allows different answers to DNS queries coming from different
IP address ranges or based on the geoipgraphic location

%package backend-lmdb
Summary: LMDB backend for %{name}
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
BuildRequires: lmdb-devel
%global backends %{backends} lmdb

%description backend-lmdb
This package contains the lmdb backend for %{name}

%package backend-tinydns
Summary: TinyDNS backend for %{name}
Group: System Environment/Daemons
Requires: %{name}%{?_isa} = %{version}-%{release}
BuildRequires: tinycdb-devel
%global backends %{backends} tinydns

%description backend-tinydns
This package contains the TinyDNS backend for %{name}

%package ixfrdist
BuildRequires: yaml-cpp-devel
Summary: A program to redistribute zones over AXFR and IXFR
Group: System Environment/Daemons

%description ixfrdist
This package contains the ixfrdist program.

%prep
%autosetup -p1 -n %{name}-%{getenv:BUILDER_VERSION}

%build
%if 0%{?rhel} == 8
export BOOST_INCLUDEDIR=/usr/include/boost1.78
export BOOST_LIBRARYDIR=/usr/lib64/boost1.78
export CPPFLAGS=-I$BOOST_INCLUDEDIR
export LDFLAGS=-L$BOOST_LIBRARYDIR
%endif
export CPPFLAGS="$CPPFLAGS -DLDAP_DEPRECATED"

%configure \
  --enable-option-checking=fatal \
  --sysconfdir=%{_sysconfdir}/%{name} \
  --disable-static \
  --disable-dependency-tracking \
  --disable-silent-rules \
  --with-modules='' \
  --with-lua=%{lua_implementation} \
  --with-dynmodules='%{backends}' \
  --enable-tools \
  --with-libsodium \
  --enable-ixfrdist \
  --enable-unit-tests \
  --enable-lua-records \
  --enable-experimental-pkcs11 \
  --enable-dns-over-tls \
  --enable-systemd

make %{?_smp_mflags}

%install
make install DESTDIR=%{buildroot}

%{__rm} -f %{buildroot}%{_libdir}/%{name}/*.la
%{__rm} -rf %{buildroot}%{_docdir}

%{buildroot}/usr/sbin/pdns_server --config=default | sed \
  -e 's!# daemon=.*!daemon=no!' \
  -e 's!# guardian=.*!guardian=no!' \
  -e 's!# launch=.*!&\\nlaunch=!' \
  -e 's!# setgid=.*!setgid=pdns!' \
  -e 's!# setuid=.*!setuid=pdns!' \
  > %{buildroot}%{_sysconfdir}/%{name}/pdns.conf
%{__rm} %{buildroot}%{_sysconfdir}/%{name}/pdns.conf-dist
%{__rm} %{buildroot}/usr/bin/stubquery

chmod 600 %{buildroot}%{_sysconfdir}/%{name}/pdns.conf

# rename zone2ldap to pdns-zone2ldap (#1193116)
%{__mv} %{buildroot}/%{_bindir}/zone2ldap %{buildroot}/%{_bindir}/pdns-zone2ldap
%{__mv} %{buildroot}/%{_mandir}/man1/zone2ldap.1 %{buildroot}/%{_mandir}/man1/pdns-zone2ldap.1

%{__install } -d %{buildroot}/%{_sharedstatedir}/%{name}

%check
PDNS_TEST_NO_IPV6=1 make %{?_smp_mflags} -C pdns check || (cat pdns/test-suite.log && false)

%pre
getent group pdns >/dev/null || groupadd -r pdns
getent passwd pdns >/dev/null || \
	useradd -r -g pdns -d /var/lib/pdns -s /sbin/nologin \
	-c "PowerDNS Authoritative Server" pdns
# Change home directory to /var/lib/pdns
if [[ $(getent passwd pdns | cut -d: -f6) == "/" ]]; then
    usermod -d /var/lib/pdns pdns
fi
exit 0

if [ "`stat -c '%U:%G' %{_sysconfdir}/%{name}`" = "root:root" ]; then
  chown -R root:pdns /etc/powerdns
  # Make sure that pdns can read it; the default used to be 0600
  chmod g+r /etc/powerdns/pdns.conf
fi
chown -R pdns:pdns /var/lib/powerdns || :

%post
systemctl daemon-reload ||:
%systemd_post pdns.service

%preun
%systemd_preun pdns.service

%postun
%systemd_postun_with_restart pdns.service

%files
%doc COPYING README
%doc pdns/bind-dnssec.4.2.0_to_4.3.0_schema.sqlite3.sql pdns/bind-dnssec.schema.sqlite3.sql
%config(noreplace) %{_sysconfdir}/%{name}/pdns.conf
%dir %{_libdir}/%{name}/
%dir %attr(-,pdns,pdns) %{_sharedstatedir}/%{name}
%{_bindir}/pdns-zone2ldap
%{_bindir}/pdns_control
%{_bindir}/pdnsutil
%{_bindir}/zone2json
%{_bindir}/zone2sql
%{_libdir}/%{name}/libbindbackend.so
%{_mandir}/man1/pdns-zone2ldap.1.gz
%{_mandir}/man1/pdns_control.1.gz
%{_mandir}/man1/pdns_server.1.gz
%{_mandir}/man1/pdnsutil.1.gz
%{_mandir}/man1/zone2json.1.gz
%{_mandir}/man1/zone2sql.1.gz
%{_sbindir}/pdns_server
%{_unitdir}/pdns.service
%{_unitdir}/pdns@.service

%files tools
%{_bindir}/calidns
%{_bindir}/dnsbulktest
%{_bindir}/dnsgram
%{_bindir}/dnspcap2calidns
%{_bindir}/dnspcap2protobuf
%{_bindir}/dnsreplay
%{_bindir}/dnsscan
%{_bindir}/dnsscope
%{_bindir}/dnstcpbench
%{_bindir}/dnswasher
%{_bindir}/dumresp
%{_bindir}/ixplore
%{_bindir}/nproxy
%{_bindir}/nsec3dig
%{_bindir}/pdns_notify
%{_bindir}/saxfr
%{_bindir}/sdig
%{_mandir}/man1/calidns.1.gz
%{_mandir}/man1/dnsbulktest.1.gz
%{_mandir}/man1/dnsgram.1.gz
%{_mandir}/man1/dnspcap2calidns.1.gz
%{_mandir}/man1/dnspcap2protobuf.1.gz
%{_mandir}/man1/dnsreplay.1.gz
%{_mandir}/man1/dnsscan.1.gz
%{_mandir}/man1/dnsscope.1.gz
%{_mandir}/man1/dnstcpbench.1.gz
%{_mandir}/man1/dnswasher.1.gz
%{_mandir}/man1/dumresp.1.gz
%{_mandir}/man1/ixplore.1.gz
%{_mandir}/man1/nproxy.1.gz
%{_mandir}/man1/nsec3dig.1.gz
%{_mandir}/man1/pdns_notify.1.gz
%{_mandir}/man1/saxfr.1.gz
%{_mandir}/man1/sdig.1.gz

%files backend-mysql
%doc modules/gmysqlbackend/schema.mysql.sql
%doc modules/gmysqlbackend/dnssec-3.x_to_3.4.0_schema.mysql.sql
%doc modules/gmysqlbackend/nodnssec-3.x_to_3.4.0_schema.mysql.sql
%doc modules/gmysqlbackend/3.4.0_to_4.1.0_schema.mysql.sql
%doc modules/gmysqlbackend/4.1.0_to_4.2.0_schema.mysql.sql
%doc modules/gmysqlbackend/4.2.0_to_4.3.0_schema.mysql.sql
%doc modules/gmysqlbackend/4.3.0_to_4.7.0_schema.mysql.sql
%doc modules/gmysqlbackend/enable-foreign-keys.mysql.sql
%{_libdir}/%{name}/libgmysqlbackend.so

%files backend-postgresql
%doc modules/gpgsqlbackend/schema.pgsql.sql
%doc modules/gpgsqlbackend/dnssec-3.x_to_3.4.0_schema.pgsql.sql
%doc modules/gpgsqlbackend/nodnssec-3.x_to_3.4.0_schema.pgsql.sql
%doc modules/gpgsqlbackend/3.4.0_to_4.1.0_schema.pgsql.sql
%doc modules/gpgsqlbackend/4.1.0_to_4.2.0_schema.pgsql.sql
%doc modules/gpgsqlbackend/4.2.0_to_4.3.0_schema.pgsql.sql
%doc modules/gpgsqlbackend/4.3.0_to_4.7.0_schema.pgsql.sql
%{_libdir}/%{name}/libgpgsqlbackend.so

%files backend-pipe
%{_libdir}/%{name}/libpipebackend.so

%files backend-remote
%{_libdir}/%{name}/libremotebackend.so

%files backend-ldap
%{_libdir}/%{name}/libldapbackend.so

%doc modules/ldapbackend/dnsdomain2.schema
%doc modules/ldapbackend/pdns-domaininfo.schema

%files backend-lua2
%{_libdir}/%{name}/liblua2backend.so

%files backend-sqlite
%doc modules/gsqlite3backend/schema.sqlite3.sql
%doc modules/gsqlite3backend/dnssec-3.x_to_3.4.0_schema.sqlite3.sql
%doc modules/gsqlite3backend/nodnssec-3.x_to_3.4.0_schema.sqlite3.sql
%doc modules/gsqlite3backend/3.4.0_to_4.0.0_schema.sqlite3.sql
%doc modules/gsqlite3backend/4.0.0_to_4.2.0_schema.sqlite3.sql
%doc modules/gsqlite3backend/4.2.0_to_4.3.0_schema.sqlite3.sql
%doc modules/gsqlite3backend/4.3.0_to_4.3.1_schema.sqlite3.sql
%doc modules/gsqlite3backend/4.3.1_to_4.7.0_schema.sqlite3.sql
%{_libdir}/%{name}/libgsqlite3backend.so

%files backend-odbc
%doc modules/godbcbackend/schema.mssql.sql
%doc modules/godbcbackend/4.0.0_to_4.2.0_schema.mssql.sql
%doc modules/godbcbackend/4.2.0_to_4.3.0_schema.mssql.sql
%doc modules/godbcbackend/4.3.0_to_4.7.0_schema.mssql.sql
%{_libdir}/%{name}/libgodbcbackend.so

%files backend-geoip
%{_libdir}/%{name}/libgeoipbackend.so

%files backend-lmdb
%{_libdir}/%{name}/liblmdbbackend.so

%files backend-tinydns
%{_libdir}/%{name}/libtinydnsbackend.so

%files ixfrdist
%{_bindir}/ixfrdist
%{_mandir}/man1/ixfrdist.1.gz
%{_mandir}/man5/ixfrdist.yml.5.gz
%{_sysconfdir}/%{name}/ixfrdist.example.yml
%{_unitdir}/ixfrdist.service
%{_unitdir}/ixfrdist@.service
