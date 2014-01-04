#
# PowerDNS server buildtest spec file
# Don't use this spec for regular builds
#
Summary:        PowerDNS
Name:           pdns-server
Version:        0.0
Release:        1
Epoch:          0
License:        GPL
Group:          System/Servers
URL:            http://www.powerdns.com/
Source0:        http://downloads.powerdns.com/releases/#FILENAME#

BuildRequires:  autoconf automake
BuildRequires:  gcc gcc-c++
BuildRequires:  zlib-devel
BuildRequires:  lua-devel
BuildRequires:  boost-devel >= 1.34.0
BuildRequires:  sqlite-devel >= 3.0.0
BuildRequires:  libcurl-devel >= 7.17.1
BuildRequires:  mysql-devel
BuildRequires:  postgresql-devel
BuildRequires:  openldap-devel
BuildRequires:  tinycdb-devel

BuildRoot:      %{_tmppath}/%{name}-%{version}-root

%description
PowerDNS testbuild

%prep
%setup -q -n #SOURCE_PATH#

%build
%configure \
    --libdir=%{_libdir} \
    --with-sqlite3 \
    --with-socketdir=/var/run/pdns-server \
    --with-modules="bind gmysql gpgsql gsqlite3 mydns tinydns remote random pipe geo ldap" \
    --with-dynmodules="" \
    --enable-unit-tests \
    --enable-tools \
    --enable-remotebackend-http

%{__make}

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
%{__make} DESTDIR=$RPM_BUILD_ROOT install
rm -rf $RPM_BUILD_ROOT/*
