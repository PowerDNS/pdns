#
# PowerDNS recursor buildtest spec file
# Don't use this spec for regular builds
#
Summary:		PowerDNS
Name:			pdns-recursor
Version:		0.0
Release:		1
Epoch:			0
Group:			System Environment/Daemons
License:		GPL
Source:			http://downloads.powerdns.com/releases/%{name}-#VERSION#.tar.bz2

BuildRequires:		boost-devel >= 1.39.0
BuildRequires:		lua-devel >= 5.2

BuildRoot:		%{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

%description
PowerDNS recursor

%prep
%setup -q -n %{name}-#VERSION#

%build
%configure

LUA=1 LUA_LIBS_CONFIG=-llua-5.2 %{__make}

%install
[ "$RPM_BUILD_ROOT" != "/" ] && rm -rf $RPM_BUILD_ROOT
%{__make} DESTDIR=$RPM_BUILD_ROOT install
rm -rf $RPM_BUILD_ROOT/*
