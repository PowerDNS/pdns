INCLUDES=-I../.. 
noinst_LTLIBRARIES = libbind2backend.la
AM_CPPFLAGS=$(BOOST_CPPFLAGS) @THREADFLAGS@

BUILT_SOURCES=bind-dnssec.schema.sqlite3.sql.h

bind-dnssec.schema.sqlite3.sql.h: ../../bind-dnssec.schema.sqlite3.sql
	( echo 'static char sqlCreate[]=' ; sed 's/$$/"/g' ../../bind-dnssec.schema.sqlite3.sql | sed 's/^/"/g'  ; echo ';' ) > $@


libbind2backend_la_SOURCES=bindbackend2.cc bindbackend2.hh bindparser.yy \
bindlexer.l ../../zoneparser-tng.cc ../../misc.cc  \
bindparser.hh ../../unix_utility.cc binddnssec.cc bind-dnssec.schema.sqlite3.sql.h

libbind2backend_la_CXXFLAGS=$(AM_CXXFLAGS)
libbind2backend_la_CFLAGS=$(AM_CFLAGS)
libbind2backend_la_LDFLAGS=-module -avoid-version

bin_PROGRAMS = zone2sql zone2ldap

EXTRA_DIST=dnslabeltext.cc bindparser.cc bindparser.h bind-dnssec.schema.sqlite3.sql.h

zone2sql_SOURCES=bindparser.yy bindlexer.l bind-dnssec.schema.sqlite3.sql.h \
../../arguments.cc ../../logger.cc zone2sql.cc ../../statbag.cc ../../misc.cc \
../../unix_utility.cc ../../qtype.cc ../../dns.cc \
../../zoneparser-tng.cc ../../dnsrecords.cc ../../sillyrecords.cc \
../../dnswriter.cc dnslabeltext.cc ../../rcpgenerator.cc ../../dnsparser.cc ../../base64.cc \
../../nsecrecords.cc ../../dnssecinfra.cc  ../../base32.cc ../../md5.cc # ../../dbdnsseckeeper.cc

zone2ldap_SOURCES=bindparser.yy bindlexer.l bind-dnssec.schema.sqlite3.sql.h \
../../arguments.cc ../../logger.cc zone2ldap.cc ../../statbag.cc ../../misc.cc \
../../unix_utility.cc ../../qtype.cc  ../../zoneparser-tng.cc ../../dnsrecords.cc \
../../dnswriter.cc dnslabeltext.cc  ../../rcpgenerator.cc ../../dnsparser.cc ../../base64.cc ../../sillyrecords.cc \
../../nsecrecords.cc ../../dnssecinfra.cc  ../../base32.cc ../../md5.cc # ../../dbdnsseckeeper.cc

zone2ldap_LDFLAGS=@THREADFLAGS@  
zone2ldap_LDADD= ../../ext/polarssl-1.1.1/library/libpolarssl.a

zone2sql_LDFLAGS=@THREADFLAGS@  
zone2sql_LDADD= ../../ext/polarssl-1.1.1/library/libpolarssl.a 

AM_LFLAGS = -s -i
AM_YFLAGS = -d --verbose --debug

dnslabeltext.cc: ../../dnslabeltext.rl
	ragel ../../dnslabeltext.rl -o dnslabeltext.cc

