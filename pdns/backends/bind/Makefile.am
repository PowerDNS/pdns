INCLUDES=-I../.. -I ../../ext/polarssl/include
noinst_LTLIBRARIES = libbind2backend.la
AM_CPPFLAGS=@THREADFLAGS@

libbind2backend_la_SOURCES=bindbackend2.cc bindbackend2.hh bindparser.yy \
bindlexer.l ../../zoneparser-tng.cc ../../misc.cc  \
bindparser.hh ../../unix_utility.cc

libbind2backend_la_CXXFLAGS=$(AM_CXXFLAGS)
libbind2backend_la_CFLAGS=$(AM_CFLAGS)
libbind2backend_la_LDFLAGS=-module -avoid-version

bin_PROGRAMS = zone2sql zone2ldap

EXTRA_DIST=bindparser.cc bindparser.h

zone2sql_SOURCES=bindparser.yy bindlexer.l \
../../arguments.cc ../../logger.cc zone2sql.cc ../../statbag.cc ../../misc.cc \
../../unix_utility.cc ../../qtype.cc ../../dnspacket.cc \
../../zoneparser-tng.cc ../../dnsrecords.cc ../../sillyrecords.cc \
../../dnswriter.cc ../../rcpgenerator.cc ../../dnsparser.cc ../../base64.cc \
../../nsecrecords.cc ../../dnssecinfra.cc ../../dnsseckeeper.cc ../../base32.cc

zone2ldap_SOURCES=bindparser.yy bindlexer.l \
../../arguments.cc ../../logger.cc zone2ldap.cc ../../statbag.cc ../../misc.cc \
../../unix_utility.cc ../../qtype.cc  ../../zoneparser-tng.cc ../../dnsrecords.cc \
../../dnswriter.cc ../../rcpgenerator.cc ../../dnsparser.cc ../../base64.cc ../../sillyrecords.cc \
../../nsecrecords.cc ../../dnssecinfra.cc ../../dnsseckeeper.cc ../../base32.cc

zone2ldap_LDFLAGS=@THREADFLAGS@ -lboost_filesystem-mt -L../../ext/polarssl/library -lpolarssl

zone2sql_LDFLAGS=@THREADFLAGS@ -lboost_filesystem-mt -L../../ext/polarssl/library -lpolarssl

AM_LFLAGS = -s -i
AM_YFLAGS = -d --verbose --debug
