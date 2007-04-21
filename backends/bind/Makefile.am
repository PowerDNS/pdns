INCLUDES=-I../..
noinst_LTLIBRARIES = libbind2backend.la
AM_CPPFLAGS=@THREADFLAGS@

libbind2backend_la_SOURCES=bindbackend2.cc bindbackend2.hh bindparser.yy \
bindlexer.l ../../zoneparser-tng.cc ../../misc.cc  \
bindparser.hh ../../unix_utility.cc

libbind2backend_la_CXXFLAGS=$(AM_CXXFLAGS)
libbind2backend_la_CFLAGS=$(AM_CFLAGS)

bin_PROGRAMS = zone2sql zone2ldap

zone2sql_SOURCES=bindparser.yy bindlexer.l \
../../arguments.cc ../../logger.cc zone2sql.cc ../../statbag.cc ../../misc.cc \
../../unix_utility.cc ../../qtype.cc ../../dnspacket.cc \
../../zoneparser-tng.cc ../../dnsrecords.cc ../../sillyrecords.cc \
../../dnswriter.cc ../../rcpgenerator.cc ../../dnsparser.cc ../../base64.cc

zone2ldap_SOURCES=bindparser.yy bindlexer.l \
../../arguments.cc ../../logger.cc zone2ldap.cc ../../statbag.cc ../../misc.cc \
../../unix_utility.cc ../../qtype.cc  ../../zoneparser-tng.cc ../../dnsrecords.cc \
../../dnswriter.cc ../../rcpgenerator.cc ../../dnsparser.cc ../../base64.cc ../../sillyrecords.cc

zone2ldap_LDFLAGS=@THREADFLAGS@

zone2sql_LDFLAGS=@THREADFLAGS@

AM_LFLAGS = -s -i
AM_YFLAGS = -d --verbose --debug
