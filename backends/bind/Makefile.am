INCLUDES=-I../..
noinst_LTLIBRARIES = libbindbackend.la libbind2backend.la

libbindbackend_la_SOURCES=bindbackend.cc bindbackend.hh bindparser.yy \
bindlexer.l zoneparser2.cc ../../misc.cc huffman.cc huffman.hh zoneparser.hh \
bindparser.hh ../../unix_utility.cc


libbind2backend_la_SOURCES=bindbackend2.cc bindbackend2.hh bindparser.yy \
bindlexer.l zoneparser2.cc ../../misc.cc huffman.cc huffman.hh zoneparser.hh \
bindparser.hh ../../unix_utility.cc

bin_PROGRAMS = zone2sql zone2ldap

zone2sql_SOURCES=bindparser.yy bindlexer.l zoneparser2.cc \
../../arguments.cc ../../logger.cc zone2sql.cc ../../statbag.cc ../../misc.cc \
../../unix_utility.cc ../../qtype.cc ../../dnspacket.cc \
../../sillyrecords.cc

zone2ldap_SOURCES=bindparser.yy bindlexer.l zoneparser2.cc \
../../arguments.cc ../../logger.cc zone2ldap.cc ../../statbag.cc ../../misc.cc \
../../unix_utility.cc ../../qtype.cc


zone2ldap_LDFLAGS=@THREADFLAGS@

zone2sql_LDFLAGS=@THREADFLAGS@

LFLAGS = -s -i
YFLAGS = -d --verbose --debug
